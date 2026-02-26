// src/routes/webauthn.js
import express from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import User from "../models/User.js";

const router = express.Router();

const rpName = process.env.RP_NAME || "GuardFile";
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || "http://localhost:5173";

/* =========================================================================
   BASE64URL HELPERS (safe for Mongo Buffer objects too)
   ========================================================================= */

function toBase64URL(input) {
  if (!input) return "";

  // already base64url / base64 string
  if (typeof input === "string") {
    // normalize classic base64 -> base64url if needed
    if (input.includes("+") || input.includes("/") || input.includes("=")) {
      try {
        return Buffer.from(input, "base64").toString("base64url");
      } catch {
        return input;
      }
    }
    return input;
  }

  // Buffer
  if (Buffer.isBuffer(input)) return input.toString("base64url");

  // Mongo can store Buffers like: { type: "Buffer", data: [...] }
  if (typeof input === "object" && input.type === "Buffer" && Array.isArray(input.data)) {
    return Buffer.from(input.data).toString("base64url");
  }

  // ArrayBuffer
  if (input instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(input)).toString("base64url");
  }

  // Uint8Array / array-like
  if (input && typeof input === "object" && typeof input.length === "number") {
    return Buffer.from(input).toString("base64url");
  }

  return "";
}

function fromBase64URL(str) {
  if (typeof str !== "string") return Buffer.alloc(0);
  try {
    return Buffer.from(str, "base64url");
  } catch {
    return Buffer.alloc(0);
  }
}

// Some browsers return credential IDs as base64url; normalize for consistent matching
function normalizeCredId(id) {
  if (!id) return "";
  return String(id).replace(/=+$/g, ""); // remove padding just in case
}

function getStoredCredIdString(c) {
  return normalizeCredId(toBase64URL(c?.credentialID));
}

function getStoredPubKeyString(c) {
  // supports either field name + any type (string/buffer/object)
  return toBase64URL(c?.publicKey || c?.credentialPublicKey);
}

/* =========================================================================
   ROUTES
   ========================================================================= */

// ✅ status: does user have any passkey saved?
router.get("/webauthn/status/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select("webauthnCredentials");
    if (!user) return res.status(404).json({ error: "User not found" });

    const creds = (user.webauthnCredentials || [])
      .map((c) => ({
        id: getStoredCredIdString(c),
        pk: getStoredPubKeyString(c),
      }))
      .filter((c) => c.id && c.pk);

    res.json({ hasPasskey: creds.length > 0 });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ 1) Start registration: get options
router.post("/webauthn/register/options", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  try {
    const user = await User.findById(userId).select("email username webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    // exclude existing creds (string base64url)
    const excludeCredentials = (user.webauthnCredentials || [])
      .map((c) => {
        const idStr = getStoredCredIdString(c);
        return idStr
          ? {
              id: idStr,
              type: "public-key",
              transports: c?.transports || [],
            }
          : null;
      })
      .filter(Boolean);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(String(user._id)),
      userName: user.email || user.username,
      timeout: 60000,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    user.currentChallenge = options.challenge;
    await user.save();

    res.json(options);
  } catch (e) {
    console.error("register/options error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ 2) Finish registration: verify + store credential
router.post("/webauthn/register/verify", async (req, res) => {
  const { userId, attResp } = req.body;
  if (!userId || !attResp) return res.status(400).json({ error: "Missing userId or attResp" });

  try {
    const user = await User.findById(userId).select("currentChallenge webauthnCredentials");
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.currentChallenge) return res.status(400).json({ error: "No challenge found. Restart registration." });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: "Registration not verified" });
    }

    // Compatible extraction across SimpleWebAuthn versions
    const credentialID =
      registrationInfo.credentialID ??
      registrationInfo.credential?.id ??
      registrationInfo.credential?.credentialID;

    const credentialPublicKey =
      registrationInfo.credentialPublicKey ??
      registrationInfo.credential?.publicKey ??
      registrationInfo.credential?.credentialPublicKey;

    const counter = registrationInfo.counter ?? registrationInfo.credential?.counter ?? 0;

    if (!credentialID || !credentialPublicKey) {
      console.error("Missing credential fields:", { registrationInfo });
      return res.status(400).json({ error: "Missing credential fields from WebAuthn registrationInfo" });
    }

    const transports = attResp?.transports || attResp?.response?.transports || [];

    const newCred = {
      credentialID: normalizeCredId(toBase64URL(credentialID)),
      publicKey: toBase64URL(credentialPublicKey),
      counter: Number(counter) || 0,
      transports,
      createdAt: new Date(),
    };

    const exists = (user.webauthnCredentials || []).some(
      (c) => getStoredCredIdString(c) === newCred.credentialID
    );
    if (!exists) user.webauthnCredentials.push(newCred);

    user.currentChallenge = null;
    await user.save();

    res.json({ message: "Passkey registered", verified: true });
  } catch (e) {
    console.error("register/verify error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ 3) Start login: get options
router.post("/webauthn/login/options", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  try {
    const user = await User.findById(userId).select("webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const allowCredentials = (user.webauthnCredentials || [])
      .map((c) => {
        const idStr = getStoredCredIdString(c);
        return idStr
          ? {
              id: idStr,
              type: "public-key",
              transports: c?.transports || [],
            }
          : null;
      })
      .filter(Boolean);

    if (allowCredentials.length === 0) {
      return res.status(400).json({ error: "No passkey found for this account" });
    }

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      rpID,
      allowCredentials,
      userVerification: "preferred",
    });

    user.currentChallenge = options.challenge;
    await user.save();

    res.json(options);
  } catch (e) {
    console.error("login/options error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ 4) Finish login: verify + update counter
router.post("/webauthn/login/verify", async (req, res) => {
  const { userId, asseResp } = req.body;
  if (!userId || !asseResp) return res.status(400).json({ error: "Missing userId or asseResp" });

  try {
    const user = await User.findById(userId).select("webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.currentChallenge) return res.status(400).json({ error: "No challenge found. Restart login." });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const incomingId = normalizeCredId(asseResp?.id);

    const cred = (user.webauthnCredentials || []).find((c) => getStoredCredIdString(c) === incomingId);
    if (!cred) return res.status(400).json({ error: "Unknown credential" });

    const credIdStr = getStoredCredIdString(cred);
    const pubKeyStr = getStoredPubKeyString(cred);

    const credentialIDBuf = fromBase64URL(credIdStr);
    const credentialPublicKeyBuf = fromBase64URL(pubKeyStr);

    if (!pubKeyStr || credentialPublicKeyBuf.length === 0) {
      console.error("Login verify: missing/invalid public key:", {
        storedId: credIdStr,
        publicKeyType: typeof cred.publicKey,
      });
      user.currentChallenge = null;
      await user.save();
      return res.status(400).json({ error: "Passkey data is broken (missing public key). Recreate passkey." });
    }

    const verification = await verifyAuthenticationResponse({
      response: asseResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: credentialIDBuf,
        publicKey: credentialPublicKeyBuf,
        counter: Number(cred.counter) || 0,
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    if (!verified) return res.status(400).json({ error: "Authentication not verified" });

    // Update counter if authenticationInfo exists
    if (authenticationInfo?.newCounter !== undefined) {
      cred.counter = authenticationInfo.newCounter;
    }
    
    user.currentChallenge = null;
    await user.save();

    res.json({ message: "Passkey login verified", verified: true });
  } catch (e) {
    console.error("login/verify error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================================================================
   DELETE WITH VERIFICATION (Face ID / Windows Hello)
   ========================================================================= */

// ✅ A) Start delete verification: get options
router.post("/webauthn/delete/options", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  try {
    const user = await User.findById(userId).select("webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const allowCredentials = (user.webauthnCredentials || [])
      .map((c) => {
        const idStr = getStoredCredIdString(c);
        return idStr
          ? {
              id: idStr,
              type: "public-key",
              transports: c?.transports || [],
            }
          : null;
      })
      .filter(Boolean);

    if (allowCredentials.length === 0) {
      return res.status(400).json({ error: "No passkey found for this account" });
    }

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      rpID,
      allowCredentials,
      userVerification: "preferred",
    });

    user.currentChallenge = options.challenge;
    await user.save();

    res.json(options);
  } catch (e) {
    console.error("delete/options error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ B) Verify then delete ALL passkeys
router.post("/webauthn/delete/verify", async (req, res) => {
  const { userId, asseResp } = req.body;
  if (!userId || !asseResp) return res.status(400).json({ error: "Missing userId or asseResp" });

  try {
    const user = await User.findById(userId).select("webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.currentChallenge) return res.status(400).json({ error: "No challenge found. Restart delete." });

    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const incomingId = normalizeCredId(asseResp?.id);

    const cred = (user.webauthnCredentials || []).find((c) => getStoredCredIdString(c) === incomingId);
    if (!cred) {
      user.currentChallenge = null;
      await user.save();
      return res.status(400).json({ error: "Unknown credential. Try again." });
    }

    const credIdStr = getStoredCredIdString(cred);
    const pubKeyStr = getStoredPubKeyString(cred);

    const credentialIDBuf = fromBase64URL(credIdStr);
    const credentialPublicKeyBuf = fromBase64URL(pubKeyStr);

    if (!pubKeyStr || credentialPublicKeyBuf.length === 0) {
      console.error("Delete verify: missing/invalid public key for credential:", {
        storedId: credIdStr,
        hasPublicKeyField: !!cred.publicKey,
        hasAltField: !!cred.credentialPublicKey,
        publicKeyType: typeof cred.publicKey,
      });

      user.currentChallenge = null;
      await user.save();

      return res.status(400).json({
        error: "This passkey is broken in the database (missing public key). Use the legacy delete, then recreate a passkey.",
      });
    }

    const verification = await verifyAuthenticationResponse({
      response: asseResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: credentialIDBuf,
        publicKey: credentialPublicKeyBuf,
        counter: Number(cred.counter) || 0,
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    if (!verified) {
      user.currentChallenge = null;
      await user.save();
      return res.status(400).json({ error: "Authentication not verified" });
    }

    // Update counter if authenticationInfo exists
    if (authenticationInfo?.newCounter !== undefined) {
      cred.counter = authenticationInfo.newCounter;
    }

    // ✅ delete all passkeys after verification
    user.webauthnCredentials = [];
    user.currentChallenge = null;
    await user.save();

    res.json({ message: "All passkeys deleted after verification", deleted: true });
  } catch (e) {
    console.error("delete/verify error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================================================================
   LEGACY DELETE (NO VERIFICATION) - keep for broken/old creds cleanup
   ========================================================================= */
router.delete("/webauthn/credentials/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).select("webauthnCredentials currentChallenge");
    if (!user) return res.status(404).json({ error: "User not found" });

    user.webauthnCredentials = [];
    user.currentChallenge = null;

    await user.save();

    res.json({ message: "All passkeys deleted", deleted: true });
  } catch (e) {
    console.error("delete passkeys error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;



