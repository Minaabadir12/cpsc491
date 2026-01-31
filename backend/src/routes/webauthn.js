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

// ---- base64url helpers (store as strings in MongoDB) ----
function toBase64URL(input) {
  // If it's already a base64url string, keep it
  if (typeof input === "string") return input;

  // Buffer
  if (Buffer.isBuffer(input)) return input.toString("base64url");

  // ArrayBuffer
  if (input instanceof ArrayBuffer) return Buffer.from(new Uint8Array(input)).toString("base64url");

  // Uint8Array / array-like
  if (input && typeof input === "object" && typeof input.length === "number") {
    return Buffer.from(input).toString("base64url");
  }

  return "";
}

function fromBase64URL(str) {
  if (typeof str !== "string") return Buffer.alloc(0);
  return Buffer.from(str, "base64url");
}

// ✅ status: does user have any passkey saved?
router.get("/webauthn/status/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select("webauthnCredentials");
    if (!user) return res.status(404).json({ error: "User not found" });

    // ✅ ADD: only count valid creds
    const creds = (user.webauthnCredentials || []).filter(
      (c) => c && typeof c.credentialID === "string" && c.credentialID.length > 0 && typeof c.publicKey === "string"
    );

    const hasPasskey = creds.length > 0;
    res.json({ hasPasskey });
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

    // ✅ ADD: ensure array exists (older users may not have this field yet)
    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    // ✅ FIX: SimpleWebAuthn expects base64url STRING ids here (not Buffers)
    // ✅ Also skip any bad/old entries
    const excludeCredentials = (user.webauthnCredentials || [])
      .filter((c) => c && typeof c.credentialID === "string" && c.credentialID.length > 0)
      .map((c) => ({
        id: c.credentialID, // ✅ string (base64url)
        type: "public-key",
        transports: c.transports || [],
      }));

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

    // ✅ ADD: ensure array exists (older users may not have this field yet)
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

    // ✅ ADD: compatible extraction across SimpleWebAuthn versions
    const credentialID =
      registrationInfo.credentialID ??
      registrationInfo.credential?.id ??
      registrationInfo.credential?.credentialID;

    const credentialPublicKey =
      registrationInfo.credentialPublicKey ??
      registrationInfo.credential?.publicKey ??
      registrationInfo.credential?.credentialPublicKey;

    const counter = registrationInfo.counter ?? registrationInfo.credential?.counter ?? 0;

    // ✅ ADD: guard before Buffer.from(...) (fixes crash)
    if (!credentialID || !credentialPublicKey) {
      console.error("Missing credential fields:", { registrationInfo });
      return res.status(400).json({ error: "Missing credential fields from WebAuthn registrationInfo" });
    }

    // ✅ ADD: transports can be in different places depending on browser/lib
    const transports = attResp?.transports || attResp?.response?.transports || [];

    const newCred = {
      credentialID: toBase64URL(credentialID),          // ✅ safe now
      publicKey: toBase64URL(credentialPublicKey),      // ✅ safe now
      counter: counter || 0,
      transports,
      createdAt: new Date(),
    };

    const exists = (user.webauthnCredentials || []).some((c) => c.credentialID === newCred.credentialID);
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

    // ✅ ADD: ensure array exists
    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    // ✅ FIX: SimpleWebAuthn expects base64url STRING ids here (not Buffers)
    // ✅ Also skip any bad/old entries
    const allowCredentials = (user.webauthnCredentials || [])
      .filter((c) => c && typeof c.credentialID === "string" && c.credentialID.length > 0)
      .map((c) => ({
        id: c.credentialID, // ✅ string (base64url)
        type: "public-key",
        transports: c.transports || [],
      }));

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

    // ✅ ADD: ensure array exists
    if (!Array.isArray(user.webauthnCredentials)) user.webauthnCredentials = [];

    const credID = asseResp?.id;
    const cred = (user.webauthnCredentials || []).find((c) => c.credentialID === credID);
    if (!cred) return res.status(400).json({ error: "Unknown credential" });

    const verification = await verifyAuthenticationResponse({
      response: asseResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: fromBase64URL(cred.credentialID),
        credentialPublicKey: fromBase64URL(cred.publicKey),
        counter: cred.counter || 0,
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    if (!verified || !authenticationInfo) return res.status(400).json({ error: "Authentication not verified" });

    cred.counter = authenticationInfo.newCounter;
    user.currentChallenge = null;
    await user.save();

    res.json({ message: "Passkey login verified", verified: true });
  } catch (e) {
    console.error("login/verify error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;



