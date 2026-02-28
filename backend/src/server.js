import webauthnRoutes from "./routes/webauthn.js";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import cors from "cors";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import authRoutes from "./routes/auth.js";
import User from "./models/User.js";
import dotenv from "dotenv";
import { nanoid } from "nanoid";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-CHANGE-THIS-IN-PRODUCTION";

const uploadDir = "uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

const upload = multer({ storage });

const app = express();

app.use(cors());
app.use(express.json());
app.use(webauthnRoutes);
app.use(authRoutes);

// ------------------- HELPER FUNCTIONS -------------------
// Activity logging helper
async function logActivity(userId, action, filename, metadata = {}) {
  try {
    const user = await User.findById(userId);
    if (!user) return;

    // Initialize recentActivity array if it doesn't exist
    if (!user.recentActivity) {
      user.recentActivity = [];
    }

    // Add new activity
    user.recentActivity.unshift({
      action,
      filename,
      timestamp: new Date(),
      ...metadata
    });

    // Keep only the last 50 activities
    if (user.recentActivity.length > 50) {
      user.recentActivity = user.recentActivity.slice(0, 50);
    }

    await user.save();
  } catch (err) {
    console.error("Failed to log activity:", err);
  }
}

// ------------------- MIDDLEWARE -------------------
// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: "No token provided" });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// ------------------- MONGODB -------------------
const mongoURI =
  "mongodb+srv://dylansm37:Mypassword123@guardfile.6pvvat8.mongodb.net/guardfile?retryWrites=true&w=majority";

mongoose.connect(mongoURI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch(err => console.error("MongoDB connection error:", err));

// ------------------- ROUTES -------------------
app.get("/", (req, res) => res.send("Backend running"));

// SIGNUP
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password_hash: hashedPassword });
    await newUser.save();
    res.json({ message: "Signup successful" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "User already exists or invalid data" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    // Check if any 2FA method is enabled
    const methods = user.twoFactorMethods || {};
    const enabledMethods = [];
    if (methods.totp?.enabled || (user.twoFactorEnabled && user.twoFactorSecret)) {
      enabledMethods.push("totp");
    }
    if (methods.email?.enabled) {
      enabledMethods.push("email");
    }

    if (enabledMethods.length > 0) {
      return res.json({
        requiresTwoFactor: true,
        message: "2FA verification required",
        email: user.email,
        enabledMethods,
      });
    }

    // Create JWT token with 10 min expiration
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.json({
      message: "Login successful",
      token,
      userId: user._id,
      username: user.username
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// REFRESH TOKEN - extends session on activity
app.post("/refresh-token", authenticateToken, (req, res) => {
  const newToken = jwt.sign(
    { userId: req.user.userId, username: req.user.username },
    JWT_SECRET,
    { expiresIn: '10m' }
  );
  
  res.json({ token: newToken });
});

// DASHBOARD FETCH - PROTECTED
app.get("/api/dashboard/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  
  // Verify the userId matches the token
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId).select("-password_hash");
    if (!user) return res.status(404).json({ message: "User not found" });
    
    // Initialize recentActivity if it doesn't exist
    if (!user.recentActivity) {
      user.recentActivity = [];
    }
    
    res.json(user.toObject());
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// UPDATE PHONE NUMBER - PROTECTED
app.patch("/api/users/:userId/phone", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { phone } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!phone) return res.status(400).json({ error: "Phone number is required" });

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.phone = phone;
    await user.save();

    res.json({ message: "Phone number updated", phone: user.phone });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update phone number" });
  }
});

// UPDATE PASSWORD - PROTECTED
app.patch("/api/users/:userId/password", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { oldPassword, newPassword } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "Old and new passwords are required" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const match = await bcrypt.compare(oldPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: "Old password is incorrect" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password_hash = hashedPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update password" });
  }
});

// UPLOAD FILES - PROTECTED
app.post("/api/upload/:userId", authenticateToken, upload.array("files"), async (req, res) => {
  const { userId } = req.params;
  const { encryptionMode, encryptionPassword } = req.body;
  const mode = encryptionMode || "none";

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (mode === "password" && !encryptionPassword) {
    return res.status(400).json({ error: "Password required for password encryption" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    let totalAddedSize = 0;
    const uploadedFiles = [];

    for (const file of req.files) {
      const filePath = path.join(uploadDir, file.filename);
      const fileSizeMB = file.size / 1024 / 1024;
      let encryptionMeta = { encryptionMode: mode };

      if (mode === "password") {
        const fileBuffer = fs.readFileSync(filePath);
        const salt = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);
        const key = crypto.pbkdf2Sync(encryptionPassword, salt, 100000, 32, "sha256");
        const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        const authTag = cipher.getAuthTag();
        fs.writeFileSync(filePath, encrypted);

        encryptionMeta.encryptionSalt = salt.toString("hex");
        encryptionMeta.encryptionIV = iv.toString("hex");
        encryptionMeta.encryptionTag = authTag.toString("hex");
      } else if (mode === "passkey") {
        const fileBuffer = fs.readFileSync(filePath);
        const randomKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", randomKey, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        const authTag = cipher.getAuthTag();
        fs.writeFileSync(filePath, encrypted);

        encryptionMeta.encryptionKey = randomKey.toString("hex");
        encryptionMeta.encryptionIV = iv.toString("hex");
        encryptionMeta.encryptionTag = authTag.toString("hex");
      }

      user.uploads.push({
        filename: file.filename,
        size: fileSizeMB,
        uploadedAt: new Date(),
        ...encryptionMeta,
      });
      totalAddedSize += fileSizeMB;
      uploadedFiles.push(file.filename);
    }

    user.storageUsed += totalAddedSize;
    await user.save();

    // Log activity for each uploaded file
    for (const filename of uploadedFiles) {
      await logActivity(userId, 'upload', filename);
    }

    res.json({ message: "Files uploaded successfully", storageUsed: user.storageUsed, uploads: user.uploads });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// DELETE FILE - PROTECTED
app.delete("/api/files/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });

    const filePath = path.join(uploadDir, filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    user.uploads = user.uploads.filter(f => f.filename !== filename);
    user.storageUsed -= file.size;
    await user.save();

    // Log delete activity
    await logActivity(userId, 'delete', filename);

    res.json({ message: "File deleted", storageUsed: user.storageUsed, uploads: user.uploads });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Delete failed" });
  }
});



// CHECK IF DEVICE IS TRUSTED
app.post("/check-device", async (req, res) => {
  const { email, deviceToken } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    
    // If device auth is not enabled, allow all devices
    // Handle undefined as false
    if (!user.deviceAuthEnabled || user.deviceAuthEnabled === undefined) {
      return res.json({ trusted: true, deviceAuthEnabled: false });
    }
    
    // Initialize trustedDevices array if it doesn't exist
    if (!user.trustedDevices) {
      user.trustedDevices = [];
    }
    
    // Check if device is in trusted list
    const trustedDevice = user.trustedDevices.find(d => d.deviceToken === deviceToken);
    
    if (trustedDevice) {
      // Update last used time
      trustedDevice.lastUsed = new Date();
      await user.save();
      return res.json({ trusted: true, deviceAuthEnabled: true });
    }
    
    return res.json({ trusted: false, deviceAuthEnabled: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// TRUST NEW DEVICE
app.post("/trust-device", async (req, res) => {
  const { email, deviceToken, deviceName, userAgent } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    
    // Initialize trustedDevices array if it doesn't exist
    if (!user.trustedDevices) {
      user.trustedDevices = [];
    }
    
    // Check if device already trusted
    const alreadyTrusted = user.trustedDevices.find(d => d.deviceToken === deviceToken);
    if (alreadyTrusted) {
      return res.json({ message: "Device already trusted" });
    }
    
    // Add device to trusted list
    user.trustedDevices.push({
      deviceToken,
      deviceName,
      userAgent,
      ipAddress: req.ip || req.connection.remoteAddress,
      trustedAt: new Date(),
      lastUsed: new Date(),
    });
    
    await user.save();
    
    // Log activity for adding trusted device
    await logActivity(user._id.toString(), 'device_added', deviceName || 'New Device', {
      deviceToken,
      userAgent,
      ipAddress: req.ip || req.connection.remoteAddress
    });
    
    res.json({ message: "Device trusted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// REMOVE TRUSTED DEVICE
app.delete("/api/users/:userId/trusted-devices/:deviceToken", authenticateToken, async (req, res) => {
  const { userId, deviceToken } = req.params;
  
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    // Find the device before removing it
    const deviceToRemove = user.trustedDevices.find(d => d.deviceToken === deviceToken);
    
    user.trustedDevices = user.trustedDevices.filter(d => d.deviceToken !== deviceToken);
    await user.save();
    
    // Log activity for removing trusted device
    if (deviceToRemove) {
      await logActivity(userId, 'device_removed', deviceToRemove.deviceName || 'Device', {
        deviceToken,
        userAgent: deviceToRemove.userAgent
      });
    }
    
    res.json({ message: "Device removed", trustedDevices: user.trustedDevices });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to remove device" });
  }
});

// TOGGLE DEVICE AUTH FEATURE
app.patch("/api/users/:userId/device-auth", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { enabled } = req.body;
  
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    user.deviceAuthEnabled = enabled;
    await user.save();
    
    res.json({ message: "Device auth setting updated", deviceAuthEnabled: user.deviceAuthEnabled });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update setting" });
  }
});

// ------------------- TWO-FACTOR AUTHENTICATION -------------------

// SETUP 2FA - Generate secret and QR code
app.post("/api/2fa/setup/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Generate a new secret
    const secret = speakeasy.generateSecret({
      name: `GuardFile:${user.email}`,
      issuer: "GuardFile",
      length: 20,
    });

    // Generate QR code as data URL
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Return secret and QR code (don't save yet - user must verify first)
    res.json({
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      otpauthUrl: secret.otpauth_url,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to setup 2FA" });
  }
});

// VERIFY 2FA SETUP - Confirm code from authenticator works
app.post("/api/2fa/verify-setup/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { secret, token } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!secret || !token) {
    return res.status(400).json({ error: "Secret and token are required" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: token,
      window: 1, // Allow 1 step before/after for clock drift
    });

    if (!verified) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    // Save secret and enable 2FA
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
    if (!user.twoFactorMethods) user.twoFactorMethods = {};
    user.twoFactorMethods.totp = { enabled: true, secret: secret };
    user.markModified("twoFactorMethods");
    await user.save();

    res.json({ message: "2FA enabled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify 2FA setup" });
  }
});

// DISABLE 2FA
app.post("/api/2fa/disable/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { password } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!password) {
    return res.status(400).json({ error: "Password is required to disable 2FA" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Verify password before disabling
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    // Clear TOTP 2FA settings
    user.twoFactorSecret = null;
    user.twoFactorEnabled = false;
    if (!user.twoFactorMethods) user.twoFactorMethods = {};
    user.twoFactorMethods.totp = { enabled: false, secret: null };
    // Check if any other method is still enabled
    const emailEnabled = user.twoFactorMethods.email?.enabled || false;
    if (emailEnabled) {
      user.twoFactorEnabled = true;
    }
    user.markModified("twoFactorMethods");
    await user.save();

    res.json({ message: "TOTP 2FA disabled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// ------------------- EMAIL 2FA -------------------

// SETUP EMAIL 2FA - Send verification code to email
app.post("/api/2fa/email/setup/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Store code with 10 min expiry
    user.twoFactorCode = code;
    user.twoFactorCodeExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.twoFactorCodeMethod = "setup-email";
    await user.save();

    // Send email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `GuardFile <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Enable Email 2FA - GuardFile",
      html: `
        <p>Hello <b>${user.username}</b>,</p>
        <p>You are enabling Email Two-Factor Authentication.</p>
        <p>Your verification code is:</p>
        <h2 style="background: #f0f0f0; padding: 15px; text-align: center; letter-spacing: 5px; font-family: monospace;">${code}</h2>
        <p>This code expires in 10 minutes.</p>
      `,
    });

    res.json({ message: "Verification code sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

// VERIFY EMAIL 2FA SETUP
app.post("/api/2fa/email/verify-setup/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { code } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!code) {
    return res.status(400).json({ error: "Verification code is required" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check code
    if (!user.twoFactorCode || !user.twoFactorCodeExpires) {
      return res.status(400).json({ error: "No verification code found. Please request a new one." });
    }

    if (new Date() > new Date(user.twoFactorCodeExpires)) {
      return res.status(400).json({ error: "Code expired. Please request a new one." });
    }

    if (user.twoFactorCode !== code) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    // Enable email 2FA
    if (!user.twoFactorMethods) user.twoFactorMethods = {};
    user.twoFactorMethods.email = { enabled: true };
    user.twoFactorEnabled = true;
    user.twoFactorCode = null;
    user.twoFactorCodeExpires = null;
    user.twoFactorCodeMethod = null;
    user.markModified("twoFactorMethods");
    await user.save();

    res.json({ message: "Email 2FA enabled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify email 2FA setup" });
  }
});

// DISABLE EMAIL 2FA
app.post("/api/2fa/email/disable/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { password } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!password) {
    return res.status(400).json({ error: "Password is required to disable 2FA" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    // Disable email 2FA
    if (!user.twoFactorMethods) user.twoFactorMethods = {};
    user.twoFactorMethods.email = { enabled: false };
    // Check if TOTP is still enabled
    const totpEnabled = user.twoFactorMethods.totp?.enabled || false;
    if (!totpEnabled) {
      user.twoFactorEnabled = false;
    }
    user.markModified("twoFactorMethods");
    await user.save();

    res.json({ message: "Email 2FA disabled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to disable email 2FA" });
  }
});

// VERIFY 2FA DURING LOGIN (supports totp and email methods)
app.post("/login/verify-2fa", async (req, res) => {
  const { email, twoFactorToken, method } = req.body;

  if (!email || !twoFactorToken) {
    return res.status(400).json({ error: "Email and 2FA code are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const selectedMethod = method || "totp";
    let verified = false;

    if (selectedMethod === "totp") {
      if (!user.twoFactorSecret) {
        return res.status(400).json({ error: "TOTP is not enabled" });
      }
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: twoFactorToken,
        window: 1,
      });
    } else if (selectedMethod === "email") {
      // Verify against stored email code
      if (!user.twoFactorCode || !user.twoFactorCodeExpires) {
        return res.status(400).json({ error: "No email code sent. Please request a code first." });
      }
      if (new Date() > new Date(user.twoFactorCodeExpires)) {
        return res.status(400).json({ error: "Code expired. Please request a new code." });
      }
      verified = user.twoFactorCode === twoFactorToken;
    }

    if (!verified) {
      return res.status(401).json({ error: "Invalid 2FA code" });
    }

    // Clear email code after successful verification
    if (selectedMethod === "email") {
      user.twoFactorCode = null;
      user.twoFactorCodeExpires = null;
      user.twoFactorCodeMethod = null;
      await user.save();
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.json({
      message: "Login successful",
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// SEND 2FA CODE VIA EMAIL (during login)
app.post("/login/send-2fa-code", async (req, res) => {
  const { email, method } = req.body;

  if (!email || !method) {
    return res.status(400).json({ error: "Email and method are required" });
  }

  if (method !== "email") {
    return res.status(400).json({ error: "Only email method is supported" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const methods = user.twoFactorMethods || {};
    if (!methods.email?.enabled) {
      return res.status(400).json({ error: "Email 2FA is not enabled" });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Store code with 10 min expiry
    user.twoFactorCode = code;
    user.twoFactorCodeExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.twoFactorCodeMethod = "email";
    await user.save();

    // Send email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `GuardFile <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Your GuardFile Verification Code",
      html: `
        <p>Hello <b>${user.username}</b>,</p>
        <p>Your verification code is:</p>
        <h2 style="background: #f0f0f0; padding: 15px; text-align: center; letter-spacing: 5px; font-family: monospace;">${code}</h2>
        <p>This code expires in 10 minutes.</p>
        <p>If you didn't request this code, please ignore this email.</p>
      `,
    });

    res.json({ message: "Verification code sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

// ------------------- FILE SHARING -------------------

// CREATE SHARE LINK - PROTECTED
app.post("/api/share/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  const { expiresIn, password, encryptionPassword } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check if file exists in user's uploads
    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });

    // Handle encrypted file sharing
    let decryptionKey = null;
    if (file.encryptionMode === "password") {
      if (!encryptionPassword) {
        return res.status(400).json({ error: "Encryption password required to share this file" });
      }
      // Verify the encryption password by attempting to derive the key and test decryption
      const filePath = path.join(uploadDir, filename);
      const encryptedData = fs.readFileSync(filePath);
      const salt = Buffer.from(file.encryptionSalt, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");
      const key = crypto.pbkdf2Sync(encryptionPassword, salt, 100000, 32, "sha256");

      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authTag);
        decipher.update(encryptedData);
        decipher.final(); // will throw if password is wrong
      } catch (decryptErr) {
        return res.status(401).json({ error: "Incorrect encryption password" });
      }

      // Store the derived key so the share download can decrypt
      decryptionKey = key.toString("hex");
    } else if (file.encryptionMode === "passkey") {
      // For passkey encryption, the key is already stored in the DB
      decryptionKey = file.encryptionKey;
    }

    // Calculate expiration date
    const expirationMs = {
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    const expiresAt = new Date(Date.now() + (expirationMs[expiresIn] || expirationMs["24h"]));

    // Generate unique link ID
    const linkId = nanoid(12);

    // Hash password if provided
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    // Add share link to user's sharedLinks array
    user.sharedLinks.push({
      linkId,
      filename,
      password: hashedPassword,
      expiresAt,
      createdAt: new Date(),
      decryptionKey,
    });
    await user.save();

    // Log share activity
    await logActivity(userId, 'share', filename, { linkId, expiresAt });

    res.json({
      message: "Share link created",
      linkId,
      expiresAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create share link" });
  }
});

// GET SHARED FILE INFO - PUBLIC
app.get("/api/shared/:linkId", async (req, res) => {
  const { linkId } = req.params;

  try {
    // Find the user with this share link
    const user = await User.findOne({ "sharedLinks.linkId": linkId });
    if (!user) return res.status(404).json({ error: "Share link not found" });

    const shareLink = user.sharedLinks.find(sl => sl.linkId === linkId);
    if (!shareLink) return res.status(404).json({ error: "Share link not found" });

    // Check if expired
    const expired = new Date() > new Date(shareLink.expiresAt);

    // Get display name (remove timestamp prefix)
    const displayName = shareLink.filename.replace(/^\d+-/, '');

    res.json({
      filename: displayName,
      requiresPassword: !!shareLink.password,
      expired,
      expiresAt: shareLink.expiresAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to get share info" });
  }
});

// DOWNLOAD SHARED FILE - PUBLIC
app.post("/api/shared/:linkId/download", async (req, res) => {
  const { linkId } = req.params;
  const { password } = req.body;

  try {
    // Find the user with this share link
    const user = await User.findOne({ "sharedLinks.linkId": linkId });
    if (!user) return res.status(404).json({ error: "Share link not found" });

    const shareLink = user.sharedLinks.find(sl => sl.linkId === linkId);
    if (!shareLink) return res.status(404).json({ error: "Share link not found" });

    // Check if expired
    if (new Date() > new Date(shareLink.expiresAt)) {
      return res.status(410).json({ error: "Share link has expired" });
    }

    // Check password if required
    if (shareLink.password) {
      if (!password) {
        return res.status(401).json({ error: "Password required" });
      }
      const match = await bcrypt.compare(password, shareLink.password);
      if (!match) {
        return res.status(401).json({ error: "Incorrect password" });
      }
    }

    // Serve the file
    const filePath = path.join(uploadDir, shareLink.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found on server" });
    }

    // Log download activity (note: this logs for the file owner, not the downloader)
    await logActivity(user._id.toString(), 'download', shareLink.filename, { via: 'share-link', linkId });

    // Get display name for download
    const displayName = shareLink.filename.replace(/^\d+-/, '');

    // If the file is encrypted and we have a decryption key, decrypt on the fly
    if (shareLink.decryptionKey) {
      const file = user.uploads.find(f => f.filename === shareLink.filename);
      if (file && file.encryptionIV && file.encryptionTag) {
        const encryptedData = fs.readFileSync(filePath);
        const key = Buffer.from(shareLink.decryptionKey, "hex");
        const iv = Buffer.from(file.encryptionIV, "hex");
        const authTag = Buffer.from(file.encryptionTag, "hex");

        try {
          const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
          decipher.setAuthTag(authTag);
          const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

          res.setHeader("Content-Disposition", `attachment; filename="${displayName}"`);
          res.setHeader("Content-Type", "application/octet-stream");
          return res.send(decrypted);
        } catch (decryptErr) {
          console.error("Share decryption failed:", decryptErr);
          return res.status(500).json({ error: "Failed to decrypt file for sharing" });
        }
      }
    }

    res.download(filePath, displayName);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to download file" });
  }
});

// REVOKE SHARE LINK - PROTECTED
app.delete("/api/share/:userId/:linkId", authenticateToken, async (req, res) => {
  const { userId, linkId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const linkIndex = user.sharedLinks.findIndex(sl => sl.linkId === linkId);
    if (linkIndex === -1) {
      return res.status(404).json({ error: "Share link not found" });
    }

    user.sharedLinks.splice(linkIndex, 1);
    await user.save();

    res.json({ message: "Share link revoked" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to revoke share link" });
  }
});

// DOWNLOAD FILE (handles encrypted files) - PROTECTED
app.post("/api/download/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  const { password, webauthnVerified } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });

    const filePath = path.join(uploadDir, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found on disk" });

    const displayName = filename.replace(/^\d+-/, "");

    if (!file.encryptionMode || file.encryptionMode === "none") {
      return res.download(filePath, displayName);
    }

    // Determine MIME type from file extension
    const ext = path.extname(displayName).toLowerCase();
    const mimeTypes = {
      ".pdf": "application/pdf",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".gif": "image/gif",
      ".webp": "image/webp",
      ".svg": "image/svg+xml",
      ".txt": "text/plain",
      ".html": "text/html",
    };
    const contentType = mimeTypes[ext] || "application/octet-stream";
    const isViewable = ext in mimeTypes;
    const disposition = isViewable ? "inline" : "attachment";

    if (file.encryptionMode === "password") {
      if (!password) return res.status(400).json({ error: "Password required to decrypt" });

      const encryptedData = fs.readFileSync(filePath);
      const salt = Buffer.from(file.encryptionSalt, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");
      const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");

      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

        res.setHeader("Content-Disposition", `${disposition}; filename="${displayName}"`);
        res.setHeader("Content-Type", contentType);
        await logActivity(userId, "download", filename);
        return res.send(decrypted);
      } catch (decryptErr) {
        return res.status(401).json({ error: "Incorrect password" });
      }
    }

    if (file.encryptionMode === "passkey") {
      if (!webauthnVerified) {
        return res.status(403).json({ error: "Passkey authentication required", requiresPasskey: true });
      }

      const encryptedData = fs.readFileSync(filePath);
      const key = Buffer.from(file.encryptionKey, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

      res.setHeader("Content-Disposition", `${disposition}; filename="${displayName}"`);
      res.setHeader("Content-Type", contentType);
      await logActivity(userId, "download", filename);
      return res.send(decrypted);
    }

    return res.status(400).json({ error: "Unknown encryption mode" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Download failed" });
  }
});

// SERVE UPLOADED FILES (unencrypted files only - encrypted files served via /api/download)
app.use("/uploads", express.static(uploadDir));

// ------------------- FILE SHARING -------------------

// CREATE SHARE LINK - PROTECTED
app.post("/api/share/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  const { expiresIn, password, encryptionPassword } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check if file exists in user's uploads
    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });

    // Handle encrypted file sharing
    let decryptionKey = null;
    if (file.encryptionMode === "password") {
      if (!encryptionPassword) {
        return res.status(400).json({ error: "Encryption password required to share this file" });
      }
      // Verify the encryption password by attempting to derive the key and test decryption
      const filePath = path.join(uploadDir, filename);
      const encryptedData = fs.readFileSync(filePath);
      const salt = Buffer.from(file.encryptionSalt, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");
      const key = crypto.pbkdf2Sync(encryptionPassword, salt, 100000, 32, "sha256");

      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authTag);
        decipher.update(encryptedData);
        decipher.final(); // will throw if password is wrong
      } catch (decryptErr) {
        return res.status(401).json({ error: "Incorrect encryption password" });
      }

      // Store the derived key so the share download can decrypt
      decryptionKey = key.toString("hex");
    } else if (file.encryptionMode === "passkey") {
      // For passkey encryption, the key is already stored in the DB
      decryptionKey = file.encryptionKey;
    }

    // Calculate expiration date
    const expirationMs = {
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    const expiresAt = new Date(Date.now() + (expirationMs[expiresIn] || expirationMs["24h"]));

    // Generate unique link ID
    const linkId = nanoid(12);

    // Hash password if provided
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    // Add share link to user's sharedLinks array
    user.sharedLinks.push({
      linkId,
      filename,
      password: hashedPassword,
      expiresAt,
      createdAt: new Date(),
      decryptionKey,
    });
    await user.save();

    // Log share activity
    await logActivity(userId, 'share', filename, { linkId, expiresAt });

    res.json({
      message: "Share link created",
      linkId,
      expiresAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create share link" });
  }
});

// GET SHARED FILE INFO - PUBLIC
app.get("/api/shared/:linkId", async (req, res) => {
  const { linkId } = req.params;

  try {
    // Find the user with this share link
    const user = await User.findOne({ "sharedLinks.linkId": linkId });
    if (!user) return res.status(404).json({ error: "Share link not found" });

    const shareLink = user.sharedLinks.find(sl => sl.linkId === linkId);
    if (!shareLink) return res.status(404).json({ error: "Share link not found" });

    // Check if expired
    const expired = new Date() > new Date(shareLink.expiresAt);

    // Get display name (remove timestamp prefix)
    const displayName = shareLink.filename.replace(/^\d+-/, '');

    res.json({
      filename: displayName,
      requiresPassword: !!shareLink.password,
      expired,
      expiresAt: shareLink.expiresAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to get share info" });
  }
});

// DOWNLOAD SHARED FILE - PUBLIC
app.post("/api/shared/:linkId/download", async (req, res) => {
  const { linkId } = req.params;
  const { password } = req.body;

  try {
    // Find the user with this share link
    const user = await User.findOne({ "sharedLinks.linkId": linkId });
    if (!user) return res.status(404).json({ error: "Share link not found" });

    const shareLink = user.sharedLinks.find(sl => sl.linkId === linkId);
    if (!shareLink) return res.status(404).json({ error: "Share link not found" });

    // Check if expired
    if (new Date() > new Date(shareLink.expiresAt)) {
      return res.status(410).json({ error: "Share link has expired" });
    }

    // Check password if required
    if (shareLink.password) {
      if (!password) {
        return res.status(401).json({ error: "Password required" });
      }
      const match = await bcrypt.compare(password, shareLink.password);
      if (!match) {
        return res.status(401).json({ error: "Incorrect password" });
      }
    }

    // Serve the file
    const filePath = path.join(uploadDir, shareLink.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found on server" });
    }

    // Log download activity (note: this logs for the file owner, not the downloader)
    await logActivity(user._id.toString(), 'download', shareLink.filename, { via: 'share-link', linkId });

    // Get display name for download
    const displayName = shareLink.filename.replace(/^\d+-/, '');

    // If the file is encrypted and we have a decryption key, decrypt on the fly
    if (shareLink.decryptionKey) {
      const file = user.uploads.find(f => f.filename === shareLink.filename);
      if (file && file.encryptionIV && file.encryptionTag) {
        const encryptedData = fs.readFileSync(filePath);
        const key = Buffer.from(shareLink.decryptionKey, "hex");
        const iv = Buffer.from(file.encryptionIV, "hex");
        const authTag = Buffer.from(file.encryptionTag, "hex");

        try {
          const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
          decipher.setAuthTag(authTag);
          const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

          res.setHeader("Content-Disposition", `attachment; filename="${displayName}"`);
          res.setHeader("Content-Type", "application/octet-stream");
          return res.send(decrypted);
        } catch (decryptErr) {
          console.error("Share decryption failed:", decryptErr);
          return res.status(500).json({ error: "Failed to decrypt file for sharing" });
        }
      }
    }

    res.download(filePath, displayName);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to download file" });
  }
});

// REVOKE SHARE LINK - PROTECTED
app.delete("/api/share/:userId/:linkId", authenticateToken, async (req, res) => {
  const { userId, linkId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const linkIndex = user.sharedLinks.findIndex(sl => sl.linkId === linkId);
    if (linkIndex === -1) {
      return res.status(404).json({ error: "Share link not found" });
    }

    user.sharedLinks.splice(linkIndex, 1);
    await user.save();

    res.json({ message: "Share link revoked" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to revoke share link" });
  }
});

// DOWNLOAD FILE (handles encrypted files) - PROTECTED
app.post("/api/download/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  const { password, webauthnVerified } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });

    const filePath = path.join(uploadDir, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found on disk" });

    const displayName = filename.replace(/^\d+-/, "");

    if (!file.encryptionMode || file.encryptionMode === "none") {
      return res.download(filePath, displayName);
    }

    // Determine MIME type from file extension
    const ext = path.extname(displayName).toLowerCase();
    const mimeTypes = {
      ".pdf": "application/pdf",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".gif": "image/gif",
      ".webp": "image/webp",
      ".svg": "image/svg+xml",
      ".txt": "text/plain",
      ".html": "text/html",
    };
    const contentType = mimeTypes[ext] || "application/octet-stream";
    const isViewable = ext in mimeTypes;
    const disposition = isViewable ? "inline" : "attachment";

    if (file.encryptionMode === "password") {
      if (!password) return res.status(400).json({ error: "Password required to decrypt" });

      const encryptedData = fs.readFileSync(filePath);
      const salt = Buffer.from(file.encryptionSalt, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");
      const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");

      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

        res.setHeader("Content-Disposition", `${disposition}; filename="${displayName}"`);
        res.setHeader("Content-Type", contentType);
        await logActivity(userId, "download", filename);
        return res.send(decrypted);
      } catch (decryptErr) {
        return res.status(401).json({ error: "Incorrect password" });
      }
    }

    if (file.encryptionMode === "passkey") {
      if (!webauthnVerified) {
        return res.status(403).json({ error: "Passkey authentication required", requiresPasskey: true });
      }

      const encryptedData = fs.readFileSync(filePath);
      const key = Buffer.from(file.encryptionKey, "hex");
      const iv = Buffer.from(file.encryptionIV, "hex");
      const authTag = Buffer.from(file.encryptionTag, "hex");

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

      res.setHeader("Content-Disposition", `${disposition}; filename="${displayName}"`);
      res.setHeader("Content-Type", contentType);
      await logActivity(userId, "download", filename);
      return res.send(decrypted);
    }

    return res.status(400).json({ error: "Unknown encryption mode" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Download failed" });
  }
});

// SERVE UPLOADED FILES (unencrypted files only - encrypted files served via /api/download)
app.use("/uploads", express.static(uploadDir));

app.listen(3000, () => console.log("Server running on port 3000"));