import webauthnRoutes from "./routes/webauthn.js";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import cors from "cors";
import multer from "multer";
import path from "path";
import fs from "fs";
import fsp from "fs/promises";
import crypto from "crypto";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { execFile } from "child_process";
import { promisify } from "util";
import authRoutes from "./routes/auth.js";
import User from "./models/User.js";
import dotenv from "dotenv";
import { nanoid } from "nanoid";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
dotenv.config();

// ------------------- SPEAKER VERIFICATION MODEL -------------------
// WavLM fine-tuned on VoxCeleb1 for speaker identity.
// Audio models have no tokenizer — use AutoProcessor + AutoModel directly.
let _speakerProcessor = null;
let _speakerModel = null;

async function getSpeakerExtractor() {
  if (!_speakerModel) {
    const { AutoProcessor, AutoModel } = await import("@xenova/transformers");
    console.log("Loading speaker verification model (first run downloads ~90MB)...");
    _speakerProcessor = await AutoProcessor.from_pretrained("Xenova/wavlm-base-plus-sv");
    _speakerModel = await AutoModel.from_pretrained("Xenova/wavlm-base-plus-sv");
    console.log("Speaker verification model ready.");
  }
  return { model: _speakerModel, processor: _speakerProcessor };
}

async function extractSpeakerEmbedding(audioFloat32) {
  const { model, processor } = await getSpeakerExtractor();
  const inputs = await processor(audioFloat32, { sampling_rate: 16000 });
  const output = await model(inputs);

  // Mean-pool the last hidden state over time: [1, T, 768] -> [768]
  if (output.last_hidden_state) {
    return Array.from(output.last_hidden_state.mean(1).data);
  }
  // Some fine-tuned variants expose a compact embedding via logits
  if (output.logits) {
    return Array.from(output.logits.data);
  }
  throw new Error("Speaker model returned no usable output");
}

// Pre-load model at startup so the first request isn't slow
getSpeakerExtractor().catch((err) =>
  console.error("Speaker model preload failed:", err)
);

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-CHANGE-THIS-IN-PRODUCTION";
const execFileAsync = promisify(execFile);

const uploadRootDir = "uploads";
const quarantineDir = path.join(uploadRootDir, "quarantine");
const cleanDir = path.join(uploadRootDir, "clean");
if (!fs.existsSync(uploadRootDir)) fs.mkdirSync(uploadRootDir);
if (!fs.existsSync(quarantineDir)) fs.mkdirSync(quarantineDir);
if (!fs.existsSync(cleanDir)) fs.mkdirSync(cleanDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, quarantineDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

const upload = multer({ storage });

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));
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

async function recordFailedAuth(user, reason = "failed_login") {
  if (!user) return;
  if (!user.authMetrics) {
    user.authMetrics = {
      failedLoginCount: 0,
      lastFailedLoginAt: null,
      lastSuccessfulLoginAt: null,
    };
  }
  user.authMetrics.failedLoginCount = (user.authMetrics.failedLoginCount || 0) + 1;
  user.authMetrics.lastFailedLoginAt = new Date();
  await user.save();

  const label = user.email || user.username || "Unknown User";
  await logActivity(user._id.toString(), "modify", label, { authEvent: reason });
}

async function recordSuccessfulAuth(user, reason = "login_success") {
  if (!user) return;
  if (!user.authMetrics) {
    user.authMetrics = {
      failedLoginCount: 0,
      lastFailedLoginAt: null,
      lastSuccessfulLoginAt: null,
    };
  }
  user.authMetrics.failedLoginCount = 0;
  user.authMetrics.lastSuccessfulLoginAt = new Date();
  await user.save();
  await logActivity(user._id.toString(), "modify", "Authentication", { authEvent: reason });
}

function normalizeEmbedding(embedding) {
  const arr = Array.isArray(embedding) ? embedding.map(Number) : [];
  if (arr.length < 8 || arr.length > 2048) return null;
  if (arr.some((n) => !Number.isFinite(n))) return null;

  let mag = 0;
  for (const v of arr) mag += v * v;
  mag = Math.sqrt(mag);
  if (!mag) return null;

  return arr.map((v) => v / mag);
}

function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return -1;
  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (!denom) return -1;
  return dot / denom;
}

const scanQueue = [];
let scanWorkerRunning = false;
const scanCache = new Map();
let scannerStatusCache = null;
let scannerStatusCacheAt = 0;
let resolvedClamScanPath = null;

function getClamScanExecutable() {
  if (resolvedClamScanPath) return resolvedClamScanPath;

  const candidates = [
    process.env.CLAMSCAN_PATH,
    "C:\\Program Files\\ClamAV\\clamscan.exe",
    "C:\\Program Files (x86)\\ClamAV\\clamscan.exe",
  ].filter(Boolean);

  for (const bin of candidates) {
    if (fs.existsSync(bin)) {
      resolvedClamScanPath = bin;
      return bin;
    }
  }

  // Fallback to PATH-based lookup if no known absolute path is found.
  resolvedClamScanPath = "clamscan";
  return resolvedClamScanPath;
}

function parseClamOutput(stdout = "") {
  const text = String(stdout || "").trim();
  if (!text) return { status: "error", engine: "clamav", signature: "no-output" };

  if (text.endsWith("OK")) {
    return { status: "clean", engine: "clamav", signature: null };
  }

  const foundMatch = text.match(/: (.+) FOUND$/m);
  if (foundMatch) {
    return { status: "infected", engine: "clamav", signature: foundMatch[1] };
  }

  if (text.includes("FOUND")) {
    return { status: "infected", engine: "clamav", signature: "malware-found" };
  }

  return { status: "error", engine: "clamav", signature: "unparsed-output" };
}

async function computeFileHash(filePath) {
  const hash = crypto.createHash("sha256");
  const data = await fsp.readFile(filePath);
  hash.update(data);
  return hash.digest("hex");
}

async function fallbackSignatureScan(filePath) {
  const fileBuffer = await fsp.readFile(filePath);
  const eicar = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  if (fileBuffer.includes(eicar)) {
    return { status: "infected", engine: "fallback-signature", signature: "EICAR-Test-File" };
  }
  return { status: "clean", engine: "fallback-signature", signature: null };
}

async function runMalwareScan(filePath) {
  const clamscanBin = getClamScanExecutable();
  try {
    const { stdout } = await execFileAsync(clamscanBin, ["--no-summary", "--stdout", filePath], {
      timeout: 120000,
    });
    return parseClamOutput(stdout);
  } catch (err) {
    const out = `${err?.stdout || ""}\n${err?.stderr || ""}`.trim();
    if (out.includes("FOUND")) {
      return parseClamOutput(out);
    }

    if (err?.code === "ENOENT") {
      return fallbackSignatureScan(filePath);
    }

    return { status: "error", engine: "clamav", signature: err?.message || "scan-failed" };
  }
}

async function getScannerStatus() {
  const cacheAgeMs = Date.now() - scannerStatusCacheAt;
  if (scannerStatusCache && cacheAgeMs < 60000) {
    return scannerStatusCache;
  }

  try {
    const clamscanBin = getClamScanExecutable();
    const { stdout } = await execFileAsync(clamscanBin, ["--version"], { timeout: 5000 });
    const versionLine = String(stdout || "").trim().split(/\r?\n/)[0] || "ClamAV";
    const shortVersionMatch = versionLine.match(/ClamAV\s+([0-9.]+)/i);
    const shortDetails = shortVersionMatch ? `ClamAV ${shortVersionMatch[1]}` : "ClamAV Active";
    scannerStatusCache = {
      mode: "clamav",
      active: true,
      details: shortDetails,
      checkedAt: new Date().toISOString(),
    };
  } catch {
    scannerStatusCache = {
      mode: "fallback-signature",
      active: false,
      details: "ClamAV unavailable; fallback scanner in use",
      checkedAt: new Date().toISOString(),
    };
  }

  scannerStatusCacheAt = Date.now();
  return scannerStatusCache;
}

function daysSince(dateLike) {
  if (!dateLike) return null;
  const value = new Date(dateLike).getTime();
  if (Number.isNaN(value)) return null;
  return Math.floor((Date.now() - value) / (1000 * 60 * 60 * 24));
}

function computeSecurityScore(user, scannerStatus) {
  let score = 0;
  const reasons = [];

  if (user.twoFactorEnabled) {
    score += 20;
    reasons.push({ impact: +20, reason: "2FA enabled" });
  } else {
    reasons.push({ impact: 0, reason: "2FA disabled" });
  }

  const passkeyCount = Array.isArray(user.webauthnCredentials) ? user.webauthnCredentials.length : 0;
  if (passkeyCount > 0) {
    score += 15;
    reasons.push({ impact: +15, reason: `Passkeys enrolled (${passkeyCount})` });
  }

  if (user.voiceBiometrics?.enabled && user.voiceBiometrics?.loginRequired) {
    score += 15;
    reasons.push({ impact: +15, reason: "Voice login required" });
  } else if (user.voiceBiometrics?.enabled) {
    score += 8;
    reasons.push({ impact: +8, reason: "Voice biometrics enabled" });
  }

  if (user.deviceAuthEnabled) {
    score += 10;
    reasons.push({ impact: +10, reason: "Device authentication enabled" });
  }

  const pwdAge = daysSince(user.passwordChangedAt || user.createdAt);
  if (pwdAge === null || pwdAge <= 90) {
    score += 10;
    reasons.push({ impact: +10, reason: "Password changed within 90 days" });
  } else if (pwdAge <= 180) {
    score += 5;
    reasons.push({ impact: +5, reason: "Password age between 91 and 180 days" });
  } else {
    reasons.push({ impact: 0, reason: "Password older than 180 days" });
  }

  const failedCount = user.authMetrics?.failedLoginCount || 0;
  if (failedCount === 0) {
    score += 10;
    reasons.push({ impact: +10, reason: "No recent failed logins" });
  } else if (failedCount <= 2) {
    score += 4;
    reasons.push({ impact: +4, reason: "Low failed-login count" });
  } else {
    const penalty = Math.min(20, failedCount * 3);
    score -= penalty;
    reasons.push({ impact: -penalty, reason: `Recent failed logins (${failedCount})` });
  }

  const lockUntil = user.voiceBiometrics?.lockUntil;
  if (lockUntil && new Date(lockUntil) > new Date()) {
    score -= 15;
    reasons.push({ impact: -15, reason: "Voice login currently locked" });
  }

  const blockedUploads = (user.uploads || []).filter((u) => u.scanStatus === "infected").length;
  if (blockedUploads > 0) {
    const penalty = Math.min(15, blockedUploads * 5);
    score -= penalty;
    reasons.push({ impact: -penalty, reason: `Blocked malware uploads (${blockedUploads})` });
  } else {
    score += 10;
    reasons.push({ impact: +10, reason: "No blocked malware uploads" });
  }

  if (scannerStatus?.active) {
    score += 10;
    reasons.push({ impact: +10, reason: "ClamAV active" });
  } else {
    score -= 10;
    reasons.push({ impact: -10, reason: "Fallback scanner mode" });
  }

  const trustedDevices = Array.isArray(user.trustedDevices) ? user.trustedDevices.length : 0;
  if (trustedDevices > 10) {
    score -= 5;
    reasons.push({ impact: -5, reason: "Many trusted devices registered" });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";

  return { score, grade, reasons };
}

async function moveFileSafe(fromPath, toPath) {
  try {
    await fsp.rename(fromPath, toPath);
  } catch (err) {
    if (err?.code !== "EXDEV") throw err;
    await fsp.copyFile(fromPath, toPath);
    await fsp.unlink(fromPath);
  }
}

function enqueueScanJob(job) {
  scanQueue.push(job);
  processScanQueue();
}

async function processScanQueue() {
  if (scanWorkerRunning) return;
  scanWorkerRunning = true;

  while (scanQueue.length > 0) {
    const job = scanQueue.shift();
    try {
      await handleScanJob(job);
    } catch (err) {
      console.error("Scan job failed:", err);
    }
  }

  scanWorkerRunning = false;
}

async function handleScanJob({ userId, filename }) {
  const user = await User.findById(userId);
  if (!user) return;

  const fileEntry = user.uploads.find((u) => u.filename === filename);
  if (!fileEntry) return;

  const quarantinePath = fileEntry.quarantinePath || path.join(quarantineDir, filename);
  if (!fs.existsSync(quarantinePath)) {
    fileEntry.scanStatus = "error";
    fileEntry.scannedAt = new Date();
    fileEntry.scanEngine = "none";
    fileEntry.scanSignature = "file-missing-in-quarantine";
    await user.save();
    return;
  }

  const sha256 = await computeFileHash(quarantinePath);
  fileEntry.sha256 = sha256;

  let result = scanCache.get(sha256);
  if (!result) {
    result = await runMalwareScan(quarantinePath);
    if (result.status === "clean" || result.status === "infected") {
      scanCache.set(sha256, result);
    }
  }

  fileEntry.scanStatus = result.status;
  fileEntry.scanEngine = result.engine || null;
  fileEntry.scanSignature = result.signature || null;
  fileEntry.scannedAt = new Date();
  if (!Array.isArray(user.recentActivity)) user.recentActivity = [];

  if (result.status === "clean") {
    const cleanPath = path.join(cleanDir, filename);
    await moveFileSafe(quarantinePath, cleanPath);
    fileEntry.cleanPath = cleanPath;
    fileEntry.quarantinePath = null;
    user.recentActivity.unshift({
      action: "modify",
      filename,
      timestamp: new Date(),
      metadata: { scanStatus: "clean", engine: result.engine },
    });
  } else if (result.status === "infected") {
    fileEntry.cleanPath = null;
    fileEntry.quarantinePath = quarantinePath;
    user.recentActivity.unshift({
      action: "modify",
      filename,
      timestamp: new Date(),
      metadata: {
        scanStatus: "infected",
        signature: result.signature,
        engine: result.engine,
      },
    });
  } else {
    fileEntry.cleanPath = null;
    fileEntry.quarantinePath = quarantinePath;
    user.recentActivity.unshift({
      action: "modify",
      filename,
      timestamp: new Date(),
      metadata: {
        scanStatus: "error",
        reason: result.signature,
        engine: result.engine,
      },
    });
  }

  if (user.recentActivity.length > 50) {
    user.recentActivity = user.recentActivity.slice(0, 50);
  }

  await user.save();
}

const VOICE_LOCK_MINUTES = 15;
const VOICE_MAX_CHALLENGE_ATTEMPTS = 3;

function issueAuthToken(user) {
  return jwt.sign(
    { userId: user._id, username: user.username },
    JWT_SECRET,
    { expiresIn: "10m" }
  );
}

function shouldRequireVoiceLogin(user) {
  const vb = user?.voiceBiometrics;
  return !!(
    vb?.enabled &&
    vb?.loginRequired &&
    Array.isArray(vb.embeddings) &&
    vb.embeddings.length > 0
  );
}

function isVoiceLocked(user) {
  const lockUntil = user?.voiceBiometrics?.lockUntil;
  return !!(lockUntil && new Date(lockUntil) > new Date());
}

function generateVoiceChallengePhrase() {
  const phrases = [
    "GuardFile protects my files",
    "My voice confirms this login",
    "I am signing in to GuardFile",
    "Security first with GuardFile",
    "This is my secure login phrase",
  ];
  const pick = phrases[Math.floor(Math.random() * phrases.length)];
  const nonce = String(Math.floor(100 + Math.random() * 900));
  return `${pick} ${nonce}`;
}

async function prepareVoiceLoginChallenge(user) {
  const challengeId = nanoid(24);
  const phrase = generateVoiceChallengePhrase();
  const expiresAt = new Date(Date.now() + 2 * 60 * 1000);

  if (!user.voiceBiometrics) {
    user.voiceBiometrics = {
      enabled: false,
      loginRequired: false,
      threshold: 0.9,
      phrase: "My voice unlocks GuardFile",
      embeddings: [],
    };
  }

  user.voiceBiometrics.pendingChallenge = {
    challengeId,
    phrase,
    expiresAt,
    attempts: 0,
  };

  await user.save();

  return {
    requiresVoice: true,
    email: user.email,
    challengeId,
    phrase,
    expiresAt,
    message: "Voice verification required",
  };
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
    const newUser = new User({
      username,
      email,
      password_hash: hashedPassword,
      passwordChangedAt: new Date(),
    });
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
    if (!match) {
      await recordFailedAuth(user, "password_invalid");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      return res.json({
        requiresTwoFactor: true,
        message: "2FA verification required",
        email: user.email,
      });
    }

    if (shouldRequireVoiceLogin(user)) {
      if (isVoiceLocked(user)) {
        return res.status(423).json({
          error: "Voice login is temporarily locked due to repeated failed attempts",
          lockUntil: user.voiceBiometrics.lockUntil,
        });
      }

      const voiceChallenge = await prepareVoiceLoginChallenge(user);
      return res.json(voiceChallenge);
    }

    const token = issueAuthToken(user);
    await recordSuccessfulAuth(user, "password_login");

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
    user.passwordChangedAt = new Date();
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
  
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    let totalAddedSize = 0;
    const uploadedFiles = [];
    
    req.files.forEach(file => {
      const fileSizeMB = file.size / 1024 / 1024;
      user.uploads.push({
        filename: file.filename,
        size: fileSizeMB,
        uploadedAt: new Date(),
        scanStatus: "pending",
        quarantinePath: path.join(quarantineDir, file.filename),
        cleanPath: null,
      });
      totalAddedSize += fileSizeMB;
      uploadedFiles.push(file.filename);
    });

    user.storageUsed += totalAddedSize;
    await user.save();

    // Log activity for each uploaded file
    for (const filename of uploadedFiles) {
      await logActivity(userId, 'upload', filename);
      enqueueScanJob({ userId, filename });
    }

    res.json({
      message: "Files uploaded. Security scan in progress.",
      storageUsed: user.storageUsed,
      uploads: user.uploads,
    });
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

    const storedPath = file.cleanPath || file.quarantinePath || path.join(cleanDir, filename);
    if (storedPath && fs.existsSync(storedPath)) fs.unlinkSync(storedPath);

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

    // Refresh last-used whenever we recognize a previously trusted device.
    if (!user.trustedDevices) {
      user.trustedDevices = [];
    }
    const trustedDevice = user.trustedDevices.find(d => d.deviceToken === deviceToken);
    if (trustedDevice) {
      trustedDevice.lastUsed = new Date();
      await user.save();
    }
    
    // If device auth is not enabled, allow all devices
    // Handle undefined as false
    if (!user.deviceAuthEnabled || user.deviceAuthEnabled === undefined) {
      return res.json({ trusted: true, deviceAuthEnabled: false });
    }

    if (trustedDevice) {
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

app.get("/api/security/scanner-status", authenticateToken, async (req, res) => {
  try {
    const status = await getScannerStatus();
    res.json(status);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to read scanner status" });
  }
});

app.get("/api/security/score/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId).select(
      "twoFactorEnabled webauthnCredentials voiceBiometrics deviceAuthEnabled passwordChangedAt createdAt authMetrics uploads trustedDevices"
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    const scannerStatus = await getScannerStatus();
    const result = computeSecurityScore(user, scannerStatus);

    res.json({
      ...result,
      scannerMode: scannerStatus.mode,
      scannerDetails: scannerStatus.details,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to compute security score" });
  }
});

// ------------------- VOICE BIOMETRICS -------------------

app.get("/api/voice/status/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId).select("voiceBiometrics");
    if (!user) return res.status(404).json({ error: "User not found" });

    const vb = user.voiceBiometrics || {};
    const sampleCount = Array.isArray(vb.embeddings) ? vb.embeddings.length : 0;

    res.json({
      enabled: !!vb.enabled,
      loginRequired: !!vb.loginRequired,
      threshold: typeof vb.threshold === "number" ? vb.threshold : 0.9,
      phrase: vb.phrase || "My voice unlocks GuardFile",
      sampleCount,
      lastVerifiedAt: vb.lastVerifiedAt || null,
      lockUntil: vb.lockUntil || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch voice biometrics status" });
  }
});

app.post("/api/voice/enroll/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { audioData, phrase } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!Array.isArray(audioData) || audioData.length < 1000) {
    return res.status(400).json({ error: "Invalid audio data" });
  }

  let normalized;
  try {
    const embedding = await extractSpeakerEmbedding(Float32Array.from(audioData));
    normalized = normalizeEmbedding(embedding);
  } catch (err) {
    console.error("Embedding extraction failed:", err);
    return res.status(500).json({ error: "Failed to extract voice embedding" });
  }
  if (!normalized) {
    return res.status(400).json({ error: "Invalid voice embedding" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.voiceBiometrics) {
      user.voiceBiometrics = {
        enabled: true,
        phrase: "My voice unlocks GuardFile",
        embeddings: [],
      };
    }

    if (!Array.isArray(user.voiceBiometrics.embeddings)) {
      user.voiceBiometrics.embeddings = [];
    }

    user.voiceBiometrics.enabled = true;
    if (typeof user.voiceBiometrics.threshold !== "number") {
      user.voiceBiometrics.threshold = 0.82;
    }
    if (phrase && typeof phrase === "string") {
      user.voiceBiometrics.phrase = phrase.slice(0, 140).trim() || user.voiceBiometrics.phrase;
    }

    user.voiceBiometrics.embeddings.push({
      vector: normalized,
      createdAt: new Date(),
    });

    if (user.voiceBiometrics.embeddings.length > 5) {
      user.voiceBiometrics.embeddings = user.voiceBiometrics.embeddings.slice(-5);
    }

    if (user.voiceBiometrics.embeddings.length >= 5) {
      user.voiceBiometrics.loginRequired = true;
    }

    await user.save();
    await logActivity(userId, "voice_enrolled", "Voice biometrics");

    res.json({
      message: "Voice sample enrolled",
      enabled: true,
      loginRequired: !!user.voiceBiometrics.loginRequired,
      sampleCount: user.voiceBiometrics.embeddings.length,
      phrase: user.voiceBiometrics.phrase,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to enroll voice sample" });
  }
});

app.post("/api/voice/verify/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { audioData } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  if (!Array.isArray(audioData) || audioData.length < 1000) {
    return res.status(400).json({ error: "Invalid audio data" });
  }

  let normalized;
  try {
    const embedding = await extractSpeakerEmbedding(Float32Array.from(audioData));
    normalized = normalizeEmbedding(embedding);
  } catch (err) {
    console.error("Embedding extraction failed:", err);
    return res.status(500).json({ error: "Failed to extract voice embedding" });
  }
  if (!normalized) {
    return res.status(400).json({ error: "Invalid voice embedding" });
  }

  try {
    const user = await User.findById(userId).select("voiceBiometrics");
    if (!user) return res.status(404).json({ error: "User not found" });

    const samples = user.voiceBiometrics?.embeddings || [];
    if (!samples.length) {
      return res.status(400).json({ error: "No voice samples enrolled" });
    }

    const validVectors = samples
      .map((s) => normalizeEmbedding(s?.vector))
      .filter(Boolean);

    if (!validVectors.length) {
      return res.status(400).json({ error: "Stored voice profile is invalid. Re-enroll required." });
    }

    if (validVectors[0].length !== normalized.length) {
      return res.status(400).json({ error: "Voice profile is outdated. Please re-enroll your voice in Settings." });
    }

    let totalScore = 0;
    for (const vec of validVectors) {
      totalScore += cosineSimilarity(normalized, vec);
    }
    const bestScore = totalScore / validVectors.length;

    const threshold = Number(user.voiceBiometrics?.threshold) || 0.82;
    const verified = bestScore >= threshold;

    if (verified) {
      user.voiceBiometrics.enabled = true;
      user.voiceBiometrics.lastVerifiedAt = new Date();
      await user.save();
      await logActivity(userId, "voice_verified", "Voice biometrics", { score: Number(bestScore.toFixed(4)) });
    } else {
      await logActivity(userId, "voice_failed", "Voice biometrics", { score: Number(bestScore.toFixed(4)) });
    }

    res.json({
      verified,
      score: Number(bestScore.toFixed(4)),
      threshold,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify voice sample" });
  }
});

app.delete("/api/voice/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.voiceBiometrics = {
      enabled: false,
      loginRequired: false,
      threshold: 0.9,
      phrase: "My voice unlocks GuardFile",
      embeddings: [],
      pendingChallenge: {
        challengeId: null,
        phrase: null,
        expiresAt: null,
        attempts: 0,
      },
      failedAttempts: 0,
      lockUntil: null,
      lastVerifiedAt: null,
    };

    await user.save();
    await logActivity(userId, "voice_removed", "Voice biometrics");

    res.json({ message: "Voice biometrics removed" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to remove voice biometrics" });
  }
});

app.patch("/api/voice/login-setting/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { loginRequired, threshold } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.voiceBiometrics) {
      user.voiceBiometrics = {
        enabled: false,
        loginRequired: false,
        threshold: 0.9,
        phrase: "My voice unlocks GuardFile",
        embeddings: [],
      };
    }

    if (typeof loginRequired === "boolean") {
      if (loginRequired) {
        const sampleCount = Array.isArray(user.voiceBiometrics.embeddings)
          ? user.voiceBiometrics.embeddings.length
          : 0;
        if (!user.voiceBiometrics.enabled || sampleCount < 3) {
          return res.status(400).json({ error: "Enroll at least 3 voice samples before enabling voice login" });
        }
      }
      user.voiceBiometrics.loginRequired = loginRequired;
    }

    if (threshold !== undefined) {
      const t = Number(threshold);
      if (!Number.isFinite(t) || t < 0.75 || t > 0.99) {
        return res.status(400).json({ error: "Threshold must be between 0.75 and 0.99" });
      }
      user.voiceBiometrics.threshold = Number(t.toFixed(2));
    }

    await user.save();
    res.json({
      message: "Voice login settings updated",
      loginRequired: !!user.voiceBiometrics.loginRequired,
      threshold: user.voiceBiometrics.threshold || 0.9,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update voice login settings" });
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

    // Clear 2FA settings
    user.twoFactorSecret = null;
    user.twoFactorEnabled = false;
    await user.save();

    res.json({ message: "2FA disabled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// VERIFY 2FA DURING LOGIN
app.post("/login/verify-2fa", async (req, res) => {
  const { email, twoFactorToken } = req.body;

  if (!email || !twoFactorToken) {
    return res.status(400).json({ error: "Email and 2FA code are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: "2FA is not enabled for this account" });
    }

    // Verify the 2FA token
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: twoFactorToken,
      window: 1,
    });

    if (!verified) {
      await recordFailedAuth(user, "2fa_invalid");
      return res.status(401).json({ error: "Invalid 2FA code" });
    }

    if (shouldRequireVoiceLogin(user)) {
      if (isVoiceLocked(user)) {
        return res.status(423).json({
          error: "Voice login is temporarily locked due to repeated failed attempts",
          lockUntil: user.voiceBiometrics.lockUntil,
        });
      }

      const voiceChallenge = await prepareVoiceLoginChallenge(user);
      return res.json(voiceChallenge);
    }

    const token = issueAuthToken(user);
    await recordSuccessfulAuth(user, "2fa_login");

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

app.post("/login/verify-voice", async (req, res) => {
  const { email, challengeId, audioData } = req.body;

  if (!email || !challengeId || !audioData) {
    return res.status(400).json({ error: "Email, challengeId, and audioData are required" });
  }

  if (!Array.isArray(audioData) || audioData.length < 1000) {
    return res.status(400).json({ error: "Invalid audio data" });
  }

  let normalized;
  try {
    const embedding = await extractSpeakerEmbedding(Float32Array.from(audioData));
    normalized = normalizeEmbedding(embedding);
  } catch (err) {
    console.error("Embedding extraction failed:", err);
    return res.status(500).json({ error: "Failed to extract voice embedding" });
  }
  if (!normalized) {
    return res.status(400).json({ error: "Invalid voice embedding" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    if (!shouldRequireVoiceLogin(user)) {
      return res.status(400).json({ error: "Voice login is not enabled for this account" });
    }

    if (isVoiceLocked(user)) {
      return res.status(423).json({
        error: "Voice login is temporarily locked due to repeated failed attempts",
        lockUntil: user.voiceBiometrics.lockUntil,
      });
    }

    const pending = user.voiceBiometrics?.pendingChallenge;
    if (!pending?.challengeId || pending.challengeId !== challengeId) {
      return res.status(400).json({ error: "Voice challenge is invalid or expired. Restart login." });
    }

    if (!pending.expiresAt || new Date(pending.expiresAt) < new Date()) {
      user.voiceBiometrics.pendingChallenge = {
        challengeId: null,
        phrase: null,
        expiresAt: null,
        attempts: 0,
      };
      await user.save();
      return res.status(400).json({ error: "Voice challenge expired. Restart login." });
    }

    const validVectors = (user.voiceBiometrics.embeddings || [])
      .map((s) => normalizeEmbedding(s?.vector))
      .filter(Boolean);

    if (!validVectors.length) {
      return res.status(400).json({ error: "No valid voice profile found. Re-enroll voice biometrics." });
    }

    if (validVectors[0].length !== normalized.length) {
      // Stale profile from before the feature upgrade — reset and let the user in
      // so they can re-enroll from Settings without being permanently locked out.
      user.voiceBiometrics = {
        enabled: false,
        loginRequired: false,
        embeddings: [],
        threshold: 0.82,
        failedAttempts: 0,
        lockUntil: null,
        pendingChallenge: { challengeId: null, phrase: null, expiresAt: null, attempts: 0 },
        phrase: "My voice unlocks GuardFile",
      };
      await user.save();
      await logActivity(user._id.toString(), "voice_removed", "Voice login", { reason: "outdated_profile_auto_reset" });
      const token = issueAuthToken(user);
      await recordSuccessfulAuth(user, "password_login");
      return res.json({
        message: "Login successful. Your voice profile was outdated and has been reset — please re-enroll in Settings.",
        token,
        userId: user._id,
        username: user.username,
        voiceReenrollRequired: true,
      });
    }

    let totalScore = 0;
    for (const vec of validVectors) {
      totalScore += cosineSimilarity(normalized, vec);
    }
    const bestScore = totalScore / validVectors.length;

    const threshold = Number(user.voiceBiometrics?.threshold) || 0.82;
    const verified = bestScore >= threshold;

    if (!verified) {
      user.voiceBiometrics.failedAttempts = (user.voiceBiometrics.failedAttempts || 0) + 1;
      user.voiceBiometrics.pendingChallenge.attempts = (user.voiceBiometrics.pendingChallenge.attempts || 0) + 1;

      const attemptsUsed = user.voiceBiometrics.pendingChallenge.attempts;
      const attemptsRemaining = Math.max(0, VOICE_MAX_CHALLENGE_ATTEMPTS - attemptsUsed);

      if (
        user.voiceBiometrics.failedAttempts >= 5 ||
        attemptsUsed >= VOICE_MAX_CHALLENGE_ATTEMPTS
      ) {
        user.voiceBiometrics.lockUntil = new Date(Date.now() + VOICE_LOCK_MINUTES * 60 * 1000);
        user.voiceBiometrics.pendingChallenge = {
          challengeId: null,
          phrase: null,
          expiresAt: null,
          attempts: 0,
        };
      }

      await user.save();
      await logActivity(user._id.toString(), "voice_failed", "Voice login", {
        score: Number(bestScore.toFixed(4)),
      });
      await recordFailedAuth(user, "voice_invalid");

      return res.status(401).json({
        error: "Voice verification failed",
        verified: false,
        score: Number(bestScore.toFixed(4)),
        threshold,
        attemptsRemaining,
        lockUntil: user.voiceBiometrics.lockUntil || null,
      });
    }

    user.voiceBiometrics.failedAttempts = 0;
    user.voiceBiometrics.lockUntil = null;
    user.voiceBiometrics.lastVerifiedAt = new Date();
    user.voiceBiometrics.pendingChallenge = {
      challengeId: null,
      phrase: null,
      expiresAt: null,
      attempts: 0,
    };
    await user.save();

    await logActivity(user._id.toString(), "voice_verified", "Voice login", {
      score: Number(bestScore.toFixed(4)),
    });

    const token = issueAuthToken(user);
    await recordSuccessfulAuth(user, "voice_login");
    return res.json({
      message: "Voice verified. Login successful",
      token,
      userId: user._id,
      username: user.username,
      score: Number(bestScore.toFixed(4)),
      threshold,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------- FILE SHARING -------------------

// CREATE SHARE LINK - PROTECTED
app.post("/api/share/:userId/:filename", authenticateToken, async (req, res) => {
  const { userId, filename } = req.params;
  const { expiresIn, password } = req.body;

  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check if file exists in user's uploads
    const file = user.uploads.find(f => f.filename === filename);
    if (!file) return res.status(404).json({ error: "File not found" });
    if (file.scanStatus !== "clean") {
      return res.status(400).json({ error: "File is not available for sharing until malware scan passes" });
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
    const uploadedFile = (user.uploads || []).find((u) => u.filename === shareLink.filename);
    const unavailable = !uploadedFile || uploadedFile.scanStatus !== "clean";

    // Get display name (remove timestamp prefix)
    const displayName = shareLink.filename.replace(/^\d+-/, '');

    res.json({
      filename: displayName,
      requiresPassword: !!shareLink.password,
      expired,
      unavailable,
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

    const uploadedFile = (user.uploads || []).find((u) => u.filename === shareLink.filename);
    if (!uploadedFile || uploadedFile.scanStatus !== "clean") {
      return res.status(403).json({ error: "File is not available for download" });
    }

    // Serve the file
    const filePath = uploadedFile.cleanPath || path.join(cleanDir, shareLink.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found on server" });
    }

    // Log download activity (note: this logs for the file owner, not the downloader)
    await logActivity(user._id.toString(), 'download', shareLink.filename, { via: 'share-link', linkId });

    // Get display name for download
    const displayName = shareLink.filename.replace(/^\d+-/, '');
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

// SERVE UPLOADED FILES
app.use("/uploads", express.static(cleanDir));

app.listen(3000, () => console.log("Server running on port 3000"));
