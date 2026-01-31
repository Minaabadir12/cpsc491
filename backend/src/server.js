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
  
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    let totalAddedSize = 0;
    req.files.forEach(file => {
      const fileSizeMB = file.size / 1024 / 1024;
      user.uploads.push({ filename: file.filename, size: fileSizeMB, uploadedAt: new Date() });
      totalAddedSize += fileSizeMB;
    });

    user.storageUsed += totalAddedSize;
    await user.save();

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
    
    user.trustedDevices = user.trustedDevices.filter(d => d.deviceToken !== deviceToken);
    await user.save();
    
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
app.use("/uploads", express.static(uploadDir));

app.listen(3000, () => console.log("Server running on port 3000"));