import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import nodemailer from "nodemailer";
import User from "../models/User.js";

const router = express.Router();

router.post("/resetpassword", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const user = await User.findOne({ email });

    //  CHANGE: return ERROR if user does not exist
    if (!user) {
      return res.status(404).json({ error: "User does not exist" });
    }

    const token = crypto.randomBytes(32).toString("hex");

    user.resetToken = token;
    user.resetTokenExpires = Date.now() + 60 * 60 * 1000; // 1 hour
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `${process.env.FRONTEND_URL}/newpassword/${token}`;

    await transporter.sendMail({
      from: `GuardFile <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Reset Your GuardFile Password",
      html: `
        <p>Hello <b>${user.username}</b>,</p>
        <p>You requested a password reset.</p>
        <p>
          <a href="${resetLink}">Reset Password</a>
        </p>
        <p>This link expires in 1 hour.</p>
      `,
    });

    //  Only success if email actually sent
    return res.status(200).json({ message: "Email sent" });

  } catch (err) {
    console.error("Reset email error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});


/**
  Reset password using token
 
 */
router.post("/resetpassword/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired reset link" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.password_hash = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;

    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Password reset error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// SEND DEVICE VERIFICATION CODE
router.post("/send-device-verification", async (req, res) => {
  const { email, deviceToken, deviceName, userAgent } = req.body;

  if (!email || !deviceToken) {
    return res.status(400).json({ error: "Email and device token required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate 6-digit code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Store code and pending device info
    user.deviceVerificationCode = verificationCode;
    user.deviceVerificationExpires = Date.now() + 15 * 60 * 1000; // 15 minutes
    user.pendingDeviceToken = deviceToken;
    user.pendingDeviceName = deviceName;
    user.pendingDeviceUserAgent = userAgent;
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
      subject: "Device Verification Code - GuardFile",
      html: `
        <p>Hello <b>${user.username}</b>,</p>
        <p>A login attempt was made from a new device:</p>
        <p><b>${deviceName || "Unknown Device"}</b></p>
        <p>Your verification code is:</p>
        <h2 style="background: #f0f0f0; padding: 15px; text-align: center; letter-spacing: 5px;">${verificationCode}</h2>
        <p>This code expires in 15 minutes.</p>
        <p>If you didn't attempt to log in, please change your password immediately.</p>
      `,
    });

    res.json({ message: "Verification code sent to your email" });
  } catch (err) {
    console.error("Device verification email error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// VERIFY DEVICE CODE
router.post("/verify-device-code", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: "Email and code required" });
  }

  try {
    const user = await User.findOne({
      email,
      deviceVerificationCode: code,
      deviceVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired verification code" });
    }

    // Initialize trustedDevices if needed
    if (!user.trustedDevices) {
      user.trustedDevices = [];
    }

    // Add device to trusted list
    user.trustedDevices.push({
      deviceToken: user.pendingDeviceToken,
      deviceName: user.pendingDeviceName,
      userAgent: user.pendingDeviceUserAgent,
      ipAddress: req.ip || req.connection.remoteAddress,
      trustedAt: new Date(),
      lastUsed: new Date(),
    });

    // Clear verification data
    user.deviceVerificationCode = undefined;
    user.deviceVerificationExpires = undefined;
    user.pendingDeviceToken = undefined;
    user.pendingDeviceName = undefined;
    user.pendingDeviceUserAgent = undefined;

    await user.save();

    res.json({ message: "Device verified and trusted successfully" });
  } catch (err) {
    console.error("Device verification error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
