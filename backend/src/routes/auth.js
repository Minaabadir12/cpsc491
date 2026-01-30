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
 * STEP 2 — Reset password using token
 * POST /resetpassword/:token
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

export default router;
