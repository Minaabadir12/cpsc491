import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  phone: { type: String, default: "" },
  storageUsed: { type: Number, default: 0 },
  storageLimit: { type: Number, default: 1000 },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, default: null },
  accountStatus: { type: String, default: "Active" },
  uploads: [
    {
      filename: String,
      size: Number,
      uploadedAt: { type: Date, default: Date.now },
    },
  ],
  devices: [
    {
      device: String,
      deviceName: String,
      location: String,
      lastActive: { type: Date, default: Date.now },
    },
  ],
  trustedDevices: [
    {
      deviceToken: { type: String, required: true, unique: true },
      deviceName: String,
      userAgent: String,
      ipAddress: String,
      trustedAt: { type: Date, default: Date.now },
      lastUsed: { type: Date, default: Date.now },
    },
  ],
  deviceAuthEnabled: { type: Boolean, default: false },
  // Password reset
  resetToken: String,
  resetTokenExpires: Date,
  // Device verification
  deviceVerificationCode: String,
  deviceVerificationExpires: Date,
  pendingDeviceToken: String, // Temporarily store device info during verification
  pendingDeviceName: String,
  pendingDeviceUserAgent: String,
  createdAt: { type: Date, default: Date.now },
  sharedLinks: [
    {
      linkId: String,
      filename: String,
      password: String,
      expiresAt: Date,
      createdAt: { type: Date, default: Date.now },
    },
  ],
  // =========================
  // PASSKEYS / BIOMETRICS (WebAuthn)
  // =========================
  currentChallenge: String,
  webauthnCredentials: [
    {
      credentialID: String,     // base64url string
      publicKey: String,        // base64url string
      counter: { type: Number, default: 0 },
      transports: [String],
      createdAt: { type: Date, default: Date.now },
    },
  ],
  // =========================
  // RECENT ACTIVITY TRACKING
  // =========================
  recentActivity: [
    {
      action: {
        type: String,
        enum: ['upload', 'delete', 'share', 'download', 'modify', 'device_added', 'device_removed'],
        required: true
      },
      filename: {
        type: String,
        required: true
      },
    ],

    sharedLinks: [
      {
        linkId: String,
        filename: String,
        password: String,
        expiresAt: Date,
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
      timestamp: {
        type: Date,
        default: Date.now
      },
      // Optional metadata for additional context
      metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    },
  ],
},
{ timestamps: true }
);

export default mongoose.model("User", userSchema);