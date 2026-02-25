import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  passwordChangedAt: { type: Date, default: Date.now },
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
      scanStatus: {
        type: String,
        enum: ["pending", "clean", "infected", "error"],
        default: "pending",
      },
      scanEngine: { type: String, default: null },
      scanSignature: { type: String, default: null },
      scannedAt: { type: Date, default: null },
      quarantinePath: { type: String, default: null },
      cleanPath: { type: String, default: null },
      sha256: { type: String, default: null },
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
        enum: ['upload', 'delete', 'share', 'download', 'modify', 'device_added', 'device_removed', 'voice_enrolled', 'voice_verified', 'voice_failed', 'voice_removed'],
        required: true
      },
      filename: {
        type: String,
        required: true
      },
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
  voiceBiometrics: {
    enabled: { type: Boolean, default: false },
    loginRequired: { type: Boolean, default: false },
    threshold: { type: Number, default: 0.9 },
    phrase: { type: String, default: "My voice unlocks GuardFile" },
    embeddings: [
      {
        vector: [{ type: Number }],
        createdAt: { type: Date, default: Date.now },
      },
    ],
    pendingChallenge: {
      challengeId: { type: String, default: null },
      phrase: { type: String, default: null },
      expiresAt: { type: Date, default: null },
      attempts: { type: Number, default: 0 },
    },
    failedAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    lastVerifiedAt: { type: Date, default: null },
  },
  authMetrics: {
    failedLoginCount: { type: Number, default: 0 },
    lastFailedLoginAt: { type: Date, default: null },
    lastSuccessfulLoginAt: { type: Date, default: null },
  },
},
{ timestamps: true }
);

export default mongoose.model("User", userSchema);
