const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },

  password: {
    type: String,
    required: true,
  },

  // ✅ Add phone number field
  phone: {
    type: String,
    default: "", // empty string for users who haven't set a number yet
  },

  // ===== DASHBOARD DATA =====
  storageUsed: {
    type: Number,
    default: 0, // in MB
  },

  storageLimit: {
    type: Number,
    default: 1024, // 1GB Free plan
  },

  plan: {
    type: String,
    enum: ["Free", "Pro", "Enterprise"],
    default: "Free",
  },

  uploads: [
    {
      filename: String,
      size: Number,
      uploadedAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  devices: [
    {
      deviceName: String,
      lastActive: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("User", UserSchema);
