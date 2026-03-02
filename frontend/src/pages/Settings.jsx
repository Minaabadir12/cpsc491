import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { fetchWithAuth, logout } from "../utils/api";
import { captureVoiceEmbedding } from "../utils/voiceBiometrics";
import Navbar from "../Components/Navbar";

const Settings = () => {
  const navigate = useNavigate();
  const userId = localStorage.getItem("userId");
  const token = localStorage.getItem("token");

  // =========================
  // USER INFO
  // =========================
  const [user, setUser] = useState({
    username: "",
    email: "",
    phone: "",
  });
  const [loading, setLoading] = useState(true);

  // =========================
  // Phone editing
  // =========================
  const [editingPhone, setEditingPhone] = useState(false);
  const [phoneInput, setPhoneInput] = useState("");

  // =========================
  // Password change
  // =========================
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // =========================
  // Security settings (display-only)
  // =========================
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [loginAlerts, setLoginAlerts] = useState(true);
  const [twoFactorAuth, setTwoFactorAuth] = useState(false);
  const [dataEncryption, setDataEncryption] = useState(true);

  // =========================
  // TWO-FACTOR AUTH (TOTP)
  // =========================
  const [showTwoFactorSetup, setShowTwoFactorSetup] = useState(false);
  const [twoFactorQrCode, setTwoFactorQrCode] = useState("");
  const [twoFactorSecret, setTwoFactorSecret] = useState("");
  const [twoFactorVerifyCode, setTwoFactorVerifyCode] = useState("");
  const [twoFactorStatus, setTwoFactorStatus] = useState("idle");
  const [showDisable2FA, setShowDisable2FA] = useState(false);
  const [disable2FAPassword, setDisable2FAPassword] = useState("");

  // =========================
  // TWO-FACTOR AUTH (Email)
  // =========================
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [emailTwoFAEnabled, setEmailTwoFAEnabled] = useState(false);
  const [showEmail2FASetup, setShowEmail2FASetup] = useState(false);
  const [email2FACode, setEmail2FACode] = useState("");
  const [email2FAStatus, setEmail2FAStatus] = useState("idle");
  const [showDisableEmail2FA, setShowDisableEmail2FA] = useState(false);
  const [disableEmail2FAPassword, setDisableEmail2FAPassword] = useState("");

  // =========================
  // PASSKEYS (WebAuthn)
  // =========================
  const [passkeyStatus, setPasskeyStatus] = useState("idle"); // idle | working
  const [hasPasskey, setHasPasskey] = useState(false);
  const [passkeyCredentials, setPasskeyCredentials] = useState([]);

  // =========================
  // DEVICE AUTH
  // =========================
  const [deviceAuthEnabled, setDeviceAuthEnabled] = useState(false);
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [voiceEnabled, setVoiceEnabled] = useState(false);
  const [voicePhrase, setVoicePhrase] = useState("My voice unlocks GuardFile");
  const [voiceSampleCount, setVoiceSampleCount] = useState(0);
  const [voiceLockUntil, setVoiceLockUntil] = useState(null);
  const [voiceLoginRequired, setVoiceLoginRequired] = useState(false);
  const [voiceThreshold, setVoiceThreshold] = useState(0.9);
  const [voiceBusy, setVoiceBusy] = useState(false);
  const [voiceFeedback, setVoiceFeedback] = useState("");

  // =========================
  // FETCH USER DATA
  // =========================
  useEffect(() => {
    if (!userId || !token) {
      navigate("/");
      return;
    }

    const fetchUser = async () => {
      try {
        const res = await fetchWithAuth(`http://localhost:3000/api/dashboard/${userId}`);
        if (!res.ok) throw new Error("Failed to fetch user data");

        const data = await res.json();
        setUser({
          username: data.username,
          email: data.email,
          phone: data.phone || "",
        });
        setPhoneInput(data.phone || "");

        setTwoFactorAuth(data.twoFactorEnabled || false);
        const methods = data.twoFactorMethods || {};
        setTotpEnabled(methods.totp?.enabled || (data.twoFactorEnabled && !!data.twoFactorSecret) || false);
        setEmailTwoFAEnabled(methods.email?.enabled || false);
        setDeviceAuthEnabled(data.deviceAuthEnabled || false);
        setTrustedDevices(data.trustedDevices || []);

        const vb = data.voiceBiometrics || {};
        setVoiceEnabled(!!vb.enabled);
        setVoiceLoginRequired(!!vb.loginRequired);
        setVoiceThreshold(typeof vb.threshold === "number" ? vb.threshold : 0.9);
        setVoicePhrase(vb.phrase || "My voice unlocks GuardFile");
        setVoiceSampleCount(Array.isArray(vb.embeddings) ? vb.embeddings.length : 0);
        setVoiceLockUntil(vb.lockUntil || null);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [userId, token, navigate]);

  // =========================
  // PHONE NUMBER HANDLERS
  // =========================
  const handlePhoneInputChange = (e) => {
    const digitsOnly = e.target.value.replace(/\D/g, "").slice(0, 10);
    setPhoneInput(digitsOnly);
  };

  const formatPhoneNumber = (phone) => {
    if (!phone) return "";
    const cleaned = phone.replace(/\D/g, "");
    if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }
    return phone;
  };

  const handlePhoneSave = async () => {
    if (!phoneInput.trim()) return alert("Phone number cannot be empty");

    const digitsOnly = phoneInput.replace(/\D/g, "");
    if (digitsOnly.length !== 10) return alert("Phone number must be 10 digits");

    try {
      const res = await fetchWithAuth(`http://localhost:3000/api/users/${userId}/phone`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone: digitsOnly }),
      });

      if (res.status === 401 || res.status === 403) {
        alert("Session expired. Please log in again.");
        logout();
        return;
      }

      const data = await res.json();
      if (!res.ok) return alert(data.error || "Failed to save phone number");

      setUser((prev) => ({ ...prev, phone: data.phone }));
      setEditingPhone(false);
      alert("Phone number saved successfully!");
    } catch (err) {
      console.error(err);
      alert("Server error while saving phone number");
    }
  };

  // =========================
  // PASSWORD HANDLERS
  // =========================
  const handlePasswordUpdate = async () => {
    if (!oldPassword || !newPassword || !confirmPassword) return alert("Please fill all fields");
    if (newPassword !== confirmPassword) return alert("New passwords do not match");
    if (newPassword.length < 6) return alert("Password must be at least 6 characters");

    try {
      const res = await fetchWithAuth(`http://localhost:3000/api/users/${userId}/password`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ oldPassword, newPassword }),
      });

      if (res.status === 401 || res.status === 403) {
        alert("Session expired. Please log in again.");
        logout();
        return;
      }

      const data = await res.json();
      if (!res.ok) return alert(data.error || "Failed to update password");

      alert("Password updated successfully!");
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      console.error(err);
      alert("Server error while updating password");
    }
  };

  // =========================
  // PASSKEY STATUS
  // =========================
  useEffect(() => {
    if (!userId) return;

    const checkPasskey = async () => {
      try {
        const res = await fetch(`http://localhost:3000/webauthn/status/${userId}`);
        if (!res.ok) return;
        const data = await res.json();
        setHasPasskey(!!data.hasPasskey);
        setPasskeyCredentials(data.credentials || []);
      } catch (err) {
        console.error(err);
      }
    };

    checkPasskey();
  }, [userId]);

  // =========================
  // PASSKEY CREATE
  // =========================
  const handleCreatePasskey = async () => {
    if (!userId) return alert("Please log in again");

    try {
      setPasskeyStatus("working");

      const optRes = await fetch("http://localhost:3000/webauthn/register/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      });
      const options = await optRes.json();
      if (!optRes.ok) throw new Error(options.error || "Failed to start passkey");

      const attResp = await startRegistration(options);

      const verRes = await fetch("http://localhost:3000/webauthn/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, attResp }),
      });
      const result = await verRes.json();
      if (!verRes.ok) throw new Error(result.error || "Passkey verification failed");

      setHasPasskey(true);
      alert("Passkey created successfully!");
    } catch (err) {
      console.error(err);
      alert(err.message || "Passkey setup failed");
    } finally {
      setPasskeyStatus("idle");
    }
  };

  // =========================
  // ✅ PASSKEY DELETE (VERIFY THEN DELETE)
  // Uses your backend:
  // 1) POST /webauthn/delete/options
  // 2) startAuthentication(options)
  // 3) POST /webauthn/delete/verify  (this deletes after verification)
  // =========================
  const handleDeletePasskey = async () => {
    if (!userId) return alert("Please log in again");
    if (!hasPasskey) return alert("No passkey found to delete.");

    const confirmDelete = window.confirm(
      "Delete your passkey? You will be asked to verify (Face ID / Windows Hello) first."
    );
    if (!confirmDelete) return;

    try {
      setPasskeyStatus("working");

      // 1) get delete-auth options
      const optRes = await fetch("http://localhost:3000/webauthn/delete/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      });

      const options = await optRes.json();
      if (!optRes.ok) throw new Error(options.error || "Failed to start delete verification");

      // 2) prompt biometric/passkey auth
      const asseResp = await startAuthentication(options);

      // 3) verify + delete on server
      const verRes = await fetch("http://localhost:3000/webauthn/delete/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, asseResp }),
      });

      const result = await verRes.json();
      if (!verRes.ok) throw new Error(result.error || "Delete verification failed");

      setHasPasskey(false);
      alert("Passkey deleted successfully!");
    } catch (err) {
      console.error(err);
      alert(err.message || "Delete passkey failed");
    } finally {
      setPasskeyStatus("idle");
    }
  };

  // =========================
  // DEVICE AUTH HANDLERS
  // =========================
  const handleDeviceAuthToggle = async () => {
    try {
      setDeviceAuthEnabled(!deviceAuthEnabled);

      await fetchWithAuth(`http://localhost:3000/api/users/${userId}/device-auth`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !deviceAuthEnabled }),
      });
    } catch (err) {
      console.error(err);
      alert("Failed to update device authentication");
    }
  };

  const handleRemoveDevice = async (deviceToken) => {
    try {
      const res = await fetchWithAuth(
        `http://localhost:3000/api/users/${userId}/trusted-devices/${deviceToken}`,
        { method: "DELETE" }
      );
      if (!res.ok) throw new Error("Failed to remove device");
      setTrustedDevices((prev) => prev.filter((d) => d.deviceToken !== deviceToken));
    } catch (err) {
      console.error(err);
      alert(err.message);
    }
  };

  const refreshVoiceStatus = async () => {
    try {
      const res = await fetchWithAuth(`http://localhost:3000/api/voice/status/${userId}`);
      if (!res.ok) return;
      const data = await res.json();
      setVoiceEnabled(!!data.enabled);
      setVoiceLoginRequired(!!data.loginRequired);
      setVoiceThreshold(typeof data.threshold === "number" ? data.threshold : 0.9);
      setVoicePhrase(data.phrase || "My voice unlocks GuardFile");
      setVoiceSampleCount(data.sampleCount || 0);
      setVoiceLockUntil(data.lockUntil || null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleEnrollVoice = async () => {
    try {
      setVoiceBusy(true);
      setVoiceFeedback("Recording voice sample...");

      const audioData = await captureVoiceEmbedding(5000);

      setVoiceFeedback("Uploading enrollment sample...");
      const res = await fetchWithAuth(`http://localhost:3000/api/voice/enroll/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          audioData,
          phrase: voicePhrase,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to enroll voice sample");

      await refreshVoiceStatus();
      setVoiceFeedback(`Voice enrolled. Total samples: ${data.sampleCount}`);
    } catch (err) {
      console.error(err);
      setVoiceFeedback(err.message || "Voice enrollment failed");
    } finally {
      setVoiceBusy(false);
    }
  };

  const handleVerifyVoice = async () => {
    try {
      setVoiceBusy(true);
      setVoiceFeedback("Recording verification sample...");

      const audioData = await captureVoiceEmbedding(5000);

      setVoiceFeedback("Verifying voice...");
      const res = await fetchWithAuth(`http://localhost:3000/api/voice/verify/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ audioData }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Voice verification failed");

      if (data.verified) {
        setVoiceFeedback(`Verified (score: ${data.score}, threshold: ${data.threshold})`);
      } else {
        setVoiceFeedback(`Not verified (score: ${data.score}, threshold: ${data.threshold})`);
      }

      await refreshVoiceStatus();
    } catch (err) {
      console.error(err);
      setVoiceFeedback(err.message || "Voice verification failed");
    } finally {
      setVoiceBusy(false);
    }
  };

  const handleRemoveVoice = async () => {
    const confirmed = window.confirm("Remove all enrolled voice samples?");
    if (!confirmed) return;

    try {
      setVoiceBusy(true);
      setVoiceFeedback("Removing voice profile...");
      const res = await fetchWithAuth(`http://localhost:3000/api/voice/${userId}`, {
        method: "DELETE",
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to remove voice profile");

      await refreshVoiceStatus();
      setVoiceFeedback("Voice biometrics removed");
    } catch (err) {
      console.error(err);
      setVoiceFeedback(err.message || "Failed to remove voice biometrics");
    } finally {
      setVoiceBusy(false);
    }
  };

  const handleSaveVoicePolicy = async () => {
    try {
      setVoiceBusy(true);
      setVoiceFeedback("Saving voice login policy...");

      const res = await fetchWithAuth(`http://localhost:3000/api/voice/login-setting/${userId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          loginRequired: voiceLoginRequired,
          threshold: Number(voiceThreshold),
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to save voice login policy");

      await refreshVoiceStatus();
      setVoiceFeedback("Voice login policy saved");
    } catch (err) {
      console.error(err);
      setVoiceFeedback(err.message || "Failed to save voice login policy");
    } finally {
      setVoiceBusy(false);
    }
  };

  // =========================
  // 2FA HANDLERS
  // =========================
  const handleSetup2FA = async () => {
    try {
      setTwoFactorStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/setup/${userId}`, {
        method: "POST",
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to setup 2FA");
      }

      const data = await res.json();
      setTwoFactorQrCode(data.qrCode);
      setTwoFactorSecret(data.secret);
      setShowTwoFactorSetup(true);
      setTwoFactorStatus("idle");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to setup 2FA");
      setTwoFactorStatus("idle");
    }
  };

  const handleVerify2FASetup = async () => {
    if (!twoFactorVerifyCode || twoFactorVerifyCode.length !== 6) {
      alert("Please enter a valid 6-digit code");
      return;
    }

    try {
      setTwoFactorStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/verify-setup/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: twoFactorSecret,
          token: twoFactorVerifyCode,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Verification failed");
      }

      setTwoFactorAuth(true);
      setTotpEnabled(true);
      setShowTwoFactorSetup(false);
      setTwoFactorQrCode("");
      setTwoFactorSecret("");
      setTwoFactorVerifyCode("");
      setTwoFactorStatus("idle");
      alert("Authenticator App 2FA enabled successfully!");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to verify 2FA");
      setTwoFactorStatus("idle");
    }
  };

  const handleDisable2FA = async () => {
    if (!disable2FAPassword) {
      alert("Please enter your password");
      return;
    }

    try {
      setTwoFactorStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/disable/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: disable2FAPassword }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to disable 2FA");
      }

      setTotpEnabled(false);
      if (!emailTwoFAEnabled) setTwoFactorAuth(false);
      setShowDisable2FA(false);
      setDisable2FAPassword("");
      setTwoFactorStatus("idle");
      alert("Authenticator App 2FA disabled");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to disable 2FA");
      setTwoFactorStatus("idle");
    }
  };

  const handleCancel2FASetup = () => {
    setShowTwoFactorSetup(false);
    setTwoFactorQrCode("");
    setTwoFactorSecret("");
    setTwoFactorVerifyCode("");
  };

  // =========================
  // EMAIL 2FA HANDLERS
  // =========================
  const handleSetupEmail2FA = async () => {
    try {
      setEmail2FAStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/email/setup/${userId}`, {
        method: "POST",
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to send verification code");
      }

      setShowEmail2FASetup(true);
      setEmail2FAStatus("idle");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to setup Email 2FA");
      setEmail2FAStatus("idle");
    }
  };

  const handleVerifyEmail2FASetup = async () => {
    if (!email2FACode || email2FACode.length !== 6) {
      alert("Please enter a valid 6-digit code");
      return;
    }

    try {
      setEmail2FAStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/email/verify-setup/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: email2FACode }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Verification failed");
      }

      setEmailTwoFAEnabled(true);
      setTwoFactorAuth(true);
      setShowEmail2FASetup(false);
      setEmail2FACode("");
      setEmail2FAStatus("idle");
      alert("Email 2FA enabled successfully!");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to verify Email 2FA");
      setEmail2FAStatus("idle");
    }
  };

  const handleDisableEmail2FA = async () => {
    if (!disableEmail2FAPassword) {
      alert("Please enter your password");
      return;
    }

    try {
      setEmail2FAStatus("loading");

      const res = await fetchWithAuth(`http://localhost:3000/api/2fa/email/disable/${userId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: disableEmail2FAPassword }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to disable Email 2FA");
      }

      setEmailTwoFAEnabled(false);
      if (!totpEnabled) setTwoFactorAuth(false);
      setShowDisableEmail2FA(false);
      setDisableEmail2FAPassword("");
      setEmail2FAStatus("idle");
      alert("Email 2FA disabled");
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to disable Email 2FA");
      setEmail2FAStatus("idle");
    }
  };

  const handleCancelEmail2FASetup = () => {
    setShowEmail2FASetup(false);
    setEmail2FACode("");
  };

  // =========================
  // RENDER
  // =========================
  if (loading) {
    return <div className="min-h-screen flex items-center justify-center">Loading settings...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-5xl mx-auto py-10 px-6">

        <div className="flex justify-end mb-4">
          <button
            onClick={() => navigate("/home")}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Back to Main Menu
          </button>
        </div>

        <h1 className="text-3xl font-bold mb-8 text-purple-800">Account Settings</h1>

        {/* PERSONAL DETAILS */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Personal Details</h2>
          <p><strong>Username:</strong> {user.username}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <div>
            <strong>Phone:</strong>{" "}
            {editingPhone ? (
              <div className="mt-2">
                <input
                  type="tel"
                  value={phoneInput}
                  onChange={handlePhoneInputChange}
                  className="input input-bordered w-full max-w-sm"
                  placeholder="Enter 10-digit phone number"
                  maxLength={10}
                />
                <div className="mt-2">
                  <button onClick={handlePhoneSave} className="btn btn-primary" disabled={phoneInput.length !== 10}>
                    Save
                  </button>
                  <button
                    onClick={() => {
                      setEditingPhone(false);
                      setPhoneInput(user.phone || "");
                    }}
                    className="btn btn-outline ml-2"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <>
                {user.phone ? formatPhoneNumber(user.phone) : "Not set"}
                <button onClick={() => setEditingPhone(true)} className="btn btn-sm btn-secondary ml-2">
                  {user.phone ? "Change" : "Add"}
                </button>
              </>
            )}
          </div>
        </div>

        {/* PASSKEYS */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Biometrics / Passkeys</h2>
          <div className="flex flex-col md:flex-row gap-6">
            {/* Left side: buttons */}
            <div className="flex flex-wrap gap-3 items-start">
              <button onClick={handleCreatePasskey} className="btn btn-primary" disabled={passkeyStatus === "working"}>
                {passkeyStatus === "working" ? "Working..." : hasPasskey ? "Add Another Passkey" : "Create Passkey"}
              </button>

              <button
                onClick={handleDeletePasskey}
                className="btn btn-outline btn-error"
                disabled={passkeyStatus === "working" || !hasPasskey}
              >
                {passkeyStatus === "working" ? "Working..." : "Delete Passkey"}
              </button>
            </div>

            {/* Right side: registered passkeys list */}
            <div className="flex-1 min-w-0">
              {passkeyCredentials.length > 0 ? (
                <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-purple-800 mb-2">
                    Registered Passkeys ({passkeyCredentials.length})
                  </h3>
                  <div className="flex flex-col gap-2">
                    {passkeyCredentials.map((cred, idx) => {
                      // Pick the most meaningful transport label
                      // Priority: internal (laptop biometric) > usb > ble > nfc > hybrid
                      const transports = cred.transports || [];
                      let type;
                      if (transports.includes("internal")) {
                        type = "Fingerprint / Windows Hello";
                      } else if (transports.includes("usb")) {
                        type = "USB Security Key";
                      } else if (transports.includes("ble")) {
                        type = "Bluetooth Security Key";
                      } else if (transports.includes("nfc")) {
                        type = "NFC Security Key";
                      } else if (transports.includes("hybrid")) {
                        type = "Phone / Tablet";
                      } else {
                        type = "Passkey";
                      }
                      const date = cred.createdAt
                        ? new Date(cred.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
                        : "Unknown date";

                      return (
                        <div key={idx} className="flex items-center gap-3 bg-white rounded-md px-3 py-2 border border-purple-100">
                          <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center flex-shrink-0">
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-purple-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M12 10v4M7 6a5 5 0 0 1 10 0c0 4-3 6-3 6H10s-3-2-3-6Z"/>
                              <rect x="8" y="16" width="8" height="4" rx="1"/>
                            </svg>
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-gray-800">{type}</p>
                            <p className="text-xs text-gray-500">Added {date}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                  <p className="text-sm text-gray-500">No passkeys registered yet. Create one to enable biometric login.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* VOICE BIOMETRICS */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Voice Biometrics</h2>
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${voiceEnabled ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-600"}`}>
              {voiceEnabled ? "Enabled" : "Disabled"}
            </span>
          </div>

          <div className="mb-3">
            <label className="block text-sm font-medium mb-1">Phrase</label>
            <input
              type="text"
              value={voicePhrase}
              onChange={(e) => setVoicePhrase(e.target.value.slice(0, 140))}
              className="input input-bordered w-full max-w-lg"
              placeholder="My voice unlocks GuardFile"
              disabled={voiceBusy}
            />
          </div>

          <div className="mb-3 grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={voiceLoginRequired}
                onChange={(e) => setVoiceLoginRequired(e.target.checked)}
                className="checkbox checkbox-primary"
                disabled={voiceBusy}
              />
              <span className="text-sm font-medium">Require at login</span>
            </label>
            <div>
              <label className="block text-sm font-medium mb-1">Threshold</label>
              <input
                type="number"
                min="0.75"
                max="0.99"
                step="0.01"
                value={voiceThreshold}
                onChange={(e) => setVoiceThreshold(e.target.value)}
                className="input input-bordered w-full max-w-xs"
                disabled={voiceBusy}
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-2 mb-3">
            <button onClick={handleEnrollVoice} className="btn btn-primary" disabled={voiceBusy}>
              {voiceBusy ? "Working..." : "Enroll Sample"}
            </button>
            <button
              onClick={handleVerifyVoice}
              className="btn btn-outline btn-success"
              disabled={voiceBusy || voiceSampleCount === 0}
            >
              {voiceBusy ? "Working..." : "Verify"}
            </button>
            <button
              onClick={handleRemoveVoice}
              className="btn btn-outline btn-error"
              disabled={voiceBusy || voiceSampleCount === 0}
            >
              Remove
            </button>
            <button
              onClick={handleSaveVoicePolicy}
              className="btn btn-outline"
              disabled={voiceBusy}
            >
              Save
            </button>
          </div>

          <div className="flex flex-wrap gap-2 text-xs mb-1">
            <span className="px-2 py-1 rounded-full bg-gray-100 text-gray-700">Samples: {voiceSampleCount}</span>
            <span className="px-2 py-1 rounded-full bg-gray-100 text-gray-700">Threshold: {Number(voiceThreshold).toFixed(2)}</span>
            <span className={`px-2 py-1 rounded-full ${voiceLockUntil ? "bg-rose-100 text-rose-700" : "bg-green-100 text-green-700"}`}>
              {voiceLockUntil ? `Locked` : "Not locked"}
            </span>
          </div>

          {voiceFeedback && (
            <p className="text-xs mt-2 text-blue-700">{voiceFeedback}</p>
          )}
        </div>

        {/* PASSWORD CHANGE */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Change Password</h2>
          <div className="flex flex-col gap-3 max-w-md">
            <input
              type="password"
              placeholder="Current password"
              className="input input-bordered w-full"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
            />
            <input
              type="password"
              placeholder="New password (min 6 chars)"
              className="input input-bordered w-full"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <input
              type="password"
              placeholder="Confirm new password"
              className="input input-bordered w-full"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />

            {newPassword && confirmPassword && (
              <p style={{ color: newPassword === confirmPassword ? "green" : "red", fontSize: "0.875rem" }}>
                {newPassword === confirmPassword ? "Passwords match ✓" : "Passwords do not match"}
              </p>
            )}

            <button onClick={handlePasswordUpdate} className="btn btn-primary mt-2">
              Update Password
            </button>
          </div>
        </div>

        {/* TWO-FACTOR AUTHENTICATION */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Two-Factor Authentication</h2>
          <p className="text-sm text-gray-500 mb-6">
            Add extra security to your account. You can enable multiple methods.
          </p>

          {/* AUTHENTICATOR APP CARD */}
          <div className="border rounded-lg p-4 mb-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-medium">Authenticator App</h3>
                <p className="text-sm text-gray-500">
                  Use Google Authenticator, Authy, Duo, or similar apps
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-sm font-medium ${totpEnabled ? "text-green-600" : "text-gray-400"}`}>
                  {totpEnabled ? "Enabled" : "Disabled"}
                </span>
              </div>
            </div>

            {!showTwoFactorSetup && !showDisable2FA && (
              <div className="mt-3">
                {totpEnabled ? (
                  <button
                    onClick={() => setShowDisable2FA(true)}
                    className="btn btn-sm btn-outline btn-error"
                    disabled={twoFactorStatus === "loading"}
                  >
                    Disable
                  </button>
                ) : (
                  <button
                    onClick={handleSetup2FA}
                    className="btn btn-sm btn-primary"
                    disabled={twoFactorStatus === "loading"}
                  >
                    {twoFactorStatus === "loading" ? "Loading..." : "Enable"}
                  </button>
                )}
              </div>
            )}

            {showTwoFactorSetup && (
              <div className="mt-4 space-y-4 border-t pt-4">
                <h4 className="font-medium">Setup Authenticator App</h4>

                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-600 mb-3">
                    1. Install an authenticator app (Google Authenticator, Authy, etc.)
                  </p>
                  <p className="text-sm text-gray-600 mb-3">
                    2. Scan this QR code with your authenticator app:
                  </p>

                  {twoFactorQrCode && (
                    <div className="flex justify-center my-4">
                      <img src={twoFactorQrCode} alt="2FA QR Code" className="border rounded" />
                    </div>
                  )}

                  <p className="text-sm text-gray-600 mb-2">Or enter this code manually:</p>
                  <code className="block bg-gray-200 p-2 rounded text-sm break-all">
                    {twoFactorSecret}
                  </code>
                </div>

                <div>
                  <p className="text-sm text-gray-600 mb-2">
                    3. Enter the 6-digit code from your authenticator app:
                  </p>
                  <input
                    type="text"
                    value={twoFactorVerifyCode}
                    onChange={(e) => setTwoFactorVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="Enter 6-digit code"
                    className="input input-bordered w-full max-w-xs"
                    maxLength={6}
                  />
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={handleVerify2FASetup}
                    className="btn btn-primary"
                    disabled={twoFactorVerifyCode.length !== 6 || twoFactorStatus === "loading"}
                  >
                    {twoFactorStatus === "loading" ? "Verifying..." : "Verify & Enable"}
                  </button>
                  <button
                    onClick={handleCancel2FASetup}
                    className="btn btn-outline"
                    disabled={twoFactorStatus === "loading"}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {showDisable2FA && (
              <div className="mt-4 space-y-4 border-t pt-4">
                <h4 className="font-medium text-red-600">Disable Authenticator App</h4>
                <p className="text-sm text-gray-600">Enter your password to confirm:</p>
                <input
                  type="password"
                  value={disable2FAPassword}
                  onChange={(e) => setDisable2FAPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="input input-bordered w-full max-w-xs"
                />
                <div className="flex gap-2">
                  <button
                    onClick={handleDisable2FA}
                    className="btn btn-error"
                    disabled={!disable2FAPassword || twoFactorStatus === "loading"}
                  >
                    {twoFactorStatus === "loading" ? "Disabling..." : "Disable"}
                  </button>
                  <button
                    onClick={() => { setShowDisable2FA(false); setDisable2FAPassword(""); }}
                    className="btn btn-outline"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* EMAIL VERIFICATION CARD */}
          <div className="border rounded-lg p-4 mb-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-medium">Email Verification</h3>
                <p className="text-sm text-gray-500">
                  Receive a code at {user.email}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-sm font-medium ${emailTwoFAEnabled ? "text-green-600" : "text-gray-400"}`}>
                  {emailTwoFAEnabled ? "Enabled" : "Disabled"}
                </span>
              </div>
            </div>

            {!showEmail2FASetup && !showDisableEmail2FA && (
              <div className="mt-3">
                {emailTwoFAEnabled ? (
                  <button
                    onClick={() => setShowDisableEmail2FA(true)}
                    className="btn btn-sm btn-outline btn-error"
                    disabled={email2FAStatus === "loading"}
                  >
                    Disable
                  </button>
                ) : (
                  <button
                    onClick={handleSetupEmail2FA}
                    className="btn btn-sm btn-primary"
                    disabled={email2FAStatus === "loading"}
                  >
                    {email2FAStatus === "loading" ? "Sending..." : "Enable"}
                  </button>
                )}
              </div>
            )}

            {showEmail2FASetup && (
              <div className="mt-4 space-y-4 border-t pt-4">
                <h4 className="font-medium">Setup Email Verification</h4>
                <p className="text-sm text-gray-600">
                  A 6-digit code has been sent to <strong>{user.email}</strong>. Enter it below:
                </p>
                <input
                  type="text"
                  value={email2FACode}
                  onChange={(e) => setEmail2FACode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="Enter 6-digit code"
                  className="input input-bordered w-full max-w-xs"
                  maxLength={6}
                />
                <div className="flex gap-2">
                  <button
                    onClick={handleVerifyEmail2FASetup}
                    className="btn btn-primary"
                    disabled={email2FACode.length !== 6 || email2FAStatus === "loading"}
                  >
                    {email2FAStatus === "loading" ? "Verifying..." : "Verify & Enable"}
                  </button>
                  <button
                    onClick={handleCancelEmail2FASetup}
                    className="btn btn-outline"
                    disabled={email2FAStatus === "loading"}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {showDisableEmail2FA && (
              <div className="mt-4 space-y-4 border-t pt-4">
                <h4 className="font-medium text-red-600">Disable Email Verification</h4>
                <p className="text-sm text-gray-600">Enter your password to confirm:</p>
                <input
                  type="password"
                  value={disableEmail2FAPassword}
                  onChange={(e) => setDisableEmail2FAPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="input input-bordered w-full max-w-xs"
                />
                <div className="flex gap-2">
                  <button
                    onClick={handleDisableEmail2FA}
                    className="btn btn-error"
                    disabled={!disableEmail2FAPassword || email2FAStatus === "loading"}
                  >
                    {email2FAStatus === "loading" ? "Disabling..." : "Disable"}
                  </button>
                  <button
                    onClick={() => { setShowDisableEmail2FA(false); setDisableEmail2FAPassword(""); }}
                    className="btn btn-outline"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* OTHER SECURITY SETTINGS */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Other Security Settings</h2>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={loginAlerts} onChange={() => setLoginAlerts(!loginAlerts)} className="checkbox checkbox-primary" />
            <span>Login Alerts</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={emailNotifications} onChange={() => setEmailNotifications(!emailNotifications)} className="checkbox checkbox-primary" />
            <span>Email Notifications</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={dataEncryption} onChange={() => setDataEncryption(!dataEncryption)} className="checkbox checkbox-primary" />
            <span>Enable Data Encryption</span>
          </label>
          <p className="text-sm text-gray-500 mt-4">Note: These preferences are currently for display only.</p>
        </div>

        {/* DEVICE AUTH */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-purple-700">Device Authentication</h2>
          <label className="flex items-center gap-2 cursor-pointer mb-4">
            <input type="checkbox" checked={deviceAuthEnabled} onChange={handleDeviceAuthToggle} className="checkbox checkbox-primary" />
            <span className="font-medium">Enable Device Authentication</span>
          </label>
          {deviceAuthEnabled && trustedDevices.length > 0 ? (
            <div className="space-y-3">
              {trustedDevices.map((device) => (
                <div key={device.deviceToken} className="flex justify-between items-center border border-gray-200 rounded-lg p-4">
                  <div>
                    <p className="font-medium">{device.deviceName || "Unknown Device"}</p>
                    <p className="text-sm text-gray-500">Added: {new Date(device.trustedAt).toLocaleDateString()}</p>
                    <p className="text-sm text-gray-500">Last used: {new Date(device.lastUsed).toLocaleDateString()}</p>
                    <p className="text-xs text-gray-400 mt-1">IP: {device.ipAddress || "Unknown"}</p>
                  </div>
                  <button onClick={() => handleRemoveDevice(device.deviceToken)} className="btn btn-sm btn-outline btn-error">Remove</button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500">No trusted devices yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default Settings;


