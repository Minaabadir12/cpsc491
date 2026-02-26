import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { fetchWithAuth, logout } from "../utils/api";
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
  // PASSKEYS (WebAuthn)
  // =========================
  const [passkeyStatus, setPasskeyStatus] = useState("idle"); // idle | working
  const [hasPasskey, setHasPasskey] = useState(false);

  // =========================
  // DEVICE AUTH
  // =========================
  const [deviceAuthEnabled, setDeviceAuthEnabled] = useState(false);
  const [trustedDevices, setTrustedDevices] = useState([]);

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
        setDeviceAuthEnabled(data.deviceAuthEnabled || false);
        setTrustedDevices(data.trustedDevices || []);
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
      setShowTwoFactorSetup(false);
      setTwoFactorQrCode("");
      setTwoFactorSecret("");
      setTwoFactorVerifyCode("");
      setTwoFactorStatus("idle");
      alert("Two-Factor Authentication enabled successfully!");
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

      setTwoFactorAuth(false);
      setShowDisable2FA(false);
      setDisable2FAPassword("");
      setTwoFactorStatus("idle");
      alert("Two-Factor Authentication disabled");
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
          <button onClick={() => navigate("/home")} className="btn btn-outline btn-accent">
            Back to Dashboard
          </button>
        </div>

        <h1 className="text-3xl font-bold mb-8">Account Settings</h1>

        {/* PERSONAL DETAILS */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Personal Details</h2>
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
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Biometrics / Passkeys</h2>
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

          <p className="text-sm text-gray-500 mt-3">
          </p>
        </div>

        {/* PASSWORD CHANGE */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Change Password</h2>
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
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Two-Factor Authentication</h2>

          {!showTwoFactorSetup && !showDisable2FA ? (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="font-medium">
                    Status:{" "}
                    {twoFactorAuth ? (
                      <span className="text-green-600">Enabled</span>
                    ) : (
                      <span className="text-gray-500">Disabled</span>
                    )}
                  </p>
                  <p className="text-sm text-gray-500 mt-1">
                    {twoFactorAuth
                      ? "Your account is protected with an authenticator app."
                      : "Add an extra layer of security to your account."}
                  </p>
                </div>
                {twoFactorAuth ? (
                  <button
                    onClick={() => setShowDisable2FA(true)}
                    className="btn btn-outline btn-error"
                    disabled={twoFactorStatus === "loading"}
                  >
                    Disable 2FA
                  </button>
                ) : (
                  <button
                    onClick={handleSetup2FA}
                    className="btn btn-primary"
                    disabled={twoFactorStatus === "loading"}
                  >
                    {twoFactorStatus === "loading" ? "Loading..." : "Enable 2FA"}
                  </button>
                )}
              </div>
            </div>
          ) : showTwoFactorSetup ? (
            <div className="space-y-4">
              <h3 className="font-medium">Setup Two-Factor Authentication</h3>

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
          ) : (
            <div className="space-y-4">
              <h3 className="font-medium text-red-600">Disable Two-Factor Authentication</h3>
              <p className="text-sm text-gray-600">Enter your password to confirm disabling 2FA:</p>
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
                  {twoFactorStatus === "loading" ? "Disabling..." : "Disable 2FA"}
                </button>
                <button
                  onClick={() => {
                    setShowDisable2FA(false);
                    setDisable2FAPassword("");
                  }}
                  className="btn btn-outline"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>

        {/* OTHER SECURITY SETTINGS */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Other Security Settings</h2>
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
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Device Authentication</h2>
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


