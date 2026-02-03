import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { fetchWithAuth, logout } from "../utils/api";

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
  const [twoFactorAuth, setTwoFactorAuth] = useState(true);
  const [dataEncryption, setDataEncryption] = useState(true);

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
  // CREATE PASSKEY
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
  // DELETE PASSKEYS (WITH VERIFICATION)
  // =========================
  const handleDeletePasskeys = async () => {
    if (!userId) return alert("Please log in again");

    const ok = window.confirm(
      "To delete passkeys, you'll need to verify with Face ID / Windows Hello. Continue?"
    );
    if (!ok) return;

    try {
      setPasskeyStatus("working");

      // 1) Get authentication options
      const optRes = await fetch("http://localhost:3000/webauthn/delete/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      });

      const options = await optRes.json();
      if (!optRes.ok) throw new Error(options.error || "Failed to start verification");

      // 2) Prompt user (Face ID / Windows Hello / PIN)
      const asseResp = await startAuthentication(options);

      // 3) Verify + delete on server
      const verRes = await fetch("http://localhost:3000/webauthn/delete/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, asseResp }),
      });

      const result = await verRes.json();
      if (!verRes.ok) throw new Error(result.error || "Delete failed");

      setHasPasskey(false);
      alert("Passkeys deleted.");
    } catch (err) {
      console.error(err);
      alert(err.message || "Delete failed");
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
  // RENDER
  // =========================
  if (loading) {
    return <div className="min-h-screen flex items-center justify-center">Loading settings...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-100">
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
                  <button
                    onClick={handlePhoneSave}
                    className="btn btn-primary"
                    disabled={phoneInput.length !== 10}
                  >
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
                <button
                  onClick={() => setEditingPhone(true)}
                  className="btn btn-sm btn-secondary ml-2"
                >
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
            <button
              onClick={handleCreatePasskey}
              className="btn btn-primary"
              disabled={passkeyStatus === "working"}
            >
              {passkeyStatus === "working"
                ? "Working..."
                : hasPasskey
                ? "Add Another Passkey"
                : "Create Passkey"}
            </button>

            <button
              onClick={handleDeletePasskeys}
              className="btn btn-error"
              disabled={passkeyStatus === "working" || !hasPasskey}
            >
              {passkeyStatus === "working" ? "Working..." : "Delete Passkeys"}
            </button>
          </div>

          <p className="text-sm text-gray-500 mt-3">
            {hasPasskey ? "Passkey is saved on this account." : "No passkey saved yet."}
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

        {/* SECURITY SETTINGS */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Security Settings</h2>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={twoFactorAuth}
              onChange={() => setTwoFactorAuth(!twoFactorAuth)}
              className="checkbox checkbox-primary"
            />
            <span>Enable Two-Factor Authentication</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={loginAlerts}
              onChange={() => setLoginAlerts(!loginAlerts)}
              className="checkbox checkbox-primary"
            />
            <span>Login Alerts</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={emailNotifications}
              onChange={() => setEmailNotifications(!emailNotifications)}
              className="checkbox checkbox-primary"
            />
            <span>Email Notifications</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={dataEncryption}
              onChange={() => setDataEncryption(!dataEncryption)}
              className="checkbox checkbox-primary"
            />
            <span>Enable Data Encryption</span>
          </label>
          <p className="text-sm text-gray-500 mt-4">
            Note: Security preferences are currently for display only. Backend integration coming soon.
          </p>
        </div>

        {/* DEVICE AUTH */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Device Authentication</h2>
          <label className="flex items-center gap-2 cursor-pointer mb-4">
            <input
              type="checkbox"
              checked={deviceAuthEnabled}
              onChange={handleDeviceAuthToggle}
              className="checkbox checkbox-primary"
            />
            <span className="font-medium">Enable Device Authentication</span>
          </label>

          {deviceAuthEnabled && trustedDevices.length > 0 ? (
            <div className="space-y-3">
              {trustedDevices.map((device) => (
                <div
                  key={device.deviceToken}
                  className="flex justify-between items-center border border-gray-200 rounded-lg p-4"
                >
                  <div>
                    <p className="font-medium">{device.deviceName || "Unknown Device"}</p>
                    <p className="text-sm text-gray-500">
                      Added: {device.trustedAt ? new Date(device.trustedAt).toLocaleDateString() : "Unknown"}
                    </p>
                    <p className="text-sm text-gray-500">
                      Last used: {device.lastUsed ? new Date(device.lastUsed).toLocaleDateString() : "Unknown"}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">IP: {device.ipAddress || "Unknown"}</p>
                  </div>
                  <button
                    onClick={() => handleRemoveDevice(device.deviceToken)}
                    className="btn btn-sm btn-outline btn-error"
                  >
                    Remove
                  </button>
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
