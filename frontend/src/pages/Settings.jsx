import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { fetchWithAuth, logout } from "../utils/api";

const Settings = () => {
  const navigate = useNavigate();
  const userId = localStorage.getItem("userId");
  const token = localStorage.getItem("token");

  const [user, setUser] = useState({
    username: "",
    email: "",
    phone: "",
  });

  const [loading, setLoading] = useState(true);

  // Phone editing
  const [editingPhone, setEditingPhone] = useState(false);
  const [phoneInput, setPhoneInput] = useState("");

  // Password change
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // Notification/security toggles
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [loginAlerts, setLoginAlerts] = useState(true);
  const [twoFactorAuth, setTwoFactorAuth] = useState(true);
  const [dataEncryption, setDataEncryption] = useState(true);

  // Load user data from backend
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
      } catch (err) {
        console.error(err);
        // fetchWithAuth will handle logout if token is invalid
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [userId, token, navigate]);

  // Handle phone number input - only allow numbers
  const handlePhoneInputChange = (e) => {
    const value = e.target.value;
    // Only allow digits, limit to 10 characters
    const digitsOnly = value.replace(/\D/g, '').slice(0, 10);
    setPhoneInput(digitsOnly);
  };

  // Format phone number for display (optional: formats as (123) 456-7890)
  const formatPhoneNumber = (phone) => {
    if (!phone) return "";
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }
    return phone;
  };

  // Update phone number
  const handlePhoneSave = async () => {
    // Validate phone number
    if (!phoneInput.trim()) {
      return alert("Phone number cannot be empty");
    }
    
    const digitsOnly = phoneInput.replace(/\D/g, '');
    
    if (digitsOnly.length !== 10) {
      return alert("Phone number must be exactly 10 digits");
    }

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

  // Change password
  const handlePasswordUpdate = async () => {
    if (!oldPassword || !newPassword || !confirmPassword) {
      return alert("Please fill in all password fields");
    }
    if (newPassword !== confirmPassword) {
      return alert("New passwords do not match");
    }
    if (newPassword.length < 6) {
      return alert("New password must be at least 6 characters");
    }

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

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Loading settings...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-5xl mx-auto py-10 px-6">
        {/* Back button */}
        <div className="flex justify-end mb-4">
          <button
            onClick={() => navigate("/home")}
            className="btn btn-outline btn-accent"
          >
            Back to Dashboard
          </button>
        </div>

        <h1 className="text-3xl font-bold mb-8">Account Settings</h1>

        {/* Personal Details */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Personal Details</h2>
          <div className="space-y-2">
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
        </div>

        {/* Change Password */}
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
              placeholder="New password (min 6 characters)"
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
              <p
                style={{
                  color: newPassword === confirmPassword ? "green" : "red",
                  fontSize: "0.875rem",
                }}
              >
                {newPassword === confirmPassword
                  ? "Passwords match ✓"
                  : "Passwords do not match"}
              </p>
            )}
            <button
              onClick={handlePasswordUpdate}
              className="btn btn-primary mt-2"
            >
              Update Password
            </button>
          </div>
        </div>

        {/* Security Settings */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Security Settings</h2>
          <div className="space-y-3">
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
          </div>
          <p className="text-sm text-gray-500 mt-4">
            Note: Security preferences are currently for display only. Backend integration coming soon.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Settings;