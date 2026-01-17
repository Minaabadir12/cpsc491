import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

const Settings = () => {
  const navigate = useNavigate();
  const userId = localStorage.getItem("userId");

  const [user, setUser] = useState({
    username: "",
    email: "",
    phone: "",
  });

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
    if (!userId) {
      navigate("/");
      return;
    }

    const fetchUser = async () => {
      try {
        const res = await fetch(`http://localhost:3000/api/dashboard/${userId}`);
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
        navigate("/");
      }
    };

    fetchUser();
  }, [userId, navigate]);

  // Update phone number
  const handlePhoneSave = async () => {
    if (!phoneInput.trim()) return alert("Phone number cannot be empty");

    try {
      const res = await fetch(`http://localhost:3000/api/users/${userId}/phone`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone: phoneInput.trim() }),
      });
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
      const res = await fetch(`http://localhost:3000/api/users/${userId}/password`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ oldPassword, newPassword }),
      });
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
          <p><strong>Username:</strong> {user.username}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p>
            <strong>Phone:</strong>{" "}
            {editingPhone ? (
              <>
                <input
                  type="text"
                  value={phoneInput}
                  onChange={(e) => setPhoneInput(e.target.value)}
                  className="input input-bordered w-full max-w-sm"
                />
                <button
                  onClick={handlePhoneSave}
                  className="btn btn-primary ml-2"
                >
                  Save
                </button>
                <button
                  onClick={() => setEditingPhone(false)}
                  className="btn btn-outline ml-2"
                >
                  Cancel
                </button>
              </>
            ) : (
              <>
                {user.phone || "Not set"}
                <button
                  onClick={() => setEditingPhone(true)}
                  className="btn btn-sm btn-secondary ml-2"
                >
                  {user.phone ? "Change" : "Add"}
                </button>
              </>
            )}
          </p>
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
              placeholder="New password"
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
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={twoFactorAuth}
              onChange={() => setTwoFactorAuth(!twoFactorAuth)}
              className="checkbox checkbox-primary"
            />
            Enable Two-Factor Authentication
          </label>
          <label className="flex items-center gap-2 mt-2">
            <input
              type="checkbox"
              checked={loginAlerts}
              onChange={() => setLoginAlerts(!loginAlerts)}
              className="checkbox checkbox-primary"
            />
            Login Alerts
          </label>
          <label className="flex items-center gap-2 mt-2">
            <input
              type="checkbox"
              checked={emailNotifications}
              onChange={() => setEmailNotifications(!emailNotifications)}
              className="checkbox checkbox-primary"
            />
            Email Notifications
          </label>
          <label className="flex items-center gap-2 mt-2">
            <input
              type="checkbox"
              checked={dataEncryption}
              onChange={() => setDataEncryption(!dataEncryption)}
              className="checkbox checkbox-primary"
            />
            Enable Data Encryption
          </label>
        </div>
      </div>
    </div>
  );
};

export default Settings;
