import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../Components/Navbar";
import { fetchWithAuth, logout } from "../utils/api";

const HomePage = () => {
  const navigate = useNavigate();
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);

  // Helper function to clean filenames
  const getDisplayName = (filename) => {
    if (!filename) return '';
    return filename.replace(/^\d+-/, '');
  };

  // Helper function to format IP address for display
  const formatIPAddress = (ip) => {
    if (!ip) return 'Unknown';
    if (ip === '::ffff:127.0.0.1' || ip === '::1' || ip === '127.0.0.1') {
      return 'Local Device';
    }
    return ip.replace('::ffff:', '');
  };

  // Helper function to get activity icon and color based on action type
  const getActivityStyle = (action) => {
    const styles = {
      upload: {
        icon: "↑",
        color: "text-green-600",
        bgColor: "bg-green-100",
        label: "Uploaded"
      },
      delete: {
        icon: "🗑",
        color: "text-red-600",
        bgColor: "bg-red-100",
        label: "Deleted"
      },
      share: {
        icon: "↗",
        color: "text-blue-600",
        bgColor: "bg-blue-100",
        label: "Shared"
      },
      download: {
        icon: "↓",
        color: "text-purple-600",
        bgColor: "bg-purple-100",
        label: "Downloaded"
      },
      modify: {
        icon: "✎",
        color: "text-yellow-600",
        bgColor: "bg-yellow-100",
        label: "Modified"
      },
      device_added: {
        icon: "💻",
        color: "text-teal-600",
        bgColor: "bg-teal-100",
        label: "Device Added"
      },
      device_removed: {
        icon: "⊗",
        color: "text-orange-600",
        bgColor: "bg-orange-100",
        label: "Device Removed"
      }
    };
    return styles[action] || styles.upload;
  };

  // Redirect to login if no user is logged in
  useEffect(() => {
    const userId = localStorage.getItem("userId");
    const token = localStorage.getItem("token");

    if (!userId || !token) {
      navigate("/");
      return;
    }

    // Fetch user dashboard data with authentication
    const fetchDashboard = async () => {
      try {
        const res = await fetchWithAuth(`http://localhost:3000/api/dashboard/${userId}`);
        if (!res.ok) throw new Error("Failed to fetch dashboard");
        const data = await res.json();
        setUserData(data);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    };

    fetchDashboard();
  }, [navigate]);

  const handleNavigation = (path) => navigate(path);

  const handleLogout = () => {
    if (window.confirm("Are you sure you want to logout?")) {
      logout();
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <p className="text-gray-500 text-lg">Loading...</p>
      </div>
    );
  }

  if (!userData) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-xl mb-4 text-gray-700">Failed to load dashboard</p>
          <button
            onClick={() => navigate("/")}
            className="bg-purple-600 text-white px-5 py-2 rounded-lg hover:bg-purple-700 transition"
          >
            Return to Login
          </button>
        </div>
      </div>
    );
  }

  // Calculate storage percentage
  const storagePercent = (userData.storageUsed / userData.storageLimit) * 100;
  const storageUsedRounded = userData.storageUsed.toFixed(2);
  const storageLimitRounded = userData.storageLimit.toFixed(2);

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar onLogout={handleLogout} />
      <div className="max-w-7xl mx-auto py-10 px-6">
        <h1 className="text-4xl font-bold text-center mb-10 text-purple-800">
          GuardFile Dashboard
        </h1>

        {/* Top Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          {/* Storage */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Storage Usage</h2>
            <p className="text-gray-600 mb-2 text-sm">
              {storageUsedRounded} GB / {storageLimitRounded} GB (
              {(userData.storageLimit / 1024).toFixed(2)} TB)
            </p>

            <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${
                  storagePercent > 90
                    ? "bg-red-500"
                    : storagePercent > 70
                    ? "bg-yellow-500"
                    : "bg-purple-500"
                }`}
                style={{ width: `${storagePercent}%` }}
              ></div>
            </div>
            <p className="text-sm text-gray-500">
              {storagePercent.toFixed(1)}% used
            </p>
          </div>

          {/* Security Score */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Security Score</h2>
            <div className="text-5xl font-bold mb-2">
              {userData.twoFactorEnabled ? (
                <span className="text-green-500">✔</span>
              ) : (
                <span className="text-yellow-500">⚠</span>
              )}
            </div>
            <p className="text-gray-600 text-sm">
              Your account is {userData.accountStatus || "Active"}.
              Keep 2FA enabled and monitor new logins.
            </p>
          </div>

          {/* Account Quick Info */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Account Status</h2>
            <p className="mb-1">
              <span className="font-medium text-gray-600">Status:</span>{" "}
              <span className="text-green-600 font-semibold">
                {userData.accountStatus || "Active"}
              </span>
            </p>
            <p className="mb-1">
              <span className="font-medium text-gray-600">2FA Enabled:</span>{" "}
              <span className={`font-semibold ${userData.twoFactorEnabled ? "text-green-600" : "text-red-500"}`}>
                {userData.twoFactorEnabled ? "Yes" : "No"}
              </span>
            </p>
            <p>
              <span className="font-medium text-gray-600">Joined:</span>{" "}
              <span className="text-gray-700">
                {userData?.createdAt
                  ? new Date(userData.createdAt).toLocaleDateString("en-US", {
                      weekday: "short",
                      year: "numeric",
                      month: "short",
                      day: "numeric",
                    })
                  : "Unknown"}
              </span>
            </p>
          </div>
        </div>

        {/* Main Grid Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Activity */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-xl font-semibold mb-4 text-purple-700">Recent Activity</h2>
            {userData.recentActivity && userData.recentActivity.length > 0 ? (
              <ul className="space-y-3">
                {userData.recentActivity.map((activity, index) => {
                  const style = getActivityStyle(activity.action);
                  return (
                    <li
                      key={index}
                      className="flex items-center justify-between border-b border-gray-100 pb-3 hover:bg-gray-50 px-2 py-2 rounded transition"
                    >
                      <div className="flex items-center gap-3 flex-1">
                        <div className={`w-8 h-8 rounded-full ${style.bgColor} flex items-center justify-center text-lg`}>
                          {style.icon}
                        </div>
                        <div className="flex-1">
                          <p className="text-gray-800 font-medium">
                            {getDisplayName(activity.filename)}
                          </p>
                          <p className={`text-sm ${style.color} font-semibold`}>
                            {style.label}
                          </p>
                        </div>
                      </div>
                      <span className="text-gray-400 text-sm whitespace-nowrap ml-4">
                        {activity.timestamp
                          ? new Date(activity.timestamp).toLocaleDateString("en-US", {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })
                          : "Unknown"}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : userData.uploads && userData.uploads.length > 0 ? (
              <ul className="space-y-3">
                {userData.uploads.map((item, index) => (
                  <li
                    key={index}
                    className="flex justify-between border-b border-gray-100 pb-2 text-gray-700"
                  >
                    <span>{getDisplayName(item.filename)}</span>
                    <span className="text-gray-400 text-sm">
                      {item.uploadedAt
                        ? new Date(item.uploadedAt).toLocaleDateString("en-US", {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                          })
                        : "Unknown"}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-400">No recent activity.</p>
            )}
          </div>

          {/* Device Management */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-xl font-semibold mb-4 text-purple-700">Active Devices</h2>
            {userData.trustedDevices && userData.trustedDevices.length > 0 ? (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-gray-200 text-gray-600">
                    <th className="py-2 font-semibold">Device</th>
                    <th className="font-semibold">Last Active</th>
                  </tr>
                </thead>
                <tbody>
                  {userData.trustedDevices.map((d, i) => (
                    <tr key={i} className="border-b border-gray-100 text-gray-600">
                      <td className="py-2">{d.deviceName || "Unknown Device"}</td>
                      <td>
                        {d.lastUsed
                          ? new Date(d.lastUsed).toLocaleDateString("en-US", {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })
                          : "Unknown"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-gray-400">No trusted devices.</p>
            )}
          </div>
        </div>

        {/* Navigation Tiles */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 mt-10">
          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md hover:border-l-purple-700 cursor-pointer transition-all"
            onClick={() => handleNavigation("/settings")}
          >
            <h2 className="text-lg font-semibold mb-1 text-purple-700">Settings</h2>
            <p className="text-gray-500 text-sm">Configure account and security preferences.</p>
          </div>

          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md hover:border-l-purple-700 cursor-pointer transition-all"
            onClick={() => handleNavigation("/upload")}
          >
            <h2 className="text-lg font-semibold mb-1 text-purple-700">Upload Files</h2>
            <p className="text-gray-500 text-sm">Securely upload new files to your storage.</p>
          </div>

          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md hover:border-l-purple-700 cursor-pointer transition-all"
            onClick={() => handleNavigation("/manage")}
          >
            <h2 className="text-lg font-semibold mb-1 text-purple-700">Manage Files</h2>
            <p className="text-gray-500 text-sm">View, share, or delete stored files.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
