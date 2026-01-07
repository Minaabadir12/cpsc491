import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../Components/Navbar";

const HomePage = () => {
  const navigate = useNavigate();

  // Simulated storage + account data
  const [usedStorage, setUsedStorage] = useState(320); // GB
  const maxStorage = 1000; // 1TB
  const storagePercent = (usedStorage / maxStorage) * 100;

  const [securityInfo, setSecurityInfo] = useState({
    score: 92,
    lastLogin: "2025-10-05 20:34 PST",
    location: "Los Angeles, CA, USA",
    accountStatus: "Active",
    twoFactorEnabled: true,
  });

  const [recentActivity, setRecentActivity] = useState([
    { type: "Upload", file: "ProjectPlan.pdf", time: "2h ago" },
    { type: "Login", file: "New device login", time: "5h ago" },
    { type: "Delete", file: "OldReport.zip", time: "1d ago" },
    { type: "Share", file: "TeamNotes.docx", time: "3d ago" },
  ]);

  const [devices, setDevices] = useState([
    { device: "Chrome on Windows", location: "Los Angeles, CA", lastActive: "2h ago" },
    { device: "Safari on iPhone", location: "San Diego, CA", lastActive: "Yesterday" },
  ]);

  const handleNavigation = (path) => navigate(path);

  useEffect(() => {
    // Placeholder for future backend calls
    // fetch('/api/dashboard').then(res => res.json()).then(data => setUsedStorage(data.usedStorage));
  }, []);

  return (
    <div className="min-h-screen bg-gray-100">
      <Navbar />
      <div className="max-w-7xl mx-auto py-10 px-6">
        <h1 className="text-4xl font-bold text-center mb-10">GuardFile Dashboard</h1>

        {/* Top Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          {/* Storage */}
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-3">Storage Usage</h2>
            <p className="text-gray-600 mb-2">
              {usedStorage} GB / {maxStorage} GB (1 TB)
            </p>
            <div className="w-full bg-gray-200 rounded-full h-4 mb-2">
              <div
                className={`h-4 rounded-full transition-all duration-500 ${
                  storagePercent > 90
                    ? "bg-red-500"
                    : storagePercent > 70
                    ? "bg-yellow-500"
                    : "bg-green-500"
                }`}
                style={{ width: `${storagePercent}%` }}
              ></div>
            </div>
            <p className="text-sm text-gray-500">{storagePercent.toFixed(1)}% used</p>
          </div>

          {/* Security Score */}
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-3">Security Score</h2>
            <div className="text-5xl font-bold text-green-600 mb-2">
              {securityInfo.score}%
            </div>
            <p className="text-gray-600 text-sm">
              Your account is in excellent standing. Keep 2FA enabled and monitor new logins.
            </p>
          </div>

          {/* Account Quick Info */}
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-3">Account Status</h2>
            <p>
              <span className="font-medium text-gray-700">Status:</span>{" "}
              <span className="text-green-600 font-semibold">
                {securityInfo.accountStatus}
              </span>
            </p>
            <p>
              <span className="font-medium text-gray-700">2FA Enabled:</span>{" "}
              <span className="text-green-600 font-semibold">
                {securityInfo.twoFactorEnabled ? "Yes" : "No"}
              </span>
            </p>
            <p>
              <span className="font-medium text-gray-700">Last Login:</span>{" "}
              {securityInfo.lastLogin}
            </p>
            <p>
              <span className="font-medium text-gray-700">Location:</span>{" "}
              {securityInfo.location}
            </p>
          </div>
        </div>

        {/* Main Grid Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Activity */}
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold mb-4">Recent Activity</h2>
            <ul className="space-y-3">
              {recentActivity.map((item, index) => (
                <li
                  key={index}
                  className="flex justify-between border-b border-gray-200 pb-2 text-gray-700"
                >
                  <span>
                    <strong>{item.type}</strong> — {item.file}
                  </span>
                  <span className="text-gray-500 text-sm">{item.time}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Device Management */}
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold mb-4">Active Devices</h2>
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-gray-300 text-gray-700">
                  <th className="py-2">Device</th>
                  <th>Location</th>
                  <th>Last Active</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d, i) => (
                  <tr key={i} className="border-b border-gray-200 text-gray-600">
                    <td className="py-2">{d.device}</td>
                    <td>{d.location}</td>
                    <td>{d.lastActive}</td>
                    <td>
                      <button className="text-red-500 hover:text-red-700 text-sm font-semibold">
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="text-right mt-3">
              <button className="text-blue-600 hover:text-blue-800 text-sm">
                Sign out all devices
              </button>
            </div>
          </div>
        </div>

        {/* Navigation Tiles (Settings, Upload, Manage) */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-8 mt-10">
          <div
            className="bg-white p-6 rounded-lg shadow-md hover:shadow-lg cursor-pointer transition"
            onClick={() => handleNavigation("/settings")}
          >
            <h2 className="text-xl font-semibold mb-2">Settings</h2>
            <p className="text-gray-600">Configure account and security preferences.</p>
          </div>

          <div
            className="bg-white p-6 rounded-lg shadow-md hover:shadow-lg cursor-pointer transition"
            onClick={() => handleNavigation("/upload")}
          >
            <h2 className="text-xl font-semibold mb-2">Upload Files</h2>
            <p className="text-gray-600">Securely upload new files to your storage.</p>
          </div>

          <div
            className="bg-white p-6 rounded-lg shadow-md hover:shadow-lg cursor-pointer transition"
            onClick={() => handleNavigation("/manage")}
          >
            <h2 className="text-xl font-semibold mb-2">Manage Files</h2>
            <p className="text-gray-600">View, share, or delete stored files.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
