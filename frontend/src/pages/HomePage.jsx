import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../Components/Navbar";
import { fetchWithAuth, logout } from "../utils/api";

const HomePage = () => {
  const navigate = useNavigate();
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [nowMs, setNowMs] = useState(Date.now());
  const [scannerStatus, setScannerStatus] = useState({
    mode: "unknown",
    active: false,
    details: "Checking scanner status...",
  });
  const [securityScore, setSecurityScore] = useState({
    score: 0,
    grade: "F",
    reasons: [],
  });

  const getDisplayName = (filename) => {
    if (!filename) return "";
    return filename.replace(/^\d+-/, "");
  };

  const truncateText = (text, max = 28) => {
    if (!text) return "";
    return text.length > max ? `${text.slice(0, max - 1)}...` : text;
  };

  const parseUserAgent = (ua) => {
    const value = (ua || "").toLowerCase();
    let browser = "Unknown";
    if (value.includes("edg/")) browser = "Edge";
    else if (value.includes("opr/") || value.includes("opera")) browser = "Opera";
    else if (value.includes("chrome/")) browser = "Chrome";
    else if (value.includes("firefox/")) browser = "Firefox";
    else if (value.includes("safari/") && !value.includes("chrome/")) browser = "Safari";
    return browser;
  };

  const getDeviceLabel = (device) => {
    const browser = parseUserAgent(device?.userAgent);
    if (browser !== "Unknown") return browser;
    return device?.deviceName || "Unknown";
  };

  const formatRelativeTime = (dateLike) => {
    if (!dateLike) return "Unknown";
    const value = new Date(dateLike).getTime();
    if (Number.isNaN(value)) return "Unknown";
    const diffSec = Math.max(0, Math.floor((nowMs - value) / 1000));
    if (diffSec < 60) return "just now";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min ago`;
    if (diffSec < 86400) {
      const hours = Math.floor(diffSec / 3600);
      return `${hours} ${hours === 1 ? "hr" : "hrs"} ago`;
    }
    const days = Math.floor(diffSec / 86400);
    return `${days} ${days === 1 ? "day" : "days"} ago`;
  };

  const getActivityStyle = (action, metadata = {}) => {
    if (action === "modify" && metadata?.scanStatus) {
      if (metadata.scanStatus === "clean") {
        return { icon: "SC", color: "text-emerald-700", bgColor: "bg-emerald-100", label: "Security Scan: Clean" };
      }
      if (metadata.scanStatus === "infected") {
        return { icon: "SB", color: "text-rose-700", bgColor: "bg-rose-100", label: "Security Scan: Blocked" };
      }
      return { icon: "SE", color: "text-amber-700", bgColor: "bg-amber-100", label: "Security Scan: Error" };
    }
    const styles = {
      upload: { icon: "↑", color: "text-green-600", bgColor: "bg-green-100", label: "Uploaded" },
      delete: { icon: "🗑", color: "text-red-600", bgColor: "bg-red-100", label: "Deleted" },
      share: { icon: "↗", color: "text-blue-600", bgColor: "bg-blue-100", label: "Shared" },
      download: { icon: "↓", color: "text-purple-600", bgColor: "bg-purple-100", label: "Downloaded" },
      modify: { icon: "✎", color: "text-yellow-600", bgColor: "bg-yellow-100", label: "Modified" },
      device_added: { icon: "💻", color: "text-teal-600", bgColor: "bg-teal-100", label: "Device Added" },
      device_removed: { icon: "⊗", color: "text-orange-600", bgColor: "bg-orange-100", label: "Device Removed" },
      voice_enrolled: { icon: "🎤", color: "text-indigo-600", bgColor: "bg-indigo-100", label: "Voice Enrolled" },
      voice_verified: { icon: "✓", color: "text-emerald-600", bgColor: "bg-emerald-100", label: "Voice Verified" },
      voice_failed: { icon: "!", color: "text-rose-600", bgColor: "bg-rose-100", label: "Voice Failed" },
      voice_removed: { icon: "✕", color: "text-slate-600", bgColor: "bg-slate-100", label: "Voice Removed" },
    };
    return styles[action] || styles.upload;
  };

  useEffect(() => {
    const userId = localStorage.getItem("userId");
    const token = localStorage.getItem("token");

    if (!userId || !token) {
      navigate("/");
      return;
    }

    const fetchDashboard = async () => {
      try {
        const res = await fetchWithAuth(`http://localhost:3000/api/dashboard/${userId}`);
        if (!res.ok) throw new Error("Failed to fetch dashboard");
        const data = await res.json();
        setUserData(data);

        const scannerRes = await fetchWithAuth("http://localhost:3000/api/security/scanner-status");
        if (scannerRes.ok) {
          const scannerData = await scannerRes.json();
          setScannerStatus(scannerData);
        }

        const scoreRes = await fetchWithAuth(`http://localhost:3000/api/security/score/${userId}`);
        if (scoreRes.ok) {
          const scoreData = await scoreRes.json();
          setSecurityScore({
            score: scoreData.score ?? 0,
            grade: scoreData.grade || "F",
            reasons: Array.isArray(scoreData.reasons) ? scoreData.reasons : [],
          });
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
    const pollId = setInterval(fetchDashboard, 30000);
    return () => clearInterval(pollId);
  }, [navigate]);

  useEffect(() => {
    const timerId = setInterval(() => setNowMs(Date.now()), 30000);
    return () => clearInterval(timerId);
  }, []);

  const handleNavigation = (path) => navigate(path);
  const handleLogout = () => {
    if (window.confirm("Are you sure you want to logout?")) logout();
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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          {/* Storage */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Storage Usage</h2>
            <p className="text-gray-600 mb-2 text-sm">
              {storageUsedRounded} GB / {storageLimitRounded} GB ({(userData.storageLimit / 1024).toFixed(2)} TB)
            </p>
            <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${
                  storagePercent > 90 ? "bg-red-500" : storagePercent > 70 ? "bg-yellow-500" : "bg-purple-500"
                }`}
                style={{ width: `${storagePercent}%` }}
              />
            </div>
            <p className="text-sm text-gray-500">{storagePercent.toFixed(1)}% used</p>
          </div>

          {/* Security Score */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Security Score</h2>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-end gap-2">
                <div
                  className={`text-5xl font-bold ${
                    securityScore.score >= 85
                      ? "text-emerald-600"
                      : securityScore.score >= 70
                      ? "text-yellow-600"
                      : "text-rose-600"
                  }`}
                >
                  {securityScore.score}
                </div>
                <div className="text-sm font-semibold text-gray-500 mb-1">/100</div>
              </div>
              <span
                className={`px-3 py-1 rounded-full text-xs font-semibold ${
                  securityScore.grade === "A"
                    ? "bg-emerald-100 text-emerald-700"
                    : securityScore.grade === "B"
                    ? "bg-green-100 text-green-700"
                    : securityScore.grade === "C"
                    ? "bg-yellow-100 text-yellow-700"
                    : "bg-rose-100 text-rose-700"
                }`}
              >
                Grade {securityScore.grade}
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${scannerStatus.active ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"}`}>
                {scannerStatus.active ? "Scanner Active" : "Fallback Scanner"}
              </span>
              <span className="px-2 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                {userData.twoFactorEnabled ? "2FA On" : "2FA Off"}
              </span>
            </div>
          </div>

          {/* Account Quick Info */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-3 text-purple-700">Account Status</h2>
            <p className="mb-1">
              <span className="font-medium text-gray-600">Status:</span>{" "}
              <span className="text-green-600 font-semibold">{userData.accountStatus || "Active"}</span>
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

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
          <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-xl font-semibold mb-3 text-purple-700">Recent Activity</h2>
            {userData.recentActivity && userData.recentActivity.length > 0 ? (
              <ul className="space-y-1 max-h-[420px] overflow-auto pr-1">
                {userData.recentActivity.slice(0, 10).map((activity, index) => {
                  const style = getActivityStyle(activity.action, activity.metadata);
                  return (
                    <li
                      key={index}
                      className="flex items-center justify-between border-b border-gray-100 hover:bg-gray-50 px-2 py-2 rounded transition"
                    >
                      <div className="flex items-center gap-3 flex-1">
                        <div
                          className={`w-7 h-7 rounded-full ${style.bgColor} flex items-center justify-center text-[10px] font-semibold`}
                        >
                          {style.icon}
                        </div>
                        <div className="flex-1">
                          <p className="text-gray-800 font-medium text-sm leading-tight">
                            <span title={getDisplayName(activity.filename)}>
                              {truncateText(getDisplayName(activity.filename), 26)}
                            </span>
                          </p>
                          <p className={`text-xs ${style.color} font-semibold`}>{style.label}</p>
                        </div>
                      </div>
                      <span className="text-gray-500 text-xs whitespace-nowrap ml-3">
                        {formatRelativeTime(activity.timestamp)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-gray-500">No recent activity.</p>
            )}
            {userData.recentActivity && userData.recentActivity.length > 10 && (
              <p className="text-xs text-gray-500 mt-2">Showing 10 of {userData.recentActivity.length} activities</p>
            )}
          </div>

          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-100 self-start w-full">
            <h2 className="text-lg font-semibold mb-2 text-purple-700">Trusted Devices</h2>
            {userData.trustedDevices && userData.trustedDevices.length > 0 ? (
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-gray-700">
                    <th className="py-2 font-semibold">Browser</th>
                    <th className="font-semibold">Last Active</th>
                  </tr>
                </thead>
                <tbody>
                  {userData.trustedDevices.map((device, i) => (
                    <tr key={i} className="border-b border-gray-100 text-gray-600">
                      <td className="py-2" title={device.userAgent || ""}>
                        {truncateText(getDeviceLabel(device), 18)}
                      </td>
                      <td className="text-xs">{formatRelativeTime(device.lastUsed)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-gray-500 text-sm">No trusted devices.</p>
            )}
          </div>
        </div>

        {/* Navigation Tiles */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 mt-10">
          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md cursor-pointer transition-all"
            onClick={() => handleNavigation("/settings")}
          >
            <h2 className="text-lg font-semibold mb-1 text-purple-700">Settings</h2>
            <p className="text-gray-500 text-sm">Configure account and security preferences.</p>
          </div>

          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md cursor-pointer transition-all"
            onClick={() => handleNavigation("/upload")}
          >
            <h2 className="text-lg font-semibold mb-1 text-purple-700">Upload Files</h2>
            <p className="text-gray-500 text-sm">Securely upload new files to your storage.</p>
          </div>

          <div
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 border-l-4 border-l-purple-500 hover:shadow-md cursor-pointer transition-all"
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
