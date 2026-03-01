import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Trash2, Download, Share2, X, Copy, Check, FolderOpen, Lock, KeyRound, ShieldCheck } from "lucide-react";
import { startAuthentication } from "@simplewebauthn/browser";
import { fetchWithAuth, logout } from "../utils/api";
import Navbar from "../Components/Navbar";

const ManageFiles = () => {
  const navigate = useNavigate();

  const [userData, setUserData] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  // Share modal state
  const [isShareModalOpen, setIsShareModalOpen] = useState(false);
  const [shareFilename, setShareFilename] = useState("");
  const [shareFileEncryptionMode, setShareFileEncryptionMode] = useState("none");
  const [shareExpiry, setShareExpiry] = useState("24h");
  const [sharePassword, setSharePassword] = useState("");
  const [shareEncryptionPassword, setShareEncryptionPassword] = useState("");
  const [generatedLink, setGeneratedLink] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  // Helper function to clean filenames
  const getDisplayName = (filename) => {
    if (!filename) return '';
    // Remove timestamp prefix (e.g., "1769034580483-" from the beginning)
    return filename.replace(/^\d+-/, '');
  };

  const getScanMeta = (status) => {
    const value = status || "pending";
    if (value === "clean") return { label: "Ready", className: "text-green-700 bg-green-100" };
    if (value === "infected") return { label: "Blocked", className: "text-red-700 bg-red-100" };
    if (value === "error") return { label: "Scan Error", className: "text-orange-700 bg-orange-100" };
    return { label: "Scanning", className: "text-blue-700 bg-blue-100" };
  };

  // ✅ Get userId and token safely
  const userId = localStorage.getItem("userId");
  const token = localStorage.getItem("token");

  // 🔐 Redirect if not logged in
  useEffect(() => {
    if (!userId || !token) {
      navigate("/");
    }
  }, [userId, token, navigate]);

  // 📡 Fetch dashboard data
  useEffect(() => {
    if (!userId || !token) return;

    const fetchDashboard = async () => {
      try {
        const res = await fetchWithAuth(
          `http://localhost:3000/api/dashboard/${userId}`,
          { cache: "no-store" } // prevent 304 Not Modified issues
        );

        if (!res.ok) throw new Error("Failed to fetch dashboard");

        const data = await res.json();

        setUserData(data);
        setFiles(data.uploads ?? []); // safe fallback
      } catch (err) {
        console.error(err);
        // fetchWithAuth will handle logout if token is invalid
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
  }, [userId, token, navigate]);

  useEffect(() => {
    if (!userId || !token) return;

    const hasPending = files.some((f) => (f.scanStatus || "pending") === "pending");
    if (!hasPending) return;

    const id = setInterval(async () => {
      try {
        const res = await fetchWithAuth(`http://localhost:3000/api/dashboard/${userId}`, { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        setUserData(data);
        setFiles(data.uploads ?? []);
      } catch (err) {
        console.error(err);
      }
    }, 8000);

    return () => clearInterval(id);
  }, [files, token, userId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <p className="text-gray-500 text-lg">Loading files...</p>
      </div>
    );
  }

  if (!userData) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-xl mb-4 text-gray-700">Failed to load files</p>
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

  // safe default values
  const usedStorage = userData?.storageUsed ?? 0;
  const totalStorage = userData?.storageLimit ?? 1; // avoid divide by zero

  const filteredFiles = files.filter((file) =>
    getDisplayName(file.filename)?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const downloadBlob = (blob, filename) => {
    const displayName = filename.replace(/^\d+-/, "");
    const viewableMimeTypes = [
      "application/pdf", "image/png", "image/jpeg", "image/gif",
      "image/webp", "image/svg+xml", "text/plain",
    ];

    const url = window.URL.createObjectURL(blob);

    if (viewableMimeTypes.includes(blob.type)) {
      // Open in a new tab for preview (same as unencrypted behavior)
      window.open(url, "_blank");
    } else {
      // Force download for non-viewable file types
      const a = document.createElement("a");
      a.href = url;
      a.download = displayName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    }
  };

  const handleDownload = async (file) => {
    if (!file?.filename) return;

    // Unencrypted: use original behavior
    if (!file.encryptionMode || file.encryptionMode === "none") {
      window.open(`http://localhost:3000/uploads/${file.filename}`, "_blank");
      return;
    }

    // Password-encrypted: prompt for password
    if (file.encryptionMode === "password") {
      const password = prompt("Enter the decryption password for this file:");
      if (!password) return;

      try {
        const res = await fetchWithAuth(
          `http://localhost:3000/api/download/${userId}/${file.filename}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password }),
          }
        );
        if (!res.ok) {
          const errData = await res.json();
          alert(errData.error || "Decryption failed");
          return;
        }
        const blob = await res.blob();
        downloadBlob(blob, file.filename);
      } catch (err) {
        alert("Download failed: " + err.message);
      }
      return;
    }

    // Passkey-encrypted: run WebAuthn ceremony first
    if (file.encryptionMode === "passkey") {
      try {
        // 1. Get WebAuthn options using the user's email
        const optRes = await fetch("http://localhost:3000/webauthn/login/options", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId }),
        });
        const optData = await optRes.json();
        if (!optRes.ok) throw new Error(optData.error || "Failed to get passkey options");

        // Remove userId from options before passing to startAuthentication
        const { userId: _uid, ...authOptions } = optData;

        // 2. Trigger biometric prompt
        const asseResp = await startAuthentication({ optionsJSON: authOptions });

        // 3. Verify with backend
        const verRes = await fetch("http://localhost:3000/webauthn/login/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId, asseResp }),
        });
        const verData = await verRes.json();
        if (!verRes.ok) throw new Error(verData.error || "Passkey verification failed");

        // 4. Download the decrypted file
        const dlRes = await fetchWithAuth(
          `http://localhost:3000/api/download/${userId}/${file.filename}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ webauthnVerified: true }),
          }
        );
        if (!dlRes.ok) {
          const errData = await dlRes.json();
          alert(errData.error || "Download failed");
          return;
        }
        const blob = await dlRes.blob();
        downloadBlob(blob, file.filename);
      } catch (err) {
        console.error(err);
        alert("Passkey download failed: " + err.message);
      }
    }
  };

  const handleDelete = async (filename) => {
    if (!filename) return;

    if (!window.confirm(`Are you sure you want to delete "${getDisplayName(filename)}"?`))
      return;

    try {
      const res = await fetchWithAuth(
        `http://localhost:3000/api/files/${userId}/${filename}`,
        { method: "DELETE" }
      );

      // Check for authentication errors
      if (res.status === 401 || res.status === 403) {
        alert("Session expired. Please log in again.");
        logout();
        return;
      }

      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Delete failed");

      setFiles(data.uploads ?? []);
      setUserData((prev) => ({
        ...prev,
        storageUsed: data.storageUsed ?? prev.storageUsed,
      }));
      
      alert("File deleted successfully!");
    } catch (err) {
      console.error(err);
      alert("Delete failed: " + err.message);
    }
  };

  const handleShare = (filename) => {
    const file = files.find((f) => f.filename === filename);
    if (!file || file.scanStatus !== "clean") {
      alert("This file is not shareable until malware scanning completes successfully.");
      return;
    }

    setShareFilename(filename);
    setShareFileEncryptionMode(file?.encryptionMode || "none");
    setShareExpiry("24h");
    setSharePassword("");
    setShareEncryptionPassword("");
    setGeneratedLink("");
    setCopied(false);
    setIsShareModalOpen(true);
  };

  const generateShareLink = async () => {
    if (shareFileEncryptionMode === "password" && !shareEncryptionPassword) {
      alert("Please enter the file's encryption password to authorize sharing.");
      return;
    }

    setIsGenerating(true);
    try {
      const res = await fetchWithAuth(
        `http://localhost:3000/api/share/${userId}/${shareFilename}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            expiresIn: shareExpiry,
            password: sharePassword || undefined,
            encryptionPassword: shareEncryptionPassword || undefined,
          }),
        }
      );

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Failed to create share link");
      }

      const data = await res.json();
      const link = `${window.location.origin}/shared/${data.linkId}`;
      setGeneratedLink(link);
    } catch (err) {
      console.error(err);
      alert("Failed to generate share link: " + err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const closeShareModal = () => {
    setIsShareModalOpen(false);
    setShareFilename("");
    setShareEncryptionPassword("");
    setGeneratedLink("");
  };

  const usedPercentage = Math.min((usedStorage / totalStorage) * 100, 100);

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-6xl mx-auto py-10 px-6">
        {/* Navigation Buttons */}
        <div className="flex justify-end gap-3 mb-4">
          <button
            onClick={() => navigate("/home")}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Back to Main Menu
          </button>
          <button
            onClick={() => navigate("/upload")}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Upload Files
          </button>
        </div>

        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <FolderOpen className="w-8 h-8 text-purple-600" />
          <h1 className="text-3xl font-bold text-purple-800">Manage Files</h1>
        </div>

        {/* Storage Info */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-8">
          <h2 className="text-lg font-semibold mb-2 text-purple-700">Storage Usage</h2>
          <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
            <div
              className={`h-3 rounded-full transition-all duration-500 ${
                usedPercentage > 90
                  ? "bg-red-500"
                  : usedPercentage > 70
                  ? "bg-yellow-500"
                  : "bg-purple-500"
              }`}
              style={{ width: `${usedPercentage}%` }}
            />
          </div>
          <p className="text-gray-500 text-sm">
            {usedStorage.toFixed(2)} GB used of {totalStorage} GB ({usedPercentage.toFixed(1)}%)
          </p>
        </div>

        {/* Search Bar */}
        <div className="mb-8 flex justify-center">
          <div className="flex w-full max-w-md">
            <button
              onClick={() => setSearchTerm(searchInput)}
              className="px-5 py-2 bg-purple-600 text-white font-medium rounded-l-lg hover:bg-purple-700 transition"
            >
              Search
            </button>
            <input
              type="text"
              placeholder="Search files..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && setSearchTerm(searchInput)}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-r-lg focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent"
            />
          </div>
        </div>

        {/* Files Grid */}
        {filteredFiles.length === 0 ? (
          <p className="text-gray-400 text-center text-lg py-12">
            {searchTerm ? "No files match your search." : "No files uploaded yet."}
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
            {filteredFiles.map((file, index) => (
              <div
                key={index}
                className="bg-white rounded-xl shadow-sm border border-gray-100 p-5 flex flex-col justify-between hover:shadow-md transition"
              >
                <div>
                  <div className="flex items-start justify-between">
                    <h3 className="font-semibold text-gray-800 break-words flex-1">
                      {getDisplayName(file.filename)}
                    </h3>
                    {file.encryptionMode && file.encryptionMode !== "none" && (
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ml-2 shrink-0 ${
                        file.encryptionMode === "password"
                          ? "bg-amber-100 text-amber-700"
                          : "bg-purple-100 text-purple-700"
                      }`}>
                        {file.encryptionMode === "password" ? (
                          <><KeyRound className="w-3 h-3" /> Password</>
                        ) : (
                          <><ShieldCheck className="w-3 h-3" /> Passkey</>
                        )}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-500 mt-1">
                    {(file.size ?? 0).toFixed(2)} MB
                  </p>
                  <p className="text-sm text-gray-400 mt-1">
                    Uploaded:{" "}
                    {file.uploadedAt
                      ? new Date(file.uploadedAt).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })
                      : "Unknown"}
                  </p>
                </div>

                <div className="flex justify-between mt-4 gap-2">
                  <button
                    onClick={() => handleDownload(file)}
                    className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 text-sm font-medium text-purple-600 border border-purple-300 rounded-lg hover:bg-purple-50 transition"
                    title="Download file"
                  >
                    <Download className="w-4 h-4" /> Download
                  </button>

                  <button
                    onClick={() => handleShare(file.filename)}
                    className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 text-sm font-medium text-blue-600 border border-blue-300 rounded-lg hover:bg-blue-50 transition"
                    title="Share file"
                  >
                    <Share2 className="w-4 h-4" /> Share
                  </button>

                  <button
                    onClick={() => handleDelete(file.filename)}
                    className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 text-sm font-medium text-red-500 border border-red-300 rounded-lg hover:bg-red-50 transition"
                    title="Delete file"
                  >
                    <Trash2 className="w-4 h-4" /> Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Share Modal */}
        {isShareModalOpen && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4 shadow-lg">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-purple-800">Share File</h2>
                <button
                  onClick={closeShareModal}
                  className="text-gray-400 hover:text-gray-600 transition"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <p className="text-gray-600 mb-4">
                Sharing: <span className="font-medium text-gray-800">{getDisplayName(shareFilename)}</span>
              </p>

              {!generatedLink ? (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Link expires in</label>
                    <select
                      value={shareExpiry}
                      onChange={(e) => setShareExpiry(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent"
                    >
                      <option value="24h">24 hours</option>
                      <option value="7d">7 days</option>
                      <option value="30d">30 days</option>
                    </select>
                  </div>

                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Link Password (optional)
                    </label>
                    <input
                      type="password"
                      value={sharePassword}
                      onChange={(e) => setSharePassword(e.target.value)}
                      placeholder="Leave empty for no password"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent"
                    />
                  </div>

                  {shareFileEncryptionMode === "password" && (
                    <div className="mb-4 p-3 bg-amber-50 border border-amber-200 rounded-lg">
                      <label className="block text-sm font-medium text-amber-800 mb-1">
                        File Encryption Password
                      </label>
                      <p className="text-xs text-amber-600 mb-2">
                        This file is password-encrypted. Enter the encryption password to authorize the recipient to download it.
                      </p>
                      <input
                        type="password"
                        value={shareEncryptionPassword}
                        onChange={(e) => setShareEncryptionPassword(e.target.value)}
                        placeholder="Enter file encryption password"
                        className="w-full px-4 py-2 border border-amber-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-amber-400 focus:border-transparent"
                      />
                    </div>
                  )}

                  {shareFileEncryptionMode === "passkey" && (
                    <div className="mb-4 p-3 bg-purple-50 border border-purple-200 rounded-lg">
                      <p className="text-sm text-purple-700">
                        <ShieldCheck className="w-4 h-4 inline mr-1" />
                        This file is passkey-encrypted. The recipient will receive a decrypted copy automatically.
                      </p>
                    </div>
                  )}

                  <button
                    onClick={generateShareLink}
                    disabled={isGenerating}
                    className="w-full px-6 py-2 bg-purple-600 text-white rounded-lg font-medium hover:bg-purple-700 transition disabled:opacity-50"
                  >
                    {isGenerating ? "Generating..." : "Generate Link"}
                  </button>
                </>
              ) : (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Share Link</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={generatedLink}
                        readOnly
                        className="flex-1 px-4 py-2 text-sm border border-gray-300 rounded-lg bg-gray-50"
                      />
                      <button
                        onClick={copyToClipboard}
                        className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition"
                        title="Copy to clipboard"
                      >
                        {copied ? <Check className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  {sharePassword && (
                    <p className="text-sm text-gray-500 mb-4">
                      This link is password protected. Share the password separately.
                    </p>
                  )}

                  <button
                    onClick={closeShareModal}
                    className="w-full px-6 py-2 border-2 border-purple-600 text-purple-600 rounded-lg font-medium hover:bg-purple-600 hover:text-white transition"
                  >
                    Done
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ManageFiles;
