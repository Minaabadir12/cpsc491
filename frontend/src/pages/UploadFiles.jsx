import React, { useCallback, useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";
import { CloudUpload, Lock, KeyRound, ShieldCheck } from "lucide-react";
import { fetchWithAuth, logout } from "../utils/api";
import Navbar from "../Components/Navbar";

const UploadFiles = () => {
  const navigate = useNavigate();

  const [files, setFiles] = useState([]);
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  // Encryption state
  const [encryptionMode, setEncryptionMode] = useState("none");
  const [encryptionPassword, setEncryptionPassword] = useState("");
  const [confirmEncryptionPassword, setConfirmEncryptionPassword] = useState("");
  const [hasPasskey, setHasPasskey] = useState(false);

  useEffect(() => {
    const userId = localStorage.getItem("userId");
    const token = localStorage.getItem("token");

    if (!userId || !token) {
      navigate("/");
      return;
    }

    const fetchDashboard = async () => {
      try {
        const res = await fetchWithAuth(
          `http://localhost:3000/api/dashboard/${userId}`
        );

        if (!res.ok) throw new Error("Failed to fetch dashboard");

        const data = await res.json();
        setUserData(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    // Check if user has a registered passkey
    const checkPasskey = async () => {
      try {
        const res = await fetch(`http://localhost:3000/webauthn/status/${userId}`);
        if (res.ok) {
          const data = await res.json();
          setHasPasskey(data.hasPasskey);
        }
      } catch (err) {
        console.error("Failed to check passkey status:", err);
      }
    };

    fetchDashboard();
    checkPasskey();
  }, [navigate]);

  const onDrop = useCallback((acceptedFiles) => {
    setFiles((prev) => [...prev, ...acceptedFiles]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
  });

  const removeFile = (indexToRemove) => {
    setFiles((prev) => prev.filter((_, i) => i !== indexToRemove));
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
          <p className="text-xl mb-4 text-gray-700">Failed to load user data</p>
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

  const usedStorage = userData?.storageUsed ?? 0;
  const totalStorage = userData?.storageLimit ?? 1000;
  const usedPercentage = Math.min(
    (usedStorage / totalStorage) * 100,
    100
  );

  const handleUpload = async () => {
    if (files.length === 0) {
      alert("No files selected");
      return;
    }

    if (encryptionMode === "password") {
      if (!encryptionPassword) {
        alert("Please enter an encryption password.");
        return;
      }
      if (encryptionPassword !== confirmEncryptionPassword) {
        alert("Encryption passwords do not match.");
        return;
      }
    }

    if (encryptionMode === "passkey" && !hasPasskey) {
      alert("You need to register a passkey in Settings before using passkey encryption.");
      return;
    }

    const userId = localStorage.getItem("userId");
    const token = localStorage.getItem("token");

    if (!token) {
      alert("Session expired. Please log in again.");
      logout();
      return;
    }

    const formData = new FormData();

    files.forEach((file) => {
      formData.append("files", file);
    });

    formData.append("encryptionMode", encryptionMode);
    if (encryptionMode === "password") {
      formData.append("encryptionPassword", encryptionPassword);
    }

    setUploading(true);

    try {
      const res = await fetch(
        `http://localhost:3000/api/upload/${userId}`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
          },
          body: formData,
        }
      );

      if (res.status === 401 || res.status === 403) {
        alert("Session expired. Please log in again.");
        logout();
        return;
      }

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");

      alert("Upload successful!");
      setFiles([]);
      setEncryptionMode("none");
      setEncryptionPassword("");
      setConfirmEncryptionPassword("");

      setUserData((prev) => ({
        ...prev,
        storageUsed: data.storageUsed,
        uploads: data.uploads,
      }));
    } catch (err) {
      console.error(err);
      alert("Upload failed: " + err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-4xl mx-auto py-10 px-6">
        {/* Navigation Buttons */}
        <div className="flex justify-end gap-3 mb-4">
          <button
            onClick={() => navigate("/home")}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Back to Main Menu
          </button>
          <button
            onClick={() => navigate("/manage")}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Manage Files
          </button>
        </div>

        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <CloudUpload className="w-8 h-8 text-purple-600" />
          <h1 className="text-3xl font-bold text-purple-800">Upload Files</h1>
        </div>

        {/* Storage Usage */}
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
            {usedStorage.toFixed(1)} GB used of {totalStorage} GB (
            {usedPercentage.toFixed(1)}%)
          </p>
        </div>

        {/* Upload Area */}
        <div
          {...getRootProps()}
          className={`border-3 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all
            ${
              isDragActive
                ? "border-purple-500 bg-purple-50"
                : "border-gray-300 bg-white shadow-sm hover:shadow-md hover:border-purple-300"
            }`}
        >
          <input {...getInputProps()} />
          <CloudUpload className={`w-12 h-12 mx-auto mb-3 ${isDragActive ? "text-purple-600" : "text-gray-400"}`} />
          {isDragActive ? (
            <p className="text-purple-600 font-medium">
              Drop the files here...
            </p>
          ) : (
            <p className="text-gray-500">
              Drag & drop files here, or click to select files
            </p>
          )}
        </div>

        {/* Selected Files */}
        {files.length > 0 && (
          <div className="mt-6 bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold mb-4 text-purple-700">
              Files to Upload:
            </h2>

            <ul className="space-y-3">
              {files.map((file, index) => (
                <li
                  key={index}
                  className="flex justify-between items-center border-b border-gray-100 pb-2"
                >
                  <span className="text-gray-700">
                    {file.name} — {Math.round(file.size / 1024)} KB
                  </span>
                  <button
                    onClick={() => removeFile(index)}
                    className="text-red-500 hover:text-red-700 font-medium text-sm"
                    disabled={uploading}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>

            {/* Encryption Mode Selector */}
            <div className="mt-6 pt-6 border-t border-gray-100">
              <h3 className="text-lg font-semibold mb-3 text-purple-700 flex items-center gap-2">
                <Lock className="w-5 h-5" />
                File Protection
              </h3>
              <div className="space-y-3">
                {/* None */}
                <label className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition ${encryptionMode === "none" ? "border-purple-400 bg-purple-50" : "border-gray-200 hover:border-gray-300"}`}>
                  <input
                    type="radio"
                    name="encryptionMode"
                    value="none"
                    checked={encryptionMode === "none"}
                    onChange={() => setEncryptionMode("none")}
                    className="accent-purple-600"
                  />
                  <div>
                    <p className="font-medium text-gray-800">No Protection</p>
                    <p className="text-sm text-gray-500">Files are stored without encryption</p>
                  </div>
                </label>

                {/* Password */}
                <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition ${encryptionMode === "password" ? "border-purple-400 bg-purple-50" : "border-gray-200 hover:border-gray-300"}`}>
                  <input
                    type="radio"
                    name="encryptionMode"
                    value="password"
                    checked={encryptionMode === "password"}
                    onChange={() => setEncryptionMode("password")}
                    className="accent-purple-600 mt-1"
                  />
                  <div className="flex-1">
                    <p className="font-medium text-gray-800 flex items-center gap-2">
                      <KeyRound className="w-4 h-4 text-purple-600" />
                      Password Protection
                    </p>
                    <p className="text-sm text-gray-500">Encrypt with a password you'll need to enter when downloading</p>
                    {encryptionMode === "password" && (
                      <div className="mt-3 space-y-2">
                        <input
                          type="password"
                          placeholder="Encryption password"
                          value={encryptionPassword}
                          onChange={(e) => setEncryptionPassword(e.target.value)}
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent text-sm"
                        />
                        <input
                          type="password"
                          placeholder="Confirm encryption password"
                          value={confirmEncryptionPassword}
                          onChange={(e) => setConfirmEncryptionPassword(e.target.value)}
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent text-sm"
                        />
                        {confirmEncryptionPassword && (
                          <p className={`text-sm ${encryptionPassword === confirmEncryptionPassword ? "text-green-600" : "text-red-500"}`}>
                            {encryptionPassword === confirmEncryptionPassword ? "\u2713 Passwords match" : "\u2717 Passwords do not match"}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </label>

                {/* Passkey */}
                <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition ${encryptionMode === "passkey" ? "border-purple-400 bg-purple-50" : "border-gray-200 hover:border-gray-300"} ${!hasPasskey ? "opacity-50" : ""}`}>
                  <input
                    type="radio"
                    name="encryptionMode"
                    value="passkey"
                    checked={encryptionMode === "passkey"}
                    onChange={() => hasPasskey && setEncryptionMode("passkey")}
                    disabled={!hasPasskey}
                    className="accent-purple-600 mt-1"
                  />
                  <div>
                    <p className="font-medium text-gray-800 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-purple-600" />
                      Passkey / Biometrics
                    </p>
                    <p className="text-sm text-gray-500">
                      {hasPasskey
                        ? "Downloading will require your fingerprint or biometric authentication"
                        : "Register a passkey in Settings to use this option"}
                    </p>
                  </div>
                </label>
              </div>
            </div>

            <div className="mt-4 flex justify-end">
              <button
                onClick={handleUpload}
                className="px-6 py-2 bg-purple-600 text-white rounded-lg font-medium hover:bg-purple-700 transition disabled:opacity-50"
                disabled={uploading}
              >
                {uploading ? "Uploading..." : "Upload Files"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UploadFiles;
