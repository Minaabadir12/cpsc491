import React, { useCallback, useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";
import { CloudUpload } from "lucide-react";
import { fetchWithAuth, logout } from "../utils/api";

const UploadFiles = () => {
  const navigate = useNavigate();

  const [files, setFiles] = useState([]);
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  // 🔹 Fetch REAL dashboard data (storage + limits)
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
        // fetchWithAuth will handle logout if token is invalid
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
  }, [navigate]);

  // 🔹 Dropzone handler
  const onDrop = useCallback((acceptedFiles) => {
    setFiles((prev) => [...prev, ...acceptedFiles]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
  });

  // 🔹 Remove selected file
  const removeFile = (indexToRemove) => {
    setFiles((prev) => prev.filter((_, i) => i !== indexToRemove));
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Loading...
      </div>
    );
  }

  if (!userData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-xl mb-4">Failed to load user data</p>
          <button 
            onClick={() => navigate("/")}
            className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
          >
            Return to Login
          </button>
        </div>
      </div>
    );
  }

  // ✅ REAL values from backend
  const usedStorage = userData?.storageUsed ?? 0;
  const totalStorage = userData?.storageLimit ?? 1000;
  const usedPercentage = Math.min(
    (usedStorage / totalStorage) * 100,
    100
  );

  // 🔹 AUTHENTICATED upload request
  const handleUpload = async () => {
    if (files.length === 0) {
      alert("No files selected");
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

    setUploading(true);

    try {
      const res = await fetch(
        `http://localhost:3000/api/upload/${userId}`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            // Don't set Content-Type for FormData - browser sets it automatically with boundary
          },
          body: formData,
        }
      );

      // Check for authentication errors
      if (res.status === 401 || res.status === 403) {
        alert("Session expired. Please log in again.");
        logout();
        return;
      }

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");

      alert("Upload successful!");
      setFiles([]);

      // 🔁 Refresh storage data after upload
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
    <div className="max-w-4xl mx-auto p-8">
      {/* Back Button */}
      <div className="flex justify-end mb-4">
        <button
          onClick={() => navigate("/home")}
          className="btn btn-outline btn-accent"
        >
          Back to Dashboard
        </button>
      </div>

      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <CloudUpload className="w-8 h-8 text-blue-600" />
        <h1 className="text-3xl font-bold">Upload Files</h1>
      </div>

      {/* Storage Usage */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <h2 className="text-xl font-semibold mb-2">Storage Usage</h2>
        <div className="w-full bg-gray-200 rounded-full h-4 mb-2">
          <div
            className={`h-4 rounded-full transition-all duration-500 ${
              usedPercentage > 90
                ? "bg-red-500"
                : usedPercentage > 70
                ? "bg-yellow-500"
                : "bg-blue-600"
            }`}
            style={{ width: `${usedPercentage}%` }}
          />
        </div>
        <p className="text-gray-600 text-sm">
          {usedStorage.toFixed(1)} GB used of {totalStorage} GB (
          {usedPercentage.toFixed(1)}%)
        </p>
      </div>

      {/* Upload Area */}
      <div
        {...getRootProps()}
        className={`border-4 border-dashed rounded-lg p-10 text-center cursor-pointer transition
          ${
            isDragActive
              ? "border-blue-500 bg-blue-50"
              : "border-gray-300 bg-white shadow-sm hover:shadow-md"
          }`}
      >
        <input {...getInputProps()} />
        {isDragActive ? (
          <p className="text-blue-600 font-medium">
            Drop the files here...
          </p>
        ) : (
          <p className="text-gray-600">
            Drag & drop files here, or click to select files
          </p>
        )}
      </div>

      {/* Selected Files */}
      {files.length > 0 && (
        <div className="mt-6 bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">
            Files to Upload:
          </h2>

          <ul className="space-y-3">
            {files.map((file, index) => (
              <li
                key={index}
                className="flex justify-between items-center border-b pb-2"
              >
                <span className="text-gray-700">
                  {file.name} — {Math.round(file.size / 1024)} KB
                </span>
                <button
                  onClick={() => removeFile(index)}
                  className="text-red-600 hover:text-red-800 font-semibold"
                  disabled={uploading}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>

          <div className="mt-4 flex justify-end">
            <button
              onClick={handleUpload}
              className="btn btn-primary"
              disabled={uploading}
            >
              {uploading ? "Uploading..." : "Upload Files"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default UploadFiles;