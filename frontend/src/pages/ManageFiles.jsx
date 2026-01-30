import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Trash2, Download, Share2 } from "lucide-react";
import { fetchWithAuth, logout } from "../utils/api";

const ManageFiles = () => {
  const navigate = useNavigate();

  const [userData, setUserData] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  // Helper function to clean filenames
  const getDisplayName = (filename) => {
    if (!filename) return '';
    // Remove timestamp prefix (e.g., "1769034580483-" from the beginning)
    return filename.replace(/^\d+-/, '');
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

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Loading files...
      </div>
    );
  }

  if (!userData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-xl mb-4">Failed to load files</p>
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

  // safe default values
  const usedStorage = userData?.storageUsed ?? 0;
  const totalStorage = userData?.storageLimit ?? 1; // avoid divide by zero

  const filteredFiles = files.filter((file) =>
    getDisplayName(file.filename)?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDownload = (filename) => {
    if (!filename) return;
    window.open(`http://localhost:3000/uploads/${filename}`, "_blank");
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
    alert(`Share feature coming soon for: ${getDisplayName(filename)}`);
  };

  return (
    <div className="max-w-6xl mx-auto p-8">
      {/* Back Button */}
      <div className="flex justify-end mb-4">
        <button
          onClick={() => navigate("/home")}
          className="btn btn-outline btn-accent"
        >
          Back to Dashboard
        </button>
      </div>

      <h1 className="text-3xl font-bold mb-6">Manage Files</h1>

      {/* Storage Info */}
      <div className="bg-white p-6 rounded-lg shadow mb-6">
        <h2 className="text-xl font-semibold mb-2">Storage Usage</h2>
        <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
          <div
            className={`h-3 rounded-full transition-all duration-500 ${
              (usedStorage / totalStorage) * 100 > 90
                ? "bg-red-500"
                : (usedStorage / totalStorage) * 100 > 70
                ? "bg-yellow-500"
                : "bg-blue-600"
            }`}
            style={{
              width: `${Math.min((usedStorage / totalStorage) * 100, 100)}%`,
            }}
          />
        </div>
        <p className="text-gray-600 text-sm">
          {usedStorage.toFixed(2)} GB used of {totalStorage} GB
        </p>
      </div>

      {/* Search Bar */}
      <div className="mb-6 flex justify-center">
        <div className="flex w-full max-w-md">
          <button
            onClick={() => setSearchTerm(searchInput)}
            className="btn btn-primary rounded-r-none"
          >
            Search
          </button>
          <input
            type="text"
            placeholder="Search files..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && setSearchTerm(searchInput)}
            className="input input-bordered flex-1 rounded-l-none"
          />
        </div>
      </div>

      {/* Files Grid */}
      {filteredFiles.length === 0 ? (
        <p className="text-gray-600 text-center">
          {searchTerm ? "No files match your search." : "No files uploaded yet."}
        </p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
          {filteredFiles.map((file, index) => (
            <div
              key={index}
              className="bg-white rounded-lg shadow p-4 flex flex-col justify-between"
            >
              <div>
                <h3 className="font-semibold text-gray-800 break-words">
                  {getDisplayName(file.filename)}
                </h3>
                <p className="text-sm text-gray-500">
                  {(file.size ?? 0).toFixed(2)} MB
                </p>
                <p className="text-sm text-gray-400 mt-1">
                  Uploaded:{" "}
                  {file.uploadedAt
                    ? new Date(file.uploadedAt).toLocaleDateString()
                    : "Unknown"}
                </p>
              </div>

              <div className="flex justify-between mt-4">
                <button
                  onClick={() => handleDownload(file.filename)}
                  className="btn btn-sm btn-outline flex items-center gap-1"
                  title="Download file"
                >
                  <Download className="w-4 h-4" /> Download
                </button>

                <button
                  onClick={() => handleShare(file.filename)}
                  className="btn btn-sm btn-outline flex items-center gap-1"
                  title="Share file"
                >
                  <Share2 className="w-4 h-4" /> Share
                </button>

                <button
                  onClick={() => handleDelete(file.filename)}
                  className="btn btn-sm btn-outline btn-error flex items-center gap-1"
                  title="Delete file"
                >
                  <Trash2 className="w-4 h-4" /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ManageFiles;