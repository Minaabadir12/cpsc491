import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { Download, Lock, AlertCircle } from "lucide-react";

const SharedFile = () => {
  const { linkId } = useParams();
  const [fileInfo, setFileInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [password, setPassword] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");

  useEffect(() => {
    const fetchFileInfo = async () => {
      try {
        const res = await fetch(`http://localhost:3000/api/shared/${linkId}`);
        const data = await res.json();

        if (!res.ok) {
          setError(data.error || "Failed to load file info");
          return;
        }

        setFileInfo(data);
      } catch (err) {
        console.error(err);
        setError("Failed to connect to server");
      } finally {
        setLoading(false);
      }
    };

    fetchFileInfo();
  }, [linkId]);

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError("");

    try {
      const res = await fetch(`http://localhost:3000/api/shared/${linkId}/download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: password || undefined }),
      });

      if (!res.ok) {
        const data = await res.json();
        setDownloadError(data.error || "Download failed");
        return;
      }

      // Get filename from Content-Disposition header or use the one we have
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileInfo.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      console.error(err);
      setDownloadError("Download failed. Please try again.");
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <p className="text-gray-600">Loading...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <div className="bg-white p-8 rounded-lg shadow-md text-center max-w-md">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-gray-800 mb-2">Link Not Found</h1>
          <p className="text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  if (fileInfo.expired) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <div className="bg-white p-8 rounded-lg shadow-md text-center max-w-md">
          <AlertCircle className="w-16 h-16 text-yellow-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-gray-800 mb-2">Link Expired</h1>
          <p className="text-gray-600">This share link has expired and is no longer available.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-full max-w-md">
        <h1 className="text-2xl font-bold text-gray-800 mb-2 text-center">Shared File</h1>

        <div className="bg-gray-50 p-4 rounded-lg mb-6">
          <p className="text-lg font-medium text-gray-800 break-words">{fileInfo.filename}</p>
          <p className="text-sm text-gray-500 mt-1">
            Expires: {new Date(fileInfo.expiresAt).toLocaleString()}
          </p>
        </div>

        {fileInfo.requiresPassword && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              <Lock className="w-4 h-4 inline mr-1" />
              Password Required
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              className="input input-bordered w-full"
            />
          </div>
        )}

        {downloadError && (
          <div className="bg-red-50 text-red-600 p-3 rounded-lg mb-4 text-sm">
            {downloadError}
          </div>
        )}

        <button
          onClick={handleDownload}
          disabled={downloading || (fileInfo.requiresPassword && !password)}
          className="btn btn-primary w-full flex items-center justify-center gap-2"
        >
          <Download className="w-5 h-5" />
          {downloading ? "Downloading..." : "Download File"}
        </button>

        <p className="text-center text-sm text-gray-500 mt-6">
          Shared via GuardFile
        </p>
      </div>
    </div>
  );
};

export default SharedFile;