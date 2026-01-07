import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import { CloudUpload } from 'lucide-react';

const UploadFiles = () => {
  const [files, setFiles] = useState([]);
  const [usedStorage, setUsedStorage] = useState(350); // Example: 350GB used
  const totalStorage = 1000; // 1TB max
  const navigate = useNavigate();

  const onDrop = useCallback((acceptedFiles) => {
    setFiles((prevFiles) => [...prevFiles, ...acceptedFiles]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
  });

  // Remove file by index
  const removeFile = (indexToRemove) => {
    setFiles(files.filter((_, index) => index !== indexToRemove));
  };

  const usedPercentage = Math.min((usedStorage / totalStorage) * 100, 100);

  // Handle "Upload Files" button click
  const handleUpload = () => {
    if (files.length === 0) {
      alert('No files to upload!');
      return;
    }

    // Simulate upload
    alert(`Uploading ${files.length} file(s)...`);

    // Update storage usage
    const totalFileSizeGB = files.reduce((acc, f) => acc + f.size / 1024 / 1024, 0); // KB -> GB
    setUsedStorage((prev) => Math.min(prev + totalFileSizeGB, totalStorage));

    // Clear uploaded files
    setFiles([]);
  };

  return (
    <div className="max-w-4xl mx-auto p-8">
      {/* Back Button */}
      <div className="flex justify-end mb-4">
        <button
          onClick={() => navigate('/home')}
          className="btn btn-outline btn-accent"
        >
          Back to Dashboard
        </button>
      </div>

      {/* Page Header */}
      <div className="flex items-center gap-3 mb-8">
        <CloudUpload className="w-8 h-8 text-blue-600" />
        <h1 className="text-3xl font-bold">Upload Files</h1>
      </div>

      {/* Storage Info */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <h2 className="text-xl font-semibold mb-2">Storage Usage</h2>
        <div className="w-full bg-gray-200 rounded-full h-4 mb-2">
          <div
            className="bg-blue-600 h-4 rounded-full transition-all duration-500"
            style={{ width: `${usedPercentage}%` }}
          ></div>
        </div>
        <p className="text-gray-600 text-sm">
          {usedStorage.toFixed(1)} GB used of {totalStorage} GB ({usedPercentage.toFixed(1)}%)
        </p>
      </div>

      {/* File Upload Area */}
      <div
        {...getRootProps()}
        className={`border-4 border-dashed rounded-lg p-10 text-center cursor-pointer transition 
          ${isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 bg-white shadow-sm hover:shadow-md'}
        `}
      >
        <input {...getInputProps()} />
        {isDragActive ? (
          <p className="text-blue-600 font-medium">Drop the files here...</p>
        ) : (
          <p className="text-gray-600">Drag & drop files here, or click to select files</p>
        )}
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div className="mt-6 bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Files to Upload:</h2>
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
                  aria-label={`Remove ${file.name}`}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>

          {/* Upload Button */}
          <div className="mt-4 flex justify-end">
            <button
              onClick={handleUpload}
              className="btn btn-primary"
            >
              Upload Files
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default UploadFiles;
