import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Trash2, Download, Share2 } from 'lucide-react';

const ManageFiles = () => {
  const navigate = useNavigate();

  // Mocked files
  const [files, setFiles] = useState([
    { name: 'ProjectProposal.pdf', size: 450, type: 'PDF', uploaded: 'Oct 1, 2025' },
    { name: 'MeetingNotes.docx', size: 120, type: 'DOCX', uploaded: 'Oct 3, 2025' },
    { name: 'Budget.xlsx', size: 210, type: 'XLSX', uploaded: 'Oct 4, 2025' },
    { name: 'Presentation.pptx', size: 520, type: 'PPTX', uploaded: 'Oct 5, 2025' },
  ]);

  const [searchInput, setSearchInput] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [usedStorage] = useState(320);
  const totalStorage = 1000;

  const filteredFiles = files.filter(file =>
    file.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // File actions
  const handleDelete = (fileName) => {
    if (window.confirm(`Are you sure you want to delete "${fileName}"?`)) {
      setFiles(files.filter(f => f.name !== fileName));
    }
  };

  const handleDownload = (fileName) => {
    alert(`Downloading ${fileName}...`);
  };

  const handleShare = (fileName) => {
    alert(`Sharing ${fileName}...`);
  };

  return (
    <div className="max-w-6xl mx-auto p-8">
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
      <h1 className="text-3xl font-bold mb-6">Manage Files</h1>

      {/* Storage Info */}
      <div className="bg-white p-6 rounded-lg shadow mb-6">
        <h2 className="text-xl font-semibold mb-2">Storage Usage</h2>
        <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
          <div
            className="bg-blue-600 h-3 rounded-full transition-all duration-500"
            style={{ width: `${(usedStorage / totalStorage) * 100}%` }}
          />
        </div>
        <p className="text-gray-600 text-sm">
          {usedStorage} GB used of {totalStorage} GB
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
            className="input input-bordered flex-1 rounded-l-none"
          />
        </div>
      </div>


      {/* Grid View */}
      {filteredFiles.length === 0 ? (
        <p className="text-gray-600">No files found.</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
          {filteredFiles.map((file, index) => (
            <div
              key={index}
              className="bg-white rounded-lg shadow p-4 flex flex-col justify-between"
            >
              <div>
                <h3 className="font-semibold text-gray-800">{file.name}</h3>
                <p className="text-sm text-gray-500">{file.type} — {file.size} KB</p>
                <p className="text-sm text-gray-400 mt-1">Uploaded: {file.uploaded}</p>
              </div>
              <div className="flex justify-between mt-4">
                <button
                  onClick={() => handleDownload(file.name)}
                  className="btn btn-sm btn-outline flex items-center gap-1"
                >
                  <Download className="w-4 h-4" /> Download
                </button>
                <button
                  onClick={() => handleShare(file.name)}
                  className="btn btn-sm btn-outline flex items-center gap-1"
                >
                  <Share2 className="w-4 h-4" /> Share
                </button>
                <button
                  onClick={() => handleDelete(file.name)}
                  className="btn btn-sm btn-outline btn-error flex items-center gap-1"
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
