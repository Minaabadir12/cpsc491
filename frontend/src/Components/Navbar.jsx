import React from 'react';
import { useNavigate } from 'react-router-dom';
import GuardFileLogo from './GuardFileLogo';

const Navbar = () => {
  const navigate = useNavigate();
  const username = localStorage.getItem('username');

  const handleLogout = () => {
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    navigate('/');
  };

  return (
    <header className="bg-white border-b border-gray-200 shadow-sm">
      <div className="mx-auto max-w-7xl px-6 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div
              className="flex items-center gap-2 cursor-pointer"
              onClick={() => navigate('/home')}
            >
              <GuardFileLogo size={36} showText={false} />
              <span className="text-xl font-bold text-purple-800 tracking-wide"
                style={{ fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif" }}
              >
                GuardFile
              </span>
            </div>
            <div className="h-8 w-px bg-gray-300" />
            <span className="text-lg font-semibold text-gray-700">
              Welcome, <span className="text-purple-700">{username || 'User'}</span>
            </span>
          </div>

          <button
            onClick={handleLogout}
            className="px-5 py-2 rounded-lg border-2 border-purple-600 text-purple-600 font-medium hover:bg-purple-600 hover:text-white transition-all duration-200"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
