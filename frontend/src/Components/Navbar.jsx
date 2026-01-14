import React from 'react';
import { useNavigate } from 'react-router-dom';

const Navbar = () => {
  const navigate = useNavigate();

  // ✅ Get the username from localStorage
  const username = localStorage.getItem('username');

  const handleLogout = () => {
    // Clear user info on logout
    localStorage.removeItem('userId');
    localStorage.removeItem('username');

    // Redirect to login page
    navigate('/');
  };

  return (
    <header className="bg-base-300 border-b border-base-content/10">
      <div className="mx-auto max-w-6xl p-4">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-primary font-mono tracking-tighter">
            Welcome {username || 'User'}
          </h1>

          {/* Logout Button on the right */}
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600 transition"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
