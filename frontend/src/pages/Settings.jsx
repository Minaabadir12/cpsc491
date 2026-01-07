import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const Settings = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState({
    name: 'User',
    email: 'User@example.com',
    phone: '714-999-9999'
  });

  const [password, setPassword] = useState('');
  const [voiceFile, setVoiceFile] = useState(null);
  const [faceImage, setFaceImage] = useState(null);

  // Notification and security toggles
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [loginAlerts, setLoginAlerts] = useState(true);
  const [twoFactorAuth, setTwoFactorAuth] = useState(true);
  const [dataEncryption, setDataEncryption] = useState(true);

  // Mocked user data
  const storageUsed = 320; // in GB
  const storageMax = 1000;
  const lastLogin = 'Oct 5, 2025 — 8:34 PM';
  const lastLocation = 'Los Angeles, CA (IP: 172.58.203.44)';
  const [trustedDevices, setTrustedDevices] = useState([
    'Windows PC - Chrome',
    'iPhone 14 Pro - Safari'
  ]);
  const [newDevice, setNewDevice] = useState('');

  const handlePasswordUpdate = () => {
    alert('Password updated!');
    setPassword('');
  };

  const handleBiometricUpdate = () => {
    if (!voiceFile || !faceImage) {
      alert('Please upload both a voice sample and a facial scan.');
      return;
    }
    alert('Biometric data submitted!');
    setVoiceFile(null);
    setFaceImage(null);
  };

  const handleAddDevice = () => {
    if (newDevice.trim() === '') {
      alert('Please enter a device name.');
      return;
    }
    setTrustedDevices([...trustedDevices, newDevice.trim()]);
    setNewDevice('');
  };

  const handleRemoveDevice = (device) => {
    const filtered = trustedDevices.filter((d) => d !== device);
    setTrustedDevices(filtered);
  };

  const handleSettingsSave = () => {
    alert(`Settings saved!
Email Notifications: ${emailNotifications ? 'On' : 'Off'}
Login Alerts: ${loginAlerts ? 'On' : 'Off'}
2FA: ${twoFactorAuth ? 'Enabled' : 'Disabled'}
Data Encryption: ${dataEncryption ? 'Enabled' : 'Disabled'}`);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-5xl mx-auto py-10 px-6">
        {/* Back button */}
        <div className="flex justify-end mb-4">
          <button
            onClick={() => navigate('/home')}
            className="btn btn-outline btn-accent"
          >
            Back to Dashboard
          </button>
        </div>

        <h1 className="text-3xl font-bold mb-8">Account Settings</h1>

        {/* Personal Info */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Personal Details</h2>
          <p><strong>Name:</strong> {user.name}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p><strong>Phone:</strong> {user.phone}</p>
        </div>

        {/* Storage Info */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Storage Information</h2>
          <div className="mb-2">
            <p>Storage Used: {storageUsed}GB / {storageMax}GB</p>
            <div className="w-full bg-gray-200 rounded-full h-3 mt-2">
              <div
                className="bg-blue-500 h-3 rounded-full"
                style={{ width: `${(storageUsed / storageMax) * 100}%` }}
              />
            </div>
          </div>
          <button className="btn btn-primary mt-3">Upgrade Storage</button>
        </div>

        {/* Change Password */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Change Password</h2>
          <div className="flex items-center gap-4 max-w-md">
            <button
              onClick={handlePasswordUpdate}
              className="btn btn-primary whitespace-nowrap"
            >
              Update Password
            </button>
            <input
              type="password"
              placeholder="Enter new password"
              className="input input-bordered w-full"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
        </div>

        {/* Biometrics */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Update Biometrics</h2>
          <div className="mb-4">
            <label className="block mb-2 font-medium">Upload Voice Sample</label>
            <input
              type="file"
              accept="audio/*"
              onChange={(e) => setVoiceFile(e.target.files[0])}
              className="file-input file-input-bordered w-full max-w-md"
            />
            {voiceFile && <p className="mt-2 text-sm text-gray-600">Selected: {voiceFile.name}</p>}
          </div>

          <div className="mb-4">
            <label className="block mb-2 font-medium">Upload Facial Scan</label>
            <input
              type="file"
              accept="image/*"
              onChange={(e) => setFaceImage(e.target.files[0])}
              className="file-input file-input-bordered w-full max-w-md"
            />
            {faceImage && <p className="mt-2 text-sm text-gray-600">Selected: {faceImage.name}</p>}
          </div>

          <button onClick={handleBiometricUpdate} className="btn btn-secondary">
            Submit Biometric Data
          </button>
        </div>

        {/* Security Settings */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Security Settings</h2>
          <div className="flex flex-col gap-4 max-w-md">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={twoFactorAuth}
                onChange={() => setTwoFactorAuth(!twoFactorAuth)}
                className="checkbox checkbox-primary"
              />
              Enable Two-Factor Authentication
            </label>

            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={loginAlerts}
                onChange={() => setLoginAlerts(!loginAlerts)}
                className="checkbox checkbox-primary"
              />
              Login Alerts
            </label>

            <div className="mt-4">
              <p><strong>Last Login:</strong> {lastLogin}</p>
              <p><strong>Location:</strong> {lastLocation}</p>

              {/* Trusted Devices List */}
              <p className="mt-4 font-semibold">Trusted Devices:</p>
              <ul className="list-disc list-inside text-gray-700 mb-4">
                {trustedDevices.map((d, i) => (
                  <li key={i} className="flex justify-between items-center">
                    <span>{d}</span>
                    <button
                      onClick={() => handleRemoveDevice(d)}
                      className="text-red-500 text-sm hover:underline"
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>

              {/* Add Trusted Device */}
              <div className="flex gap-2 mt-2">
                <input
                  type="text"
                  placeholder="Enter new device"
                  className="input input-bordered w-full"
                  value={newDevice}
                  onChange={(e) => setNewDevice(e.target.value)}
                />
                <button
                  onClick={handleAddDevice}
                  className="btn btn-sm btn-primary"
                >
                  Add Trusted Device
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Privacy & Notifications */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Privacy & Notifications</h2>
          <div className="flex flex-col gap-4 max-w-md">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={emailNotifications}
                onChange={() => setEmailNotifications(!emailNotifications)}
                className="checkbox checkbox-primary"
              />
              Email Notifications
            </label>

            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={dataEncryption}
                onChange={() => setDataEncryption(!dataEncryption)}
                className="checkbox checkbox-primary"
              />
              Enable Data Encryption
            </label>

            <button className="btn btn-outline btn-secondary mt-4">
              Download Activity Log
            </button>

            <button
              onClick={handleSettingsSave}
              className="btn btn-primary mt-4 max-w-fit"
            >
              Save All Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
