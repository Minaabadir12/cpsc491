// Generate a unique device token
export const getOrCreateDeviceToken = () => {
  let deviceToken = localStorage.getItem("deviceToken");
  
  if (!deviceToken) {
    // Generate new unique token for this device
    deviceToken = crypto.randomUUID();
    localStorage.setItem("deviceToken", deviceToken);
  }
  
  return deviceToken;
};

// Get device information for display
export const getDeviceInfo = () => {
  const ua = navigator.userAgent;
  let deviceName = "Unknown Device";
  
  // Detect browser
  if (ua.includes("Chrome")) deviceName = "Chrome";
  else if (ua.includes("Firefox")) deviceName = "Firefox";
  else if (ua.includes("Safari")) deviceName = "Safari";
  else if (ua.includes("Edge")) deviceName = "Edge";
  
  // Detect OS
  if (ua.includes("Windows")) deviceName += " on Windows";
  else if (ua.includes("Mac")) deviceName += " on Mac";
  else if (ua.includes("Linux")) deviceName += " on Linux";
  else if (ua.includes("Android")) deviceName += " on Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) deviceName += " on iOS";
  
  return {
    deviceName,
    userAgent: ua,
  };
};

// Remove device token (when user logs out or untrusts device)
export const clearDeviceToken = () => {
  localStorage.removeItem("deviceToken");
};