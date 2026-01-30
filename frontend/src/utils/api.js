// Helper function to make authenticated API requests
export const fetchWithAuth = async (url, options = {}) => {
  const token = localStorage.getItem("token");
  
  if (!token) {
    // No token, redirect to login
    window.location.href = "/";
    throw new Error("No authentication token");
  }

  const headers = {
    ...options.headers,
    "Authorization": `Bearer ${token}`,
  };

  // Don't override Content-Type if it's already set (for FormData)
  if (!options.headers || !options.headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    // If token expired or invalid, logout
    if (response.status === 401 || response.status === 403) {
      console.log("❌ Authentication failed (status " + response.status + "), logging out");
      logout();
      throw new Error("Session expired");
    }

    return response;
  } catch (error) {
    console.error("❌ API request failed:", error);
    throw error;
  }
};

// Logout function
export const logout = () => {
  console.log("🚪 Logging out...");
  localStorage.removeItem("token");
  localStorage.removeItem("userId");
  localStorage.removeItem("username");
  window.location.href = "/";
};

// Refresh token to extend session
export const refreshToken = async () => {
  console.log("🔑 refreshToken function called");
  const token = localStorage.getItem("token");
  
  if (!token) {
    console.log("❌ No token to refresh");
    return false;
  }
  
  console.log("📤 Sending refresh request to server...");

  try {
    const response = await fetch("http://localhost:3000/refresh-token", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    console.log("📥 Server response status:", response.status);

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem("token", data.token);
      console.log("✅ Token refreshed successfully at", new Date().toLocaleTimeString());
      return true;
    } else {
      const errorText = await response.text();
      console.log("❌ Token refresh failed with status:", response.status, "Error:", errorText);
      return false;
    }
  } catch (error) {
    console.error("❌ Token refresh error:", error);
    return false;
  }
};