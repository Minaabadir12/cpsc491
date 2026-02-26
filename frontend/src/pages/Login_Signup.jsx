import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./LoginPage.css";
import { getOrCreateDeviceToken, getDeviceInfo } from "../utils/deviceFingerprint";

import user_icon from "../Components/Assets/person.png";
import email_icon from "../Components/Assets/email.png";
import password_icon from "../Components/Assets/password.png";

const LoginPage = () => {
  const [action, setAction] = useState("Sign Up");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  
  // Device verification states
  const [showVerification, setShowVerification] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const [loginData, setLoginData] = useState(null);

  // 2FA states
  const [showTwoFactor, setShowTwoFactor] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState("");
  const [pendingEmail, setPendingEmail] = useState("");

  const navigate = useNavigate();

  const handleSubmit = async () => {
    // Basic required field validation
    if (!email || !password || (action === "Sign Up" && !username)) {
      alert("Please fill in all required fields.");
      return;
    }

    // Confirm password match validation for Sign Up
    if (action === "Sign Up" && password !== confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    const url =
      action === "Sign Up"
        ? "http://localhost:3000/signup"
        : "http://localhost:3000/login";

    const body =
      action === "Sign Up"
        ? { username, email, password }
        : { email, password };

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        alert(data.error || "Something went wrong.");
        return;
      }

      // ✅ LOGIN SUCCESS
      if (action === "Login") {
        // Check if 2FA is required
        if (data.requiresTwoFactor) {
          setPendingEmail(data.email);
          setShowTwoFactor(true);
          return;
        }

        // Get device token
        const deviceToken = getOrCreateDeviceToken();
        const deviceInfo = getDeviceInfo();

        // Check if device is trusted
        const deviceCheckRes = await fetch("http://localhost:3000/check-device", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, deviceToken }),
        });

        const deviceCheckData = await deviceCheckRes.json();

        // If device auth is enabled and device is not trusted
        if (deviceCheckData.deviceAuthEnabled && !deviceCheckData.trusted) {
          // Send verification code to email
          const verifyRes = await fetch("http://localhost:3000/send-device-verification", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email,
              deviceToken,
              deviceName: deviceInfo.deviceName,
              userAgent: deviceInfo.userAgent,
            }),
          });

          if (verifyRes.ok) {
            // Store login data and show verification input
            setLoginData(data);
            setShowVerification(true);
            alert("A verification code has been sent to your email. Please check your inbox.");
            return;
          } else {
            alert("Failed to send verification code. Please try again.");
            return;
          }
        }

        // Device is trusted or auth not enabled - proceed with login
        localStorage.setItem("token", data.token);
        localStorage.setItem("userId", data.userId);
        localStorage.setItem("username", data.username);
        navigate("/home");
        return;
      }

      // ✅ SIGNUP SUCCESS
      alert("Signup successful. Please log in.");
      setAction("Login");

      // Clear all fields
      setUsername("");
      setEmail("");
      setPassword("");
      setConfirmPassword("");
    } catch (err) {
      console.error(err);
      alert("Server error");
    }
  };

  const handleVerifyCode = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      alert("Please enter a valid 6-digit code");
      return;
    }

    try {
      const res = await fetch("http://localhost:3000/verify-device-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          code: verificationCode,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        alert(data.error || "Verification failed");
        return;
      }

      // Verification successful - complete login
      localStorage.setItem("token", loginData.token);
      localStorage.setItem("userId", loginData.userId);
      localStorage.setItem("username", loginData.username);
      
      alert("Device verified successfully!");
      navigate("/home");
    } catch (err) {
      console.error(err);
      alert("Server error during verification");
    }
  };

  const handleVerify2FA = async () => {
    if (!twoFactorCode || twoFactorCode.length !== 6) {
      alert("Please enter a valid 6-digit code");
      return;
    }

    try {
      const res = await fetch("http://localhost:3000/login/verify-2fa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: pendingEmail,
          twoFactorToken: twoFactorCode,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        alert(data.error || "Invalid 2FA code");
        return;
      }

      // Get device token for device verification check
      const deviceToken = getOrCreateDeviceToken();
      const deviceInfo = getDeviceInfo();

      // Check if device is trusted
      const deviceCheckRes = await fetch("http://localhost:3000/check-device", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingEmail, deviceToken }),
      });

      const deviceCheckData = await deviceCheckRes.json();

      // If device auth is enabled and device is not trusted
      if (deviceCheckData.deviceAuthEnabled && !deviceCheckData.trusted) {
        // Send verification code to email
        const verifyRes = await fetch("http://localhost:3000/send-device-verification", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: pendingEmail,
            deviceToken,
            deviceName: deviceInfo.deviceName,
            userAgent: deviceInfo.userAgent,
          }),
        });

        if (verifyRes.ok) {
          setLoginData(data);
          setShowTwoFactor(false);
          setShowVerification(true);
          alert("A verification code has been sent to your email.");
          return;
        }
      }

      // Device is trusted or auth not enabled - complete login
      localStorage.setItem("token", data.token);
      localStorage.setItem("userId", data.userId);
      localStorage.setItem("username", data.username);
      navigate("/home");
    } catch (err) {
      console.error(err);
      alert("Server error during 2FA verification");
    }
  };

  // If showing 2FA verification screen
  if (showTwoFactor) {
    return (
      <div className="title">
        <h1>GuardFile</h1>
        <div className="container">
          <div className="header">
            <div className="text">Two-Factor Authentication</div>
            <div className="underline"></div>
          </div>

          <div className="inputs">
            <p style={{ textAlign: "center", marginBottom: "20px", color: "#666" }}>
              Enter the 6-digit code from your authenticator app
            </p>

            <div className="input">
              <img src={password_icon} width={25} height={25} alt="2FA Code" />
              <input
                type="text"
                placeholder="Enter 6-digit code"
                value={twoFactorCode}
                onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                maxLength={6}
              />
            </div>
          </div>

          <div className="submit-container">
            <div className="submit" onClick={handleVerify2FA}>
              Verify
            </div>
            <div
              className="submit gray"
              onClick={() => {
                setShowTwoFactor(false);
                setTwoFactorCode("");
                setPendingEmail("");
              }}
            >
              Cancel
            </div>
          </div>
        </div>
      </div>
    );
  }

  // If showing verification screen
  if (showVerification) {
    return (
      <div className="title">
        <h1>GuardFile</h1>
        <div className="container">
          <div className="header">
            <div className="text">Verify Device</div>
            <div className="underline"></div>
          </div>

          <div className="inputs">
            <p style={{ textAlign: "center", marginBottom: "20px", color: "#666" }}>
              Enter the 6-digit code sent to <strong>{email}</strong>
            </p>
            
            <div className="input">
              <img src={email_icon} width={25} height={25} alt="Code" />
              <input
                type="text"
                placeholder="Enter 6-digit code"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
              />
            </div>
          </div>

          <div className="submit-container">
            <div className="submit" onClick={handleVerifyCode}>
              Verify Code
            </div>
            <div
              className="submit gray"
              onClick={() => {
                setShowVerification(false);
                setVerificationCode("");
                setLoginData(null);
              }}
            >
              Cancel
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Regular login/signup screen
  return (
    <div className="title">
      <h1>GuardFile</h1>

      <div className="container">
        <div className="header">
          <div className="text">{action}</div>
          <div className="underline"></div>
        </div>

        <div className="inputs">
          {action === "Sign Up" && (
            <div className="input">
              <img src={user_icon} width={25} height={25} alt="User" />
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
          )}

          <div className="input">
            <img src={email_icon} width={25} height={25} alt="Email" />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="input">
            <img src={password_icon} width={25} height={25} alt="Password" />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {/* Confirm Password for Sign Up */}
          {action === "Sign Up" && (
            <div className="input">
              <img src={password_icon} width={25} height={25} alt="Confirm Password" />
              <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              {/* Real-time password match feedback */}
              {confirmPassword && (
                <p
                  style={{
                    color: password === confirmPassword ? "green" : "red",
                    fontSize: "0.8rem",
                    marginTop: "0.2rem",
                  }}
                >
                  {password === confirmPassword
                    ? "Passwords match"
                    : "Passwords do not match"}
                </p>
              )}
            </div>
          )}
        </div>

        {action === "Login" && (
          <div className="forgot-password">
            Lost password?{" "}
            <span
              style={{ cursor: "pointer", color: "blue" }}
              onClick={() => navigate("/resetpassword")}
            >
              click here
            </span>
          </div>
        )}

        <div className="submit-container">
          <div className="submit" onClick={handleSubmit}>
            {action}
          </div>

          <div
            className="submit gray"
            onClick={() =>
              setAction(action === "Login" ? "Sign Up" : "Login")
            }
          >
            {action === "Login" ? "Switch to Sign Up" : "Switch to Login"}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;