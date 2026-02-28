import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { startAuthentication } from "@simplewebauthn/browser";
import "./LoginPage.css";
import { getOrCreateDeviceToken, getDeviceInfo } from "../utils/deviceFingerprint";

import user_icon from "../Components/Assets/person.png";
import email_icon from "../Components/Assets/email.png";
import password_icon from "../Components/Assets/password.png";
import GuardFileLogo from "../Components/GuardFileLogo";

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
  const [enabledMethods, setEnabledMethods] = useState([]);
  const [selectedMethod, setSelectedMethod] = useState(null);
  const [codeSent, setCodeSent] = useState(false);
  const [sendingCode, setSendingCode] = useState(false);

  // Passkey login state
  const [passkeyLoading, setPasskeyLoading] = useState(false);

  const navigate = useNavigate();

  const handlePasskeyLogin = async () => {
    if (!email) {
      alert("Please enter your email first.");
      return;
    }
    setPasskeyLoading(true);
    try {
      // 1. Get authentication options
      const optRes = await fetch("http://localhost:3000/webauthn/login/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) throw new Error(optData.error || "Failed to get passkey options");

      const userId = optData.userId;
      const { userId: _uid, ...authOptions } = optData;

      // 2. Trigger browser biometric prompt
      let asseResp;
      try {
        asseResp = await startAuthentication({ optionsJSON: authOptions });
      } catch (authErr) {
        asseResp = await startAuthentication(authOptions);
      }

      // 3. Verify with backend
      const verRes = await fetch("http://localhost:3000/webauthn/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: String(userId), asseResp }),
      });
      const verData = await verRes.json();
      if (!verRes.ok) throw new Error(verData.error || "Passkey verification failed");

      // 4. Store credentials and navigate
      localStorage.setItem("token", verData.token);
      localStorage.setItem("userId", String(verData.userId));
      localStorage.setItem("username", verData.username);
      navigate("/home");
    } catch (err) {
      console.error(err);
      alert("Passkey login failed: " + err.message);
    } finally {
      setPasskeyLoading(false);
    }
  };

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
          const methods = data.enabledMethods || ["totp"];
          setEnabledMethods(methods);
          // Auto-select if only one method
          if (methods.length === 1) {
            setSelectedMethod(methods[0]);
          }
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
          method: selectedMethod || "totp",
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

  // Send email 2FA code
  const handleSend2FACode = async () => {
    setSendingCode(true);
    try {
      const res = await fetch("http://localhost:3000/login/send-2fa-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingEmail, method: "email" }),
      });

      if (res.ok) {
        setCodeSent(true);
      } else {
        const data = await res.json();
        alert(data.error || "Failed to send code");
      }
    } catch (err) {
      console.error(err);
      alert("Failed to send verification code");
    } finally {
      setSendingCode(false);
    }
  };

  // Select 2FA method
  const handleSelectMethod = (method) => {
    setSelectedMethod(method);
    setTwoFactorCode("");
    setCodeSent(false);
    if (method === "email") {
      handleSend2FACodeDirect();
    }
  };

  // Direct send for email (called when selecting email method)
  const handleSend2FACodeDirect = async () => {
    setSendingCode(true);
    try {
      const res = await fetch("http://localhost:3000/login/send-2fa-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingEmail, method: "email" }),
      });

      if (res.ok) {
        setCodeSent(true);
      } else {
        const data = await res.json();
        alert(data.error || "Failed to send code");
      }
    } catch (err) {
      console.error(err);
      alert("Failed to send verification code");
    } finally {
      setSendingCode(false);
    }
  };

  // Cancel 2FA and go back
  const handleCancel2FA = () => {
    setShowTwoFactor(false);
    setTwoFactorCode("");
    setPendingEmail("");
    setEnabledMethods([]);
    setSelectedMethod(null);
    setCodeSent(false);
  };

  // If showing 2FA verification screen
  if (showTwoFactor) {
    // Step 1: Method selection (only if multiple methods and none selected yet)
    if (enabledMethods.length > 1 && !selectedMethod) {
      return (
        <div className="title">
          <GuardFileLogo size={90} />
          <div className="container" style={{ paddingBottom: "40px" }}>
            <div className="header">
              <div className="text" style={{ fontSize: "32px", lineHeight: "1.2" }}>
                Verify Your Identity
              </div>
              <div className="underline"></div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "12px", marginTop: "25px", marginBottom: "25px", width: "80%" }}>
              <p style={{ textAlign: "center", marginBottom: "8px", color: "#666", fontSize: "15px" }}>
                Choose a verification method
              </p>

              {enabledMethods.includes("totp") && (
                <div
                  onClick={() => handleSelectMethod("totp")}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "18px",
                    width: "100%",
                    padding: "18px 24px",
                    background: "#f8f8f8",
                    borderRadius: "12px",
                    cursor: "pointer",
                    border: "2px solid #e0e0e0",
                    transition: "border-color 0.2s, background 0.2s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "#4c00b4";
                    e.currentTarget.style.background = "#f0eaf8";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "#e0e0e0";
                    e.currentTarget.style.background = "#f8f8f8";
                  }}
                >
                  <div style={{
                    width: "44px", height: "44px", borderRadius: "10px",
                    background: "#ede7f6", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                  }}>
                    <img src={password_icon} width={24} height={24} alt="Authenticator" />
                  </div>
                  <div>
                    <p style={{ margin: 0, fontWeight: "600", color: "#333", fontSize: "16px" }}>Authenticator App</p>
                    <p style={{ margin: 0, color: "#888", fontSize: "13px" }}>Use Google Authenticator, Authy, or Duo</p>
                  </div>
                </div>
              )}

              {enabledMethods.includes("email") && (
                <div
                  onClick={() => handleSelectMethod("email")}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "18px",
                    width: "100%",
                    padding: "18px 24px",
                    background: "#f8f8f8",
                    borderRadius: "12px",
                    cursor: "pointer",
                    border: "2px solid #e0e0e0",
                    transition: "border-color 0.2s, background 0.2s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "#4c00b4";
                    e.currentTarget.style.background = "#f0eaf8";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "#e0e0e0";
                    e.currentTarget.style.background = "#f8f8f8";
                  }}
                >
                  <div style={{
                    width: "44px", height: "44px", borderRadius: "10px",
                    background: "#ede7f6", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                  }}>
                    <img src={email_icon} width={24} height={24} alt="Email" />
                  </div>
                  <div>
                    <p style={{ margin: 0, fontWeight: "600", color: "#333", fontSize: "16px" }}>Email Code</p>
                    <p style={{ margin: 0, color: "#888", fontSize: "13px" }}>Send a verification code to your email</p>
                  </div>
                </div>
              )}
            </div>

            <div className="submit-container">
              <div className="submit gray" onClick={handleCancel2FA}>
                Cancel
              </div>
            </div>
          </div>
        </div>
      );
    }

    // Step 2: Code entry screen
    const methodLabel = selectedMethod === "email"
      ? "Enter the 6-digit code sent to your email"
      : "Enter the 6-digit code from your authenticator app";

    return (
      <div className="title">
        <GuardFileLogo size={90} />
        <div className="container">
          <div className="header">
            <div className="text">Two-Factor Authentication</div>
            <div className="underline"></div>
          </div>

          <div className="inputs">
            <p style={{ textAlign: "center", marginBottom: "20px", color: "#666" }}>
              {selectedMethod === "email" && sendingCode
                ? "Sending code to your email..."
                : methodLabel}
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

            {selectedMethod === "email" && codeSent && (
              <p style={{ textAlign: "center", fontSize: "0.85rem", color: "#888", marginTop: "10px" }}>
                Code sent! Check your inbox.{" "}
                <span
                  style={{ color: "blue", cursor: "pointer" }}
                  onClick={handleSend2FACode}
                >
                  Resend
                </span>
              </p>
            )}
          </div>

          <div className="submit-container">
            <div className="submit" onClick={handleVerify2FA}>
              Verify
            </div>
            {enabledMethods.length > 1 ? (
              <div
                className="submit gray"
                onClick={() => {
                  setSelectedMethod(null);
                  setTwoFactorCode("");
                  setCodeSent(false);
                }}
              >
                Back
              </div>
            ) : (
              <div className="submit gray" onClick={handleCancel2FA}>
                Cancel
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // If showing verification screen
  if (showVerification) {
    return (
      <div className="title">
        <GuardFileLogo size={90} />
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
      <GuardFileLogo size={90} />

      <div className="container">
        <div className="header">
          <div className="text">{action}</div>
          <div className="underline"></div>
        </div>

        <div className="inputs">
          {action === "Sign Up" && (
            <div className="input">
              <img src={user_icon} alt="" />
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
          )}

          <div className="input">
            <img src={email_icon} alt="" />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="input">
            <img src={password_icon} alt="" />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {action === "Sign Up" && (
            <>
              <div className="input">
                <img src={password_icon} alt="" />
                <input
                  type="password"
                  placeholder="Confirm Password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
              </div>
              {confirmPassword && (
                <p
                  style={{
                    color: password === confirmPassword ? "#22c55e" : "#ef4444",
                    fontSize: "13px",
                    marginTop: "-6px",
                    textAlign: "left",
                    fontWeight: 500,
                  }}
                >
                  {password === confirmPassword
                    ? "\u2713 Passwords match"
                    : "\u2717 Passwords do not match"}
                </p>
              )}
            </>
          )}
        </div>

        {action === "Login" && (
          <div className="forgot-password">
            Lost password?{" "}
            <span onClick={() => navigate("/resetpassword")}>
              Click here
            </span>
          </div>
        )}

        <div className="submit-container">
          <div className="submit" onClick={handleSubmit}>
            {action === "Login" ? "Log In" : "Create Account"}
          </div>

          <div
            className="submit gray"
            onClick={() =>
              setAction(action === "Login" ? "Sign Up" : "Login")
            }
          >
            {action === "Login" ? "Sign Up" : "Log In"}
          </div>
        </div>

        {action === "Login" && (
          <div style={{ width: "100%", marginTop: "8px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                margin: "12px 0",
              }}
            >
              <div style={{ flex: 1, height: "1px", background: "#ddd" }} />
              <span style={{ color: "#999", fontSize: "13px" }}>or</span>
              <div style={{ flex: 1, height: "1px", background: "#ddd" }} />
            </div>
            <div
              className="submit"
              onClick={passkeyLoading ? null : handlePasskeyLogin}
              style={{
                width: "100%",
                background: passkeyLoading
                  ? "#ccc"
                  : "linear-gradient(135deg, #7c3aed 0%, #4c00b4 100%)",
                cursor: passkeyLoading ? "not-allowed" : "pointer",
                opacity: passkeyLoading ? 0.7 : 1,
              }}
            >
              {passkeyLoading ? "Authenticating..." : "Login with Passkey"}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoginPage;
