import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./LoginPage.css";
import { getOrCreateDeviceToken, getDeviceInfo } from "../utils/deviceFingerprint";
import { captureVoiceEmbedding } from "../utils/voiceBiometrics";

import user_icon from "../Components/Assets/person.png";
import email_icon from "../Components/Assets/email.png";
import password_icon from "../Components/Assets/password.png";

const LoginPage = () => {
  const [action, setAction] = useState(() => localStorage.getItem("authMode") || "Login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // Device verification states
  const [showVerification, setShowVerification] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const [verificationEmail, setVerificationEmail] = useState("");
  const [loginData, setLoginData] = useState(null);

  // 2FA states
  const [showTwoFactor, setShowTwoFactor] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState("");
  const [pendingEmail, setPendingEmail] = useState("");

  // Voice verification states
  const [showVoice, setShowVoice] = useState(false);
  const [voiceBusy, setVoiceBusy] = useState(false);
  const [voiceFeedback, setVoiceFeedback] = useState("");
  const [voiceChallenge, setVoiceChallenge] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    localStorage.setItem("authMode", action);
  }, [action]);

  const finalizeLoginWithToken = async (authPayload, loginEmail) => {
    const deviceToken = getOrCreateDeviceToken();
    const deviceInfo = getDeviceInfo();

    const deviceCheckRes = await fetch("http://localhost:3000/check-device", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: loginEmail, deviceToken }),
    });
    const deviceCheckData = await deviceCheckRes.json();

    if (deviceCheckData.deviceAuthEnabled && !deviceCheckData.trusted) {
      const verifyRes = await fetch("http://localhost:3000/send-device-verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: loginEmail,
          deviceToken,
          deviceName: deviceInfo.deviceName,
          userAgent: deviceInfo.userAgent,
        }),
      });

      if (!verifyRes.ok) {
        alert("Failed to send device verification code. Please try again.");
        return;
      }

      setLoginData(authPayload);
      setVerificationEmail(loginEmail);
      setShowVerification(true);
      alert("A verification code has been sent to your email. Please check your inbox.");
      return;
    }

    localStorage.setItem("token", authPayload.token);
    localStorage.setItem("userId", authPayload.userId);
    localStorage.setItem("username", authPayload.username);
    navigate("/home");
  };

  const startVoiceFlow = (payload, emailForVoice) => {
    setVoiceChallenge({
      email: payload.email || emailForVoice,
      challengeId: payload.challengeId,
      phrase: payload.phrase,
      expiresAt: payload.expiresAt,
    });
    setVoiceFeedback("");
    setShowTwoFactor(false);
    setShowVoice(true);
  };

  const handleSubmit = async () => {
    if (!email || !password || (action === "Sign Up" && !username)) {
      alert("Please fill in all required fields.");
      return;
    }

    if (action === "Sign Up" && password !== confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    const url = action === "Sign Up" ? "http://localhost:3000/signup" : "http://localhost:3000/login";
    const body = action === "Sign Up" ? { username, email, password } : { email, password };

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();

      if (!res.ok) {
        const lockMsg = data.lockUntil
          ? ` Locked until ${new Date(data.lockUntil).toLocaleString()}.`
          : "";
        alert((data.error || "Something went wrong.") + lockMsg);
        return;
      }

      if (action === "Login") {
        if (data.requiresTwoFactor) {
          setPendingEmail(data.email);
          setShowTwoFactor(true);
          return;
        }

        if (data.requiresVoice) {
          startVoiceFlow(data, email);
          return;
        }

        if (data.token) {
          await finalizeLoginWithToken(data, email);
        }
        return;
      }

      alert("Signup successful. Please log in.");
      setAction("Login");
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
          email: verificationEmail,
          code: verificationCode,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        alert(data.error || "Verification failed");
        return;
      }

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
        const lockMsg = data.lockUntil
          ? ` Locked until ${new Date(data.lockUntil).toLocaleString()}.`
          : "";
        alert((data.error || "Invalid 2FA code") + lockMsg);
        return;
      }

      if (data.requiresVoice) {
        startVoiceFlow(data, pendingEmail);
        return;
      }

      if (data.token) {
        await finalizeLoginWithToken(data, pendingEmail);
      }
    } catch (err) {
      console.error(err);
      alert("Server error during 2FA verification");
    }
  };

  const handleVerifyVoice = async () => {
    if (!voiceChallenge?.email || !voiceChallenge?.challengeId) {
      alert("Voice challenge is missing. Please login again.");
      setShowVoice(false);
      return;
    }

    try {
      setVoiceBusy(true);
      setVoiceFeedback("Recording voice sample...");
      const audioData = await captureVoiceEmbedding(5000);

      setVoiceFeedback("Verifying voice...");
      const res = await fetch("http://localhost:3000/login/verify-voice", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: voiceChallenge.email,
          challengeId: voiceChallenge.challengeId,
          audioData,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        const lockMsg = data.lockUntil
          ? ` Locked until ${new Date(data.lockUntil).toLocaleString()}.`
          : "";
        setVoiceFeedback(`${data.error || "Voice verification failed"}${lockMsg}`);
        return;
      }

      setShowVoice(false);
      setVoiceChallenge(null);
      setVoiceFeedback("");
      await finalizeLoginWithToken(data, voiceChallenge.email);
    } catch (err) {
      console.error(err);
      setVoiceFeedback("Voice verification failed. Please try again.");
    } finally {
      setVoiceBusy(false);
    }
  };

  if (showVoice) {
    return (
      <div className="title">
        <h1>GuardFile</h1>
        <div className="container">
          <div className="header">
            <div className="text">Voice Verification</div>
            <div className="underline"></div>
          </div>

          <div className="inputs">
            <p style={{ textAlign: "center", marginBottom: "16px", color: "#666" }}>
              Speak this phrase clearly:
            </p>
            <p
              style={{
                textAlign: "center",
                marginBottom: "12px",
                fontWeight: 700,
                background: "#f5f5f5",
                padding: "10px",
                borderRadius: "8px",
              }}
            >
              {voiceChallenge?.phrase || "My voice confirms this login"}
            </p>
            {voiceChallenge?.expiresAt && (
              <p style={{ textAlign: "center", marginBottom: "16px", color: "#777", fontSize: "0.9rem" }}>
                Expires: {new Date(voiceChallenge.expiresAt).toLocaleTimeString()}
              </p>
            )}
            {voiceFeedback && (
              <p style={{ textAlign: "center", marginBottom: "12px", color: "#444" }}>
                {voiceFeedback}
              </p>
            )}
          </div>

          <div className="submit-container">
            <div className="submit" onClick={handleVerifyVoice}>
              {voiceBusy ? "Verifying..." : "Record & Verify Voice"}
            </div>
            <div
              className="submit gray"
              onClick={() => {
                setShowVoice(false);
                setVoiceBusy(false);
                setVoiceFeedback("");
                setVoiceChallenge(null);
              }}
            >
              Cancel
            </div>
          </div>
        </div>
      </div>
    );
  }

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
              Enter the 6-digit code sent to <strong>{verificationEmail}</strong>
            </p>

            <div className="input">
              <img src={email_icon} width={25} height={25} alt="Code" />
              <input
                type="text"
                placeholder="Enter 6-digit code"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
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
                setVerificationEmail("");
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

          {action === "Sign Up" && (
            <div className="input">
              <img src={password_icon} width={25} height={25} alt="Confirm Password" />
              <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              {confirmPassword && (
                <p
                  style={{
                    color: password === confirmPassword ? "green" : "red",
                    fontSize: "0.8rem",
                    marginTop: "0.2rem",
                  }}
                >
                  {password === confirmPassword ? "Passwords match" : "Passwords do not match"}
                </p>
              )}
            </div>
          )}
        </div>

        {action === "Login" && (
          <div className="forgot-password">
            Lost password?{" "}
            <span style={{ cursor: "pointer", color: "blue" }} onClick={() => navigate("/resetpassword")}>
              click here
            </span>
          </div>
        )}

        <div className="submit-container">
          <div className="submit" onClick={handleSubmit}>
            {action}
          </div>

          <div className="submit gray" onClick={() => setAction(action === "Login" ? "Sign Up" : "Login")}>
            {action === "Login" ? "Switch to Sign Up" : "Switch to Login"}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
