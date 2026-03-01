import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { startAuthentication } from "@simplewebauthn/browser";
import "./LoginPage.css";
import { getOrCreateDeviceToken, getDeviceInfo } from "../utils/deviceFingerprint";
import { captureVoiceEmbedding } from "../utils/voiceBiometrics";
import GuardFileLogo from "../Components/GuardFileLogo";

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
  const [enabledMethods, setEnabledMethods] = useState([]);
  const [selectedMethod, setSelectedMethod] = useState("");
  const [codeSent, setCodeSent] = useState(false);
  const [sendingCode, setSendingCode] = useState(false);

  // Passkey login state
  const [passkeyLoading, setPasskeyLoading] = useState(false);

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

  const handlePasskeyLogin = async () => {
    const passkeyEmail = prompt("Enter your email to login with passkey:");
    if (!passkeyEmail) return;

    setPasskeyLoading(true);
    try {
      const optionsRes = await fetch("http://localhost:3000/webauthn/login/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: passkeyEmail }),
      });

      const optionsData = await optionsRes.json();
      if (!optionsRes.ok) {
        alert(optionsData.error || "Failed to get passkey options");
        setPasskeyLoading(false);
        return;
      }

      const { userId, ...optionsJSON } = optionsData;
      const authResponse = await startAuthentication({ optionsJSON });

      const verifyRes = await fetch("http://localhost:3000/webauthn/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, asseResp: authResponse }),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok) {
        alert(verifyData.error || "Passkey verification failed");
        setPasskeyLoading(false);
        return;
      }

      localStorage.setItem("token", verifyData.token);
      localStorage.setItem("userId", verifyData.userId);
      localStorage.setItem("username", verifyData.username);
      navigate("/home");
    } catch (err) {
      console.error("Passkey login error:", err);
      if (err.name === "NotAllowedError") {
        alert("Passkey authentication was cancelled.");
      } else {
        alert("Passkey login failed. Please try again.");
      }
    } finally {
      setPasskeyLoading(false);
    }
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
          setEnabledMethods(data.enabledMethods || ["totp"]);
          setShowTwoFactor(true);

          // Auto-select if only one method
          if (data.enabledMethods && data.enabledMethods.length === 1) {
            const method = data.enabledMethods[0];
            setSelectedMethod(method);
            if (method === "email") {
              handleSend2FACodeDirect(data.email);
            }
          }
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

  const handleSend2FACodeDirect = async (targetEmail) => {
    setSendingCode(true);
    try {
      const res = await fetch("http://localhost:3000/login/send-2fa-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: targetEmail, method: "email" }),
      });
      if (res.ok) {
        setCodeSent(true);
      } else {
        const data = await res.json();
        alert(data.error || "Failed to send code");
      }
    } catch (err) {
      console.error(err);
      alert("Failed to send email code");
    } finally {
      setSendingCode(false);
    }
  };

  const handleSend2FACode = async () => {
    await handleSend2FACodeDirect(pendingEmail);
  };

  const handleSelectMethod = (method) => {
    setSelectedMethod(method);
    setTwoFactorCode("");
    setCodeSent(false);
    if (method === "email") {
      handleSend2FACodeDirect(pendingEmail);
    }
  };

  const handleCancel2FA = () => {
    setShowTwoFactor(false);
    setTwoFactorCode("");
    setPendingEmail("");
    setEnabledMethods([]);
    setSelectedMethod("");
    setCodeSent(false);
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

  const handlePasskeyVoiceBypass = async () => {
    if (!voiceChallenge?.email) {
      setVoiceFeedback("Voice challenge is missing. Please restart login.");
      return;
    }

    try {
      setPasskeyLoading(true);
      setVoiceFeedback("Use your device biometrics to continue...");

      const optRes = await fetch("http://localhost:3000/webauthn/login/options-by-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: voiceChallenge.email }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) {
        setVoiceFeedback(optData.error || "Failed to start passkey login.");
        return;
      }

      const authResponse = await startAuthentication(optData.options);

      const verRes = await fetch("http://localhost:3000/webauthn/login/verify-by-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: optData.email || voiceChallenge.email,
          userId: optData.userId,
          asseResp: authResponse,
          bypassVoice: true,
        }),
      });
      const verData = await verRes.json();
      if (!verRes.ok) {
        const lockMsg = verData.lockUntil
          ? ` Locked until ${new Date(verData.lockUntil).toLocaleString()}.`
          : "";
        setVoiceFeedback((verData.error || "Passkey login failed.") + lockMsg);
        return;
      }

      setShowVoice(false);
      setVoiceChallenge(null);
      setVoiceFeedback("");
      await finalizeLoginWithToken(verData, optData.email || voiceChallenge.email);
    } catch (err) {
      console.error("Voice bypass passkey error:", err);
      if (err?.name === "NotAllowedError") {
        setVoiceFeedback("Passkey prompt was canceled or timed out.");
      } else {
        setVoiceFeedback("Passkey bypass failed. Please try again.");
      }
    } finally {
      setPasskeyLoading(false);
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
              onClick={!passkeyLoading ? handlePasskeyVoiceBypass : undefined}
              style={{ opacity: passkeyLoading ? 0.6 : 1 }}
            >
              {passkeyLoading ? "Use Device Biometrics..." : "Use Passkey Instead"}
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
        <GuardFileLogo size={90} />
        <div className="container">
          <div className="header">
            <div className="text">Two-Factor Authentication</div>
            <div className="underline"></div>
          </div>

          <div className="inputs">
            {/* Method selection - show if multiple methods enabled */}
            {enabledMethods.length > 1 && !selectedMethod && (
              <div style={{ textAlign: "center" }}>
                <p style={{ marginBottom: "16px", color: "#666" }}>
                  Choose your verification method:
                </p>
                {enabledMethods.includes("totp") && (
                  <div
                    className="submit"
                    style={{ marginBottom: "10px" }}
                    onClick={() => handleSelectMethod("totp")}
                  >
                    Authenticator App
                  </div>
                )}
                {enabledMethods.includes("email") && (
                  <div
                    className="submit"
                    onClick={() => handleSelectMethod("email")}
                  >
                    Email Code
                  </div>
                )}
              </div>
            )}

            {/* Code entry - show after method selected or if only one method */}
            {selectedMethod && (
              <>
                <p style={{ textAlign: "center", marginBottom: "10px", color: "#666" }}>
                  {selectedMethod === "totp"
                    ? "Enter the 6-digit code from your authenticator app"
                    : codeSent
                    ? "Enter the 6-digit code sent to your email"
                    : "Sending code to your email..."}
                </p>

                {selectedMethod === "email" && !codeSent && (
                  <div style={{ textAlign: "center" }}>
                    <div
                      className="submit"
                      onClick={handleSend2FACode}
                      style={{ opacity: sendingCode ? 0.6 : 1 }}
                    >
                      {sendingCode ? "Sending..." : "Send Code"}
                    </div>
                  </div>
                )}

                {(selectedMethod === "totp" || codeSent) && (
                  <div className="input">
                    <img src={password_icon} width={25} height={25} alt="2FA Code" />
                    <input
                      type="text"
                      placeholder="Enter 6-digit code"
                      value={twoFactorCode}
                      onChange={(e) =>
                        setTwoFactorCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                      }
                      maxLength={6}
                    />
                  </div>
                )}

                {selectedMethod === "email" && codeSent && (
                  <p
                    style={{
                      textAlign: "center",
                      fontSize: "13px",
                      color: "#7c3aed",
                      cursor: "pointer",
                    }}
                    onClick={handleSend2FACode}
                  >
                    Resend code
                  </p>
                )}
              </>
            )}
          </div>

          <div className="submit-container">
            {selectedMethod && (selectedMethod === "totp" || codeSent) && (
              <div className="submit" onClick={handleVerify2FA}>
                Verify
              </div>
            )}
            <div className="submit gray" onClick={handleCancel2FA}>
              Cancel
            </div>
            {enabledMethods.length > 1 && selectedMethod && (
              <div
                className="submit gray"
                onClick={() => {
                  setSelectedMethod("");
                  setTwoFactorCode("");
                  setCodeSent(false);
                }}
              >
                Other Method
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

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
      <GuardFileLogo size={90} />

      <div className="container">
        <div className="header">
          <div className="text">{action === "Sign Up" ? "Create Account" : "Welcome Back"}</div>
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
                    color: password === confirmPassword ? "#22c55e" : "#ef4444",
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
            <span onClick={() => navigate("/resetpassword")}>
              click here
            </span>
          </div>
        )}

        <div className="submit-container">
          <div className="submit" onClick={handleSubmit}>
            {action === "Sign Up" ? "Sign Up" : "Log In"}
          </div>

          <div className="submit gray" onClick={() => setAction(action === "Login" ? "Sign Up" : "Login")}>
            {action === "Login" ? "Create Account" : "Switch to Login"}
          </div>
        </div>

        {/* Passkey login - only shown in Login mode */}
        {action === "Login" && (
          <>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "12px",
                margin: "20px 0 10px",
                width: "100%",
              }}
            >
              <div style={{ flex: 1, height: "1px", background: "#ddd" }} />
              <span style={{ color: "#999", fontSize: "13px" }}>or</span>
              <div style={{ flex: 1, height: "1px", background: "#ddd" }} />
            </div>

            <div
              className="submit"
              style={{
                width: "100%",
                background: passkeyLoading
                  ? "#ccc"
                  : "linear-gradient(135deg, #4c00b4 0%, #2d004d 100%)",
                cursor: passkeyLoading ? "not-allowed" : "pointer",
              }}
              onClick={!passkeyLoading ? handlePasskeyLogin : undefined}
            >
              {passkeyLoading ? "Authenticating..." : "Login with Passkey"}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default LoginPage;
