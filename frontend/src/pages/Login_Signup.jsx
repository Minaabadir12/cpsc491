import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./LoginPage.css";

import user_icon from "../Components/Assets/person.png";
import email_icon from "../Components/Assets/email.png";
import password_icon from "../Components/Assets/password.png";

const LoginPage = () => {
  const [action, setAction] = useState("Sign Up");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

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
        // Store the JWT token
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