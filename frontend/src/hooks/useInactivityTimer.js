import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { logout } from "../utils/api";

const TIMEOUT_DURATION = 10 * 60 * 10000; // 10 minutes
const WARNING_TIME = 1 * 60 * 10000; // 1 minute

export const useInactivityTimer = () => {
  const location = useLocation();

  const lastActivityRef = useRef(Date.now());
  const warningShownRef = useRef(false);

  // Update last activity timestamp only (NO API CALLS HERE)
  const updateActivity = () => {
    lastActivityRef.current = Date.now();
  };

  useEffect(() => {
    const publicRoutes = ["/", "/resetpassword"];
    const isPublicRoute =
      publicRoutes.includes(location.pathname) ||
      location.pathname.startsWith("/newpassword/");

    const token = localStorage.getItem("token");

    if (isPublicRoute || !token) return;

    const events = [
      "mousedown",
      "mousemove",
      "keypress",
      "scroll",
      "touchstart",
      "click",
    ];

    // Attach activity listeners
    events.forEach((event) => {
      document.addEventListener(event, updateActivity, true);
    });

    // Main inactivity checker
    const interval = setInterval(() => {
      const inactiveTime = Date.now() - lastActivityRef.current;

      // Show warning once
      if (
        inactiveTime >= TIMEOUT_DURATION - WARNING_TIME &&
        inactiveTime < TIMEOUT_DURATION &&
        !warningShownRef.current
      ) {
        warningShownRef.current = true;

        const stayLoggedIn = window.confirm(
          "You've been inactive. You will be logged out soon. Click OK to stay signed in."
        );

        if (stayLoggedIn) {
          lastActivityRef.current = Date.now();
          warningShownRef.current = false;
        }
      }

      // Logout after timeout
      if (inactiveTime >= TIMEOUT_DURATION) {
        alert("You've been logged out due to inactivity.");
        logout();
      }
    }, 1000);

    // Cleanup
    return () => {
      events.forEach((event) => {
        document.removeEventListener(event, updateActivity, true);
      });
      clearInterval(interval);
    };
  }, [location.pathname]);
};