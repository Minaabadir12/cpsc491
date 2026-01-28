import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { logout, refreshToken } from "../utils/api";

const TIMEOUT_DURATION = 10 * 60 * 1000; // 10 minutes
const WARNING_TIME = 1 * 60 * 1000; // 1 minute warning

export const useInactivityTimer = () => {
  const timerRef = useRef(null);
  const warningTimerRef = useRef(null);
  const warningShownRef = useRef(false);
  const location = useLocation();

  const resetTimer = async () => {
    // Reset warning sown flag
    warningShownRef.current = false;
    
    // Clear existing timers
    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    if (warningTimerRef.current) {
      clearTimeout(warningTimerRef.current);
    }

    // Refresh the JWT token on activity
    const refreshed = await refreshToken();
    
    if (!refreshed) {
      logout();
      return;
    }

    // Set warning timer
    warningTimerRef.current = setTimeout(() => {
      if (warningShownRef.current) {
        return;
      }
      
      warningShownRef.current = true;
      
      const shouldStay = window.confirm(
        "You've been inactive. You'll be logged out in " + (WARNING_TIME / 1000) + " seconds. Click OK to stay logged in."
      );
      
      if (shouldStay) {
        resetTimer();
      } else {
      }
    }, TIMEOUT_DURATION - WARNING_TIME);


    // Set logout timer
    timerRef.current = setTimeout(() => {
      alert("You've been logged out due to inactivity.");
      logout();
    }, TIMEOUT_DURATION);
    
  };

  useEffect(() => {
    
    // Don't run timer on login/signup pages - use EXACT matches
    const publicRoutes = ["/", "/resetpassword"];
    const isPublicRoute = publicRoutes.includes(location.pathname) || 
                          location.pathname.startsWith("/newpassword/");
    
    if (isPublicRoute) {
      return;
    }
    
    // Only start timer if user is logged in
    const token = localStorage.getItem("token");
    if (!token) {
      return;
    }

    // Activity events to track
    const activityEvents = [
      "mousedown",
      "mousemove",
      "keypress",
      "scroll",
      "touchstart",
      "click",
    ];

    // Throttle the resetTimer to avoid too many refresh calls
    let throttleTimeout;
    const throttledResetTimer = () => {
      if (throttleTimeout) {
        return;
      }
      
      throttleTimeout = setTimeout(() => {
        resetTimer();
        throttleTimeout = null;
      }, 5000); // Only refresh token at most once every 5 seconds
    };

    // Add event listeners
    activityEvents.forEach((event) => {
      document.addEventListener(event, throttledResetTimer, true);
    });
    
    // Initialize timer
    resetTimer();

    // Cleanup
    return () => {

      activityEvents.forEach((event) => {
        document.removeEventListener(event, throttledResetTimer, true);
      });
      if (timerRef.current) clearTimeout(timerRef.current);
      if (warningTimerRef.current) clearTimeout(warningTimerRef.current);
      if (throttleTimeout) clearTimeout(throttleTimeout);
    };
  }, [location.pathname]); // Re-run when route changes

  return null;
};