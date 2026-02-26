import React from "react";

const GuardFileLogo = ({ size = 90, showText = true }) => {
  const shieldSize = size;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: showText ? "12px" : "0px", marginBottom: showText ? "10px" : "0px" }}>
      {/* Shield shape using CSS clip-path */}
      <div
        style={{
          width: `${shieldSize}px`,
          height: `${shieldSize * 1.15}px`,
          background: "linear-gradient(180deg, #7c3aed 0%, #4c00b4 100%)",
          clipPath: "polygon(50% 0%, 100% 15%, 100% 55%, 75% 80%, 50% 100%, 25% 80%, 0% 55%, 0% 15%)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          position: "relative",
        }}
      >
        {/* Lock icon using pure CSS */}
        <div style={{ marginTop: "-2px", display: "flex", flexDirection: "column", alignItems: "center" }}>
          {/* Shackle */}
          <div
            style={{
              width: `${shieldSize * 0.28}px`,
              height: `${shieldSize * 0.22}px`,
              border: `${shieldSize * 0.04}px solid white`,
              borderBottom: "none",
              borderRadius: `${shieldSize * 0.14}px ${shieldSize * 0.14}px 0 0`,
            }}
          />
          {/* Lock body */}
          <div
            style={{
              width: `${shieldSize * 0.38}px`,
              height: `${shieldSize * 0.26}px`,
              backgroundColor: "white",
              borderRadius: `${shieldSize * 0.03}px`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {/* Keyhole */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div
                style={{
                  width: `${shieldSize * 0.08}px`,
                  height: `${shieldSize * 0.08}px`,
                  backgroundColor: "#4c00b4",
                  borderRadius: "50%",
                }}
              />
              <div
                style={{
                  width: `${shieldSize * 0.04}px`,
                  height: `${shieldSize * 0.07}px`,
                  backgroundColor: "#4c00b4",
                  borderRadius: `0 0 ${shieldSize * 0.02}px ${shieldSize * 0.02}px`,
                  marginTop: "-1px",
                }}
              />
            </div>
          </div>
        </div>
      </div>

      {showText && (
        <span
          style={{
            fontSize: `${Math.max(size * 0.32, 26)}px`,
            fontWeight: 700,
            color: "#ffffff",
            letterSpacing: "2px",
            fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
          }}
        >
          GuardFile
        </span>
      )}
    </div>
  );
};

export default GuardFileLogo;
