import { Routes, Route } from "react-router-dom";
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/Login_Signup";
import UploadFiles from "./pages/UploadFiles";
import Settings from "./pages/Settings";
import Manage from "./pages/ManageFiles";
import ResetPassword from "./pages/ResetPassword";
import NewPassword from "./pages/NewPassword";
import { useInactivityTimer } from "./hooks/useInactivityTimer";

function App() {
  useInactivityTimer();
  return (
    <Routes>
      <Route path="/" element={<LoginPage />} />
      <Route path="/home" element={<HomePage />} />
      <Route path="/upload" element={<UploadFiles />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/manage" element={<Manage />} />
      <Route path="/resetpassword" element={<ResetPassword />} />
      <Route path="/newpassword/:token" element={<NewPassword />} />
      
    </Routes>
  );
}

export default App;
