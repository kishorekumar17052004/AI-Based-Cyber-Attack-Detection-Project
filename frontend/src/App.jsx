import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Activity, AlertTriangle,
  Settings as SettingsIcon, Link2, BrainCircuit
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import LiveTraffic from './pages/LiveTraffic';
import ThreatAlerts from './pages/ThreatAlerts';
import SettingsPage from './pages/Settings';
import DeviceConnection from './pages/DeviceConnection';
import PacketMonitor from './pages/PacketMonitor';
import ToastContainer from './components/ToastContainer';
import { ToastProvider } from './context/ToastContext';
import './index.css';

const API_BASE = 'http://localhost:5000/api';

function App() {
  return (
    <ToastProvider>
      <Router>
        <div className="app-container">
          {/* Sidebar */}
          <aside className="sidebar">
            <div className="logo">
              <div className="logo-icon">
                <Shield color="white" size={22} />
              </div>
              <span className="logo-text">CyberShield AI</span>
            </div>

            <nav className="nav-menu">
              <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end>
                <LayoutDashboard size={18} />
                <span>Dashboard</span>
              </NavLink>
              <NavLink to="/connect" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <Link2 size={18} />
                <span>Device Connection</span>
              </NavLink>
              <NavLink to="/live-packets" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <Activity size={18} />
                <span>Live Packets</span>
              </NavLink>
              <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <AlertTriangle size={18} />
                <span>Attack Logs</span>
              </NavLink>
              <NavLink to="/prediction" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <BrainCircuit size={18} />
                <span>Model Prediction</span>
              </NavLink>

              <div className="nav-spacer" />

              <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <SettingsIcon size={18} />
                <span>Settings</span>
              </NavLink>
            </nav>
          </aside>

          {/* Main Content */}
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/connect" element={<DeviceConnection />} />
              <Route path="/live-packets" element={<PacketMonitor />} />
              <Route path="/prediction" element={<LiveTraffic />} />
              <Route path="/alerts" element={<ThreatAlerts />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>

          <ToastContainer />
        </div>
      </Router>
    </ToastProvider>
  );
}

export default App;
