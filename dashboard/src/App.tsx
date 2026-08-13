import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './styles/theme.css';
import { Navigation } from './components/Navigation';
import { Header } from './components/Header';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { EndpointsPage, EndpointDetailPage } from './pages/EndpointsPage';
import { AlertsPage } from './pages/AlertsPage';
import {
  IncidentsPage,
  MitreMatrixPage,
  ThreatIntelPage,
  TimelinePage,
  PoliciesPage,
  RulesPage,
  SettingsPage,
  UsersPage,
  ReportsPage,
  AuditLogPage,
  LiveLogsPage,
} from './pages/OtherPages';
import { useLiveUpdates } from './hooks/useLiveUpdates';
import { LiveContext } from './contexts/LiveContext';
import { api } from './services/api';

const AuthenticatedApp: React.FC<{ onLogout: () => void }> = ({ onLogout }) => {
  const { alerts, liveLogs, connected } = useLiveUpdates();

  return (
    <LiveContext.Provider value={{ alerts, liveLogs, connected, onLogout }}>
      <Router>
        <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
          <Navigation />
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Header />
            <main style={{ flex: 1, padding: '25px', overflowY: 'auto' }}>
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/endpoints" element={<EndpointsPage />} />
                <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/mitre" element={<MitreMatrixPage />} />
                <Route path="/threat-intel" element={<ThreatIntelPage />} />
                <Route path="/timeline" element={<TimelinePage />} />
                <Route path="/policies" element={<PoliciesPage />} />
                <Route path="/rules" element={<RulesPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/audit-log" element={<AuditLogPage />} />
                <Route path="/live-logs" element={<LiveLogsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </LiveContext.Provider>
  );
};

export const App: React.FC = () => {
  // null = still verifying, true = authenticated, false = not authenticated
  const [authenticated, setAuthenticated] = useState<boolean | null>(() => {
    // Only set to true initially if a token exists — we'll verify it below
    return localStorage.getItem('access_token') ? null : false;
  });

  useEffect(() => {
    // If we found a stored token, verify it against the server before trusting it
    if (authenticated === null) {
      fetch('http://localhost:8000/api/v1/auth/me', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }
      })
        .then(res => {
          if (res.ok) {
            setAuthenticated(true);
          } else {
            // Token is invalid/expired — clear it and show login
            api.logout();
            setAuthenticated(false);
          }
        })
        .catch(() => {
          // Network error — server may be down, show login
          api.logout();
          setAuthenticated(false);
        });
    }
  }, [authenticated]);

  const handleLogout = () => {
    api.logout();
    setAuthenticated(false);
  };

  // Show a minimal loading screen while verifying the stored token
  if (authenticated === null) {
    return (
      <div style={{
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        height: '100vh', background: 'var(--bg-primary)', color: 'var(--text-secondary)',
        fontFamily: 'var(--font-family)', flexDirection: 'column', gap: '16px'
      }}>
        <div style={{
          width: '48px', height: '48px', border: '3px solid rgba(168, 85, 247, 0.2)',
          borderTop: '3px solid var(--accent-purple-light)',
          borderRadius: '50%', animation: 'spin 0.8s linear infinite'
        }} />
        <span style={{ fontSize: '0.85rem' }}>Verifying session...</span>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  if (!authenticated) {
    return <LoginPage onLogin={() => setAuthenticated(true)} />;
  }

  return <AuthenticatedApp onLogout={handleLogout} />;
};

export default App;
