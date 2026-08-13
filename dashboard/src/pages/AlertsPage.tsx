import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Alert } from '../services/api';
import { AlertTriangle } from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAlerts().then(res => {
      setAlerts(res.items || []);
      setLoading(false);
    });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Security Alerts Management</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time threat detection alerts and analyst triage queue</p>
      </div>

      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <AlertTriangle size={18} /> Fleet Security Alerts ({alerts.length})
        </h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Description</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading security alerts...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '25px' }}>No active security alerts logged in system. Fleet telemetry is normal.</td></tr>
            ) : (
              alerts.map(alert => (
                <tr key={alert.id}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{alert.title}</td>
                  <td><span className={`badge badge-${alert.severity}`}>{alert.severity}</span></td>
                  <td><span className="badge badge-medium">{alert.status}</span></td>
                  <td style={{ color: 'var(--text-secondary)' }}>{alert.description}</td>
                  <td>{new Date(alert.created_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
