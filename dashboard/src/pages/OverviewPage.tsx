import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Agent, Alert } from '../services/api';
import { Monitor, AlertTriangle, ShieldCheck, Activity, ShieldAlert } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.getAgents(), api.getAlerts()]).then(([aData, alData]) => {
      setAgents(aData);
      setAlerts(alData.items || []);
      setLoading(false);
    });
  }, []);

  const activeAgents = agents.filter(a => a.status === 'active').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
  const avgRisk = agents.length ? Math.round(agents.reduce((acc, a) => acc + a.current_risk_score, 0) / agents.length) : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Executive Threat Overview</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time Cyber Defense Command Metrics across 37 Managed Endpoints</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px' }}>
        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ padding: '10px', background: 'rgba(168, 85, 247, 0.15)', borderRadius: '10px', border: '1px solid var(--border-glow)' }}>
            <Monitor size={32} color="var(--accent-purple-light)" />
          </div>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Total Endpoints</span>
            <h2 style={{ fontSize: '1.6rem', marginTop: '4px', color: '#fff' }}>{agents.length}</h2>
          </div>
        </div>

        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ padding: '10px', background: 'rgba(16, 185, 129, 0.15)', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
            <ShieldCheck size={32} color="var(--accent-green)" />
          </div>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Active Online</span>
            <h2 style={{ fontSize: '1.6rem', marginTop: '4px', color: '#fff' }}>{activeAgents}</h2>
          </div>
        </div>

        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ padding: '10px', background: 'rgba(239, 68, 68, 0.15)', borderRadius: '10px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <AlertTriangle size={32} color="var(--accent-red)" />
          </div>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>High/Critical Alerts</span>
            <h2 style={{ fontSize: '1.6rem', marginTop: '4px', color: '#fff' }}>{criticalAlerts}</h2>
          </div>
        </div>

        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ padding: '10px', background: 'rgba(245, 158, 11, 0.15)', borderRadius: '10px', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
            <Activity size={32} color="var(--accent-yellow)" />
          </div>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Fleet Risk Average</span>
            <h2 style={{ fontSize: '1.6rem', marginTop: '4px', color: '#fff' }}>{avgRisk} <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>/ 100</span></h2>
          </div>
        </div>
      </div>

      <div className="glass-card">
        <h3 style={{ marginBottom: '15px', fontSize: '1rem', color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={18} /> Live Security Incident Stream
        </h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading fleet alerts...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '20px' }}>No active security alerts. Agent telemetry streams are clear.</td></tr>
            ) : (
              alerts.map(a => (
                <tr key={a.id}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.title}</td>
                  <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                  <td><span className="badge badge-medium">{a.status}</span></td>
                  <td>{new Date(a.created_at).toLocaleTimeString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
