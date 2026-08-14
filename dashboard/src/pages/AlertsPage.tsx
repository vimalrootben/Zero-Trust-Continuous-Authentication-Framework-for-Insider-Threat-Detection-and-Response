import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Alert } from '../services/api';
import {
  AlertTriangle,
  Zap,
  XCircle,
  Lock,
  LogOut,
  WifiOff,
  Wifi,
  FileText,
  X
} from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [actionModal, setActionModal] = useState<{
    action: string;
    endpoint: string;
    title: string;
    description: string;
    params?: any;
  } | null>(null);
  const [executing, setExecuting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchAlerts = async () => {
    setLoading(true);
    const res = await api.getAlerts();
    setAlerts(res.items || []);
    setLoading(false);
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const openDetail = async (alert: Alert) => {
    setSelectedAlert(alert);
    const full = await api.getAlert(alert.id);
    if (full) setSelectedAlert(full);
  };

  const handleLifecycle = async (actionType: 'acknowledge' | 'investigate' | 'resolve') => {
    if (!selectedAlert) return;
    try {
      let updated: Alert;
      if (actionType === 'acknowledge') updated = await api.acknowledgeAlert(selectedAlert.id);
      else if (actionType === 'investigate') updated = await api.investigateAlert(selectedAlert.id);
      else updated = await api.resolveAlert(selectedAlert.id);

      setSelectedAlert(updated);
      fetchAlerts();
    } catch (err: any) {
      alert(err.message || 'Lifecycle transition failed');
    }
  };

  const executeResponseAction = async () => {
    if (!selectedAlert || !actionModal) return;
    setExecuting(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      const resp = await api.executeAlertResponse(selectedAlert.id, actionModal.endpoint, actionModal.params || {});
      setActionSuccess(`Action '${actionModal.title}' dispatched. Response ID: ${resp.id}`);
      setActionModal(null);
      // Refresh detail
      const full = await api.getAlert(selectedAlert.id);
      if (full) setSelectedAlert(full);
      fetchAlerts();
    } catch (err: any) {
      setActionError(err.message || 'Failed to dispatch response action');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Security Alerts & Real Response Engine</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>
          Real-time threat detection alerts and automated/SOC analyst endpoint response dispatching
        </p>
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
              <th>Response Status</th>
              <th>Process / Target</th>
              <th>Timestamp</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading security alerts...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '25px' }}>No active security alerts logged in system. Fleet telemetry is normal.</td></tr>
            ) : (
              alerts.map(alert => (
                <tr key={alert.id} onClick={() => openDetail(alert)} style={{ cursor: 'pointer' }}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{alert.title}</td>
                  <td><span className={`badge badge-${alert.severity}`}>{alert.severity}</span></td>
                  <td><span className="badge badge-medium">{alert.status}</span></td>
                  <td>
                    {alert.response_status ? (
                      <span className={`badge ${alert.response_status === 'success' ? 'badge-low' : alert.response_status === 'failed' ? 'badge-high' : 'badge-medium'}`}>
                        {alert.response_status}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>None</span>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                    {alert.process_name ? `${alert.process_name} (PID ${alert.process_id || 'N/A'})` : alert.file_path || 'Endpoint'}
                  </td>
                  <td>{new Date(alert.created_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="btn btn-secondary"
                      onClick={(e) => { e.stopPropagation(); openDetail(alert); }}
                      style={{ padding: '4px 10px', fontSize: '0.8rem' }}
                    >
                      View & Respond
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Alert Detail & Response Modal */}
      {selectedAlert && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(5px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px'
        }}>
          <div className="glass-card" style={{ maxWidth: '850px', width: '100%', maxHeight: '90vh', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <div>
                <span className={`badge badge-${selectedAlert.severity}`} style={{ marginRight: '10px' }}>{selectedAlert.severity.toUpperCase()}</span>
                <span className="badge badge-medium">{selectedAlert.status.toUpperCase()}</span>
                <h2 style={{ fontSize: '1.25rem', marginTop: '6px', fontWeight: 700 }}>{selectedAlert.title}</h2>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Alert ID: {selectedAlert.alert_id || selectedAlert.id} | Agent: {selectedAlert.agent_id}
                </div>
              </div>
              <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={24} />
              </button>
            </div>

            {/* Notifications */}
            {actionSuccess && <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', color: '#10b981', padding: '10px', borderRadius: '6px', fontSize: '0.85rem' }}>{actionSuccess}</div>}
            {actionError && <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#ef4444', padding: '10px', borderRadius: '6px', fontSize: '0.85rem' }}>{actionError}</div>}

            {/* Description & Target Metadata */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', background: 'rgba(255,255,255,0.03)', padding: '15px', borderRadius: '8px' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: 600 }}>Description</div>
                <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>{selectedAlert.description || 'No description provided'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: 600 }}>Target Details</div>
                <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                  {selectedAlert.process_name && <div>Process: <strong>{selectedAlert.process_name}</strong> (PID {selectedAlert.process_id})</div>}
                  {selectedAlert.file_path && <div>File: <code>{selectedAlert.file_path}</code></div>}
                  {selectedAlert.remote_ip && <div>Remote IP: {selectedAlert.remote_ip}:{selectedAlert.remote_port}</div>}
                  {selectedAlert.username && <div>User: {selectedAlert.username}</div>}
                </div>
              </div>
            </div>

            {/* Alert Lifecycle Controls */}
            <div>
              <h4 style={{ fontSize: '0.9rem', marginBottom: '10px', color: 'var(--text-primary)' }}>Alert Lifecycle Management</h4>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button className="btn btn-secondary" onClick={() => handleLifecycle('acknowledge')}>Acknowledge</button>
                <button className="btn btn-secondary" onClick={() => handleLifecycle('investigate')}>Start Investigation</button>
                <button className="btn btn-primary" onClick={() => handleLifecycle('resolve')}>Mark Resolved</button>
              </div>
            </div>

            {/* Response Actions Section */}
            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '15px' }}>
              <h4 style={{ fontSize: '0.9rem', marginBottom: '12px', color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Zap size={16} /> Real Endpoint Response Controls
              </h4>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #ef4444' }}
                  onClick={() => setActionModal({
                    action: 'PROCESS_TERMINATE',
                    endpoint: 'process-terminate',
                    title: 'Terminate Target Process',
                    description: `Terminates process ${selectedAlert.process_name || ''} (PID ${selectedAlert.process_id || ''}) on host.`,
                    params: { pid: selectedAlert.process_id, process_name: selectedAlert.process_name }
                  })}
                >
                  <XCircle size={16} color="#ef4444" /> Terminate Process
                </button>

                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #f59e0b' }}
                  onClick={() => setActionModal({
                    action: 'NETWORK_ISOLATE',
                    endpoint: 'network-isolate',
                    title: 'Isolate Host Network',
                    description: 'Enforces netsh Windows Firewall host isolation rules blocking non-EDR traffic.'
                  })}
                >
                  <WifiOff size={16} color="#f59e0b" /> Network Isolate
                </button>

                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #10b981' }}
                  onClick={() => setActionModal({
                    action: 'NETWORK_UNISOLATE',
                    endpoint: 'network-unisolate',
                    title: 'Unisolate Host Network',
                    description: 'Removes Windows Firewall host isolation rules restoring full network connectivity.'
                  })}
                >
                  <Wifi size={16} color="#10b981" /> Network Unisolate
                </button>

                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #3b82f6' }}
                  onClick={() => setActionModal({
                    action: 'FILE_QUARANTINE',
                    endpoint: 'quarantine',
                    title: 'Quarantine File',
                    description: `Safely moves file ${selectedAlert.file_path || ''} to .quarantine folder preserving metadata.`,
                    params: { file_path: selectedAlert.file_path }
                  })}
                >
                  <FileText size={16} color="#3b82f6" /> File Quarantine
                </button>

                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #8b5cf6' }}
                  onClick={() => setActionModal({
                    action: 'WORKSTATION_LOCK',
                    endpoint: 'lock',
                    title: 'Lock Workstation',
                    description: 'Calls Windows user32.dll LockWorkStation() to immediately lock host session.'
                  })}
                >
                  <Lock size={16} color="#8b5cf6" /> Lock Workstation
                </button>

                <button
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '3px solid #ec4899' }}
                  onClick={() => setActionModal({
                    action: 'USER_LOGOUT',
                    endpoint: 'logout',
                    title: 'Logoff Remote User',
                    description: `Logs off user session ${selectedAlert.username || ''} via Windows shutdown logoff call.`,
                    params: { username: selectedAlert.username }
                  })}
                >
                  <LogOut size={16} color="#ec4899" /> User Logout
                </button>
              </div>
            </div>

            {/* Response History */}
            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '15px' }}>
              <h4 style={{ fontSize: '0.9rem', marginBottom: '10px' }}>Response Attempt History</h4>
              {!selectedAlert.responses || selectedAlert.responses.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>No response actions recorded for this alert yet.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedAlert.responses.map(r => (
                    <div key={r.id} style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                        <span>Action: {r.action.toUpperCase()}</span>
                        <span className={`badge ${r.status === 'success' ? 'badge-low' : r.status === 'failed' ? 'badge-high' : 'badge-medium'}`}>{r.status.toUpperCase()}</span>
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: '4px' }}>
                        Requested At: {r.requested_at ? new Date(r.requested_at).toLocaleString() : 'N/A'} | Correlation ID: {r.correlation_id || 'N/A'}
                      </div>
                      {r.error_message && <div style={{ color: '#ef4444', fontSize: '0.8rem', marginTop: '4px' }}>Error: {r.error_message}</div>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {actionModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(5px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, padding: '20px'
        }}>
          <div className="glass-card" style={{ maxWidth: '450px', width: '100%', padding: '20px' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-purple-light)' }}>
              Confirm Response Action: {actionModal.title}
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '8px', lineHeight: 1.4 }}>
              {actionModal.description}
            </p>
            <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '10px', borderRadius: '6px', marginTop: '12px', fontSize: '0.8rem', color: '#fca5a5' }}>
              <strong>Warning:</strong> This will dispatch a cryptographically signed command to the Agent to execute real host modification actions.
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button className="btn btn-secondary" onClick={() => setActionModal(null)} disabled={executing}>Cancel</button>
              <button className="btn btn-primary" onClick={executeResponseAction} disabled={executing}>
                {executing ? 'Dispatching...' : 'Confirm & Execute'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
