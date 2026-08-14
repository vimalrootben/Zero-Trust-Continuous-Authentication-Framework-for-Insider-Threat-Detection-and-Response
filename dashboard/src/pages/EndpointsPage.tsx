import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Agent, ListeningPort, NetworkEvent } from '../services/api';
import { useNavigate, useParams } from 'react-router-dom';
import { Monitor, ShieldAlert, Terminal, Power, Wifi, WifiOff, Radio, Activity, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpRight, ArrowDownLeft } from 'lucide-react';

export const EndpointsPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmModal, setConfirmModal] = useState<{ open: boolean; agentId: string; action: 'isolate' | 'unisolate'; hostname: string }>({
    open: false,
    agentId: '',
    action: 'isolate',
    hostname: ''
  });
  const [actionPending, setActionPending] = useState<string | null>(null);
  const navigate = useNavigate();

  const loadAgents = () => {
    api.getAgents().then(data => {
      setAgents(data);
      setLoading(false);
    });
  };

  useEffect(() => {
    loadAgents();

    // Listen to real-time WebSocket events
    const handleWs = (e: any) => {
      const msg = e.detail;
      if (msg && (msg.type === 'AGENT_STATUS_CHANGED' || msg.type === 'ISOLATION_STATE_CHANGED' || msg.type === 'AGENT_HEARTBEAT')) {
        loadAgents();
      }
    };

    window.addEventListener('edr-ws-message', handleWs);
    return () => window.removeEventListener('edr-ws-message', handleWs);
  }, []);

  const openConfirmation = (e: React.MouseEvent, agent: Agent, action: 'isolate' | 'unisolate') => {
    e.stopPropagation();
    setConfirmModal({
      open: true,
      agentId: agent.id,
      action,
      hostname: agent.hostname
    });
  };

  const executeIsolationAction = async () => {
    const { agentId, action } = confirmModal;
    setConfirmModal(prev => ({ ...prev, open: false }));
    setActionPending(agentId);

    try {
      if (action === 'isolate') {
        await api.isolateAgent(agentId);
      } else {
        await api.unisolateAgent(agentId);
      }
      setTimeout(loadAgents, 1000);
    } catch (err: any) {
      alert(`Action error: ${err.message}`);
    } finally {
      setActionPending(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Endpoints (Managed EDR Agents)</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time host inventory and zero-trust containment status</p>
        </div>
        <button className="btn btn-secondary" onClick={loadAgents} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <RefreshCw size={14} /> Refresh Endpoints
        </button>
      </div>

      <div className="glass-card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Risk Score</th>
              <th>OS Version</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading active agents...</td></tr>
            ) : agents.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No registered agents found.</td></tr>
            ) : (
              agents.map(agent => {
                const isIsolated = agent.status === 'quarantined' || agent.status === 'isolated';
                const isPending = actionPending === agent.id;
                return (
                  <tr key={agent.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/endpoints/${agent.id}`)}>
                    <td style={{ fontWeight: 600, color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Monitor size={16} />
                      {agent.hostname}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{agent.ip_address || '127.0.0.1'}</td>
                    <td>
                      <span className={`badge ${isIsolated ? 'badge-critical' : agent.status === 'active' ? 'badge-low' : 'badge-medium'}`}>
                        {isIsolated ? 'ISOLATED' : agent.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: agent.current_risk_score > 70 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                      {agent.current_risk_score} <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>/ 100</span>
                    </td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{agent.os_version || 'Windows 11 Enterprise'}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleTimeString() : 'Recent'}
                    </td>
                    <td>
                      {isIsolated ? (
                        <button 
                          className="btn btn-secondary" 
                          style={{ padding: '4px 12px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px', borderColor: 'var(--accent-green)', color: 'var(--accent-green)' }} 
                          onClick={(e) => openConfirmation(e, agent, 'unisolate')}
                          disabled={isPending}
                        >
                          <Wifi size={12} /> {isPending ? 'Reconnecting...' : 'Unisolate'}
                        </button>
                      ) : (
                        <button 
                          className="btn btn-secondary" 
                          style={{ padding: '4px 12px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px' }} 
                          onClick={(e) => openConfirmation(e, agent, 'isolate')}
                          disabled={isPending}
                        >
                          <Power size={12} /> {isPending ? 'Isolating...' : 'Isolate'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Confirmation Modal */}
      {confirmModal.open && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(5, 2, 18, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '440px', padding: '24px', border: '1px solid var(--border-glow)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <AlertTriangle color={confirmModal.action === 'isolate' ? 'var(--accent-red)' : 'var(--accent-green)'} size={24} />
              <h3 style={{ margin: 0, fontSize: '1.15rem' }}>
                {confirmModal.action === 'isolate' ? 'Confirm Network Isolation' : 'Confirm Network Restoration'}
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '20px' }}>
              {confirmModal.action === 'isolate'
                ? `Are you sure you want to isolate endpoint "${confirmModal.hostname}"? This will activate real Windows Firewall block rules on the endpoint, stopping all non-EDR inbound and outbound network communications.`
                : `Are you sure you want to restore network connectivity for endpoint "${confirmModal.hostname}"? This will remove the EDR host isolation firewall rules.`}
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmModal(prev => ({ ...prev, open: false }))}>
                Cancel
              </button>
              <button 
                className="btn" 
                style={{
                  background: confirmModal.action === 'isolate' ? 'var(--accent-red)' : 'var(--accent-green)',
                  color: '#fff',
                  borderColor: confirmModal.action === 'isolate' ? 'rgba(239,68,68,0.6)' : 'rgba(34,197,94,0.6)'
                }}
                onClick={executeIsolationAction}
              >
                {confirmModal.action === 'isolate' ? 'Execute Isolation' : 'Restore Network'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export const EndpointDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [commands, setCommands] = useState<any[]>([]);
  const [listeningPorts, setListeningPorts] = useState<ListeningPort[]>([]);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [customCmd, setCustomCmd] = useState('');
  const [isolationState, setIsolationState] = useState<string>('NOT_ISOLATED');
  const [confirmIsolateOpen, setConfirmIsolateOpen] = useState(false);
  const [confirmUnisolateOpen, setConfirmUnisolateOpen] = useState(false);

  const fetchDetails = () => {
    if (!id) return;
    setLoading(true);
    Promise.all([
      api.getAgent(id),
      api.getCommands(id),
      api.getListeningPorts(id),
      api.getNetworkEvents(id, 50)
    ])
      .then(([agentData, cmdData, portsData, eventsData]) => {
        setAgent(agentData);
        setCommands(cmdData);
        setListeningPorts(portsData);
        setNetworkEvents(eventsData);

        if (agentData?.status === 'quarantined' || agentData?.status === 'isolated') {
          setIsolationState('ISOLATED');
        } else {
          setIsolationState('NOT_ISOLATED');
        }
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchDetails();

    // Listen to real-time WebSocket events
    const handleWs = (e: any) => {
      const msg = e.detail;
      if (!msg) return;

      if (msg.type === 'AGENT_STATUS_CHANGED' && msg.agent_id === id) {
        setAgent(prev => prev ? { ...prev, status: msg.payload?.status || prev.status } : null);
      } else if (msg.type === 'ISOLATION_STATE_CHANGED' && msg.agent_id === id) {
        setIsolationState(msg.payload?.isolation_status || 'NOT_ISOLATED');
        if (msg.payload?.isolation_status === 'ISOLATED') {
          setAgent(prev => prev ? { ...prev, status: 'quarantined' } : null);
        } else if (msg.payload?.isolation_status === 'NOT_ISOLATED') {
          setAgent(prev => prev ? { ...prev, status: 'active' } : null);
        }
      } else if (msg.type === 'NETWORK_EVENT' && id && msg.agent_id === id) {
        // Refetch ports and network events
        api.getListeningPorts(id).then(setListeningPorts);
        api.getNetworkEvents(id, 50).then(setNetworkEvents);
      }
    };

    window.addEventListener('edr-ws-message', handleWs);
    return () => window.removeEventListener('edr-ws-message', handleWs);
  }, [id]);

  const handleCommand = async (commandType: string, params: any = {}) => {
    if (!id) return;
    try {
      if (commandType === 'DISABLE_NETWORK') {
        setIsolationState('ISOLATION_PENDING');
      } else if (commandType === 'ENABLE_NETWORK') {
        setIsolationState('UNISOLATION_PENDING');
      }

      await api.issueCommand(id, commandType, params);
      api.getCommands(id).then(setCommands);
    } catch (err: any) {
      alert(`Failed to issue command: ${err.message}`);
      if (commandType === 'DISABLE_NETWORK') setIsolationState('ISOLATION_FAILED');
      if (commandType === 'ENABLE_NETWORK') setIsolationState('UNISOLATION_FAILED');
    }
  };

  if (loading) {
    return <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '50px' }}>Loading endpoint telemetry details...</div>;
  }

  if (!agent) {
    return <div style={{ color: 'var(--accent-red)', padding: '20px' }}>Endpoint agent not found in database.</div>;
  }

  const isIsolated = isolationState === 'ISOLATED' || agent.status === 'quarantined' || agent.status === 'isolated';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Endpoint Control: {agent.hostname}</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time host profile and active mitigation control center</p>
        </div>
        <button className="btn btn-secondary" onClick={fetchDetails} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="glass-card">
            <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Monitor size={18} /> System Profile & Identity
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '12px', fontSize: '0.88rem' }}>
              <div style={{ color: 'var(--text-secondary)' }}>Agent ID:</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-purple-light)' }}>{agent.id}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Hostname:</div>
              <div style={{ fontWeight: 600, color: '#fff' }}>{agent.hostname}</div>
              <div style={{ color: 'var(--text-secondary)' }}>IP Address:</div>
              <div style={{ fontFamily: 'var(--font-mono)' }}>{agent.ip_address || '127.0.0.1'}</div>
              <div style={{ color: 'var(--text-secondary)' }}>OS Version:</div>
              <div>{agent.os_version || 'Windows 11'}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Connection:</div>
              <div>
                <span className={`badge ${agent.status === 'active' ? 'badge-low' : 'badge-medium'}`}>
                  {agent.status === 'active' ? 'ONLINE' : agent.status.toUpperCase()}
                </span>
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>Isolation State:</div>
              <div>
                <span className={`badge ${isIsolated ? 'badge-critical' : isolationState.includes('PENDING') ? 'badge-medium' : 'badge-low'}`}>
                  {isolationState}
                </span>
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>Risk Score:</div>
              <div style={{ fontWeight: 700, color: agent.current_risk_score > 70 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                {agent.current_risk_score} / 100
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>Last Heartbeat:</div>
              <div>{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Recent'}</div>
            </div>
          </div>

          <div className="glass-card">
            <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} /> Real Network Containment & Controls
            </h3>
            
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginBottom: '15px' }}>
              {isIsolated ? (
                <button 
                  className="btn btn-secondary" 
                  style={{ borderColor: 'var(--accent-green)', color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: '6px' }}
                  onClick={() => setConfirmUnisolateOpen(true)}
                  disabled={isolationState === 'UNISOLATION_PENDING'}
                >
                  <Wifi size={14} /> {isolationState === 'UNISOLATION_PENDING' ? 'Restoring Network...' : 'Unisolate Host Network'}
                </button>
              ) : (
                <button 
                  className="btn" 
                  style={{ background: 'var(--accent-red)', color: '#fff', borderColor: 'rgba(239,68,68,0.5)', display: 'flex', alignItems: 'center', gap: '6px' }}
                  onClick={() => setConfirmIsolateOpen(true)}
                  disabled={isolationState === 'ISOLATION_PENDING'}
                >
                  <WifiOff size={14} /> {isolationState === 'ISOLATION_PENDING' ? 'Disabling Network...' : 'Full Network Isolation'}
                </button>
              )}

              <button 
                className="btn btn-secondary" 
                onClick={() => handleCommand('LOGOFF_USER')}
              >
                Logoff User
              </button>
              <button 
                className="btn btn-secondary"
                onClick={() => {
                  const pid = prompt("Enter process ID to terminate:");
                  if (pid) handleCommand('KILL_PROCESS', { pid: parseInt(pid) });
                }}
              >
                Kill Malicious Process
              </button>
            </div>

            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '15px' }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                <Terminal size={14} color="var(--accent-purple-light)" /> Execute Remote PowerShell Command
              </label>
              <div style={{ display: 'flex', gap: '10px' }}>
                <input 
                  type="text" 
                  value={customCmd}
                  onChange={e => setCustomCmd(e.target.value)}
                  placeholder="Get-NetTCPConnection | Select-Object -First 5"
                  style={{ flex: 1, padding: '10px', background: 'rgba(18, 11, 36, 0.8)', border: '1px solid var(--border-color)', borderRadius: '6px', color: '#fff', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
                />
                <button 
                  className="btn"
                  onClick={() => {
                    if (customCmd.trim()) {
                      handleCommand('POWERSHELL_EXEC', { script: customCmd });
                      setCustomCmd('');
                    }
                  }}
                >
                  Execute
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Command Audit Trail */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px' }}>Command Audit Trail</h3>
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '420px' }}>
            {commands.length === 0 ? (
              <div style={{ color: 'var(--text-secondary)', textAlign: 'center', marginTop: '30px' }}>No response commands issued to this agent.</div>
            ) : (
              <table className="data-table" style={{ fontSize: '0.85rem' }}>
                <thead>
                  <tr>
                    <th>Command</th>
                    <th>Status</th>
                    <th>Issued At</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {commands.map(cmd => (
                    <tr key={cmd.id}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{cmd.command_type}</td>
                      <td>
                        <span className={`badge ${cmd.status === 'success' ? 'badge-low' : cmd.status === 'failed' ? 'badge-critical' : 'badge-medium'}`}>
                          {cmd.status}
                        </span>
                      </td>
                      <td>{new Date(cmd.issued_at).toLocaleTimeString()}</td>
                      <td>
                        {cmd.result_json ? (
                          <pre style={{ margin: 0, fontSize: '0.75rem', background: 'rgba(0,0,0,0.3)', padding: '4px', borderRadius: '4px', maxWidth: '150px', overflowX: 'auto', border: '1px solid var(--border-color)' }}>
                            {JSON.stringify(cmd.result_json)}
                          </pre>
                        ) : (
                          '-'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Real Listening Ports Section */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h3 style={{ color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Radio size={18} /> Real Listening Ports ({listeningPorts.length})
          </h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Live host sockets reported by EDR Agent</span>
        </div>
        {listeningPorts.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '20px' }}>No listening ports reported yet.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ fontSize: '0.85rem' }}>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Local Address</th>
                  <th>Port</th>
                  <th>PID</th>
                  <th>Process Name</th>
                  <th>Path</th>
                  <th>User</th>
                  <th>State</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {listeningPorts.map(port => (
                  <tr key={`${port.protocol}-${port.local_address}-${port.local_port}-${port.pid}`}>
                    <td style={{ fontWeight: 600, color: 'var(--accent-purple-light)' }}>{port.protocol}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{port.local_address}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{port.local_port}</td>
                    <td>{port.pid}</td>
                    <td style={{ fontWeight: 600 }}>{port.process_name}</td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={port.process_path}>
                      {port.process_path || '-'}
                    </td>
                    <td>{port.username || '-'}</td>
                    <td>
                      <span className="badge badge-low">{port.state}</span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {new Date(port.last_seen_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Real Network Events Section */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h3 style={{ color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Activity size={18} /> Real Network Connection Events ({networkEvents.length})
          </h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Real-time connection opened / closed telemetry</span>
        </div>
        {networkEvents.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '20px' }}>No network connection events recorded.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ fontSize: '0.85rem' }}>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Direction</th>
                  <th>Source IP:Port</th>
                  <th>Destination IP:Port</th>
                  <th>Protocol</th>
                  <th>Process</th>
                  <th>PID</th>
                  <th>User</th>
                </tr>
              </thead>
              <tbody>
                {networkEvents.map(ev => {
                  const isOutbound = ev.direction === 'outbound';
                  return (
                    <tr key={ev.id}>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <span className={`badge ${ev.event_type.includes('OPEN') ? 'badge-low' : 'badge-medium'}`}>
                          {ev.event_type}
                        </span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.8rem' }}>
                          {isOutbound ? <ArrowUpRight size={14} color="var(--accent-yellow)" /> : <ArrowDownLeft size={14} color="var(--accent-green)" />}
                          {ev.direction}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.local_address}:{ev.local_port}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{ev.remote_address ? `${ev.remote_address}:${ev.remote_port}` : '-'}</td>
                      <td>{ev.protocol}</td>
                      <td style={{ fontWeight: 600 }}>{ev.process_name || '-'}</td>
                      <td>{ev.pid || '-'}</td>
                      <td>{ev.username || '-'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Confirmation Modal for Detail Page Isolation */}
      {confirmIsolateOpen && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(5, 2, 18, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '440px', padding: '24px', border: '1px solid var(--border-glow)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <AlertTriangle color="var(--accent-red)" size={24} />
              <h3 style={{ margin: 0, fontSize: '1.15rem' }}>Confirm Host Network Isolation</h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '20px' }}>
              This will instruct the agent on "{agent.hostname}" to activate native Windows Firewall isolation rules, blocking all inbound and outbound traffic.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmIsolateOpen(false)}>Cancel</button>
              <button 
                className="btn" 
                style={{ background: 'var(--accent-red)', color: '#fff', borderColor: 'rgba(239,68,68,0.6)' }}
                onClick={() => {
                  setConfirmIsolateOpen(false);
                  handleCommand('DISABLE_NETWORK');
                }}
              >
                Execute Isolation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Detail Page Unisolation */}
      {confirmUnisolateOpen && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(5, 2, 18, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '440px', padding: '24px', border: '1px solid var(--border-glow)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <CheckCircle2 color="var(--accent-green)" size={24} />
              <h3 style={{ margin: 0, fontSize: '1.15rem' }}>Confirm Network Restoration</h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '20px' }}>
              This will remove the EDR isolation firewall rules on "{agent.hostname}" and restore normal network communication.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmUnisolateOpen(false)}>Cancel</button>
              <button 
                className="btn" 
                style={{ background: 'var(--accent-green)', color: '#fff', borderColor: 'rgba(34,197,94,0.6)' }}
                onClick={() => {
                  setConfirmUnisolateOpen(false);
                  handleCommand('ENABLE_NETWORK');
                }}
              >
                Restore Network
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

