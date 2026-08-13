import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Agent } from '../services/api';
import { useNavigate, useParams } from 'react-router-dom';
import { Monitor, ShieldAlert, Terminal, Power } from 'lucide-react';

export const EndpointsPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.getAgents().then(data => {
      setAgents(data);
      setLoading(false);
    });
  }, []);

  const handleQuickIsolate = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await api.issueCommand(id, 'DISABLE_NETWORK');
      alert(`Network isolation command dispatched to agent ${id}`);
      api.getAgents().then(setAgents);
    } catch (err: any) {
      alert(`Error: ${err.message}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Endpoints (Managed EDR Agents)</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time host inventory and zero-trust containment status</p>
        </div>
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
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading active agents...</td></tr>
            ) : agents.length === 0 ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No registered agents found.</td></tr>
            ) : (
              agents.map(agent => (
                <tr key={agent.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/endpoints/${agent.id}`)}>
                  <td style={{ fontWeight: 600, color: 'var(--accent-purple-light)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Monitor size={16} />
                    {agent.hostname}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{agent.ip_address || '127.0.0.1'}</td>
                  <td>
                    <span className={`badge ${agent.status === 'active' ? 'badge-low' : agent.status === 'isolated' ? 'badge-critical' : 'badge-medium'}`}>
                      {agent.status}
                    </span>
                  </td>
                  <td style={{ fontWeight: 700, color: agent.current_risk_score > 70 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {agent.current_risk_score} <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>/ 100</span>
                  </td>
                  <td style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{agent.os_version || 'Windows 11 Enterprise'}</td>
                  <td>
                    <button 
                      className="btn btn-secondary" 
                      style={{ padding: '4px 12px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px' }} 
                      onClick={(e) => handleQuickIsolate(e, agent.id)}
                      disabled={agent.status === 'isolated'}
                    >
                      <Power size={12} /> Isolate
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const EndpointDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [commands, setCommands] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [customCmd, setCustomCmd] = useState('');

  const fetchDetails = () => {
    if (!id) return;
    setLoading(true);
    Promise.all([api.getAgent(id), api.getCommands(id)])
      .then(([agentData, cmdData]) => {
        setAgent(agentData);
        setCommands(cmdData);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchDetails();
  }, [id]);

  const handleCommand = async (commandType: string, params: any = {}) => {
    if (!id) return;
    try {
      await api.issueCommand(id, commandType, params);
      alert(`Issued response command: ${commandType}`);
      api.getCommands(id).then(setCommands);
    } catch (err: any) {
      alert(`Failed to issue command: ${err.message}`);
    }
  };

  if (loading) {
    return <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '50px' }}>Loading endpoint telemetry details...</div>;
  }

  if (!agent) {
    return <div style={{ color: 'var(--accent-red)', padding: '20px' }}>Endpoint agent not found in database.</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Endpoint Control: {agent.hostname}</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time host profile and active mitigation control center</p>
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
              <div style={{ color: 'var(--text-secondary)' }}>Status:</div>
              <div>
                <span className={`badge ${agent.status === 'active' ? 'badge-low' : agent.status === 'isolated' ? 'badge-critical' : 'badge-medium'}`}>
                  {agent.status}
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
              <ShieldAlert size={18} /> Remote Response Controls
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
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
              <button 
                className="btn" 
                style={{ background: 'var(--accent-red)', color: '#fff', borderColor: 'rgba(239,68,68,0.5)' }}
                onClick={() => handleCommand('DISABLE_NETWORK')}
                disabled={agent.status === 'isolated'}
              >
                Full Network Isolation
              </button>
            </div>

            <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-color)', paddingTop: '15px' }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                <Terminal size={14} color="var(--accent-purple-light)" /> Execute Remote PowerShell Command
              </label>
              <div style={{ display: 'flex', gap: '10px' }}>
                <input 
                  type="text" 
                  value={customCmd}
                  onChange={e => setCustomCmd(e.target.value)}
                  placeholder="Get-Process | Select-Object -First 5"
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

        {/* Right Column */}
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
    </div>
  );
};
