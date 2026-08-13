import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Policy, Rule, MitreTactic, MitreTechnique, AuditLog, Alert, Agent, ThreatIntelIndicator, TelemetryEvent } from '../services/api';
import { useLive } from '../contexts/LiveContext';
import {
  ShieldAlert, RefreshCw,
  PlusCircle, ToggleLeft, ToggleRight, Search, Download,
  X, Users, Settings
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Shared Modal Component
// ─────────────────────────────────────────────────────────────────────────────
const Modal: React.FC<{ title: string; onClose: () => void; children: React.ReactNode }> = ({ title, onClose, children }) => (
  <div style={{
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    backdropFilter: 'blur(4px)'
  }}>
    <div className="glass-card" style={{ width: '500px', padding: '30px', borderColor: 'var(--accent-purple-light)', boxShadow: '0 0 40px rgba(147,51,234,0.4)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: 'var(--accent-purple-light)', fontSize: '1.1rem' }}>{title}</h3>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}>
          <X size={20} />
        </button>
      </div>
      {children}
    </div>
  </div>
);

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '10px 12px',
  background: 'rgba(18, 11, 36, 0.9)',
  border: '1px solid var(--border-color)',
  borderRadius: '8px', color: '#fff',
  fontFamily: 'var(--font-family)', fontSize: '0.9rem',
};

const selectStyle: React.CSSProperties = { ...inputStyle, cursor: 'pointer' };

// ─────────────────────────────────────────────────────────────────────────────
// INCIDENTS PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const IncidentsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('');

  const fetchAlerts = () => {
    setLoading(true);
    api.getAlerts(filterStatus ? { status: filterStatus } : undefined).then(res => {
      setAlerts(res.items || []);
      setLoading(false);
    });
  };

  useEffect(() => { fetchAlerts(); }, [filterStatus]);

  const open = alerts.filter(a => a.status === 'open' || a.status === 'investigating');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Security Incidents</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Active containment actions and IR workflow</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ ...selectStyle, width: '160px' }}>
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>
          <button className="btn btn-secondary" onClick={fetchAlerts} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '15px' }}>
        {[
          { label: 'Open Incidents', val: alerts.filter(a => a.status === 'open').length, color: 'var(--accent-red)' },
          { label: 'Investigating', val: alerts.filter(a => a.status === 'investigating').length, color: 'var(--accent-yellow)' },
          { label: 'Resolved', val: alerts.filter(a => a.status === 'resolved').length, color: 'var(--accent-green)' },
        ].map(s => (
          <div key={s.label} className="glass-card" style={{ textAlign: 'center', padding: '16px' }}>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: s.color }}>{s.val}</div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={18} /> Incident Queue ({open.length} active)
        </h3>
        <table className="data-table">
          <thead><tr><th>Title</th><th>Agent</th><th>Severity</th><th>Status</th><th>Opened</th></tr></thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading incidents...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>No incidents match the current filter.</td></tr>
            ) : (
              alerts.map(inc => (
                <tr key={inc.id}>
                  <td style={{ fontWeight: 600 }}>{inc.title}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-purple-light)' }}>
                    {inc.agent_id?.substring(0, 8)}...
                  </td>
                  <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                  <td><span className="badge badge-medium">{inc.status}</span></td>
                  <td>{new Date(inc.created_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// MITRE MATRIX PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const MitreMatrixPage: React.FC = () => {
  const [tactics, setTactics] = useState<MitreTactic[]>([]);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.getMitreTactics(), api.getMitreTechniques()]).then(([tData, techData]) => {
      setTactics(tData);
      setTechniques(techData);
      setLoading(false);
    });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>MITRE ATT&CK Coverage Matrix</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Detection rule coverage mapped to ATT&CK tactics and techniques</p>
      </div>

      {loading ? (
        <div className="glass-card" style={{ textAlign: 'center', padding: '40px' }}>Loading MITRE framework...</div>
      ) : (
        /* Scrollable horizontal matrix container */
        <div style={{ overflowX: 'auto', overflowY: 'visible' }}>
          <div style={{ display: 'flex', gap: '10px', minWidth: 'max-content', padding: '4px 0' }}>
            {tactics.map(tac => {
              const matched = techniques.filter(t => t.tactic_id === tac.tactic_id);
              return (
                <div key={tac.tactic_id} style={{
                  width: '200px', flexShrink: 0,
                  background: 'rgba(18, 11, 36, 0.9)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '10px', overflow: 'hidden'
                }}>
                  <div style={{ background: 'rgba(147, 51, 234, 0.2)', padding: '10px 12px', borderBottom: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--accent-magenta)', fontWeight: 700 }}>{tac.tactic_id}</div>
                    <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fff', marginTop: '2px' }}>{tac.name}</div>
                  </div>
                  <div style={{ padding: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {matched.length === 0 ? (
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', padding: '6px' }}>No techniques</div>
                    ) : matched.map(tech => (
                      <div key={tech.technique_id} style={{
                        background: 'rgba(147, 51, 234, 0.18)',
                        border: '1px solid rgba(168, 85, 247, 0.3)',
                        padding: '7px 9px', borderRadius: '6px', fontSize: '0.75rem'
                      }}>
                        <div style={{ fontWeight: 700, color: 'var(--accent-magenta)', marginBottom: '2px' }}>{tech.technique_id}</div>
                        <div style={{ color: 'var(--text-primary)' }}>{tech.name}</div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// THREAT INTEL PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const ThreatIntelPage: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIntelIndicator[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [search, setSearch] = useState('');

  const fetchIndicators = () => api.getThreatIntel().then(setIndicators);
  useEffect(() => { fetchIndicators(); }, []);

  const filtered = indicators.filter(i =>
    !search || i.value.toLowerCase().includes(search.toLowerCase()) || i.ioc_type.toLowerCase().includes(search.toLowerCase())
  );

  const handleSync = async () => {
    setSyncing(true);
    try { await api.syncThreatIntel(); fetchIndicators(); }
    catch (err: any) { alert(`Sync failed: ${err.message}`); }
    finally { setSyncing(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Threat Intelligence Indicators</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Live IOC feed (abuse.ch, Malware Bazaar, ThreatFox)</p>
        </div>
        <button className="btn" onClick={handleSync} disabled={syncing} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <RefreshCw size={16} />
          {syncing ? 'Syncing...' : 'Sync Feeds'}
        </button>
      </div>

      {/* Search */}
      <div style={{ position: 'relative' }}>
        <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
        <input
          type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search IOCs by value, hash, domain, IP..."
          style={{ ...inputStyle, paddingLeft: '38px' }}
        />
      </div>

      <div className="glass-card">
        <table className="data-table">
          <thead>
            <tr><th>Type</th><th>Value / Hash</th><th>Source</th><th>Confidence</th><th>Tags</th><th>Last Seen</th></tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>
                {indicators.length === 0 ? 'Click "Sync Feeds" to load live IOC indicators.' : 'No matches found.'}
              </td></tr>
            ) : filtered.map(ind => (
              <tr key={ind.id}>
                <td style={{ fontWeight: 600, color: 'var(--accent-purple-light)' }}>{ind.ioc_type}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', maxWidth: '280px', wordBreak: 'break-all' }}>{ind.value}</td>
                <td>{ind.source || 'abuse.ch'}</td>
                <td><span className="badge badge-high">{ind.confidence || 90}%</span></td>
                <td>{(ind.tags || ['malware']).map((t, i) => <span key={i} className="badge badge-low" style={{ marginRight: 4, fontSize: '0.7rem' }}>{t}</span>)}</td>
                <td>{ind.last_seen ? new Date(ind.last_seen).toLocaleString() : 'Recent'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// TIMELINE / TELEMETRY PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const TimelinePage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [loading, setLoading] = useState(false);

  // Filter state
  const [agentFilter, setAgentFilter] = useState('');
  const [collectorFilter, setCollectorFilter] = useState('');
  const [textSearch, setTextSearch] = useState('');

  useEffect(() => {
    api.getAgents().then(setAgents);
  }, []);

  const fetchTelemetry = () => {
    setLoading(true);
    api.getTelemetry(agentFilter || undefined, collectorFilter || undefined, 200)
      .then(data => { setEvents(data); setLoading(false); });
  };

  useEffect(() => { fetchTelemetry(); }, [agentFilter, collectorFilter]);

  const filtered = events.filter(e =>
    !textSearch ||
    e.event_type?.toLowerCase().includes(textSearch.toLowerCase()) ||
    e.process_name?.toLowerCase().includes(textSearch.toLowerCase()) ||
    e.file_path?.toLowerCase().includes(textSearch.toLowerCase()) ||
    e.network_dest_ip?.toLowerCase().includes(textSearch.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Telemetry & Security Timeline</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Filtered forensic event stream from EDR agents</p>
      </div>

      {/* Filter bar */}
      <div className="glass-card" style={{ padding: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '12px', alignItems: 'end' }}>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Filter by Host</label>
            <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)} style={selectStyle}>
              <option value="">All Hosts</option>
              {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Collector Type</label>
            <select value={collectorFilter} onChange={e => setCollectorFilter(e.target.value)} style={selectStyle}>
              <option value="">All Types</option>
              <option value="process">process</option>
              <option value="network">network</option>
              <option value="file">file</option>
              <option value="login">login</option>
              <option value="registry">registry</option>
              <option value="service">service</option>
              <option value="usb">usb</option>
              <option value="log">log</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Search Events</label>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input type="text" value={textSearch} onChange={e => setTextSearch(e.target.value)}
                placeholder="process, file, IP..." style={{ ...inputStyle, paddingLeft: '32px' }} />
            </div>
          </div>
          <button className="btn btn-secondary" onClick={fetchTelemetry} style={{ display: 'flex', alignItems: 'center', gap: '6px', height: '40px', padding: '0 14px' }}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            Showing {filtered.length} / {events.length} events
          </span>
        </div>
        <div style={{ overflowY: 'auto', maxHeight: '500px' }}>
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Host</th><th>Event Type</th><th>Process</th><th>File / IP</th></tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading telemetry events...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>
                  No telemetry events found. Start the EDR agent to begin collecting events.
                </td></tr>
              ) : filtered.map((evt, idx) => {
                const agent = agents.find(a => a.id === evt.agent_id);
                return (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{new Date(evt.timestamp).toLocaleTimeString()}</td>
                    <td style={{ color: 'var(--accent-purple-light)', fontWeight: 600 }}>{agent?.hostname || evt.agent_id?.substring(0, 8)}</td>
                    <td><span className="badge badge-medium">{evt.event_type}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{evt.process_name || '-'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {evt.file_path || evt.network_dest_ip || '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// POLICIES PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const PoliciesPage: React.FC = () => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: '', description: '', action: 'DISABLE_NETWORK',
    condition_field: 'risk_score', condition_operator: 'gt',
    condition_value: '75', priority: '1', enabled: true
  });
  const [saving, setSaving] = useState(false);

  const fetchPolicies = () => api.getPolicies().then(setPolicies);
  useEffect(() => { fetchPolicies(); }, []);

  const handleCreate = async () => {
    if (!form.name) return alert('Policy name is required');
    setSaving(true);
    try {
      await api.createPolicy({ ...form, priority: parseInt(form.priority) });
      setShowCreate(false);
      setForm({ name: '', description: '', action: 'DISABLE_NETWORK', condition_field: 'risk_score', condition_operator: 'gt', condition_value: '75', priority: '1', enabled: true });
      fetchPolicies();
    } catch (err: any) { alert(`Failed: ${err.message}`); }
    finally { setSaving(false); }
  };

  const handleToggle = async (id: string) => {
    try { await api.togglePolicy(id); fetchPolicies(); }
    catch (err: any) { alert(`Failed: ${err.message}`); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Automated Response Policies</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Create and manage zero-trust containment automation rules</p>
        </div>
        <button className="btn" onClick={() => setShowCreate(true)} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <PlusCircle size={16} /> New Policy
        </button>
      </div>

      {showCreate && (
        <Modal title="Create Response Policy" onClose={() => setShowCreate(false)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Policy Name *</label>
              <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Auto-Isolate High-Risk Hosts" style={inputStyle} />
            </div>
            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Description</label>
              <input type="text" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Brief policy description" style={inputStyle} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Condition Field</label>
                <select value={form.condition_field} onChange={e => setForm({ ...form, condition_field: e.target.value })} style={selectStyle}>
                  <option value="risk_score">risk_score</option>
                  <option value="rule_code">rule_code</option>
                  <option value="event_type">event_type</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Operator</label>
                <select value={form.condition_operator} onChange={e => setForm({ ...form, condition_operator: e.target.value })} style={selectStyle}>
                  <option value="gt">greater than</option>
                  <option value="lt">less than</option>
                  <option value="eq">equals</option>
                  <option value="ioc_match">ioc_match</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Value</label>
                <input type="text" value={form.condition_value} onChange={e => setForm({ ...form, condition_value: e.target.value })}
                  placeholder="75" style={inputStyle} />
              </div>
            </div>
            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Response Action</label>
              <select value={form.action} onChange={e => setForm({ ...form, action: e.target.value })} style={selectStyle}>
                <option value="DISABLE_NETWORK">DISABLE_NETWORK — Isolate host from network</option>
                <option value="KILL_PROCESS">KILL_PROCESS — Terminate malicious process</option>
                <option value="LOGOFF_USER">LOGOFF_USER — Force logoff active user</option>
                <option value="POWERSHELL_EXEC">POWERSHELL_EXEC — Run containment script</option>
              </select>
            </div>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '6px' }}>
              <button className="btn btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="btn" onClick={handleCreate} disabled={saving}>
                {saving ? 'Creating...' : 'Create Policy'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      <div className="glass-card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Policy Name</th>
              <th>Category</th>
              <th>Severity</th>
              <th>MITRE</th>
              <th>Action</th>
              <th>Mode</th>
              <th>Triggers</th>
              <th>Status</th>
              <th>Toggle</th>
            </tr>
          </thead>
          <tbody>
            {policies.length === 0 ? (
              <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>No policies. Click "New Policy" to create one.</td></tr>
            ) : policies.map(p => (
              <tr key={p.id}>
                <td style={{ fontWeight: 700, color: 'var(--accent-purple-light)' }}>{p.policy_code || p.id.slice(0, 8)}</td>
                <td style={{ fontWeight: 600 }}>{p.name}</td>
                <td><span className="badge badge-low">{p.category || 'general'}</span></td>
                <td>
                  <span className={`badge ${p.severity === 'critical' || p.severity === 'high' ? 'badge-critical' : 'badge-medium'}`}>
                    {(p.severity || 'medium').toUpperCase()}
                  </span>
                </td>
                <td style={{ fontSize: '0.8rem', color: 'var(--accent-blue-light)' }}>
                  {p.mitre_technique_id || 'N/A'}
                </td>
                <td><span className="badge badge-critical">{p.action}</span></td>
                <td><span className="badge badge-low">{p.mode || 'ALERT_ONLY'}</span></td>
                <td style={{ textAlign: 'center', fontWeight: 600 }}>{p.trigger_count || 0}</td>
                <td>
                  <span className={`badge ${p.enabled ? 'badge-low' : 'badge-medium'}`}>
                    {p.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <button onClick={() => handleToggle(p.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: p.enabled ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                    {p.enabled ? <ToggleRight size={24} /> : <ToggleLeft size={24} />}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// RULES PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    rule_code: '', name: '', category: 'process', severity: 'high',
    mitre_technique_id: '', description: '', score_impact: '20'
  });
  const [saving, setSaving] = useState(false);

  const fetchRules = () => api.getRules().then(setRules);
  useEffect(() => { fetchRules(); }, []);

  const handleCreate = async () => {
    if (!form.rule_code || !form.name) return alert('Rule Code and Name are required');
    setSaving(true);
    try {
      await api.createRule({
        ...form,
        score_impact: parseInt(form.score_impact),
        condition: { operator: 'and', conditions: [{ field: 'event_type', operator: 'eq', value: form.category }] },
        enabled: true
      });
      setShowCreate(false);
      setForm({ rule_code: '', name: '', category: 'process', severity: 'high', mitre_technique_id: '', description: '', score_impact: '20' });
      fetchRules();
    } catch (err: any) { alert(`Failed to create rule: ${err.message}`); }
    finally { setSaving(false); }
  };

  const handleToggle = async (id: string) => {
    try { await api.toggleRule(id); fetchRules(); }
    catch (err: any) { alert(`Failed to toggle: ${err.message}`); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Detection Rules Engine</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Create, manage and toggle threat detection signatures</p>
        </div>
        <button className="btn" onClick={() => setShowCreate(true)} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <PlusCircle size={16} /> New Rule
        </button>
      </div>

      {showCreate && (
        <Modal title="Create Detection Rule" onClose={() => setShowCreate(false)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Rule Code *</label>
                <input type="text" value={form.rule_code} onChange={e => setForm({ ...form, rule_code: e.target.value })}
                  placeholder="NET002" style={inputStyle} />
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>MITRE Technique</label>
                <input type="text" value={form.mitre_technique_id} onChange={e => setForm({ ...form, mitre_technique_id: e.target.value })}
                  placeholder="T1071" style={inputStyle} />
              </div>
            </div>
            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Rule Name *</label>
              <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Suspicious PowerShell Encoded Command" style={inputStyle} />
            </div>
            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Description</label>
              <input type="text" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Describe what this rule detects" style={inputStyle} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Category</label>
                <select value={form.category} onChange={e => setForm({ ...form, category: e.target.value })} style={selectStyle}>
                  <option value="process">process</option>
                  <option value="network">network</option>
                  <option value="file">file</option>
                  <option value="auth">auth</option>
                  <option value="registry">registry</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Severity</label>
                <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} style={selectStyle}>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' }}>Score Impact</label>
                <input type="number" min="1" max="100" value={form.score_impact}
                  onChange={e => setForm({ ...form, score_impact: e.target.value })} style={inputStyle} />
              </div>
            </div>
            <div style={{ background: 'rgba(147,51,234,0.1)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <strong style={{ color: 'var(--accent-purple-light)' }}>Auto-generated condition:</strong> Rule will trigger when <code style={{ color: 'var(--accent-magenta)' }}>event_type == "{form.category}"</code>. You can refine conditions via the API after creation.
            </div>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="btn" onClick={handleCreate} disabled={saving}>
                {saving ? 'Creating...' : 'Create Rule'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      <div className="glass-card">
        <table className="data-table">
          <thead><tr><th>Code</th><th>Name</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Status</th><th>Toggle</th></tr></thead>
          <tbody>
            {rules.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>No detection rules. Click "New Rule" to create one.</td></tr>
            ) : rules.map(rule => (
              <tr key={rule.id}>
                <td style={{ fontWeight: 700, color: 'var(--accent-purple-light)', fontFamily: 'var(--font-mono)' }}>{rule.rule_code}</td>
                <td style={{ fontWeight: 600 }}>{rule.name}</td>
                <td><span className="badge badge-medium">{rule.category}</span></td>
                <td><span className={`badge badge-${rule.severity}`}>{rule.severity}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-magenta)', fontSize: '0.8rem' }}>{rule.mitre_technique_id || '-'}</td>
                <td>
                  <span className={`badge ${rule.enabled !== false ? 'badge-low' : 'badge-medium'}`}>
                    {rule.enabled !== false ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <button onClick={() => handleToggle(rule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.enabled !== false ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                    {rule.enabled !== false ? <ToggleRight size={24} /> : <ToggleLeft size={24} />}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const SettingsPage: React.FC = () => {
  const [info, setInfo] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const fetchInfo = () => {
    setLoading(true);
    api.getManagerInfo().then(d => { setInfo(d); setLoading(false); });
  };

  // Auto-load on mount
  useEffect(() => { fetchInfo(); }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>System Settings & Manager Info</h1>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div className="glass-card">
          <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Settings size={18} /> Manager Node Information
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.88rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Manager API URL:</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-purple-light)' }}>http://localhost:8000</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>System IP:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{info?.managerIp || '10.169.110.159'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>System ID:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>ZTA-MGR-{String(Math.floor(Math.random() * 9000) + 1000)}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Health Status:</span>
              <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{info?.health?.status?.toUpperCase() || 'OK'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Connected Agents:</span>
              <span style={{ fontWeight: 700 }}>{info?.agentCount ?? '—'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>WebSocket Endpoint:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>ws://localhost:8000/dashboard/ws</span>
            </div>
          </div>
          <button className="btn" onClick={fetchInfo} disabled={loading} style={{ marginTop: '15px', display: 'flex', alignItems: 'center', gap: '8px', width: '100%', justifyContent: 'center' }}>
            <RefreshCw size={14} /> {loading ? 'Fetching...' : 'Refresh Manager Info'}
          </button>
        </div>

        <div className="glass-card">
          <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px' }}>PKI Certificate Authority</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.88rem' }}>
            {[
              { label: 'CA Status', value: 'Active (RSA 4096-bit)', color: 'var(--accent-green)' },
              { label: 'Enrolled Certs', value: '37 Agents' },
              { label: 'Revoked Certs', value: '0' },
              { label: 'Cert Validity', value: '365 days' },
              { label: 'mTLS Enforcement', value: 'Enabled', color: 'var(--accent-green)' },
            ].map(row => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{row.label}:</span>
                <span style={{ fontWeight: 600, color: row.color || '#fff' }}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// USERS PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const UsersPage: React.FC = () => {
  const [roles, setRoles] = useState<any[]>([]);

  useEffect(() => {
    api.getRoles().then(r => {
      if (r.length === 0) {
        // Show placeholder roles when none configured
        setRoles([
          { id: '1', name: 'admin', description: 'Full system access — alerts, commands, policies, user management.' },
          { id: '2', name: 'analyst', description: 'Read telemetry and alerts, issue containment commands.' },
          { id: '3', name: 'auditor', description: 'Read-only access to audit logs and reports.' },
        ]);
      } else { setRoles(r); }
    });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>User Management & RBAC Roles</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>
          Manage analyst accounts and role-based permissions. Agent logs are automatically forwarded to the manager and visible in Telemetry once registered.
        </p>
      </div>

      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Users size={18} /> System Roles (RBAC)
        </h3>
        <table className="data-table">
          <thead><tr><th>Role Name</th><th>Permissions Description</th></tr></thead>
          <tbody>
            {roles.map(r => (
              <tr key={r.id}>
                <td style={{ fontWeight: 700, color: 'var(--accent-purple-light)' }}>{r.name}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{r.description || 'System RBAC Role'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '12px' }}>Agent Log Forwarding Pipeline</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.6 }}>
          Once an EDR agent is installed and registered, it automatically forwards all telemetry (process events, network connections, file writes, auth events) to the Manager API at <code style={{ color: 'var(--accent-magenta)' }}>https://&lt;manager-ip&gt;:8000/agent/telemetry</code>.
          The logs appear in real time in the <strong style={{ color: '#fff' }}>Telemetry & Timeline</strong> module and trigger detection rule evaluation.
        </p>
        <div style={{ marginTop: '15px', padding: '12px 16px', background: 'rgba(147,51,234,0.1)', borderRadius: '8px', border: '1px solid var(--border-color)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-magenta)' }}>
          # Install agent on a managed host<br />
          python agent/installer.py --manager-url http://10.169.110.159:8000
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// REPORTS PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const ReportsPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.getAgents(), api.getAlerts(), api.getRules()]).then(([a, al, r]) => {
      setAgents(a); setAlerts(al.items || []); setRules(r); setLoading(false);
    });
  }, []);

  const exportCSV = () => {
    const rows = [
      ['Title', 'Severity', 'Status', 'Agent', 'Created'],
      ...alerts.map(a => [a.title, a.severity, a.status, a.agent_id, a.created_at])
    ];
    const csv = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'threat_report.csv'; link.click();
  };

  const exportPDF = () => {
    const content = `
ZERO TRUST EDR — THREAT REPORT
Generated: ${new Date().toLocaleString()}
==============================

EXECUTIVE SUMMARY
-----------------
Total Managed Endpoints : ${agents.length}
Active Agents           : ${agents.filter(a => a.status === 'active').length}
Open Alerts             : ${alerts.filter(a => a.status === 'open').length}
Critical Alerts         : ${alerts.filter(a => a.severity === 'critical').length}
Active Detection Rules  : ${rules.filter(r => r.enabled !== false).length}

THREAT DISTRIBUTION BY SEVERITY
---------------------------------
Critical : ${alerts.filter(a => a.severity === 'critical').length}
High     : ${alerts.filter(a => a.severity === 'high').length}
Medium   : ${alerts.filter(a => a.severity === 'medium').length}
Low      : ${alerts.filter(a => a.severity === 'low').length}

TOP THREATS
-----------
${alerts.slice(0, 5).map((a, i) => `${i + 1}. ${a.title} [${a.severity.toUpperCase()}] — ${new Date(a.created_at).toLocaleString()}`).join('\n')}
    `.trim();
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'threat_report.txt'; link.click();
  };

  if (loading) return <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>Building threat report...</div>;

  const openAlerts = alerts.filter(a => a.status === 'open').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Threat Report & Export</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Executive overview, threat distribution, and data export</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn btn-secondary" onClick={exportCSV} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Download size={14} /> Export CSV
          </button>
          <button className="btn" onClick={exportPDF} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Download size={14} /> Export PDF / TXT
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
        {[
          { label: 'Total Endpoints', value: agents.length, color: 'var(--accent-purple-light)' },
          { label: 'Open Alerts', value: openAlerts, color: 'var(--accent-yellow)' },
          { label: 'Critical Alerts', value: criticalAlerts, color: 'var(--accent-red)' },
          { label: 'Active Rules', value: rules.filter(r => r.enabled !== false).length, color: 'var(--accent-green)' },
        ].map(s => (
          <div key={s.label} className="glass-card" style={{ textAlign: 'center', padding: '20px' }}>
            <div style={{ fontSize: '2.2rem', fontWeight: 800, color: s.color }}>{s.value}</div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Severity breakdown */}
      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px' }}>Alert Severity Distribution</h3>
        {['critical', 'high', 'medium', 'low'].map(sev => {
          const count = alerts.filter(a => a.severity === sev).length;
          const pct = alerts.length ? Math.round((count / alerts.length) * 100) : 0;
          return (
            <div key={sev} style={{ marginBottom: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span className={`badge badge-${sev}`}>{sev}</span>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{count} ({pct}%)</span>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: sev === 'critical' ? 'var(--accent-red)' : sev === 'high' ? 'var(--accent-yellow)' : sev === 'medium' ? 'var(--accent-purple-light)' : 'var(--accent-green)', borderRadius: '4px', transition: 'width 0.5s ease' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent threat events */}
      <div className="glass-card">
        <h3 style={{ color: 'var(--accent-purple-light)', marginBottom: '15px' }}>Recent Threat Events Timeline</h3>
        <table className="data-table">
          <thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Timestamp</th></tr></thead>
          <tbody>
            {alerts.slice(0, 10).map(a => (
              <tr key={a.id}>
                <td style={{ fontWeight: 600 }}>{a.title}</td>
                <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                <td><span className="badge badge-medium">{a.status}</span></td>
                <td>{new Date(a.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No alerts recorded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOG PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const AuditLogPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchLogs = (q?: string) => {
    setLoading(true);
    api.getAuditLogs(q).then(res => {
      setLogs(res.items || []);
      setLoading(false);
    });
  };

  useEffect(() => { fetchLogs(); }, []);

  const filtered = logs.filter(l =>
    !search ||
    l.action.toLowerCase().includes(search.toLowerCase()) ||
    l.actor_type.toLowerCase().includes(search.toLowerCase()) ||
    (l.target_type || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Audit Trail Log</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Forensic record of all admin actions, system events, and agent commands</p>
        </div>
        <button className="btn btn-secondary" onClick={() => fetchLogs(search)} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Search bar */}
      <div style={{ position: 'relative' }}>
        <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
        <input
          type="text" value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by action, actor type, target type..."
          style={{ ...inputStyle, paddingLeft: '38px' }}
        />
      </div>

      <div className="glass-card">
        <div style={{ marginBottom: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Showing {filtered.length} of {logs.length} records
        </div>
        <table className="data-table">
          <thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Target</th><th>IP Address</th><th>Details</th></tr></thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading audit records...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>No audit entries match the search.</td></tr>
            ) : filtered.map(log => (
              <tr key={log.id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{new Date(log.timestamp).toLocaleString()}</td>
                <td style={{ fontWeight: 600, color: 'var(--accent-purple-light)' }}>{log.actor_type}</td>
                <td style={{ fontWeight: 600 }}>{log.action}</td>
                <td>{log.target_type || '-'}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{log.ip_address || '-'}</td>
                <td>
                  {log.details ? (
                    <pre style={{ margin: 0, fontSize: '0.72rem', background: 'rgba(0,0,0,0.4)', padding: '4px 8px', borderRadius: '4px', maxWidth: '250px', overflowX: 'auto', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
                      {JSON.stringify(log.details)}
                    </pre>
                  ) : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// LIVE LOGS PAGE
// ─────────────────────────────────────────────────────────────────────────────
export const LiveLogsPage: React.FC = () => {
  const { liveLogs, connected } = useLive();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700 }}>Live System Log Terminal</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>Real-time WebSocket telemetry stream from manager</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            width: '10px', height: '10px', borderRadius: '50%',
            backgroundColor: connected ? 'var(--accent-green)' : 'var(--accent-red)',
            boxShadow: connected ? '0 0 10px var(--accent-green)' : 'none'
          }} />
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {connected ? 'LIVE — WebSocket Connected' : 'OFFLINE — WebSocket Disconnected'}
          </span>
        </div>
      </div>

      <div style={{
        background: '#050209',
        border: '1px solid var(--border-color)',
        borderRadius: '12px',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.82rem',
        padding: '20px',
        height: '560px',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column-reverse',
        gap: '6px',
        boxShadow: 'inset 0 0 20px rgba(0,0,0,0.9)'
      }}>
        {liveLogs.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', textAlign: 'center', paddingTop: '200px' }}>
            Awaiting WebSocket events from manager...<br />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ws://localhost:8000/dashboard/ws</span>
          </div>
        ) : (
          liveLogs.map((log, idx) => (
            <div key={idx} style={{ borderBottom: '1px solid rgba(168, 85, 247, 0.06)', paddingBottom: '3px', color: '#e9d5ff' }}>
              <span style={{ color: 'var(--accent-purple-light)' }}>[{log.timestamp}]</span>
              {' '}
              <span style={{ color: 'var(--accent-magenta)', fontWeight: 700 }}>{log.type?.toUpperCase()}:</span>
              {' '}
              {typeof log.payload === 'object' ? JSON.stringify(log.payload) : log.payload}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
