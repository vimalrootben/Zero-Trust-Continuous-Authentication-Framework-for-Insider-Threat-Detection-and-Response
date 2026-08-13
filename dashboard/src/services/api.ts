// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface Agent {
  id: string;
  hostname: string;
  ip_address: string | null;
  status: string;
  current_risk_score: number;
  last_seen_at: string | null;
  department: string | null;
  os_version: string | null;
  agent_version: string | null;
}

export interface Alert {
  id: string;
  agent_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assigned_to?: string;
  created_at: string;
}

export interface TimelineEvent {
  id: string;
  agent_id?: string;
  incident_id?: string;
  event_source: string;
  description: string;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  actor_type: string;
  actor_id?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  details?: any;
  ip_address?: string;
  timestamp: string;
}

export interface ThreatIntelIndicator {
  id: string;
  ioc_type: string;
  value: string;
  source?: string;
  confidence?: number;
  first_seen?: string;
  last_seen?: string;
  tags?: string[];
}

export interface Rule {
  id: string;
  rule_code: string;
  name: string;
  category: string;
  severity: string;
  mitre_technique_id?: string;
  score_impact: number;
  condition: any;
  enabled?: boolean;
  description?: string;
}

export interface Policy {
  id: string;
  policy_code?: string;
  name: string;
  description?: string;
  category?: string;
  severity?: string;
  risk_impact?: number;
  mitre_technique_id?: string;
  action: string;
  condition: any;
  priority: number;
  enabled: boolean;
  mode?: string;
  trigger_count?: number;
  last_triggered_at?: string;
  created_at: string;
}

export interface MitreTactic {
  tactic_id: string;
  name: string;
  description: string;
}

export interface MitreTechnique {
  technique_id: string;
  tactic_id: string;
  name: string;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
}

export interface TelemetryEvent {
  id: string;
  agent_id: string;
  event_type: string;
  process_name?: string;
  file_path?: string;
  network_dest_ip?: string;
  timestamp: string;
  raw_data?: any;
}

// ─────────────────────────────────────────────────────────────────────────────
// API Client
// ─────────────────────────────────────────────────────────────────────────────

class ApiClient {
  private token: string | null = typeof localStorage !== 'undefined' ? localStorage.getItem('access_token') : null;
  private baseUrl = 'http://localhost:8000';

  setToken(token: string) {
    this.token = token;
    if (typeof localStorage !== 'undefined') localStorage.setItem('access_token', token);
  }

  logout() {
    this.token = null;
    if (typeof localStorage !== 'undefined') localStorage.removeItem('access_token');
  }

  getToken(): string | null {
    return this.token;
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const res = await fetch(url, { ...options, headers });
    if (!res.ok) {
      if (res.status === 401) this.logout();
      const errBody = await res.json().catch(() => ({}));
      const msg = errBody?.error?.message || errBody?.detail || `HTTP ${res.status}: ${res.statusText}`;
      throw new Error(msg);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  // ── Auth ──────────────────────────────────────────────────
  async login(username: string, password: string): Promise<{ access_token: string }> {
    const data = await this.request('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (data?.access_token) this.setToken(data.access_token);
    return data;
  }

  // ── System Info (for Settings page) ───────────────────────
  async getManagerInfo(): Promise<any> {
    try {
      const [health, agents] = await Promise.all([
        fetch(`${this.baseUrl}/healthz`).then(r => r.json()),
        this.getAgents(),
      ]);
      return { health, agentCount: agents.length, managerUrl: this.baseUrl };
    } catch {
      return { health: { status: 'unknown' }, agentCount: 0, managerUrl: this.baseUrl };
    }
  }

  // ── Agents ────────────────────────────────────────────────
  async getAgents(): Promise<Agent[]> {
    try {
      const data = await this.request('/api/v1/agents');
      if (Array.isArray(data)) return data;
      if (data?.items) return data.items;
      return [];
    } catch { return []; }
  }

  async getAgent(id: string): Promise<Agent | null> {
    try { return await this.request(`/api/v1/agents/${id}`); }
    catch { return null; }
  }

  // ── Alerts ────────────────────────────────────────────────
  async getAlerts(filters?: { status?: string; severity?: string }): Promise<{ items: Alert[]; total: number }> {
    try {
      let url = '/api/v1/alerts';
      const params: string[] = [];
      if (filters?.status) params.push(`status=${filters.status}`);
      if (filters?.severity) params.push(`severity=${filters.severity}`);
      if (params.length) url += '?' + params.join('&');
      const data = await this.request(url);
      if (data?.items) return { items: data.items, total: data.total ?? data.items.length };
      if (Array.isArray(data)) return { items: data, total: data.length };
      return { items: [], total: 0 };
    } catch { return { items: [], total: 0 }; }
  }

  // ── Telemetry ─────────────────────────────────────────────
  async getTelemetry(agentId?: string, collectorType?: string, limit = 100): Promise<TelemetryEvent[]> {
    try {
      // Backend accepts: agent_id, collector_type, event_type, page, page_size
      const params = new URLSearchParams();
      params.set('page_size', String(Math.min(limit, 200)));
      if (agentId) params.set('agent_id', agentId);
      if (collectorType) params.set('collector_type', collectorType);
      const data = await this.request(`/api/v1/telemetry?${params.toString()}`);
      if (Array.isArray(data)) return data;
      if (data?.items) return data.items;
      return [];
    } catch { return []; }
  }

  // ── Timeline ──────────────────────────────────────────────
  async getTimeline(agentId: string): Promise<TimelineEvent[]> {
    try {
      const data = await this.request(`/api/v1/agents/${agentId}/timeline`);
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  // ── Audit Logs ────────────────────────────────────────────
  async getAuditLogs(search?: string): Promise<{ items: AuditLog[]; total: number }> {
    try {
      // Backend accepts: actor_id, action, actor_type, target_type, target_id, from, to, page, page_size
      // 'search' is not a backend param — match against action or actor_type
      let url = '/api/v1/audit-logs?page_size=100';
      if (search) url += `&action=${encodeURIComponent(search)}`;
      const data = await this.request(url);
      if (data?.items) return { items: data.items, total: data.total ?? data.items.length };
      if (Array.isArray(data)) return { items: data, total: data.length };
      return { items: [], total: 0 };
    } catch { return { items: [], total: 0 }; }
  }

  // ── Threat Intel ──────────────────────────────────────────
  async getThreatIntel(): Promise<ThreatIntelIndicator[]> {
    try {
      const data = await this.request('/api/v1/threat-intel/indicators');
      if (data?.data) return data.data;
      if (Array.isArray(data)) return data;
      return [];
    } catch { return []; }
  }

  async syncThreatIntel(): Promise<any> {
    return this.request('/api/v1/threat-intel/feeds/sync', { method: 'POST' });
  }

  // ── Rules ─────────────────────────────────────────────────
  async getRules(): Promise<Rule[]> {
    try {
      const data = await this.request('/api/v1/rules');
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  async createRule(rule: {
    rule_code: string; name: string; category: string; severity: string;
    mitre_technique_id?: string; description?: string; score_impact?: number;
    condition?: any; enabled?: boolean;
  }): Promise<Rule> {
    return this.request('/api/v1/rules', {
      method: 'POST',
      body: JSON.stringify({
        ...rule,
        condition: rule.condition ?? { operator: 'and', conditions: [] },
        score_impact: rule.score_impact ?? 20,
        enabled: rule.enabled ?? true,
      }),
    });
  }

  async toggleRule(ruleId: string): Promise<Rule> {
    return this.request(`/api/v1/rules/${ruleId}/toggle`, { method: 'PUT' });
  }

  // ── Policies ──────────────────────────────────────────────
  async getPolicies(): Promise<Policy[]> {
    try {
      const data = await this.request('/api/v1/policies');
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  async createPolicy(policy: {
    name: string; description?: string; action: string;
    condition_field: string; condition_operator: string; condition_value: string;
    priority?: number; enabled?: boolean;
  }): Promise<Policy> {
    return this.request('/api/v1/policies', {
      method: 'POST',
      body: JSON.stringify(policy),
    });
  }

  async togglePolicy(policyId: string): Promise<Policy> {
    return this.request(`/api/v1/policies/${policyId}/toggle`, { method: 'PUT' });
  }

  // ── MITRE ATT&CK ──────────────────────────────────────────
  async getMitreTactics(): Promise<MitreTactic[]> {
    try {
      const data = await this.request('/api/v1/mitre/tactics');
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  async getMitreTechniques(): Promise<MitreTechnique[]> {
    try {
      const data = await this.request('/api/v1/mitre/techniques');
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  // ── Users / Roles ─────────────────────────────────────────
  async getRoles(): Promise<Role[]> {
    try {
      const data = await this.request('/api/v1/roles');
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  // ── Commands ──────────────────────────────────────────────
  async issueCommand(agentId: string, commandType: string, params: any = {}): Promise<any> {
    return this.request('/api/v1/commands', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, command_type: commandType, params }),
    });
  }

  async getCommands(agentId: string): Promise<any[]> {
    try {
      const data = await this.request(`/api/v1/commands/agent/${agentId}`);
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }
}

export const api = new ApiClient();
