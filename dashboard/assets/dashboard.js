'use strict';

const $ = id => document.getElementById(id);
const state = {
  events: [], agents: [], incidents: [], rules: [], policies: [],
  timeline: [], auditLogs: [], services: [], overview: {},
  schema: null,
  view: 'dashboard', rulesPoliciesSubtab: 'rules',
  page: 0, rows: [], loading: false, ws: null,
  role: null, adminToken: sessionStorage.getItem('ztaAccessToken'), permissions: [],
  ruleBuilderTree: null,
  policyBuilderTree: null,
  activeDeleteTarget: null // { type: 'rule' | 'policy', id: string, name: string }
};

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.adminToken) headers.set('Authorization', `Bearer ${state.adminToken}`);
  const response = await fetch(url, {...options, headers});
  if (response.status === 401 && !url.endsWith('/auth/login')) lockDashboard();
  return response;
}

function lockDashboard(message = '') {
  sessionStorage.removeItem('ztaAccessToken');
  state.adminToken = null; state.role = null; state.permissions = [];
  if (state.ws) { state.ws.onclose = null; state.ws.close(); state.ws = null; }
  document.body.classList.add('auth-pending');
  $('app-shell').hidden = true;
  $('login-page').hidden = false;
  $('login-error').hidden = !message;
  text('login-error', message);
  setTimeout(() => $('login-username').focus(), 0);
}

function unlockDashboard(identity) {
  state.role = identity.role;
  state.permissions = identity.permissions || [];
  $('user-role').value = state.role;
  $('create-user').hidden = !state.permissions.includes('users:manage');
  $('change-password').hidden = Boolean(identity.legacy);
  $('sign-out').hidden = false;
  $('login-page').hidden = true;
  $('app-shell').hidden = false;
  document.body.classList.remove('auth-pending');
}

const colors = ['#00749b', '#429fc0', '#007ac5', '#34cbb5', '#008779', '#f34d3f', '#e67e22', '#9b59b6'];
const escapeHTML = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const text = (id, value) => { const el = $(id); if (el) el.textContent = value; };
const fmt = value => Number(value || 0).toLocaleString();
function date(value) { return new Date(value && !/(Z|[+-]\d\d:\d\d)$/.test(value) ? `${value}Z` : value); }

function showToast(message, type = 'info') {
  const toast = $('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast ${type}`;
  toast.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.hidden = true; }, 4000);
}

function unpack(event) {
  let raw = {};
  try { raw = JSON.parse(event.raw_event_json || '{}'); } catch (_) {}
  return {
    ...event,
    raw,
    level: raw.rule?.level ?? null,
    description: raw.rule?.description || event.description || event.event_type,
    groups: raw.rule?.groups || []
  };
}

// ----------------------------------------------------------------------
// SCHEMA & DATA FETCHING
// ----------------------------------------------------------------------
async function fetchSchema() {
  if (state.schema) return state.schema;
  try {
    const res = await apiFetch('/api/zta/schema');
    if (res.ok) {
      state.schema = await res.json();
      populateSchemaDropdowns();
    }
  } catch (err) {
    console.warn('Schema fetch error:', err);
  }
  return state.schema;
}

function populateSchemaDropdowns() {
  if (!state.schema) return;
  const categories = state.schema.categories || [];
  const severities = state.schema.severities || ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const tactics = state.schema.mitre_tactics || [];
  const actions = state.schema.response_actions || [];
  const modes = state.schema.policy_modes || [];

  // Filter dropdowns
  const fillSelect = (selectId, items, hasEmpty = true, emptyLabel = 'All') => {
    const el = $(selectId);
    if (!el) return;
    const current = el.value;
    el.innerHTML = hasEmpty ? `<option value="">${emptyLabel}</option>` : '';
    items.forEach(it => {
      const val = typeof it === 'string' ? it : it.id || it.action || it.mode || it.name;
      const lbl = typeof it === 'string' ? it : it.label || it.name || val;
      el.innerHTML += `<option value="${escapeHTML(val)}">${escapeHTML(lbl)}</option>`;
    });
    if (current) el.value = current;
  };

  fillSelect('filter-rule-category', categories, true, 'All Categories');
  fillSelect('filter-policy-category', categories, true, 'All Categories');
  fillSelect('rb-category', categories, false);
  fillSelect('rb-severity', severities, false);
  fillSelect('rb-mitre-tactic', tactics, true, 'None');
  fillSelect('pb-category', categories, false);
  fillSelect('pb-severity', severities, false);
  fillSelect('pb-mode', modes, false);
  fillSelect('pb-action', actions, false);
}

// ----------------------------------------------------------------------
// VISUAL CONDITION BUILDER
// ----------------------------------------------------------------------
let _nodeIdCounter = 1;

function createLeafCondition(field = 'process.name', op = 'contains', value = '') {
  return { id: `node_${_nodeIdCounter++}`, type: 'condition', field, op, value };
}

function createGroupCondition(combinator = 'all', children = null) {
  return {
    id: `node_${_nodeIdCounter++}`,
    type: 'group',
    combinator,
    children: children || [createLeafCondition()]
  };
}

function conditionToTree(cond) {
  if (!cond || typeof cond !== 'object') {
    return createGroupCondition('all', [createLeafCondition()]);
  }
  if (cond.all && Array.isArray(cond.all)) {
    return {
      id: `node_${_nodeIdCounter++}`,
      type: 'group',
      combinator: 'all',
      children: cond.all.map(conditionToTree)
    };
  }
  if (cond.any && Array.isArray(cond.any)) {
    return {
      id: `node_${_nodeIdCounter++}`,
      type: 'group',
      combinator: 'any',
      children: cond.any.map(conditionToTree)
    };
  }
  if (cond.not) {
    return {
      id: `node_${_nodeIdCounter++}`,
      type: 'group',
      combinator: 'not',
      children: [conditionToTree(cond.not)]
    };
  }
  if (cond.field) {
    let val = cond.value !== undefined ? cond.value : '';
    if (typeof val === 'object') {
      try { val = JSON.stringify(val); } catch (_) {}
    }
    return {
      id: `node_${_nodeIdCounter++}`,
      type: 'condition',
      field: cond.field,
      op: cond.op || 'eq',
      value: String(val)
    };
  }
  return createGroupCondition('all', [createLeafCondition()]);
}

function treeToCondition(node) {
  if (!node) return {};
  if (node.type === 'condition') {
    let val = node.value;
    if (['gt', 'gte', 'lt', 'lte'].includes(node.op)) {
      const num = Number(val);
      val = isNaN(num) ? val : num;
    } else if (['in', 'not_in'].includes(node.op)) {
      try {
        const parsed = JSON.parse(val);
        if (Array.isArray(parsed)) val = parsed;
        else val = val.split(',').map(s => s.trim());
      } catch (_) {
        val = val.split(',').map(s => s.trim());
      }
    }
    const res = { field: node.field, op: node.op };
    if (!['exists', 'not_exists'].includes(node.op)) {
      res.value = val;
    }
    return res;
  }
  if (node.type === 'group') {
    const validChildren = (node.children || []).map(treeToCondition).filter(c => Object.keys(c).length > 0);
    if (node.combinator === 'not') {
      return { not: validChildren[0] || {} };
    }
    return { [node.combinator]: validChildren };
  }
  return {};
}

function renderConditionNode(node, container, onChange, isRoot = false) {
  const fields = state.schema?.supported_fields || [
    { path: 'process.name', label: 'process.name' },
    { path: 'process.command_line', label: 'process.command_line' },
    { path: 'user.name', label: 'user.name' },
    { path: 'destination_ip', label: 'destination_ip' },
    { path: 'risk_score', label: 'risk_score' },
    { path: 'trust_score', label: 'trust_score' }
  ];
  const operators = state.schema?.supported_operators || [
    { op: 'eq', label: 'equals (==)' },
    { op: 'ne', label: 'not equals (!=)' },
    { op: 'contains', label: 'contains' },
    { op: 'contains_icase', label: 'contains (case-insensitive)' },
    { op: 'gt', label: 'greater than (>)' },
    { op: 'lt', label: 'less than (<)' },
    { op: 'in', label: 'in (list)' },
    { op: 'exists', label: 'exists' },
    { op: 'regex', label: 'matches regex' }
  ];

  if (node.type === 'group') {
    const groupEl = document.createElement('div');
    groupEl.className = 'condition-group-node';
    groupEl.dataset.nodeId = node.id;

    const header = document.createElement('div');
    header.className = 'condition-group-header';

    const combSelect = document.createElement('select');
    combSelect.className = 'combinator-select';
    combSelect.innerHTML = `
      <option value="all" ${node.combinator === 'all' ? 'selected' : ''}>ALL (AND)</option>
      <option value="any" ${node.combinator === 'any' ? 'selected' : ''}>ANY (OR)</option>
      <option value="not" ${node.combinator === 'not' ? 'selected' : ''}>NOT</option>
    `;
    combSelect.onchange = () => {
      node.combinator = combSelect.value;
      if (node.combinator === 'not' && node.children.length > 1) {
        node.children = [node.children[0]];
      }
      onChange();
    };
    header.appendChild(combSelect);

    const addCondBtn = document.createElement('button');
    addCondBtn.type = 'button';
    addCondBtn.className = 'btn-sm outline';
    addCondBtn.textContent = '+ Condition';
    addCondBtn.onclick = () => {
      node.children.push(createLeafCondition());
      onChange();
    };
    header.appendChild(addCondBtn);

    const addGrpBtn = document.createElement('button');
    addGrpBtn.type = 'button';
    addGrpBtn.className = 'btn-sm outline';
    addGrpBtn.textContent = '+ Sub-Group';
    addGrpBtn.onclick = () => {
      node.children.push(createGroupCondition('all'));
      onChange();
    };
    header.appendChild(addGrpBtn);

    if (!isRoot) {
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn-remove-cond';
      removeBtn.textContent = '✕';
      removeBtn.title = 'Remove Group';
      removeBtn.onclick = () => {
        container._removeCallback(node.id);
      };
      header.appendChild(removeBtn);
    }

    groupEl.appendChild(header);

    const childrenContainer = document.createElement('div');
    childrenContainer.className = 'condition-tree-container';
    childrenContainer._removeCallback = childId => {
      node.children = node.children.filter(c => c.id !== childId);
      if (node.children.length === 0) {
        node.children.push(createLeafCondition());
      }
      onChange();
    };

    node.children.forEach(child => {
      renderConditionNode(child, childrenContainer, onChange, false);
    });

    groupEl.appendChild(childrenContainer);
    container.appendChild(groupEl);
  } else {
    // Leaf Condition Row
    const rowEl = document.createElement('div');
    rowEl.className = 'condition-row-node';
    rowEl.dataset.nodeId = node.id;

    // Field Select
    const fieldSelect = document.createElement('select');
    fieldSelect.className = 'cond-field-select';
    let fieldMatched = false;
    fields.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.path;
      opt.textContent = f.path;
      if (f.path === node.field) { opt.selected = true; fieldMatched = true; }
      fieldSelect.appendChild(opt);
    });
    if (!fieldMatched && node.field) {
      const opt = document.createElement('option');
      opt.value = node.field;
      opt.textContent = `${node.field} (custom)`;
      opt.selected = true;
      fieldSelect.appendChild(opt);
    }
    fieldSelect.onchange = () => { node.field = fieldSelect.value; onChange(); };
    rowEl.appendChild(fieldSelect);

    // Operator Select
    const opSelect = document.createElement('select');
    opSelect.className = 'cond-op-select';
    operators.forEach(op => {
      const opt = document.createElement('option');
      opt.value = op.op;
      opt.textContent = op.label;
      if (op.op === node.op) opt.selected = true;
      opSelect.appendChild(opt);
    });
    rowEl.appendChild(opSelect);

    // Value Input
    const valInput = document.createElement('input');
    valInput.className = 'cond-val-input';
    valInput.type = 'text';
    valInput.placeholder = 'Value (e.g. powershell.exe)';
    valInput.value = node.value || '';
    valInput.disabled = ['exists', 'not_exists'].includes(node.op);
    valInput.oninput = () => { node.value = valInput.value; };
    rowEl.appendChild(valInput);

    opSelect.onchange = () => {
      node.op = opSelect.value;
      valInput.disabled = ['exists', 'not_exists'].includes(node.op);
      if (valInput.disabled) valInput.value = '';
      onChange();
    };

    // Remove Button
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn-remove-cond';
    removeBtn.textContent = '✕';
    removeBtn.title = 'Remove Condition';
    removeBtn.onclick = () => {
      container._removeCallback(node.id);
    };
    rowEl.appendChild(removeBtn);

    container.appendChild(rowEl);
  }
}

function mountConditionBuilder(rootNode, containerId, statusId) {
  const container = $(containerId);
  if (!container) return;
  container.innerHTML = '';
  const onChange = () => {
    mountConditionBuilder(rootNode, containerId, statusId);
    if (statusId) {
      const stat = $(statusId);
      if (stat) stat.textContent = '';
    }
  };
  renderConditionNode(rootNode, container, onChange, true);
}

// ----------------------------------------------------------------------
// RULE BUILDER & MODALS
// ----------------------------------------------------------------------
function openCreateRuleModal() {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Creating rules requires ADMIN role.', 'error');
    return;
  }
  text('rule-builder-title', 'Create Detection Rule');
  $('rb-editing-id').value = '';
  $('rb-code').value = `RULE-${String(state.rules.length + 1).padStart(4, '0')}`;
  $('rb-code').disabled = false;
  $('rb-name').value = '';
  $('rb-desc').value = '';
  $('rb-category').value = 'Execution';
  $('rb-severity').value = 'HIGH';
  $('rb-risk-delta').value = '25';
  $('rb-enabled').checked = true;
  $('rb-mitre-tactic').value = 'Execution';
  $('rb-mitre-technique').value = '';
  $('rb-validate-status').textContent = '';
  $('rb-dryrun-box').hidden = true;

  state.ruleBuilderTree = createGroupCondition('all', [
    createLeafCondition('process.name', 'contains', 'powershell.exe')
  ]);
  mountConditionBuilder(state.ruleBuilderTree, 'rb-condition-tree-root', 'rb-validate-status');
  $('rule-builder-modal').showModal();
}

function openEditRuleModal(rule) {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Editing rules requires ADMIN role.', 'error');
    return;
  }
  text('rule-builder-title', `Edit Detection Rule: ${rule.code || rule.rule_id}`);
  $('rb-editing-id').value = rule.rule_id;
  $('rb-code').value = rule.code || rule.rule_id;
  $('rb-code').disabled = true;
  $('rb-name').value = rule.name || '';
  $('rb-desc').value = rule.description || '';
  $('rb-category').value = rule.category || 'General';
  $('rb-severity').value = rule.severity || 'MEDIUM';
  $('rb-risk-delta').value = rule.risk_delta !== undefined ? rule.risk_delta : 25;
  $('rb-enabled').checked = Boolean(rule.enabled);
  $('rb-mitre-tactic').value = rule.mitre_tactic || '';
  $('rb-mitre-technique').value = rule.mitre_technique_id || '';
  $('rb-validate-status').textContent = '';
  $('rb-dryrun-box').hidden = true;

  state.ruleBuilderTree = conditionToTree(rule.condition);
  mountConditionBuilder(state.ruleBuilderTree, 'rb-condition-tree-root', 'rb-validate-status');
  $('rule-builder-modal').showModal();
}

async function validateRuleCondition() {
  const cond = treeToCondition(state.ruleBuilderTree);
  const statusEl = $('rb-validate-status');
  statusEl.textContent = 'Validating…';
  statusEl.className = 'validate-status';

  try {
    const res = await apiFetch('/api/zta/rules/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ condition: cond })
    });
    const data = await res.json();
    if (res.ok && data.valid) {
      statusEl.textContent = '✓ Logic syntax is valid and ready';
      statusEl.className = 'validate-status valid';
    } else {
      statusEl.textContent = `✕ Validation Error: ${data.error || 'Invalid condition'}`;
      statusEl.className = 'validate-status invalid';
    }
  } catch (err) {
    statusEl.textContent = `✕ Error: ${err.message}`;
    statusEl.className = 'validate-status invalid';
  }
}

async function runRuleDryRun() {
  const cond = treeToCondition(state.ruleBuilderTree);
  const sampleText = $('rb-sample-event').value.trim();
  const resEl = $('rb-dryrun-result');
  let eventPayload = {};
  try {
    eventPayload = sampleText ? JSON.parse(sampleText) : {};
  } catch (err) {
    resEl.hidden = false;
    resEl.textContent = `Invalid JSON in sample event: ${err.message}`;
    return;
  }

  try {
    const res = await apiFetch('/api/zta/rules/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ condition: cond, event: eventPayload })
    });
    const data = await res.json();
    resEl.hidden = false;
    resEl.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    resEl.hidden = false;
    resEl.textContent = `Dry run error: ${err.message}`;
  }
}

async function saveRule(e) {
  e.preventDefault();
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Requires ADMIN role.', 'error');
    return;
  }
  const editingId = $('rb-editing-id').value;
  const cond = treeToCondition(state.ruleBuilderTree);
  const payload = {
    code: $('rb-code').value.trim(),
    name: $('rb-name').value.trim(),
    description: $('rb-desc').value.trim(),
    category: $('rb-category').value,
    severity: $('rb-severity').value,
    risk_delta: Number($('rb-risk-delta').value) || 0,
    enabled: $('rb-enabled').checked ? 1 : 0,
    mitre_tactic: $('rb-mitre-tactic').value || null,
    mitre_technique_id: $('rb-mitre-technique').value.trim() || null,
    condition: cond
  };

  try {
    const url = editingId ? `/api/zta/rules/${editingId}` : '/api/zta/rules';
    const method = editingId ? 'PUT' : 'POST';
    const res = await apiFetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': state.role
      },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);

    showToast(`Rule ${payload.code} saved successfully. Engine reloaded.`, 'success');
    $('rule-builder-modal').close();
    await refresh();
  } catch (err) {
    showToast(`Failed to save rule: ${err.message}`, 'error');
  }
}

async function toggleRule(ruleId, enabled) {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Toggling rules requires ADMIN role.', 'error');
    await refresh();
    return;
  }
  try {
    const res = await apiFetch(`/api/zta/rules/${ruleId}/toggle`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': state.role
      },
      body: JSON.stringify({ enabled: enabled ? 1 : 0 })
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);
    showToast(`Rule ${ruleId} is now ${enabled ? 'ENABLED' : 'DISABLED'}.`, 'success');
    await refresh();
  } catch (err) {
    showToast(`Could not toggle rule: ${err.message}`, 'error');
    await refresh();
  }
}

function openRuleDetails(rule) {
  text('rd-title', rule.name);
  text('rd-code-badge', rule.code || rule.rule_id);
  const statusBadge = $('rd-status-badge');
  statusBadge.textContent = rule.enabled ? 'ENABLED' : 'DISABLED';
  statusBadge.className = `badge ${rule.enabled ? 'ACTIVE' : 'DISABLED'}`;

  text('rd-category', rule.category);
  text('rd-severity', rule.severity);
  text('rd-risk-delta', `+${rule.risk_delta}`);
  text('rd-total-matches', fmt(rule.total_matches || 0));
  text('rd-desc', rule.description || 'No description provided.');
  text('rd-mitre-tactic', rule.mitre_tactic || 'None');
  text('rd-mitre-technique', rule.mitre_technique_id || 'None');

  $('rd-condition-display').textContent = JSON.stringify({condition:rule.condition, last_evaluated:rule.last_evaluated, last_matched:rule.last_matched, evaluations:rule.evaluation_history}, null, 2);

  // Linked Policies
  const linkedPolicies = rule.linked_policies || [];
  const linkedList = $('rd-linked-policies');
  if (linkedPolicies.length) {
    linkedList.innerHTML = linkedPolicies.map(lp => `
      <div class="linked-item-row">
        <div>
          <strong>${escapeHTML(lp.code || lp.policy_id)}</strong> - ${escapeHTML(lp.name)}
          <span class="badge ${lp.severity}">${lp.severity}</span>
          <span class="badge ${lp.mode}">${lp.mode}</span>
          <span class="badge">${lp.action}</span>
        </div>
        <button class="btn-sm outline" data-view-linked-policy="${lp.policy_id}">View Policy</button>
      </div>
    `).join('');
    linkedList.querySelectorAll('[data-view-linked-policy]').forEach(btn => {
      btn.onclick = () => {
        $('rule-details-modal').close();
        const pol = state.policies.find(p => p.policy_id === btn.dataset.viewLinkedPolicy);
        if (pol) openPolicyDetails(pol);
      };
    });
  } else {
    linkedList.innerHTML = '<span class="subtle">No adaptive policies are currently linked to this rule.</span>';
  }

  // Matches and Evaluation Trace
  const recentList = $('rd-recent-matches');
  const matchingAlerts = state.incidents.filter(inc => {
    try {
      const meta = JSON.parse(inc.context_metadata || '{}');
      return meta.rule_id === rule.rule_id || meta.rule_code === rule.code;
    } catch (_) { return false; }
  });

  if (matchingAlerts.length) {
    recentList.innerHTML = matchingAlerts.slice(0, 5).map(inc => `
      <div class="linked-item-row">
        <div>
          <b>${date(inc.created_at).toLocaleString()}</b> | Agent: ${escapeHTML(inc.agent_name || inc.agent_id)}
          <div class="subtle">${escapeHTML(inc.trigger_reason)}</div>
        </div>
        <span class="badge ${inc.severity}">${inc.severity}</span>
      </div>
    `).join('');
  } else {
    recentList.innerHTML = '<span class="subtle">No recorded telemetry matches in current database history.</span>';
  }

  $('rd-btn-edit').onclick = () => {
    $('rule-details-modal').close();
    openEditRuleModal(rule);
  };

  $('rule-details-modal').showModal();
}

// ----------------------------------------------------------------------
// POLICY BUILDER & MODALS
// ----------------------------------------------------------------------
function openCreatePolicyModal() {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Creating policies requires ADMIN role.', 'error');
    return;
  }
  text('policy-builder-title', 'Create Adaptive Policy');
  $('pb-editing-id').value = '';
  $('pb-code').value = `POL-${String(state.policies.length + 1).padStart(3, '0')}`;
  $('pb-code').disabled = false;
  $('pb-name').value = '';
  $('pb-desc').value = '';
  $('pb-category').value = 'General';
  $('pb-severity').value = 'HIGH';
  $('pb-mode').value = 'ENFORCE';
  $('pb-enabled').checked = true;
  $('pb-action').value = 'MONITOR';
  updatePolicyActionHint();

  $('pb-min-risk').value = '85';
  $('pb-max-risk').value = '100';
  $('pb-allow-offline').checked = false;

  // Populate linked rules dropdown
  const ruleSelect = $('pb-linked-rule');
  ruleSelect.innerHTML = '<option value="">-- None (Trigger Purely on Risk Threshold) --</option>';
  state.rules.forEach(r => {
    ruleSelect.innerHTML += `<option value="${r.rule_id}">[${escapeHTML(r.code || r.rule_id)}] ${escapeHTML(r.name)}</option>`;
  });

  state.policyBuilderTree = createGroupCondition('all', []);
  mountConditionBuilder(state.policyBuilderTree, 'pb-condition-tree-root', 'pb-validate-status');
  $('policy-builder-modal').showModal();
}

function openEditPolicyModal(policy) {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Editing policies requires ADMIN role.', 'error');
    return;
  }
  text('policy-builder-title', `Edit Adaptive Policy: ${policy.code || policy.policy_id}`);
  $('pb-editing-id').value = policy.policy_id;
  $('pb-code').value = policy.code || policy.policy_id;
  $('pb-code').disabled = true;
  $('pb-name').value = policy.name || '';
  $('pb-desc').value = policy.description || '';
  $('pb-category').value = policy.category || 'General';
  $('pb-severity').value = policy.severity || 'HIGH';
  $('pb-mode').value = policy.mode || 'ENFORCE';
  $('pb-enabled').checked = Boolean(policy.enabled);
  $('pb-action').value = policy.action || 'MONITOR';
  updatePolicyActionHint();

  $('pb-min-risk').value = policy.min_risk !== undefined ? policy.min_risk : 85;
  $('pb-max-risk').value = policy.max_risk !== undefined ? policy.max_risk : 100;
  $('pb-allow-offline').checked = Boolean(policy.allow_offline);

  const ruleSelect = $('pb-linked-rule');
  ruleSelect.innerHTML = '<option value="">-- None (Trigger Purely on Risk Threshold) --</option>';
  state.rules.forEach(r => {
    const isSelected = r.rule_id === policy.rule_id ? 'selected' : '';
    ruleSelect.innerHTML += `<option value="${r.rule_id}" ${isSelected}>[${escapeHTML(r.code || r.rule_id)}] ${escapeHTML(r.name)}</option>`;
  });

  state.policyBuilderTree = conditionToTree(policy.condition);
  mountConditionBuilder(state.policyBuilderTree, 'pb-condition-tree-root', 'pb-validate-status');
  $('policy-builder-modal').showModal();
}

function updatePolicyActionHint() {
  const action = $('pb-action').value;
  const hintEl = $('pb-action-hint');
  const hints = {
    MONITOR: 'Passive telemetry recording; does not dispatch containment commands.',
    ALERT: 'Generates real-time incident alert for SOC dashboard review.',
    NOTIFY_SOC: 'Escalates incident directly to security analysts.',
    LOGOUT_USER: 'Terminates active interactive session on endpoint agent.',
    KILL_PROCESS: 'Terminates suspicious malicious process tree on endpoint.',
    ISOLATE_ENDPOINT: 'Quarantines endpoint network stack except for ZTA Manager communication.'
  };
  hintEl.textContent = hints[action] || '';
}

async function validatePolicyLogic() {
  const statusEl = $('pb-validate-status');
  statusEl.textContent = 'Validating…';
  statusEl.className = 'validate-status';

  const cond = state.policyBuilderTree?.children?.length ? treeToCondition(state.policyBuilderTree) : null;
  const payload = {
    policy_id: $('pb-editing-id').value || 'validate-temp',
    name: $('pb-name').value,
    action: $('pb-action').value,
    min_risk: Number($('pb-min-risk').value),
    max_risk: Number($('pb-max-risk').value),
    mode: $('pb-mode').value,
    condition: cond
  };

  try {
    const res = await apiFetch('/api/zta/policies/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy: payload })
    });
    const data = await res.json();
    if (res.ok && data.valid) {
      statusEl.textContent = '✓ Policy logic is valid';
      statusEl.className = 'validate-status valid';
    } else {
      statusEl.textContent = `✕ Validation Error: ${data.error || 'Invalid policy'}`;
      statusEl.className = 'validate-status invalid';
    }
  } catch (err) {
    statusEl.textContent = `✕ Error: ${err.message}`;
    statusEl.className = 'validate-status invalid';
  }
}

async function savePolicy(e) {
  e.preventDefault();
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Requires ADMIN role.', 'error');
    return;
  }
  const editingId = $('pb-editing-id').value;
  const cond = state.policyBuilderTree?.children?.length ? treeToCondition(state.policyBuilderTree) : null;
  const payload = {
    code: $('pb-code').value.trim(),
    name: $('pb-name').value.trim(),
    description: $('pb-desc').value.trim(),
    category: $('pb-category').value,
    severity: $('pb-severity').value,
    mode: $('pb-mode').value,
    action: $('pb-action').value,
    rule_id: $('pb-linked-rule').value || null,
    min_risk: Number($('pb-min-risk').value) || 0,
    max_risk: Number($('pb-max-risk').value) || 100,
    allow_offline: $('pb-allow-offline').checked ? 1 : 0,
    enabled: $('pb-enabled').checked ? 1 : 0,
    condition: cond
  };

  try {
    const url = editingId ? `/api/zta/policies/${editingId}` : '/api/zta/policies';
    const method = editingId ? 'PUT' : 'POST';
    const res = await apiFetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': state.role
      },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);

    showToast(`Policy ${payload.code} saved successfully. Engine reloaded.`, 'success');
    $('policy-builder-modal').close();
    await refresh();
  } catch (err) {
    showToast(`Failed to save policy: ${err.message}`, 'error');
  }
}

async function togglePolicy(policyId, enabled) {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Toggling policies requires ADMIN role.', 'error');
    await refresh();
    return;
  }
  try {
    const res = await apiFetch(`/api/zta/policies/${policyId}/toggle`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': state.role
      },
      body: JSON.stringify({ enabled: enabled ? 1 : 0 })
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);
    showToast(`Policy ${policyId} is now ${enabled ? 'ACTIVE' : 'DISABLED'}.`, 'success');
    await refresh();
  } catch (err) {
    showToast(`Could not toggle policy: ${err.message}`, 'error');
    await refresh();
  }
}

function openPolicyDetails(policy) {
  text('pd-title', policy.name);
  text('pd-code-badge', policy.code || policy.policy_id);
  const statusBadge = $('pd-status-badge');
  statusBadge.textContent = policy.enabled ? 'ACTIVE' : 'DISABLED';
  statusBadge.className = `badge ${policy.enabled ? 'ACTIVE' : 'DISABLED'}`;

  text('pd-mode', policy.mode || 'UNKNOWN');
  text('pd-action', policy.action);
  text('pd-risk-range', `[${policy.min_risk} – ${policy.max_risk}]`);
  text('pd-total-triggers', fmt(policy.total_triggers || 0));
  text('pd-desc', policy.description || 'No description provided.');

  // Linked Rule Card
  const ruleCard = $('pd-linked-rule-box');
  if (policy.rule_id) {
    const linkedRule = state.rules.find(r => r.rule_id === policy.rule_id);
    ruleCard.innerHTML = `
      <div>
        <strong>Linked Rule: ${escapeHTML(policy.rule_id)}</strong>
        <div>${linkedRule ? escapeHTML(linkedRule.name) : 'Detection Rule'}</div>
        ${linkedRule ? `<span class="badge ${linkedRule.severity}">${linkedRule.severity}</span>` : ''}
      </div>
      <button class="btn-sm" id="pd-view-linked-rule">View Linked Rule ↗</button>
    `;
    const btn = $('pd-view-linked-rule');
    if (btn && linkedRule) {
      btn.onclick = () => {
        $('policy-details-modal').close();
        openRuleDetails(linkedRule);
      };
    }
  } else {
    ruleCard.innerHTML = `
      <div>
        <strong>Rule Linking: None</strong>
        <div class="subtle">This policy triggers purely based on Endpoint Risk Range [${policy.min_risk} - ${policy.max_risk}].</div>
      </div>
    `;
  }

  // Extra condition
  if (policy.condition || policy.evaluations?.length) {
    $('pd-condition-section').hidden = false;
    $('pd-condition-display').textContent = JSON.stringify({condition:policy.condition, evaluations:policy.evaluations}, null, 2);
  } else {
    $('pd-condition-section').hidden = true;
  }

  // Trigger history from incidents
  const triggerList = $('pd-recent-triggers');
  const matchingTriggers = state.incidents.filter(inc => {
    return inc.policy_action === policy.action || (inc.action_taken && inc.action_taken.includes(policy.action));
  });

  if (matchingTriggers.length) {
    triggerList.innerHTML = matchingTriggers.slice(0, 5).map(inc => `
      <div class="linked-item-row">
        <div>
          <b>${date(inc.created_at).toLocaleString()}</b> | Agent: ${escapeHTML(inc.agent_name || inc.agent_id)}
          <div class="subtle">Response Action: ${escapeHTML(inc.action_taken || policy.action)} (${escapeHTML(inc.response_status || 'COMPLETED')})</div>
        </div>
        <span class="badge ${inc.severity}">${inc.severity}</span>
      </div>
    `).join('');
  } else {
    triggerList.innerHTML = '<span class="subtle">No trigger events recorded yet for this adaptive policy.</span>';
  }

  $('pd-btn-edit').onclick = () => {
    $('policy-details-modal').close();
    openEditPolicyModal(policy);
  };

  $('policy-details-modal').showModal();
}

// ----------------------------------------------------------------------
// SAFE DELETION MODAL WITH IMPACT WARNINGS
// ----------------------------------------------------------------------
function openDeleteModal(type, item) {
  if (state.role !== 'ADMIN') {
    showToast('Permission Denied: Deletion requires ADMIN role.', 'error');
    return;
  }
  state.activeDeleteTarget = {
    type,
    id: type === 'rule' ? item.rule_id : item.policy_id,
    name: item.name || item.code || item.rule_id || item.policy_id,
    item
  };

  const list = $('del-impact-list');
  list.innerHTML = '';

  if (type === 'rule') {
    text('del-message', `Are you sure you want to permanently delete Detection Rule: ${item.code || item.rule_id} (${item.name})?`);
    const matches = item.total_matches || 0;
    const linkedCount = (item.linked_policies || []).length;
    list.innerHTML += `<li><b>Historical Telemetry Matches:</b> ${matches} recorded</li>`;
    if (linkedCount > 0) {
      list.innerHTML += `<li style="color:#b91c1c;font-weight:600;">⚠️ <b>Linked Policies Dependency:</b> ${linkedCount} active adaptive policy is linked to this rule. Deleting this rule will unlink it from the policy!</li>`;
    } else {
      list.innerHTML += `<li><b>Linked Policies:</b> 0 policies linked</li>`;
    }
  } else {
    text('del-message', `Are you sure you want to permanently delete Adaptive Policy: ${item.code || item.policy_id} (${item.name})?`);
    const triggers = item.total_triggers || 0;
    list.innerHTML += `<li><b>Historical Policy Triggers:</b> ${triggers} recorded</li>`;
    if (item.rule_id) {
      list.innerHTML += `<li><b>Linked Detection Rule:</b> ${item.rule_id} (rule will remain intact)</li>`;
    }
  }

  $('delete-confirm-modal').showModal();
}

async function confirmDelete() {
  if (!state.activeDeleteTarget) return;
  const { type, id, name } = state.activeDeleteTarget;
  try {
    const ep = type === 'rule' ? `/api/zta/rules/${id}` : `/api/zta/policies/${id}`;
    const res = await apiFetch(ep, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': state.role
      }
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);

    showToast(`Successfully deleted ${type}: ${name}. Historical records preserved.`, 'success');
    $('delete-confirm-modal').close();
    state.activeDeleteTarget = null;
    await refresh();
  } catch (err) {
    showToast(`Deletion failed: ${err.message}`, 'error');
  }
}

// ----------------------------------------------------------------------
// FORENSIC DETAILS MODAL
// ----------------------------------------------------------------------
async function showForensicDetails(row) {
  try {
    if (row.incident_id) {
      const response = await apiFetch(`/api/zta/incidents/${encodeURIComponent(row.incident_id)}`);
      if (!response.ok) throw new Error('Could not load alert evidence');
      row = (await response.json()).incident;
    } else if (row.id && !row.event_id) {
      const response = await apiFetch(`/api/zta/agents/${encodeURIComponent(row.id)}`);
      if (response.ok) {
        const agentData = await response.json();
        if (agentData.agent) row = agentData.agent;
      }
    }
    text('detail-title', row.incident_id ? 'Alert Forensic Chain' : (row.id ? `Endpoint Details: ${row.name || row.id}` : 'Recorded Backend Evidence'));
    text('detail-body', JSON.stringify(row, null, 2));
    const chain = $('forensic-chain-container');
    chain.hidden = !row.incident_id;
    if (row.incident_id) {
      const stages = [
        ['DETECTION', row.detection], ['RULE EVALUATION', row.rule_evaluations],
        ['RULE MATCH', row.rule_matches], ['RISK', row.risk_history],
        ['POLICY EVALUATION', row.policy_evaluations], ['COMMAND / AGENT RESULT', row.commands],
        ['AUDIT', row.audit], ['EXECUTION SOURCE', {source:row.execution_source, synced_at:row.synced_at, is_demo:Boolean(row.is_demo)}]
      ];
      $('forensic-pipeline').innerHTML = stages.map(([name, evidence]) =>
        `<div class="pipeline-step"><span class="step-badge">${escapeHTML(name)}</span><div class="step-content"><pre>${escapeHTML(JSON.stringify(evidence ?? null, null, 2))}</pre></div></div>`).join('');
    }
    $('details').showModal();
  } catch (error) { showToast(error.message, 'error'); }
}

// ----------------------------------------------------------------------
// FILTERING & CHARTS
// ----------------------------------------------------------------------
function filteredEvents() {
  const query = $('search').value.toLowerCase().trim();
  const severity = $('severity').value;
  const period = $('period').value;
  const now = Date.now();
  const start = period === 'all' ? -Infinity : period === 'custom' ? new Date($('from').value).getTime() : now - Number(period) * 3600000;
  const end = period === 'custom' ? new Date($('to').value).getTime() : now;

  return state.events.filter(e => {
    const ts = date(e.timestamp).getTime();
    return ts >= start && ts <= end &&
      (!severity || e.severity === severity) &&
      (!query || [e.agent_name, e.agent_id, e.description, e.mitre_tactic, e.mitre_technique_id, e.wazuh_rule_id, e.severity].join(' ').toLowerCase().includes(query));
  });
}

function legend(entries) {
  return `<ul class="legend">${entries.map(([name], i) => `<li><span class="dot" style="background:${colors[i % colors.length]}"></span>${escapeHTML(name)}</li>`).join('')}</ul>`;
}

function charts(events) {
  if (!events.length) {
    $('evolution').innerHTML = '<div class="chart-empty"><strong>No alerts in this time range</strong>Adjust filters or send real endpoint telemetry to ZTA Manager.</div>';
    $('tactics').innerHTML = '<div class="chart-empty"><strong>No MITRE tactics to display</strong>Tactics appear when incoming alerts match MITRE mappings.</div>';
    return;
  }
  const counts = new Map();
  events.forEach(e => counts.set(e.agent_name, (counts.get(e.agent_name) || 0) + 1));
  const agents = [...counts].sort((a,b) => b[1]-a[1]).slice(0,5);
  const times = events.map(e => date(e.timestamp).getTime());
  const start = Math.floor(Math.min(...times)/1800000)*1800000;
  const interval = Math.max(1800000, Math.ceil((Math.max(...times)-start+1)/30/1800000)*1800000);
  const bins = Array.from({length: Math.max(1,Math.ceil((Math.max(...times)-start+1)/interval))}, () => Array(agents.length).fill(0));
  events.forEach(e => {
    const index = agents.findIndex(([name]) => name === e.agent_name);
    if (index >= 0) bins[Math.floor((date(e.timestamp).getTime()-start)/interval)][index]++;
  });
  const max = Math.ceil(Math.max(1,...bins.map(bin => bin.reduce((a,b)=>a+b,0)))/4)*4;
  const width = 650, height = 215, plot = 565, bar = plot/bins.length;
  let svg = `<svg viewBox="0 0 ${width} 265" role="img" aria-label="Alert counts by agent over time">`;
  for (let i=0; i<=4; i++) {
    const y = height-i*height/4;
    svg += `<line x1="50" x2="625" y1="${y}" y2="${y}" stroke="#e2e8f0"/><text x="42" y="${y+4}" text-anchor="end" fill="#64748b" font-size="11">${Math.round(max*i/4)}</text>`;
  }
  bins.forEach((bin, index) => {
    let y = height;
    bin.forEach((count, a) => {
      const h = count/max*height;
      y -= h;
      svg += `<rect x="${52+index*bar}" y="${y}" width="${Math.max(2,bar-4)}" height="${h}" fill="${colors[a]}"><title>${escapeHTML(agents[a][0])}: ${count} · ${escapeHTML(new Date(start+index*interval).toLocaleString())}</title></rect>`;
    });
    if (index % Math.max(1,Math.ceil(bins.length/5)) === 0) {
      svg += `<text x="${52+index*bar}" y="237" fill="#64748b" font-size="10">${new Date(start+index*interval).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</text>`;
    }
  });
  svg += `<text x="335" y="260" text-anchor="middle" fill="#64748b" font-size="11">${interval/60000} minute intervals · local time</text></svg>`;
  $('evolution').innerHTML = svg + legend(agents);

  const tactics = new Map();
  events.forEach(e => { if (e.mitre_tactic) tactics.set(e.mitre_tactic, (tactics.get(e.mitre_tactic)||0)+1); });
  const ranked = [...tactics].sort((a,b)=>b[1]-a[1]);
  const entries = ranked.slice(0, ranked.length<=5?5:4);
  if (ranked.length > 5) entries.push(['Other tactics', ranked.slice(4).reduce((sum,e)=>sum+e[1],0)]);
  if (!entries.length) {
    $('tactics').innerHTML = '<div class="chart-empty"><strong>No MITRE mappings</strong>Telemetry has not triggered mapped MITRE techniques.</div>';
    return;
  }
  const total = entries.reduce((sum,e)=>sum+e[1],0);
  let offset = 0;
  const segments = entries.map((entry,i)=>{
    const s = offset;
    offset += entry[1]/total*100;
    return `${colors[i % colors.length]} ${s}% ${offset}%`;
  });
  $('tactics').innerHTML = `<div class="pie" role="img" aria-label="${escapeHTML(entries.map(e=>e.join(': ')).join(', '))}" style="background:conic-gradient(${segments.join(',')})"></div>${legend(entries.map(([name,n])=>[`${name} (${n})`]))}`;
}

// ----------------------------------------------------------------------
// RENDER VIEWS & TABLES
// ----------------------------------------------------------------------
function render() {
  const events = filteredEvents();
  text('total', fmt(state.overview.total_events || events.length));
  text('total-agents', state.overview.online_agents !== undefined ? `${state.overview.online_agents} Online / ${state.overview.total_endpoints || 0} Total` : fmt(state.agents.length));
  text('critical', fmt(state.overview.open_incidents !== undefined ? state.overview.open_incidents : state.incidents.length));
  text('policy-triggers', fmt(state.overview.policy_triggers !== undefined ? state.overview.policy_triggers : 0));

  charts(events);
  $('dashboard-view').hidden = state.view !== 'dashboard';
  $('rules-policies-header').hidden = state.view !== 'rules_policies';

  // Subtab badges
  text('rules-count-badge', state.rules.length);
  text('policies-count-badge', state.policies.length);

  document.querySelectorAll('.tab').forEach(tab => {
    const active = tab.dataset.view === state.view ||
      (state.view === 'rules_policies' && tab.dataset.view === 'rules_policies');
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });

  const query = $('search').value.toLowerCase().trim();
  let headings = [];

  if (state.view === 'agents') {
    text('table-title', 'Endpoint Inventory');
    headings = ['Agent ID', 'Hostname', 'Primary IP', 'Observed Source IP', 'Operating System', 'Status', 'Risk Score', 'Active Alerts', 'Last Seen', 'Agent Version', 'Sync State', 'Queued Events'];
    state.rows = state.agents.filter(a => JSON.stringify(a).toLowerCase().includes(query));
  } else if (state.view === 'rules_policies') {
    if (state.rulesPoliciesSubtab === 'rules') {
      text('table-title', 'Detection & Correlation Rules');
      headings = ['Rule Code', 'Rule Name', 'Category', 'Severity', 'MITRE ATT&CK', 'Risk Delta', 'Matches', 'Linked Policies', 'Status', 'Actions'];
      const catFilter = $('filter-rule-category').value;
      const sevFilter = $('filter-rule-severity').value;
      const statFilter = $('filter-rule-status').value;
      state.rows = state.rules.filter(r => {
        const matchesQuery = !query || JSON.stringify(r).toLowerCase().includes(query);
        const matchesCat = !catFilter || r.category === catFilter;
        const matchesSev = !sevFilter || r.severity === sevFilter;
        const matchesStat = !statFilter || (statFilter === 'enabled' ? r.enabled : !r.enabled);
        return matchesQuery && matchesCat && matchesSev && matchesStat;
      });
    } else {
      text('table-title', 'Adaptive Zero Trust Policies');
      headings = ['Policy Code', 'Policy Name', 'Category', 'Severity', 'Mode', 'Risk Range', 'Action', 'Linked Rule', 'Total Triggers', 'Status', 'Actions'];
      const catFilter = $('filter-policy-category').value;
      const sevFilter = $('filter-policy-severity').value;
      const modeFilter = $('filter-policy-mode').value;
      const actFilter = $('filter-policy-action').value;
      const statFilter = $('filter-policy-status').value;
      state.rows = state.policies.filter(p => {
        const matchesQuery = !query || JSON.stringify(p).toLowerCase().includes(query);
        const matchesCat = !catFilter || p.category === catFilter;
        const matchesSev = !sevFilter || p.severity === sevFilter;
        const matchesMode = !modeFilter || p.mode === modeFilter;
        const matchesAct = !actFilter || p.action === actFilter;
        const matchesStat = !statFilter || (statFilter === 'active' ? p.enabled : !p.enabled);
        return matchesQuery && matchesCat && matchesSev && matchesMode && matchesAct && matchesStat;
      });
    }
  } else if (state.view === 'incidents') {
    text('table-title', 'Security Alerts & Incidents');
    headings = ['Alert ID', 'Created Time', 'Agent', 'Severity', 'Risk Score', 'Trigger Reason', 'Policy Action', 'Status'];
    state.rows = state.incidents.filter(i => JSON.stringify(i).toLowerCase().includes(query) && (!$('severity').value || i.severity === $('severity').value));
  } else if (state.view === 'timeline') {
    text('table-title', 'Unified Security Timeline');
    headings = ['Timestamp', 'Type', 'Title', 'Agent', 'Details'];
    state.rows = state.timeline.filter(t => JSON.stringify(t).toLowerCase().includes(query));
  } else if (state.view === 'audit') {
    text('table-title', 'Security Audit Trail');
    headings = ['Timestamp', 'Event Type', 'Action', 'Agent / User', 'Source', 'Status'];
    state.rows = state.auditLogs.filter(a => JSON.stringify(a).toLowerCase().includes(query));
  } else if (state.view === 'services') {
    text('table-title', 'Background Manager Services Monitor');
    headings = ['Service Name', 'Operational Status', 'Last Activity', 'Heartbeat'];
    state.rows = state.services.filter(s => JSON.stringify(s).toLowerCase().includes(query));
  } else {
    text('table-title', 'Security Alerts Stream');
    headings = ['Time ↓', 'Agent Name', 'MITRE ID', 'MITRE Tactic', 'Rule Description', 'Severity', 'Rule ID'];
    state.rows = events;
  }

  const isFilterable = state.view === 'dashboard' || state.view === 'events' || state.view === 'incidents';
  $('period').disabled = !isFilterable;
  $('dates').disabled = !isFilterable;

  state.page = Math.min(state.page, Math.max(0, Math.ceil(state.rows.length / 10) - 1));
  text('result-count', `${fmt(state.rows.length)} ${state.view === 'rules_policies' ? state.rulesPoliciesSubtab : state.view}`);
  $('table-head').innerHTML = `<tr>${headings.map(h => `<th scope="col">${h}</th>`).join('')}</tr>`;

  const page = state.rows.slice(state.page * 10, state.page * 10 + 10);
  $('table-body').innerHTML = page.length ? page.map((row, index) => {
    let cells = [];

    if (state.view === 'agents') {
      cells = [
        `<button class="row-code-btn" data-row="${index}">${escapeHTML(row.id)}</button>`,
        escapeHTML(row.name),
        escapeHTML(row.local_ipv4 || row.ip || '—'),
        escapeHTML(row.manager_observed_ip || '—'),
        escapeHTML(row.os || '—'),
        `<span class="badge ${row.status}">${row.status}</span>`,
        row.risk_score !== null && row.risk_score !== undefined ? `${row.risk_score} (${row.risk_level || 'LOW'})` : 'UNASSESSED',
        row.active_alerts_count || 0,
        date(row.last_seen).toLocaleString(), escapeHTML(row.agent_version || '—'), escapeHTML(row.sync_state), fmt(row.queue_depth)
      ];
    } else if (state.view === 'rules_policies' && state.rulesPoliciesSubtab === 'rules') {
      const linkedCount = (row.linked_policies || []).length;
      const isDemo = Boolean(row.is_demo || (row.code && row.code.startsWith('DEMO-')));
      const demoBadge = isDemo ? ' <span class="badge" style="background:#4b5563;color:#f3f4f6;font-size:10px;">DEMO</span>' : '';
      cells = [
        `<button class="row-code-btn" data-view-rule="${row.rule_id}">› ${escapeHTML(row.code || row.rule_id)}</button>${demoBadge}`,
        escapeHTML(row.name),
        escapeHTML(row.category),
        `<span class="badge ${row.severity}">${row.severity}</span>`,
        row.mitre_technique_id ? `${escapeHTML(row.mitre_technique_id)} (${escapeHTML(row.mitre_tactic || '')})` : '—',
        `+${row.risk_delta}`,
        fmt(row.total_matches || 0),
        linkedCount ? `<span class="badge">${linkedCount} linked</span>` : '<span class="subtle">0 linked</span>',
        `<label class="switch" title="Toggle rule active state"><input type="checkbox" ${row.enabled ? 'checked' : ''} data-toggle-rule="${row.rule_id}"><span class="slider"></span></label>`,
        `<div class="action-btns">
          <button class="btn-icon" title="View Rule Details" data-view-rule="${row.rule_id}">👁</button>
          <button class="btn-icon" title="Edit Rule" data-edit-rule="${row.rule_id}">✏️</button>
          <button class="btn-icon danger" title="Delete Rule Safely" data-delete-rule="${row.rule_id}">🗑️</button>
        </div>`
      ];
    } else if (state.view === 'rules_policies' && state.rulesPoliciesSubtab === 'policies') {
      const linkedRuleLink = row.rule_id
        ? `<button class="rule-link-btn" data-open-rule="${row.rule_id}">🔗 ${escapeHTML(row.rule_id)}</button>`
        : '<span class="subtle">None (Risk range)</span>';
      cells = [
        `<button class="row-code-btn" data-view-policy="${row.policy_id}">› ${escapeHTML(row.code || row.policy_id)}</button>`,
        escapeHTML(row.name),
        escapeHTML(row.category),
        `<span class="badge ${row.severity}">${row.severity}</span>`,
        `<span class="badge ${row.mode || 'UNKNOWN'}">${row.mode || 'UNKNOWN'}</span>`,
        `[${row.min_risk} – ${row.max_risk}]`,
        `<span class="badge">${row.action}</span>`,
        linkedRuleLink,
        fmt(row.total_triggers || 0),
        `<label class="switch" title="Toggle policy active state"><input type="checkbox" ${row.enabled ? 'checked' : ''} data-toggle-policy="${row.policy_id}"><span class="slider"></span></label>`,
        `<div class="action-btns">
          <button class="btn-icon" title="View Policy Details" data-view-policy="${row.policy_id}">👁</button>
          <button class="btn-icon" title="Edit Policy" data-edit-policy="${row.policy_id}">✏️</button>
          <button class="btn-icon danger" title="Delete Policy Safely" data-delete-policy="${row.policy_id}">🗑️</button>
        </div>`
      ];
    } else if (state.view === 'incidents') {
      const isDemo = Boolean(row.is_demo || (row.rule_code && row.rule_code.startsWith('DEMO-')));
      const demoBadge = isDemo ? ' <span class="badge" style="background:#4b5563;color:#f3f4f6;font-size:10px;">DEMO/TEST</span>' : '';
      cells = [
        `<button class="row-code-btn" data-row="${index}">› ${escapeHTML(row.incident_id)}</button>${demoBadge}`,
        date(row.created_at).toLocaleString(),
        escapeHTML(row.agent_name || row.agent_id),
        `<span class="badge ${row.severity}">${row.severity}</span>`,
        `${row.risk_score || 0} / 100`,
        escapeHTML(row.trigger_reason),
        `${escapeHTML(row.action_taken || 'MONITOR')} (${escapeHTML(row.response_status || 'PENDING')})`,
        `<span class="badge ${row.status}">${row.status}</span>`
      ];
    } else if (state.view === 'timeline') {
      cells = [
        date(row.timestamp).toLocaleString(),
        `<span class="badge">${row.type}</span>`,
        escapeHTML(row.title),
        escapeHTML(row.agent_name || row.agent_id || 'Manager'),
        escapeHTML(JSON.stringify(row.details || {}).slice(0, 80)) + '...'
      ];
    } else if (state.view === 'audit') {
      cells = [
        date(row.timestamp).toLocaleString(),
        `<span class="badge">${row.event_type}</span>`,
        escapeHTML(row.action),
        escapeHTML(row.agent_id || row.user || 'System'),
        escapeHTML(row.execution_source || 'MANAGER'),
        `<span class="badge ${row.status}">${row.status}</span>`
      ];
    } else if (state.view === 'services') {
      cells = [
        escapeHTML(row.service_name),
        `<span class="badge ${row.status}">${row.status}</span>`,
        row.last_activity ? date(row.last_activity).toLocaleString() : 'No recorded activity',
        date(row.last_heartbeat).toLocaleTimeString()
      ];
    } else {
      cells = [
        date(row.timestamp).toLocaleString(),
        escapeHTML(row.agent_name),
        escapeHTML(row.mitre_technique_id || '—'),
        escapeHTML(row.mitre_tactic || '—'),
        escapeHTML(row.description),
        `<span class="badge ${row.severity}">${row.severity}</span>`,
        escapeHTML(row.wazuh_rule_id || '—')
      ];
    }

    return `<tr>${cells.map(cell => `<td>${cell}</td>`).join('')}</tr>`;
  }).join('') : `<tr><td colspan="${headings.length}" class="empty-cell">No records found for ${state.view === 'rules_policies' ? state.rulesPoliciesSubtab : state.view}. Real-time telemetry and mutations update automatically.</td></tr>`;

  // Attach event listeners for table buttons
  const tbody = $('table-body');

  tbody.querySelectorAll('[data-row]').forEach(btn => {
    btn.onclick = () => showForensicDetails(page[Number(btn.dataset.row)]);
  });

  tbody.querySelectorAll('[data-view-rule]').forEach(btn => {
    btn.onclick = () => {
      const rule = state.rules.find(r => r.rule_id === btn.dataset.viewRule);
      if (rule) openRuleDetails(rule);
    };
  });

  tbody.querySelectorAll('[data-edit-rule]').forEach(btn => {
    btn.onclick = () => {
      const rule = state.rules.find(r => r.rule_id === btn.dataset.editRule);
      if (rule) openEditRuleModal(rule);
    };
  });

  tbody.querySelectorAll('[data-delete-rule]').forEach(btn => {
    btn.onclick = () => {
      const rule = state.rules.find(r => r.rule_id === btn.dataset.deleteRule);
      if (rule) openDeleteModal('rule', rule);
    };
  });

  tbody.querySelectorAll('[data-toggle-rule]').forEach(input => {
    input.onchange = () => toggleRule(input.dataset.toggleRule, input.checked);
  });

  tbody.querySelectorAll('[data-view-policy]').forEach(btn => {
    btn.onclick = () => {
      const pol = state.policies.find(p => p.policy_id === btn.dataset.viewPolicy);
      if (pol) openPolicyDetails(pol);
    };
  });

  tbody.querySelectorAll('[data-edit-policy]').forEach(btn => {
    btn.onclick = () => {
      const pol = state.policies.find(p => p.policy_id === btn.dataset.editPolicy);
      if (pol) openEditPolicyModal(pol);
    };
  });

  tbody.querySelectorAll('[data-delete-policy]').forEach(btn => {
    btn.onclick = () => {
      const pol = state.policies.find(p => p.policy_id === btn.dataset.deletePolicy);
      if (pol) openDeleteModal('policy', pol);
    };
  });

  tbody.querySelectorAll('[data-toggle-policy]').forEach(input => {
    input.onchange = () => togglePolicy(input.dataset.togglePolicy, input.checked);
  });

  tbody.querySelectorAll('[data-open-rule]').forEach(btn => {
    btn.onclick = () => {
      const rule = state.rules.find(r => r.rule_id === btn.dataset.openRule);
      if (rule) openRuleDetails(rule);
    };
  });

  text('page-info', state.rows.length ? `${state.page * 10 + 1}–${Math.min(state.page * 10 + 10, state.rows.length)} of ${fmt(state.rows.length)}` : '0 results');
  $('previous').disabled = state.page === 0;
  $('next').disabled = (state.page + 1) * 10 >= state.rows.length;
}

// ----------------------------------------------------------------------
// DATA REFRESH & WEBSOCKETS
// ----------------------------------------------------------------------
async function refresh() {
  if (state.loading) { state.refreshPending = true; return; }
  state.loading = true;
  $('refresh').disabled = true;
  text('connection', 'Refreshing…');
  try {
    await fetchSchema();
    const endpoints = [
      'events?limit=10000', 'agents', 'incidents', 'overview',
      'rules', 'policies', 'timeline', 'background-services'
    ];
    if (state.permissions.includes('audit:read')) endpoints.push('audit');
    const results = await Promise.all(endpoints.map(async ep => {
      const response = await apiFetch(`/api/zta/${ep}`, {
        headers: { 'X-User-Role': state.role },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      return response.json();
    }));

    state.events = results[0].events.map(unpack);
    state.agents = results[1].agents || [];
    state.incidents = results[2].incidents || [];
    state.overview = results[3] || {};
    state.rules = results[4].rules || [];
    state.policies = results[5].policies || [];
    state.timeline = results[6].timeline || [];
    state.services = results[7].background_services || [];
    state.auditLogs = state.permissions.includes('audit:read') ? (results[8].audit_logs || []) : [];

    $('notice').hidden = (state.overview.total_events || 0) <= state.events.length;
    if (!$('notice').hidden) {
      text('notice', 'Showing the latest 10,000 stored alerts. Filters and charts apply to loaded records.');
    }
    text('connection', `● Manager Connected · ${state.agents.length} Endpoints Registered`);
    text('updated', `Updated ${new Date().toLocaleTimeString()}`);
    text('manager-status', `Manager ${state.overview.status || 'UNKNOWN'}`);
    text('operational-summary', JSON.stringify(state.overview, null, 2));
    render();
  } catch (error) {
    text('connection', 'Manager API Unavailable');
    text('manager-status', 'Manager API Unavailable');
    $('notice').hidden = false;
    text('notice', `Could not refresh ZTA data: ${error.message}. Ensure the ZTA Manager server is running.`);
  } finally {
    state.loading = false;
    $('refresh').disabled = false;
    if (state.refreshPending) { state.refreshPending = false; queueMicrotask(refresh); }
  }
}

function initWebSocket() {
  if (!state.adminToken || !state.permissions.includes('stream')) return;
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${location.host}/api/zta/ws`;
  try {
    const ws = new WebSocket(wsUrl, [`zta-token.${state.adminToken}`]);
    state.ws = ws;
    ws.onopen = () => {
      text('connection', `● Real-Time WebSocket Connected · ${state.agents.length} Endpoints`);
    };
    ws.onmessage = event => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event && (msg.event.startsWith('rule.') || msg.event.startsWith('policy.'))) {
          // Rule or policy mutation occurred
          refresh();
        } else {
          refresh();
        }
      } catch (_) {}
    };
    ws.onclose = () => {
      setTimeout(initWebSocket, 3000);
    };
    ws.onerror = () => {
      ws.close();
    };
  } catch (_) {}
}

// ----------------------------------------------------------------------
// NAVIGATION & VIEW SWITCHING
// ----------------------------------------------------------------------
function switchView(view) {
  if (view === 'rules' || view === 'policies') {
    state.view = 'rules_policies';
    switchSubtab(view);
    return;
  }
  state.view = view;
  state.page = 0;
  $('navigation').hidden = true;
  $('menu').setAttribute('aria-expanded', 'false');
  $('date-range').hidden = true;
  render();
}

function switchSubtab(subtab) {
  state.rulesPoliciesSubtab = subtab;
  state.page = 0;
  const isRules = subtab === 'rules';

  $('subtab-rules-btn').classList.toggle('active', isRules);
  $('subtab-rules-btn').setAttribute('aria-selected', String(isRules));
  $('subtab-policies-btn').classList.toggle('active', !isRules);
  $('subtab-policies-btn').setAttribute('aria-selected', String(!isRules));

  $('btn-create-rule').hidden = !isRules;
  $('btn-create-policy').hidden = isRules;

  $('rules-filterbar').hidden = !isRules;
  $('policies-filterbar').hidden = isRules;

  render();
}

// ----------------------------------------------------------------------
// EVENT LISTENERS INITIALIZATION
// ----------------------------------------------------------------------
document.querySelectorAll('[data-view]').forEach(button => {
  button.addEventListener('click', () => switchView(button.dataset.view));
});

$('subtab-rules-btn').onclick = () => switchSubtab('rules');
$('subtab-policies-btn').onclick = () => switchSubtab('policies');

$('btn-create-rule').onclick = openCreateRuleModal;
$('btn-create-policy').onclick = openCreatePolicyModal;

// Authenticated operator session
$('user-role').value = 'VIEWER';
$('login-form').onsubmit = async event => {
  event.preventDefault();
  const username = $('login-username').value.trim();
  const password = $('login-password').value;
  const submit = $('login-submit');
  submit.disabled = true; submit.textContent = 'Verifying…';
  $('login-error').hidden = true;
  const response = await fetch('/api/zta/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username, password})});
  const result = await response.json();
  submit.disabled = false; submit.textContent = 'Sign in securely';
  $('login-password').value = '';
  if (!response.ok) {
    $('login-error').hidden = false;
    text('login-error', result.error || 'Authentication failed');
    return;
  }
  state.adminToken = result.access_token;
  sessionStorage.setItem('ztaAccessToken', state.adminToken);
  const identity = result.user;
  unlockDashboard(identity);
  showToast(`${identity.username} authenticated as ${state.role}`, 'success');
  await refresh();
  initWebSocket();
};
$('sign-out').onclick = async () => {
  if (state.adminToken) await apiFetch('/api/zta/auth/logout', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
  lockDashboard();
  history.replaceState(null, '', location.pathname);
};
$('create-user').onclick = async () => {
  $('user-create').showModal();
  const response = await apiFetch('/api/zta/users');
  const result = await response.json();
  $('user-list').innerHTML = response.ok ? result.users.map(user => `<article class="user-row"><span class="user-avatar">${escapeHTML(user.username.slice(0, 2).toUpperCase())}</span><span><strong>${escapeHTML(user.username)}</strong><small>${escapeHTML(user.role.replace('_', ' '))}</small></span><span class="user-state">${user.enabled ? 'Active' : 'Disabled'}</span></article>`).join('') : `<p class="form-error">${escapeHTML(result.error || 'Unable to load operators')}</p>`;
};
$('cancel-user-create').onclick = () => $('user-create').close();
$('user-create-form').onsubmit = async event => {
  event.preventDefault();
  $('user-create-error').hidden = true;
  const response = await apiFetch('/api/zta/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:$('new-username').value.trim(), password:$('new-password').value, role:$('new-role').value})});
  const result = await response.json();
  if (!response.ok) { $('user-create-error').hidden = false; text('user-create-error', result.error || 'User creation failed'); return; }
  event.target.reset(); $('user-create').close();
  showToast(`Created ${result.user.username} as ${result.user.role}`, 'success');
};
$('change-password').onclick = () => $('password-change').showModal();
$('cancel-password-change').onclick = () => $('password-change').close();
$('password-change-form').onsubmit = async event => {
  event.preventDefault();
  const error = $('password-change-error'); error.hidden = true;
  if ($('changed-password').value !== $('confirm-password').value) {
    error.hidden = false; text('password-change-error', 'New passwords do not match.'); return;
  }
  const response = await apiFetch('/api/zta/auth/password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({current_password:$('current-password').value, new_password:$('changed-password').value})});
  const result = await response.json();
  if (!response.ok) { error.hidden = false; text('password-change-error', result.error || 'Password change failed'); return; }
  event.target.reset(); $('password-change').close(); showToast('Password changed successfully', 'success');
};

// Modals close buttons
$('close-rule-builder').onclick = () => $('rule-builder-modal').close();
$('rb-cancel').onclick = () => $('rule-builder-modal').close();
$('rule-builder-form').onsubmit = saveRule;
$('rb-btn-validate').onclick = validateRuleCondition;
$('rb-btn-dryrun-toggle').onclick = () => {
  $('rb-dryrun-box').hidden = !$('rb-dryrun-box').hidden;
};
$('rb-btn-run-test').onclick = runRuleDryRun;

$('close-policy-builder').onclick = () => $('policy-builder-modal').close();
$('pb-cancel').onclick = () => $('policy-builder-modal').close();
$('policy-builder-form').onsubmit = savePolicy;
$('pb-btn-validate').onclick = validatePolicyLogic;
$('pb-action').onchange = updatePolicyActionHint;

$('close-rule-details').onclick = () => $('rule-details-modal').close();
$('close-rule-details-btn').onclick = () => $('rule-details-modal').close();

$('close-policy-details').onclick = () => $('policy-details-modal').close();
$('close-policy-details-btn').onclick = () => $('policy-details-modal').close();

$('close-delete-modal').onclick = () => $('delete-confirm-modal').close();
$('del-cancel').onclick = () => $('delete-confirm-modal').close();
$('del-confirm').onclick = confirmDelete;

$('close-details').onclick = () => $('details').close();

// Filter changes
['filter-rule-category', 'filter-rule-severity', 'filter-rule-status',
 'filter-policy-category', 'filter-policy-severity', 'filter-policy-mode',
 'filter-policy-action', 'filter-policy-status'].forEach(id => {
  const el = $(id);
  if (el) el.onchange = () => { state.page = 0; render(); };
});

$('menu').onclick = () => {
  $('navigation').hidden = !$('navigation').hidden;
  $('menu').setAttribute('aria-expanded', String(!$('navigation').hidden));
};
$('explore').onclick = () => switchView('agents');
$('refresh').onclick = refresh;
$('search-form').onsubmit = event => { event.preventDefault(); state.page = 0; render(); };
$('search').addEventListener('input', () => { state.page = 0; render(); });
$('severity').onchange = () => { state.page = 0; render(); };
$('period').onchange = () => {
  if ($('period').value === 'custom') {
    $('date-range').hidden = false;
    return;
  }
  state.page = 0;
  render();
};
$('dates').onclick = () => { $('date-range').hidden = !$('date-range').hidden; };
const localInput = value => new Date(value.getTime() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
$('from').value = localInput(new Date(Date.now() - 86400000));
$('to').value = localInput(new Date());
$('apply-dates').onclick = () => {
  if (!$('from').value || !$('to').value || new Date($('from').value) > new Date($('to').value)) {
    $('notice').hidden = false;
    text('notice', 'Choose a valid start and end date.');
    return;
  }
  $('notice').hidden = true;
  $('period').value = 'custom';
  state.page = 0;
  render();
};
$('clear').onclick = () => {
  $('search').value = '';
  $('severity').value = '';
  $('period').value = '24';
  $('filter-rule-category').value = '';
  $('filter-rule-severity').value = '';
  $('filter-rule-status').value = '';
  $('filter-policy-category').value = '';
  $('filter-policy-severity').value = '';
  $('filter-policy-mode').value = '';
  $('filter-policy-action').value = '';
  $('filter-policy-status').value = '';
  $('date-range').hidden = true;
  state.page = 0;
  render();
};
$('previous').onclick = () => { state.page--; render(); };
$('next').onclick = () => { state.page++; render(); };

$('report').onclick = () => {
  const report = {
    project: 'ZTA Zero Trust Architecture EDR',
    generated_at: new Date().toISOString(),
    view: state.view,
    subtab: state.view === 'rules_policies' ? state.rulesPoliciesSubtab : null,
    role: state.role,
    records: state.rows
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `zta-${state.view}-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

// Initial start: restore a session or require login before loading protected data.
(async () => {
  const storedToken = state.adminToken;
  lockDashboard();
  state.adminToken = storedToken;
  if (state.adminToken) {
    const response = await apiFetch('/api/zta/session');
    if (response.ok) {
      const identity = await response.json();
      unlockDashboard(identity);
      await refresh(); initWebSocket(); return;
    }
  }
  lockDashboard();
})();
