"""Authenticated durable ingestion and idempotent response transitions."""
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4
from zta.engine.events.serialization import decode
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.agent.commands.authorization import canonical, sign


def command_result(handler, payload):
    repo, hub = handler.repo, handler.hub
    status = payload.get('status')
    if status not in ('EXECUTING', 'SUCCESS', 'FAILED'):
        raise ValueError('Explicit EXECUTING, SUCCESS or FAILED result is required')
    now = datetime.now(timezone.utc).isoformat()
    with repo.db.transaction() as conn:
        row = conn.execute('SELECT * FROM commands WHERE command_id=? AND agent_id=?', (payload.get('command_id'), payload.get('agent_id'))).fetchone()
        if not row:
            raise ValueError('Unknown command or wrong agent')
        cmd = dict(row)
        verification = payload.get('verification')
        if status == 'SUCCESS' and cmd['action_type'] == 'KILL_PROCESS' and verification != 'PROCESS_NOT_ACTIVE':
            raise ValueError('Process SUCCESS requires PROCESS_NOT_ACTIVE verification')
        if status == 'SUCCESS' and cmd['action_type'] in ('LOGOUT_USER','LOGOFF_USER') and verification != 'SESSION_NOT_ACTIVE':
            raise ValueError('Logout SUCCESS requires SESSION_NOT_ACTIVE verification')
        if cmd['status'] in ('SUCCESS', 'FAILED'):
            if cmd['status'] != status or cmd['verification'] != verification or cmd['error_message'] != payload.get('error'):
                raise ValueError('Conflicting terminal command result')
            return False
        if cmd['status'] not in ('DISPATCHED', 'EXECUTING', 'EXPIRED'):
            raise ValueError('Command has not been dispatched')
        if cmd['status'] == 'EXPIRED':
            # Delayed uploads are valid only if endpoint execution began within authorization lifetime.
            started = datetime.fromisoformat(payload.get('executed_at', ''))
            expires = datetime.fromisoformat(cmd['expires_at']) if cmd['expires_at'] else None
            if status == 'EXECUTING' or started.tzinfo is None or expires is None or started > expires:
                raise ValueError('Expired command cannot begin execution')
        if status == 'EXECUTING':
            if cmd['status'] == 'EXECUTING': return False
            conn.execute("UPDATE commands SET status='EXECUTING',executing_at=? WHERE command_id=?", (now, cmd['command_id']))
        else:
            repo.update_command_result(cmd['command_id'], status, payload.get('output', ''), payload.get('error'), verification)
            conn.execute('UPDATE commands SET executing_at=COALESCE(executing_at,?), completed_at=? WHERE command_id=?',
                         (payload.get('executed_at'), payload.get('completed_at') or now, cmd['command_id']))
        conn.execute('UPDATE incidents SET response_status=?,updated_at=? WHERE incident_id=?', (status, now, cmd['alert_id']))
        conn.execute('UPDATE policy_evaluations SET status=? WHERE alert_id=? AND policy_id=?', (status, cmd['alert_id'], cmd['policy_id']))
        action = 'LOGOUT' if cmd['action_type'] in ('LOGOUT_USER','LOGOFF_USER') else 'RESPONSE'
        audit = action + ('_EXECUTING' if status == 'EXECUTING' else '_SUCCEEDED' if status == 'SUCCESS' else '_FAILED')
        repo.save_audit(audit, cmd['action_type'], cmd['agent_id'], details={**payload, 'alert_id': cmd['alert_id']}, status=status)
    hub.broadcast('command.executing' if status == 'EXECUTING' else 'response.success' if status == 'SUCCESS' else 'response.failed', {**payload, 'alert_id': cmd['alert_id']})
    hub.broadcast('alert.updated', {'alert_id': cmd['alert_id'], 'response_status': status})
    return True


def ingest(handler, payload, offline=False):
    repo, hub = handler.repo, handler.hub
    if isinstance(payload, list):
        records = payload
        agent_id = ((records[0].get('agent') or {}).get('id') if records else None)
        if not agent_id and records:
            agent_id = (records[0].get('telemetry') or {}).get('agent_id')
        envelope = {}
    elif isinstance(payload, dict):
        records = payload.get('telemetry', [])
        agent_id = payload.get('agent_id')
        envelope = payload
        offline = offline or bool(payload.get('batch_id'))
    else:
        raise ValueError('Expected telemetry batch')
    secret = handler._authenticate_agent(agent_id)
    if not isinstance(records, list) or len(records) > 500:
        raise ValueError('Expected up to 500 telemetry records')
    batch_id = envelope.get('batch_id') or hashlib.sha256(canonical(records)).hexdigest()
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    accepted = []
    hub.begin()
    try:
        with repo.db.transaction() as conn:
            receipt = conn.execute('SELECT * FROM sync_receipts WHERE agent_id=? AND batch_id=?', (agent_id, batch_id)).fetchone()
            if receipt:
                if receipt['payload_hash'] != digest: raise ValueError('Batch ID belongs to different evidence')
                hub.rollback()
                return json.loads(receipt['response_json'])
            if offline:
                hub.broadcast('offline.sync_started', {'agent_id': agent_id, 'batch_id': batch_id})
                repo.save_audit('SYNC_STARTED', 'Offline batch received', agent_id, details={'batch_id': batch_id})
            for item in records:
                if not isinstance(item, dict): raise ValueError('Telemetry record must be an object')
                if 'log_entry' in item:
                    log_data = item['log_entry']
                    repo.save_agent_log(log_data, execution_source='AGENT_OFFLINE', synced_at=now)
                    accepted.append(log_data.get('log_id') or item.get('id') or str(uuid4()))
                    continue
                if 'normalized_event' in item:
                    event = decode(item['normalized_event'])
                elif 'telemetry' in item:
                    meta = item['telemetry']
                    event = ZTAEventAdapter.from_dict({'id': item.get('id') or item.get('event_id'), 'timestamp': meta.get('timestamp'),
                        'agent': {'id': meta.get('agent_id'), 'name': meta.get('hostname', agent_id)}, 'event_type': 'HEARTBEAT_FAILURE', 'data': item})
                else:
                    event = ZTAEventAdapter.from_dict(item)
                if not (item.get('id') or item.get('event_id') or item.get('normalized_event', {}).get('event_id')):
                    raise ValueError('Stable event ID is required for durable ingestion')
                if event.agent.id != agent_id:
                    raise ValueError('Batch contains telemetry for another agent')
                source = item.get('execution_source', 'AGENT_OFFLINE' if offline else 'AGENT_ONLINE')
                if source not in ('AGENT_ONLINE','AGENT_OFFLINE'): raise ValueError('Invalid execution source')
                inserted = repo.save_event(event, source, now if offline else None)
                if inserted and item.get('offline_evidence'):
                    import_offline(handler, event, item['offline_evidence'], secret, now)
                    conn.execute("UPDATE zta_events SET processing_state='COMPLETED' WHERE event_id=?", (event.event_id,))
                accepted.append(event.event_id)
                if offline: hub.broadcast('offline.sync_progress', {'agent_id':agent_id,'batch_id':batch_id,'accepted':len(accepted),'total':len(records)})
            for result in envelope.get('results', []):
                if result.get('agent_id') != agent_id: raise ValueError('Result agent mismatch')
                command_result(handler, result)
            if envelope.get('responses'):
                raise ValueError('Offline responses require their complete offline_evidence chain')
            response = {'status': 'ACCEPTED', 'accepted': len(accepted), 'accepted_event_ids': accepted, 'batch_id': batch_id}
            if offline:
                repo.update_service_heartbeat('Offline Sync Processor', activity=True)
                repo.record_sync_batch({'sync_id': 'sync-' + hashlib.sha256((agent_id+batch_id).encode()).hexdigest(),
                    'agent_id': agent_id, 'batch_id': batch_id, 'events_count': len(accepted), 'status': 'COMPLETED', 'synced_at': now})
                repo.save_audit('SYNC_COMPLETED', 'Offline batch durably stored', agent_id, details={'batch_id': batch_id, 'events_count': len(accepted)})
                hub.broadcast('offline.sync_completed', {'agent_id': agent_id, 'batch_id': batch_id, 'accepted': len(accepted)})
            conn.execute('INSERT INTO sync_receipts VALUES (?,?,?,?)', (agent_id, batch_id, digest, json.dumps(response)))
        hub.commit()
    except BaseException:
        hub.rollback()
        raise
    return response


def import_offline(handler, event, evidence, secret, synced_at):
    """Import endpoint-reported evidence only with its authenticated configuration."""
    import hmac
    from zta.engine.events.conditions import ConditionEvaluator
    from zta.engine.events.serialization import context
    repo = handler.repo
    cache = evidence['configuration']
    if cache.get('agent_id') != event.agent.id or not hmac.compare_digest(sign(cache, secret)['signature'], str(cache.get('signature', ''))):
        raise ValueError('Invalid offline configuration authorization')
    evaluated_at = datetime.fromisoformat(evidence['evaluated_at'])
    if evaluated_at.tzinfo is None or evaluated_at > datetime.fromisoformat(cache['expires_at']):
        raise ValueError('Offline execution used expired configuration')
    rules = {r['rule_id']: r for r in cache['rules'] if r.get('enabled') and r.get('allow_offline')}
    policies = {p['policy_id']: p for p in cache['policies']}
    matches = evidence.get('rule_matches', [])
    for match in matches:
        rule = rules.get(match['rule_id'])
        if not rule or match['event_id'] != event.event_id or match['agent_id'] != event.agent.id:
            raise ValueError('Offline rule was not authorized for this event')
        if not ConditionEvaluator().evaluate(rule['condition'], context(event)):
            raise ValueError('Offline rule does not match supplied telemetry')
        repo.save_rule_match(match)
    alert_ids = {m['alert_id'] for m in matches}
    for incident in evidence.get('incidents', []):
        if incident['incident_id'] not in alert_ids or incident['agent_id'] != event.agent.id: raise ValueError('Offline alert linkage mismatch')
        repo.save_incident(incident)
    for pe in evidence.get('policy_evaluations', []):
        if pe['alert_id'] not in alert_ids or pe['agent_id'] != event.agent.id: raise ValueError('Offline policy linkage mismatch')
        policy = policies.get(pe['policy_id'])
        if not policy: raise ValueError('Unknown cached offline policy')
        from zta.engine.policy.engine import ZTAPolicyEngine
        decision = ZTAPolicyEngine([]).evaluate_single_policy(policy, {**context(event), 'agent_id':event.agent.id,
            'rule_id':pe['rule_id'],'rule_code':rules.get(pe['rule_id'],{}).get('code',pe['rule_id']), 'risk_score':pe['risk_score'],'trust_score':pe['trust_score'], 'execution_source':'AGENT_OFFLINE'})
        if decision.evaluation_result != pe['evaluation_result'] or decision.action != pe['action'] or decision.mode != pe['mode']:
            raise ValueError('Offline policy evaluation does not agree with authorized definition')
        if pe.get('condition_trace_json') and json.loads(pe['condition_trace_json']) != decision.condition_trace:
            raise ValueError('Offline policy condition trace differs from real evaluation')
        repo.save_policy_evaluation(pe)
        with repo.db.get_connection() as conn:
            conn.execute('UPDATE policy_evaluations SET condition_trace_json=? WHERE eval_id=?', (pe.get('condition_trace_json'), pe['eval_id']))
    for cmd in evidence.get('commands', []):
        pol = policies.get(cmd.get('policy_id'))
        if not pol or not pol.get('enabled') or not pol.get('allow_offline') or pol['mode'] != 'ENFORCE':
            raise ValueError('Offline policy does not authorize enforcement')
        if cmd['action_type'] != pol['action'] or cmd['alert_id'] not in alert_ids or cmd['agent_id'] != event.agent.id:
            raise ValueError('Offline command linkage mismatch')
        if cmd['status'] not in ('SUCCESS','FAILED','INTERRUPTED'): raise ValueError('Offline command lacks a terminal result')
        if cmd['status'] == 'SUCCESS' and cmd['action_type'] in ('LOGOUT_USER','LOGOFF_USER') and cmd.get('verification') != 'SESSION_NOT_ACTIVE':
            raise ValueError('Offline logout success lacks verification')
        evaluations = [pe for pe in evidence.get('policy_evaluations',[]) if pe['policy_id']==cmd['policy_id'] and pe['alert_id']==cmd['alert_id'] and pe['evaluation_result']=='TRIGGERED']
        if not evaluations: raise ValueError('Offline command lacks a triggered policy evaluation')
        from zta.engine.response.command_builder import build_command
        from zta.powershell.ps_executor import PowerShellExecutor
        PowerShellExecutor().execute_template(cmd['action_type'],cmd.get('params',{}),dry_run=True)
        if cmd['action_type'] in ('LOGOUT_USER','LOGOFF_USER'):
            target = event.user.name
            if target and event.user.domain and '\\' not in target: target=event.user.domain+'\\'+target
            if cmd['params'] != {'UserName':target,'SessionId':str(event.user.session_id or '')}:
                raise ValueError('Offline logout target differs from event')
        repo.save_command(cmd)
        with repo.db.get_connection() as conn:
            conn.execute('UPDATE commands SET synced_at=?,executing_at=? WHERE command_id=?', (synced_at, cmd.get('executing_at'), cmd['command_id']))
        repo.save_audit('OFFLINE_RESPONSE_EXECUTED', cmd['action_type'], event.agent.id, details={'command_id': cmd['command_id'], 'alert_id': cmd['alert_id'], 'status': cmd['status']}, execution_source='AGENT_OFFLINE', status=cmd['status'], timestamp=cmd.get('completed_at'))
    # Persist exact local evaluation/risk/audit timestamps; do not re-run responses.
    with repo.db.get_connection() as conn:
        for re in evidence.get('rule_evaluations', []):
            if re['event_id'] != event.event_id or re['agent_id'] != event.agent.id: raise ValueError('Offline evaluation linkage mismatch')
            conn.execute('INSERT OR IGNORE INTO rule_evaluations VALUES (?,?,?,?,?,?,?,?)', tuple(re[k] for k in ('evaluation_id','event_id','rule_id','agent_id','result','trace_json','timestamp','execution_source')))
        for risk in evidence.get('risk_history', []):
            if risk['agent_id'] != event.agent.id: raise ValueError('Offline risk linkage mismatch')
            conn.execute('INSERT INTO risk_history (timestamp,agent_id,previous_score,delta,new_score,reason,finding_id) VALUES (?,?,?,?,?,?,?)', tuple(risk[k] for k in ('timestamp','agent_id','previous_score','delta','new_score','reason','finding_id')))
    for audit in evidence.get('audit', []):
        repo.save_audit(audit['event_type'], audit['action'], event.agent.id, details=audit.get('details', {}), execution_source='AGENT_OFFLINE', status=audit['status'], timestamp=audit['timestamp'])
    handler.hub.broadcast('alert.updated', {'agent_id': event.agent.id, 'execution_source': 'AGENT_OFFLINE', 'synced_at': synced_at})
