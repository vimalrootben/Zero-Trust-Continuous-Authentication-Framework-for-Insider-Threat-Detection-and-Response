"""Existing manager pipeline, persisted atomically by its background worker."""
import hashlib
import json
from datetime import datetime, timezone
from zta.engine.events.serialization import context
from zta.engine.response.command_builder import build_command


def identifier(prefix, *parts):
    return prefix + '-' + hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:32]


def process(engine, event, execution_source='AGENT_ONLINE', synced_at=None):
    repo, hub = engine.repo, engine.hub
    now = datetime.now(timezone.utc).isoformat()
    agent_id = event.agent.id
    alerts = []
    with repo.db.transaction() as conn:
        state = conn.execute('SELECT processing_state FROM zta_events WHERE event_id=?', (event.event_id,)).fetchone()
        if state and state[0] == 'COMPLETED':
            return []
        # Restore persisted risk before each unit of work, including after restart/rollback.
        row = conn.execute('SELECT new_score FROM risk_history WHERE agent_id=? ORDER BY timestamp DESC, id DESC LIMIT 1', (agent_id,)).fetchone()
        engine.risk_engine._scores[agent_id] = row[0] if row else 0
        engine._reload_policies()
        event_data = context(event)
        # Rebuild the existing correlation window from committed evidence on restart/retry.
        from zta.engine.correlation.engine import ZTACorrelationEngine
        from zta.engine.events.serialization import decode
        engine.correlation_engine = ZTACorrelationEngine(window_seconds=300)
        previous = conn.execute("SELECT normalized_json FROM zta_events WHERE agent_id=? AND processing_state='COMPLETED' AND timestamp<=? ORDER BY timestamp DESC LIMIT 1000", (agent_id, event.timestamp.isoformat())).fetchall()
        for old in reversed(previous):
            if old[0]:
                engine.correlation_engine.process_event(decode(json.loads(old[0])))
        findings = engine.correlation_engine.process_event(event)
        for finding in findings:
            risk = engine.risk_engine.apply_delta(agent_id, finding.risk_delta, finding.description)
            repo.save_risk_event(risk)
            repo.save_audit('RISK_UPDATED', finding.description, agent_id, details={'event_id': event.event_id, 'new_score': risk.new_score}, execution_source=execution_source)
            hub.broadcast('risk.updated', {'agent_id': agent_id, 'risk_score': risk.new_score})
        for rule in repo.get_rules():
            if not rule.get('enabled') or (getattr(engine, 'offline_enforcement', False) and not rule.get('allow_offline')):
                continue
            try:
                # A supplied rule ID cannot override a configured condition tree.
                if rule.get('condition'):
                    trace = engine.evaluator.explain(rule['condition'], event_data)
                else:
                    trace = {'result': False, 'reason': 'No executable condition configured'}
            except (ValueError, TypeError) as exc:
                trace = {'result': False, 'error': str(exc)}
            evaluation = dict(evaluation_id=identifier('re', event.event_id, rule['rule_id']),
                              event_id=event.event_id, rule_id=rule['rule_id'], agent_id=agent_id,
                              result=bool(trace['result']), trace=trace, timestamp=now, execution_source=execution_source)
            conn.execute('INSERT OR IGNORE INTO rule_evaluations VALUES (?,?,?,?,?,?,?,?)',
                         (evaluation['evaluation_id'], event.event_id, rule['rule_id'], agent_id, int(trace['result']), json.dumps(trace), now, execution_source))
            conn.execute('UPDATE rules SET last_evaluated=? WHERE rule_id=?', (now, rule['rule_id']))
            repo.save_audit('RULE_EVALUATED', rule['name'], agent_id, details=evaluation, execution_source=execution_source)
            hub.broadcast('rule.evaluated', evaluation)
            if not trace['result']:
                continue
            match_id = identifier('rm', event.event_id, rule['rule_id'])
            alert_id = identifier('alt', event.event_id, rule['rule_id'])
            match = dict(match_id=match_id, rule_id=rule['rule_id'], rule_code=rule['code'], rule_name=rule['name'],
                         rule_version=rule.get('current_version', 1),
                         agent_id=agent_id, agent_name=event.agent.name, event_id=event.event_id,
                         severity=rule['severity'], mitre_tactic=rule.get('mitre_tactic'), mitre_technique_id=rule.get('mitre_technique_id'),
                         matched_conditions=trace, condition_result=True, risk_delta=rule['risk_delta'], matched_at=now,
                         alert_id=alert_id, execution_source=execution_source)
            repo.save_rule_match(match)
            repo.save_audit('RULE_MATCHED', rule['name'], agent_id, details=match, execution_source=execution_source)
            risk = engine.risk_engine.apply_delta(agent_id, rule['risk_delta'], 'Rule matched: '+rule['name'], match_id)
            repo.save_risk_event(risk)
            trust = engine.trust_engine.evaluate_trust(agent_id)
            repo.save_audit('RISK_UPDATED', risk.reason, agent_id, details={'alert_id': alert_id, 'event_id': event.event_id, 'previous_score': risk.previous_score, 'new_score': risk.new_score}, execution_source=execution_source)
            incident = dict(incident_id=alert_id, agent_id=agent_id, agent_name=event.agent.name, user_name=event.user.name,
                            severity=rule['severity'], risk_score=risk.new_score, trust_score=trust.trust_score, status='OPEN',
                            trigger_reason='Rule matched: '+rule['name'], action_taken='MONITOR', rule_id=rule['rule_id'], rule_code=rule['code'],
                            rule_name=rule['name'], rule_version=rule.get('current_version', 1), response_action='MONITOR', response_status='NOT_REQUESTED',
                            detection_json={'event_id': event.event_id, 'rule_version': rule.get('current_version', 1), 'matched_conditions': trace, 'process': event_data['process'], 'user': event_data['user']},
                            created_at=now, updated_at=now, execution_source=execution_source)
            repo.save_incident(incident)
            repo.save_audit('ALERT_CREATED', rule['name'], agent_id, details={'alert_id': alert_id, 'event_id': event.event_id}, execution_source=execution_source)
            policy_context = {**event_data, 'agent_id': agent_id, 'rule_id': rule['rule_id'], 'rule_code': rule['code'],
                              'risk_score': risk.new_score, 'trust_score': trust.trust_score, 'alert_id': alert_id}
            # Historical replay evaluates manager policy, but never sends retrospective destructive commands.
            if getattr(engine, 'offline_enforcement', False):
                policy_context['execution_source'] = 'AGENT_OFFLINE'
            selected = None
            repo.update_service_heartbeat('Policy Engine', activity=True)
            from zta.engine.policy.engine import policy_sort_key
            for policy in sorted(engine.policy_engine.policies, key=policy_sort_key):
                decision = engine.policy_engine.evaluate_single_policy(policy, policy_context)
                eval_id = identifier('pe', alert_id, policy.policy_id)
                pe = dict(eval_id=eval_id, policy_id=policy.policy_id, policy_code=decision.policy_code,
                          policy_name=policy.name, rule_id=rule['rule_id'], agent_id=agent_id, alert_id=alert_id,
                          risk_score=risk.new_score, trust_score=trust.trust_score, mode=decision.mode, action=decision.action,
                          evaluation_result=decision.evaluation_result, reason=decision.reason, status='EVALUATED', timestamp=now,
                          execution_source=execution_source, condition_trace=decision.condition_trace)
                if decision.triggered:
                    if selected is not None:
                        pe['status'] = 'NOT_SELECTED'
                        pe['reason'] += '; higher-priority matching policy selected'
                    else:
                        selected = decision
                        pe['status'] = 'RECOMMENDED_ONLY' if decision.mode == 'ALERT_ONLY' else 'NOT_EXECUTED'
                        if decision.mode == 'ENFORCE' and decision.action not in ('MONITOR', 'ALERT', 'NOTIFY_SOC'):
                            if execution_source == 'AGENT_OFFLINE' and not getattr(engine, 'offline_enforcement', False):
                                pe['status'] = 'HISTORICAL_ONLY'
                                pe['reason'] += '; historical sync does not dispatch new responses'
                            else:
                                try:
                                    cmd = build_command(decision, event, identifier('cmd', alert_id, policy.policy_id), alert_id, execution_source)
                                    repo.save_command(cmd)
                                    pe['status'] = 'QUEUED'
                                    repo.save_audit('COMMAND_CREATED', decision.action, agent_id, details={'command_id': cmd['command_id'], 'alert_id': alert_id, 'policy_id': policy.policy_id}, execution_source=execution_source)
                                    hub.broadcast('command.created', cmd)
                                except Exception as exc:
                                    pe['status'] = 'BLOCKED'
                                    pe['reason'] += '; ' + str(exc)
                        incident.update(policy_id=policy.policy_id, policy_name=policy.name, response_action=decision.action,
                                        action_taken=decision.action, response_status=pe['status'])
                        conn.execute('UPDATE rule_matches SET policy_id=? WHERE match_id=?', (policy.policy_id, match_id))
                    repo.save_audit('POLICY_TRIGGERED', policy.name, agent_id, details=pe, execution_source=execution_source)
                    hub.broadcast('policy.triggered', pe)
                repo.save_policy_evaluation(pe)
                conn.execute('UPDATE policy_evaluations SET condition_trace_json=? WHERE eval_id=?', (json.dumps(decision.condition_trace), eval_id))
                conn.execute('UPDATE policies SET last_evaluated=? WHERE policy_id=?', (now, policy.policy_id))
                repo.save_audit('POLICY_EVALUATED', policy.name, agent_id, details=pe, execution_source=execution_source)
                hub.broadcast('policy.evaluated', pe)
            repo.save_incident(incident)
            alerts.append(incident)
            hub.broadcast('rule.matched', match)
            hub.broadcast('risk.updated', {'agent_id': agent_id, 'risk_score': risk.new_score, 'trust_score': trust.trust_score})
            hub.broadcast('alert.created', incident)
        repo.update_service_heartbeat('Telemetry Processor', activity=True)
        repo.update_service_heartbeat('Rule Engine', activity=True)
        conn.execute("UPDATE zta_events SET processing_state='COMPLETED', processing_error=NULL WHERE event_id=?", (event.event_id,))
    return alerts
