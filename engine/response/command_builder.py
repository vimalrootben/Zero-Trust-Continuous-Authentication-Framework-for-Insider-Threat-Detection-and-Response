"""Translate existing policy decisions into exact, allowlisted endpoint targets."""
from datetime import datetime, timedelta, timezone
from zta.powershell.ps_executor import PowerShellExecutor


def build_command(decision, event, command_id, alert_id, source='MANAGER'):
    now = datetime.now(timezone.utc)
    if event.timestamp.tzinfo is None or not event.raw_event.get('timestamp'):
        raise ValueError('Response requires an actual timezone-aware event timestamp')
    age = (now-event.timestamp).total_seconds()
    if age > 300 or age < -60:
        raise ValueError('Event is outside the live response freshness window')
    action = decision.action
    if action in ('LOGOUT_USER', 'LOGOFF_USER'):
        name = event.user.name
        if name and event.user.domain and '\\' not in name:
            name = event.user.domain + '\\' + name
        params = {'UserName': name, 'SessionId': str(event.user.session_id or '')}
    elif action == 'KILL_PROCESS':
        if not event.process.pid or not event.process.name:
            raise ValueError('Process response requires actual process ID and name')
        params = {'ProcessName': event.process.name, 'ProcessId': str(event.process.pid)}
    else:
        raise ValueError('Action has no verified response provider: ' + action)
    PowerShellExecutor().execute_template(action, params, dry_run=True)
    now = datetime.now(timezone.utc)
    return dict(command_id=command_id, agent_id=event.agent.id, policy_id=decision.policy_id,
                policy_code=decision.policy_code, alert_id=alert_id, action_type=action,
                params=params, status='QUEUED', executor='WINDOWS_POWERSHELL',
                created_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat(),
                execution_source=source)
