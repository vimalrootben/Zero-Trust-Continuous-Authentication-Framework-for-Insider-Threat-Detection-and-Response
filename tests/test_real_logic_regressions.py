"""Regression fixtures only: none of these tests executes a Windows action."""
from datetime import datetime
from unittest.mock import MagicMock, patch
import time

import pytest

from zta.engine.events.conditions import ConditionEvaluator, InvalidConditionError
from zta.engine.events.models import ZTAEvent, ZTAAgent, ZTAProcess
from zta.agent.rules.local_rule_engine import LocalRuleEngine
from zta.engine.policy.engine import ZTAPolicyEngine, ZTAPolicy
from zta.engine.response.engine import ZTAResponseEngine
from zta.agent.commands.command_receiver import AgentCommandReceiver
from zta.agent.storage.offline_queue import OfflineQueue, OfflineQueueError
from zta.powershell.ps_executor import PowerShellExecutor, InvalidParameterError


@pytest.mark.parametrize('op,actual,value,result', [
    ('eq', 2, 2, True), ('ne', 2, 2, False), ('gt', 2, 1, True),
    ('gte', 2, 2, True), ('lt', 2, 1, False), ('lte', 2, 2, True),
    ('in', 'a', ['a', 'b'], True), ('not_in', 'c', ['a'], True),
    ('contains', 'abc', 'b', True), ('contains_icase', 'PowerShell', 'SHELL', True),
    ('regex', 'abc12', '[0-9]+$', True), ('exists', 0, None, True),
    ('not_exists', None, None, True), ('gt', 'not-a-number', 2, False),
])
def test_real_operator_results(op, actual, value, result):
    trace = ConditionEvaluator().explain({'field': 'data.x', 'op': op, 'value': value}, {'data': {'x': actual}})
    assert trace['result'] is result
    assert trace['actual'] == actual


def test_nested_logic_records_every_branch():
    leaf = {'field': 'x', 'op': 'eq', 'value': 1}
    tree = {'all': [leaf, {'any': [leaf, {'not': leaf}]}]}
    trace = ConditionEvaluator().explain(tree, {'x': 1})
    assert trace['result'] is True
    assert trace['children'][1]['children'][1]['result'] is False
    assert ConditionEvaluator().evaluate(tree, {'x': 2}) is False


def test_regex_input_limit_and_timeout_are_safe():
    evaluator = ConditionEvaluator()
    oversized = evaluator.explain({'field':'x','op':'regex','value':'a+'}, {'x':'a' * 4097})
    assert oversized['result'] is False
    assert oversized['evaluation_error'] == 'REGEX_INPUT_LIMIT'

    started = time.monotonic()
    expensive = evaluator.explain({'field':'x','op':'regex','value':'((a|aa)+)+$'}, {'x':'a' * 3000 + '!'})
    assert time.monotonic() - started < .5
    assert expensive['result'] is False
    assert expensive['evaluation_error'] == 'REGEX_TIMEOUT'


def test_normal_regex_behavior_is_preserved():
    trace = ConditionEvaluator().explain({'field':'process.name','op':'regex','value':r'^power(shell)?\.exe$'}, {'process':{'name':'powershell.exe'}})
    assert trace['result'] is True
    assert 'evaluation_error' not in trace


@pytest.mark.parametrize('tree', [{}, {'all': []}, {'not': []}, {'all': [], 'any': []},
    {'field': 'x', 'op': 'in', 'value': 'a'}, {'field': 'x', 'op': 'shell', 'value': 'x'}])
def test_malformed_conditions_rejected(tree):
    with pytest.raises(InvalidConditionError):
        ConditionEvaluator().validate(tree)


def test_no_policy_matches_or_disabled_policy():
    policy = ZTAPolicy('existing', 'existing', 85, 100, 'LOGOUT_USER', False)
    assert ZTAPolicyEngine([policy]).evaluate('a', 99, 1) is None
    policy.enabled = True
    assert ZTAPolicyEngine([policy]).evaluate('a', 10, 90) is None
    assert ZTAPolicyEngine([]).evaluate('a', 99, 1) is None


def test_explicit_empty_rules_and_av_presence():
    event = ZTAEvent('e', datetime.now(), ZTAAgent('a', 'host'),
                     process=ZTAProcess(name='MsMpEng.exe'))
    assert LocalRuleEngine([]).evaluate(event) is None
    assert LocalRuleEngine().evaluate(event) is None
    event.event_type = 'PROCESS_TERMINATION'
    assert LocalRuleEngine().evaluate(event).rule_id == 'LOC-RULE-002'


def test_queue_capacity_retry_and_conflicting_identity(tmp_path):
    queue = OfflineQueue(str(tmp_path / 'queue.db'), max_size=1)
    queue.enqueue('1', 'process', 'LOW', {'data': 1})
    queue.enqueue('1', 'process', 'LOW', {'data': 1})
    queue.enqueue('2', 'process', 'LOW', {'data': 2})
    assert queue.queue_depth() == 2
    with pytest.raises(OfflineQueueError):
        queue.enqueue('1', 'process', 'LOW', {'data': 99})
    assert queue.dequeue_batch()[0]['payload'] == {'data': 1}


def test_unknown_action_is_not_success():
    assert ZTAResponseEngine().execute_action('NO_SUCH_ACTION', 'a').status == 'FAILED'
    assert ZTAResponseEngine().execute_action('NOTIFY_SOC', 'a').status == 'NOT_EXECUTED'


def test_unsigned_command_never_executes():
    executor = MagicMock()
    report = AgentCommandReceiver(executor).process_command({'command_id': 'c', 'action': 'LOGOUT_USER'})
    assert report.status == 'FAILED'
    executor.execute_template.assert_not_called()


@pytest.mark.parametrize('params', [{}, {'UserName': '*', 'SessionId': '1'},
    {'UserName': 'user', 'SessionId': '0'}, {'UserName': 'user', 'SessionId': 'bad'},
    {'UserName': 'user', 'SessionId': '1', 'Command': 'unexpected'}])
def test_logout_requires_exact_target(params):
    with patch('zta.powershell.ps_executor.subprocess.run') as run:
        with pytest.raises(InvalidParameterError):
            PowerShellExecutor().execute_template('LOGOUT_USER', params)
        run.assert_not_called()


@pytest.mark.parametrize('gone', [True, False])
def test_logout_success_requires_session_disappearance(gone):
    with patch('zta.powershell.ps_executor.WindowsSessions') as sessions, \
         patch('zta.powershell.ps_executor.subprocess.run') as run:
        sessions.return_value.verify_gone.return_value = gone
        run.return_value = MagicMock(returncode=0, stdout='request submitted', stderr='')
        result = PowerShellExecutor().execute_template('LOGOUT_USER', {'UserName': 'user', 'SessionId': '7'})
        sessions.return_value.validate_target.assert_called_once_with(7, 'user')
        assert result.success is gone
        assert result.verification == ('SESSION_NOT_ACTIVE' if gone else 'SESSION_STILL_PRESENT')


def test_logout_query_failure_is_not_success():
    with patch('zta.powershell.ps_executor.WindowsSessions') as sessions, \
         patch('zta.powershell.ps_executor.subprocess.run') as run:
        sessions.return_value.validate_target.side_effect = OSError('Access denied')
        result = PowerShellExecutor().execute_template('LOGOUT_USER', {'UserName': 'user', 'SessionId': '7'})
        assert result.success is False
        assert 'Access denied' in result.error
        run.assert_not_called()


def test_network_isolation_does_not_claim_unverified_success():
    with patch('zta.powershell.ps_executor.subprocess.run') as run:
        result = PowerShellExecutor().execute_template('NETWORK_ISOLATION')
        assert not result.success
        assert 'verification' in result.error
        run.assert_not_called()


@pytest.mark.parametrize('accepted,remaining', [(['1'], ['2']), (None, ['1', '2']), (['unrelated'], ['1', '2'])])
def test_sync_only_deletes_explicitly_acknowledged_ids(tmp_path, accepted, remaining):
    from zta.agent.agent_daemon import ZTAAgentDaemon
    agent = ZTAAgentDaemon(db_path=str(tmp_path / 'agent.db'))
    for identifier in ['1', '2']:
        agent.offline_queue.enqueue(identifier, 'process', 'LOW', {'data': identifier})
    response = MagicMock(status_code=201)
    response.json.return_value = {'accepted_event_ids': accepted}
    with patch('zta.agent.agent_daemon.requests.post', return_value=response):
        agent.sync_offline_queue()
    assert [e['event_id'] for e in agent.offline_queue.dequeue_batch()] == remaining


def test_event_retry_preserves_original_evidence(tmp_path):
    from zta.storage.database import ZTADatabase, ZTARepository
    repository = ZTARepository(ZTADatabase(str(tmp_path / 'manager.db')))
    event = ZTAEvent('e', datetime.now(), ZTAAgent('a', 'host'), raw_event={'original': True})
    repository.save_event(event)
    event.raw_event = {'replaced': True}
    with pytest.raises(ValueError):
        repository.save_event(event)
    rows = repository.get_recent_events()
    assert len(rows) == 1
    assert rows[0]['raw_event_json'] == '{"original": true}'
