"""Unit tests for PowerShellExecutor."""

import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone
from types import SimpleNamespace

from zta.powershell.ps_executor import (
    InvalidParameterError,
    PSResult,
    PowerShellExecutor,
    UnknownTemplateError,
)
from zta.agent.commands.command_receiver import AgentCommandReceiver
from zta.engine.events.models import ZTAAgent, ZTAEvent, ZTAProcess
from zta.engine.response.command_builder import build_command


def test_allowlisted_template_dry_run():
    """Test dry-run parameter validation for allowlisted templates."""
    executor = PowerShellExecutor()

    res = executor.execute_template(
        "KILL_PROCESS", params={"ProcessName": "calc.exe", "ProcessId":"777", "ProcessPath":"C:\\Windows\\calc.exe", "ProcessCreatedAt":"2026-09-14T10:00:00Z"}, dry_run=True
    )
    assert res.success is True
    assert "[DRY_RUN]" in res.output
    assert "kill_process.ps1" in res.output


def test_unknown_template_rejected():
    """Test that non-allowlisted actions raise UnknownTemplateError."""
    executor = PowerShellExecutor()
    with pytest.raises(UnknownTemplateError):
        executor.execute_template("ARBITRARY_SHELL_EXECUTION", dry_run=True)


def test_command_injection_parameters_rejected():
    """Test that command injection characters raise InvalidParameterError."""
    executor = PowerShellExecutor()

    # Test semicolon injection
    with pytest.raises(InvalidParameterError):
        executor.execute_template(
            "KILL_PROCESS", params={"ProcessName": "calc.exe; Start-Process cmd.exe"}, dry_run=True
        )

    # Test pipe injection
    with pytest.raises(InvalidParameterError):
        executor.execute_template(
            "LOGOFF_USER", params={"UserName": "testuser | Remove-Item C:\\"}, dry_run=True
        )

    # Test backtick injection
    with pytest.raises(InvalidParameterError):
        executor.execute_template(
            "NETWORK_ISOLATION", params={"ManagerIP": "`whoami`"}, dry_run=True
        )


def test_network_isolation_preserves_configured_manager_address():
    executor=MagicMock();executor.execute_template.return_value=PSResult(True,'ok',verification='ISOLATION_VERIFIED')
    receiver=AgentCommandReceiver(executor,command_validator=lambda command: None,manager_address='manager.internal')
    report=receiver.process_command({'command_id':'isolate','action_type':'ISOLATE_ENDPOINT','params':{'ManagerIP':'wrong.example'}})
    assert report.status=='SUCCESS'
    executor.execute_template.assert_called_once_with(
        action_type='NETWORK_ISOLATION',params={'ManagerIP':'manager.internal'},dry_run=False)


def test_command_builder_routes_isolation_and_allowlisted_script_actions(monkeypatch):
    monkeypatch.setenv('ZTA_MANAGER_IP','10.20.30.40')
    event=ZTAEvent('event',datetime.now(timezone.utc),ZTAAgent('agent','host'),
                   raw_event={'timestamp':datetime.now(timezone.utc).isoformat(),'script_id':'DEMO_LOG_PUSH'})
    isolation=build_command(SimpleNamespace(action='ISOLATE_ENDPOINT',policy_id='p1',policy_code='P1'),event,'c1','a1')
    assert isolation['params']=={'Action':'ISOLATE','ManagerIP':'10.20.30.40'}
    script=build_command(SimpleNamespace(action='DEMO_SCRIPT',policy_id='p2',policy_code='P2'),event,'c2','a2')
    assert script['executor']=='ALLOWLISTED_SCRIPT'
    assert script['params']=={'script_id':'DEMO_LOG_PUSH','correlation_id':'a2'}


def test_network_isolation_template_is_explicitly_unavailable():
    script=(PowerShellExecutor().scripts_dir/'network_isolation.ps1').read_text(encoding='utf-8')
    assert 'Network isolation is unavailable' in script
    assert 'Disable-NetFirewallRule' not in script and 'Enable-NetFirewallRule' not in script
    result = PowerShellExecutor().execute_template('NETWORK_ISOLATION', {'Action':'ISOLATE','ManagerIP':'127.0.0.1'})
    assert result.success is False
    assert result.verification == 'UNAVAILABLE'


def test_process_command_carries_pid_reuse_identity():
    now = datetime.now(timezone.utc)
    event = ZTAEvent('event-process', now, ZTAAgent('agent','host'),
                     process=ZTAProcess(name='worker.exe', path='C:\\Temp\\worker.exe', pid=777,
                                        created_at=now.isoformat()), raw_event={'timestamp':now.isoformat()})
    command = build_command(SimpleNamespace(action='KILL_PROCESS',policy_id='p1',policy_code='P1'), event, 'cmd', 'alert')
    assert command['params'] == {'ProcessName':'worker.exe','ProcessId':'777',
                                 'ProcessPath':'C:\\Temp\\worker.exe','ProcessCreatedAt':now.isoformat()}


def test_process_handler_has_all_fail_closed_identity_and_protection_checks():
    script=(PowerShellExecutor().scripts_dir/'kill_process.ps1').read_text(encoding='utf-8')
    for contract in ('Target process does not exist', 'PID identity name changed',
                     'PID executable path changed', 'PID creation time changed',
                     'Protected process target', 'Protected system/security process target',
                     'Target process remains active', 'PROCESS_NOT_ACTIVE'):
        assert contract in script
