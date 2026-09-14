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
from zta.engine.events.models import ZTAAgent, ZTAEvent
from zta.engine.response.command_builder import build_command


def test_allowlisted_template_dry_run():
    """Test dry-run parameter validation for allowlisted templates."""
    executor = PowerShellExecutor()

    res = executor.execute_template(
        "KILL_PROCESS", params={"ProcessName": "calc.exe", "ProcessId":"777"}, dry_run=True
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


def test_network_isolation_template_snapshots_allow_rules_and_restores_them():
    script=(PowerShellExecutor().scripts_dir/'network_isolation.ps1').read_text(encoding='utf-8')
    assert 'disabled_allow_rules' in script
    assert 'Disable-NetFirewallRule' in script and 'Enable-NetFirewallRule' in script
    assert 'ZTA_Manager_Reachability' in script and 'ZTA_DNS_Reachability' in script
    assert 'ISOLATION_VERIFIED' in script and 'UNISOLATION_VERIFIED' in script
