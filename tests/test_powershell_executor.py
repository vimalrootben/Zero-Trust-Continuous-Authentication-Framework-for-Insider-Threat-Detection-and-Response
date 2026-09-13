"""Unit tests for PowerShellExecutor."""

import pytest

from zta.powershell.ps_executor import (
    InvalidParameterError,
    PSResult,
    PowerShellExecutor,
    UnknownTemplateError,
)


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
