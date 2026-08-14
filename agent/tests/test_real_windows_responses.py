import os
import sys
import pytest
import platform
from agent.responses.response_handler import AgentResponseHandler, QUARANTINE_DIR

def test_agent_response_handler_kill_process_dry_run():
    handler = AgentResponseHandler(mode="DRY_RUN")
    res = handler.execute_action("KILL_PROCESS", {"pid": 1234, "process_name": "test.exe"})
    assert res.success is True
    assert res.mode == "DRY_RUN"
    assert res.details["would_execute"] is True

def test_agent_response_handler_isolate_host_enforce():
    handler = AgentResponseHandler(mode="ENFORCE")
    res = handler.execute_action("ISOLATE_HOST", {})
    assert res.action == "ISOLATE_HOST"
    assert isinstance(res.success, bool)

def test_agent_response_handler_unisolate_host_enforce():
    handler = AgentResponseHandler(mode="ENFORCE")
    res = handler.execute_action("UNISOLATE_HOST", {})
    assert res.action == "UNISOLATE_HOST"
    assert isinstance(res.success, bool)

def test_agent_response_handler_quarantine_file_nonexistent():
    handler = AgentResponseHandler(mode="ENFORCE")
    res = handler.execute_action("QUARANTINE_FILE", {"file_path": "C:\\invalid_path_xyz_12345.exe"})
    assert res.success is False
    assert "does not exist" in res.message

def test_agent_response_handler_quarantine_file_real_tmp(tmp_path):
    test_file = tmp_path / "malicious_sample.exe"
    test_file.write_bytes(b"MZ_DUMMY_BINARY_DATA")

    handler = AgentResponseHandler(mode="ENFORCE")
    res = handler.execute_action("QUARANTINE_FILE", {"file_path": str(test_file)})

    assert res.success is True
    assert res.action == "QUARANTINE_FILE"
    assert not os.path.exists(str(test_file))
    assert "quarantine_path" in res.details
    assert os.path.exists(res.details["quarantine_path"])

def test_agent_response_handler_unsupported_action():
    handler = AgentResponseHandler(mode="ENFORCE")
    res = handler.execute_action("INVALID_ACTION_XYZ", {})
    assert res.success is False
    assert "Unsupported action type" in res.message
