"""Credentials for isolated test endpoints only; never deployed to runtime data."""
import json
import pytest

@pytest.fixture(autouse=True)
def test_credentials(monkeypatch):
    agents = ['abc','001','TEST-HOST-01','agent-runtime-01','win-agent-01','win-agent-02','win-agent-03','offline-agent-01','sync-agent-01','ws-agent-test']
    monkeypatch.setenv('ZTA_AGENT_TOKENS',json.dumps({a:'fixture-agent-token' for a in agents}))
    monkeypatch.setenv('ZTA_ADMIN_TOKEN','fixture-admin-token')
