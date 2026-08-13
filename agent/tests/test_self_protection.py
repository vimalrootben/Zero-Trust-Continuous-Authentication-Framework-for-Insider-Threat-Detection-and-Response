import pytest
from agent.config.config import agent_config
from agent.selfprotection.self_protection_manager import SelfProtectionManager

def test_self_protection_manager_start_stop():
    manager = SelfProtectionManager(agent_config)
    assert len(manager.guards) == 3
    manager.start()
    manager.stop()
