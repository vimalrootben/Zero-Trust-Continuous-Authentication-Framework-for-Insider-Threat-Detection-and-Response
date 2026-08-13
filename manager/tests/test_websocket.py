import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock

from manager.websocket.connection_manager import ConnectionManager
from manager.websocket.command_dispatcher import CommandDispatcher

@pytest.mark.asyncio
async def test_connection_manager_agent_lifecycle():
    mgr = ConnectionManager()
    agent_id = uuid.uuid4()
    ws_mock = AsyncMock()

    await mgr.connect_agent(agent_id, ws_mock)
    assert agent_id in mgr.active_agents

    mgr.disconnect_agent(agent_id)
    assert agent_id not in mgr.active_agents

@pytest.mark.asyncio
async def test_connection_manager_dashboard_lifecycle():
    mgr = ConnectionManager()
    user_id = uuid.uuid4()
    ws_mock = AsyncMock()

    await mgr.connect_dashboard(user_id, ws_mock)
    assert user_id in mgr.active_dashboards
    assert ws_mock in mgr.active_dashboards[user_id]

    mgr.disconnect_dashboard(user_id, ws_mock)
    assert user_id not in mgr.active_dashboards

@pytest.mark.asyncio
async def test_command_dispatcher_push_and_offline_fallback():
    mgr = ConnectionManager()
    agent_id = uuid.uuid4()
    cmd_id = uuid.uuid4()
    
    dispatcher = CommandDispatcher(connection_manager=mgr)
    
    payload = {
        "command_id": str(cmd_id),
        "command_type": "LOGOFF_USER",
        "agent_id": str(agent_id)
    }

    # When agent is disconnected -> returns False
    session_mock = AsyncMock()
    pushed = await dispatcher.dispatch(cmd_id, payload, db_session=session_mock)
    assert pushed is False

    # When agent is connected -> pushes command
    ws_mock = AsyncMock()
    await mgr.connect_agent(agent_id, ws_mock)

    cmd_row_mock = MagicMock()
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = cmd_row_mock
    session_mock.execute.return_value = exec_result

    pushed_online = await dispatcher.dispatch(cmd_id, payload, db_session=session_mock)
    assert pushed_online is True
    ws_mock.send_json.assert_called_once()
