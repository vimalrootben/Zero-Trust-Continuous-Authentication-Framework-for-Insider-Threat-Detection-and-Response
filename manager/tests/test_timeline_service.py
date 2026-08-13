import uuid
from datetime import datetime, timezone
import pytest

from manager.timeline.timeline_service import TimelineService

@pytest.mark.asyncio
async def test_timeline_event_recording_and_retrieval(db_session):
    agent_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    service = TimelineService(db_session)

    # Record agent timeline event
    e1 = await service.record_event(
        event_source="telemetry",
        description="Process started: cmd.exe",
        agent_id=agent_id,
        db_session=db_session
    )

    # Record incident timeline event
    e2 = await service.record_event(
        event_source="alert",
        description="High risk alert triggered",
        incident_id=incident_id,
        db_session=db_session
    )

    agent_timeline = await service.get_agent_timeline(agent_id, db_session=db_session)
    assert len(agent_timeline) == 1
    assert agent_timeline[0].description == "Process started: cmd.exe"

    incident_timeline = await service.get_incident_timeline(incident_id, db_session=db_session)
    assert len(incident_timeline) == 1
    assert incident_timeline[0].description == "High risk alert triggered"
