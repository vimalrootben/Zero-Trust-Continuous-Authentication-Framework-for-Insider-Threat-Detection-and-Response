import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.collectors.network_collector import NetworkConnectionProvider
from agent.storage.models import TelemetryEventDTO
from manager.database.session import async_session_maker
from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.telemetry import TelemetryEvent
from sqlalchemy import select

async def populate_real_host_network():
    print("Collecting real listening ports and active sockets from host...")
    provider = NetworkConnectionProvider()
    conns = provider.get_connections()
    print(f"Discovered {len(conns)} active network sockets on host.")

    async with async_session_maker() as db:
        agents = (await db.execute(select(Agent))).scalars().all()
        if not agents:
            print("No agents in DB.")
            return

        for agent in agents:
            print(f"Syncing real network sockets for Agent {agent.hostname} ({agent.id})...")
            for c in conns:
                is_listen = c.get("is_listening")
                event_type = "LISTEN_STARTED" if is_listen else "CONNECTION_OPENED"
                event = TelemetryEvent(
                    id=uuid.uuid4(),
                    agent_id=agent.id,
                    collector_type="network",
                    event_type=event_type,
                    raw_data=c,
                    timestamp=datetime.now(timezone.utc),
                    processed=False
                )
                db.add(event)
            await db.commit()
            print(f"Committed real network events for {agent.hostname}.")

if __name__ == "__main__":
    asyncio.run(populate_real_host_network())
