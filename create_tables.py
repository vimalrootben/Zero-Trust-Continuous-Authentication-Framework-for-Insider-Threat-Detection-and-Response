"""
Bootstrap script: Creates all tables from SQLAlchemy ORM models and stamps Alembic to head.
Run this when the DB is fresh (no tables) or has been reset.
"""
import asyncio
import sys
sys.path.insert(0, '.')

from manager.database.base import Base
from manager.database.session import engine
import manager.database.models  # noqa: F401 — registers all models

async def create_all_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("All tables created successfully.")

asyncio.run(create_all_tables())
