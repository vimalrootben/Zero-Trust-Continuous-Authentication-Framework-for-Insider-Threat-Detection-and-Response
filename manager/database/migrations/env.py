import asyncio
import sys
import os
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# Ensure the project root (parent of manager/) is on sys.path
# so that `from manager.xxx import ...` works when alembic is invoked
# from any directory.
_here = os.path.dirname(__file__)  # .../manager/database/migrations
_root = os.path.abspath(os.path.join(_here, "..", "..", ".."))  # .../ztav2/
if _root not in sys.path:
    sys.path.insert(0, _root)

# Import settings and Base
from manager.config import settings  # noqa: E402
from manager.database.base import Base  # noqa: E402
import manager.database.models  # noqa: E402, F401 — registers all table metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generates SQL without a live DB)."""
    url = settings.DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode using asyncpg."""
    connectable = create_async_engine(
        settings.DATABASE_URL,
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
