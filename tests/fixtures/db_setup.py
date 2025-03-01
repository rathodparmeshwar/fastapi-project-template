import os
import secrets
import string
from typing import AsyncGenerator, Tuple

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config.settings import settings


@pytest_asyncio.fixture(loop_scope="function")
async def pg_connection() -> AsyncGenerator[AsyncEngine, None]:
    """Create an async connection to the db."""
    #settings.TESTING_DATABASE_URL = "postgresql+asyncpg://postgres:asd@localhost:5432/"
    print(f"Creating connection to DB server, {settings.TESTING_DATABASE_URL}postgres")

    engine = create_async_engine(
        f"{settings.TESTING_DATABASE_URL}postgres", isolation_level="AUTOCOMMIT"
    )
    try:
        yield engine
    finally:
        print("Closing connection to DB server")
        await engine.dispose()


@pytest.fixture(scope="function")
async def init_pg_db(
    pg_connection: AsyncEngine,
) -> AsyncGenerator[Tuple[AsyncEngine, async_sessionmaker[AsyncSession]], None]:
    """Create and drop the database."""
    db_name = "wakura_test_" + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )

    async with pg_connection.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{db_name}"'))

    print(f"Created test database {db_name}...")
    engine = create_async_engine(f"{settings.TESTING_DATABASE_URL}{db_name}")
    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    try:
        yield engine, async_session
    finally:
        await engine.dispose()
        async with pg_connection.connect() as conn:
            await conn.execute(text(f'DROP DATABASE "{db_name}"'))
        print(f"Deleted test database {db_name}...")


@pytest.fixture(scope="function")
async def empty_pg_db(
    init_pg_db: Tuple[AsyncEngine, async_sessionmaker[AsyncSession]]
) -> AsyncGenerator[Tuple[AsyncEngine, async_sessionmaker[AsyncSession]], None]:
    """Set up empty database with schema."""
    engine, async_session = init_pg_db

    async with engine.begin() as conn:
        try:
            print(f"Base cwd is: {os.getcwd()}")
            with open("./tests/pg_db_setup/setup.sql", encoding="utf8") as file:
                setup_sql = file.read()
                await conn.execute(text(setup_sql))

            files = [
                filename
                for filename in os.scandir("./tests/pg_db_setup/schemas")
                if filename.is_file()
            ]
            sorted_files = sorted(files, key=lambda f: f.name)

            for filename in sorted_files:
                print(f"Applying schema {filename.path}")
                with open(filename.path, encoding="utf8") as file:
                    commands = file.read()
                
                for command in commands.split(";"):
                    await conn.execute(text(command))

        except Exception as e:
            print(f"Error setting up database: {e}")
            raise

    yield engine, async_session


@pytest.fixture(scope="function")
async def db_session(
    empty_pg_db: Tuple[AsyncEngine, async_sessionmaker[AsyncSession]]
) -> AsyncGenerator[AsyncSession, None]:
    """Provide async database session for tests."""
    engine, async_session = empty_pg_db

    async with async_session() as session:
        try:
            #async with session.begin():
            yield session
        finally:
            await session.rollback()
            await session.close()