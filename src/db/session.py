"""This module contains the database session and engine."""

from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    async_sessionmaker,
    create_async_engine,
)

from sqlalchemy.orm import DeclarativeBase

from src.core.config import settings

async_engine = create_async_engine(
    url=settings.DATABASE_URL,
    echo=True,
)

async_session = async_sessionmaker(async_engine, expire_on_commit=False)


class Base(AsyncAttrs, DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        yield session
