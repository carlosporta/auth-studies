from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


AsyncSessionMaker = async_sessionmaker(expire_on_commit=False)


async def get_async_session():
    async with AsyncSessionMaker() as session:
        yield session


DBSession = Annotated[AsyncSession, Depends(get_async_session)]


async def create_tables(engine: AsyncEngine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
