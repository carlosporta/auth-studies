from fastapi.testclient import TestClient
from pytest import fixture
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import selectinload
from sqlalchemy.pool import StaticPool

from ecom.auth.models import AccountModel
from ecom.auth.schemas import (
    RegisterAccountWithCredentialsSchema,
    RegisterAccountWithMagicLinkSchema,
)
from ecom.auth.types import Username
from ecom.auth.usecases import (
    register_account_with_credentials_usecase,
    register_account_with_magic_link_usecase,
)
from ecom.db import AsyncSessionMaker, create_tables
from ecom.main import create_app


@fixture(name="async_engine")
async def async_engine_fixture():
    engine = create_async_engine(
        "sqlite+aiosqlite:///",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    return engine


@fixture(name="async_session_maker")
async def async_session_maker_fixture(async_engine: AsyncEngine):
    async_session_maker = async_sessionmaker(async_engine, expire_on_commit=False)
    return async_session_maker


@fixture(name="async_session")
async def async_session_fixture(
    async_session_maker: async_sessionmaker,
):
    async with async_session_maker() as session:
        yield session


@fixture(name="client")
async def client_fixture(async_engine: AsyncEngine):
    await create_tables(async_engine)
    AsyncSessionMaker.configure(bind=async_engine)
    app = create_app()
    with TestClient(app) as client:
        yield client


@fixture(name="username")
def username_fixture() -> str:
    return "johndoe@example.com"


@fixture(name="password")
def password_fixture() -> str:
    return "password"


@fixture(name="account_with_password")
async def account_with_password_fixture(
    async_session: AsyncSession,
    async_engine: AsyncEngine,
    username: str,
    password: str,
) -> AccountModel:
    await create_tables(async_engine)
    schema = RegisterAccountWithCredentialsSchema(
        username=Username(username),
        password=password,
        password_confirmation=password,
    )
    await register_account_with_credentials_usecase(schema, async_session)
    stmt = (
        select(AccountModel)
        .options(
            selectinload(AccountModel.password_auth),
            selectinload(AccountModel.totp_auth),
        )
        .where(AccountModel.username == username)
    )
    result = await async_session.execute(stmt)
    account = result.scalars().first()
    return account  # type: ignore


@fixture(name="account_with_magic_link")
async def account_with_magic_link_fixture(
    async_session: AsyncSession,
    async_engine: AsyncEngine,
    username: str,
) -> AccountModel:
    await create_tables(async_engine)
    schema = RegisterAccountWithMagicLinkSchema(username=Username(username))
    await register_account_with_magic_link_usecase(schema, async_session)
    stmt = (
        select(AccountModel)
        .options(
            selectinload(AccountModel.magic_link_auth),
        )
        .where(AccountModel.username == username)
    )
    result = await async_session.execute(stmt)
    return result.scalars().first()  # type: ignore


@fixture(name="account_without_auth")
async def account_without_auth_fixture(
    async_session: AsyncSession,
    async_engine: AsyncEngine,
    username: str,
) -> AccountModel:
    await create_tables(async_engine)
    model = AccountModel(username=username)
    async_session.add(model)
    await async_session.commit()
    return model
