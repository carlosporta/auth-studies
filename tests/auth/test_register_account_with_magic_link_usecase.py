from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ecom.auth.models import AccountModel


async def test_should_register_account_with_magic_link_successfully(
    client: TestClient,
    username: str,
    async_session: AsyncSession,
):
    response = client.post(
        "/auth/register-with-magic-link",
        json={
            "username": username,
        },
    )
    assert response.status_code == status.HTTP_201_CREATED

    stmt = select(AccountModel).where(AccountModel.username == username)
    result = await async_session.execute(stmt)
    account = result.scalars().first()
    assert account


async def test_should_return_409_when_registering_account_with_an_existing_username(
    client: TestClient,
    account_with_password: AccountModel,
):
    response = client.post(
        "/auth/register-with-magic-link",
        json={
            "username": account_with_password.username,
        },
    )
    assert response.status_code == status.HTTP_409_CONFLICT


async def test_should_return_422_when_registering_account_with_an_invalid_username(
    client: TestClient,
):
    response = client.post(
        "/auth/register-with-magic-link",
        json={
            "username": "invalid",
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
