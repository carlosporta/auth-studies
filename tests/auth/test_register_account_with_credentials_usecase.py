from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ecom.auth.models import AccountModel


async def test_should_register_account_successfully(
    client: TestClient,
    async_session: AsyncSession,
    username: str,
    password: str,
):
    response = client.post(
        "/auth/register-with-credentials",
        json={
            "username": username,
            "password": password,
            "password_confirmation": password,
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    stmt = select(AccountModel).where(AccountModel.username == username)
    result = await async_session.execute(stmt)
    account = result.scalars().first()
    assert account


async def test_should_not_register_account_when_passwords_do_not_match(
    client: TestClient,
    username: str,
    password: str,
):
    response = client.post(
        "/auth/register-with-credentials",
        json={
            "username": username,
            "password": password,
            "password_confirmation": "password123",
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_should_not_register_account_when_username_already_exists(
    client: TestClient,
    account_with_password: AccountModel,
    password: str,
):
    response = client.post(
        "/auth/register-with-credentials",
        json={
            "username": account_with_password.username,
            "password": password,
            "password_confirmation": password,
        },
    )
    assert response.status_code == status.HTTP_409_CONFLICT


async def test_should_not_register_account_when_username_is_invalid(
    client: TestClient,
    password: str,
):
    response = client.post(
        "/auth/register-with-credentials",
        json={
            "username": "invalid",
            "password": password,
            "password_confirmation": password,
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_should_not_register_account_when_password_is_invalid(
    client: TestClient,
    username: str,
):
    response = client.post(
        "/auth/register-with-credentials",
        json={
            "username": username,
            "password": "123",
            "password_confirmation": "123",
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
