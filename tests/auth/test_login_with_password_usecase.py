from fastapi import status
from fastapi.testclient import TestClient

from ecom.auth.crypto import decode_jwt_token
from ecom.auth.models import AccountModel
from ecom.settings import settings


async def test_should_login_with_password_successfully(
    client: TestClient,
    account_with_password: AccountModel,
    password: str,
):
    response = client.post(
        "/auth/password-verify",
        json={
            "username": account_with_password.username,
            "password": password,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    token = response.json().get("access_token")

    assert token is not None
    decoded = decode_jwt_token(
        token,
        settings.auth.tmp_jwt_secret,
        settings.auth.tmp_jwt_algorithm,
    )
    assert decoded.sub == str(account_with_password.id)
    assert decoded.scopes == ["totp:login"]


async def test_should_not_login_with_a_non_existing_account(
    client: TestClient,
    username: str,
    password: str,
):
    response = client.post(
        "/auth/password-verify",
        json={
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_login_with_a_wrong_password(
    client: TestClient,
    account_with_password: AccountModel,
):
    response = client.post(
        "/auth/password-verify",
        json={
            "username": account_with_password.username,
            "password": "wrong_password",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_login_with_an_account_without_password_auth(
    client: TestClient,
    account_without_auth: AccountModel,
    password: str,
):
    response = client.post(
        "/auth/password-verify",
        json={
            "username": account_without_auth.username,
            "password": password,
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
