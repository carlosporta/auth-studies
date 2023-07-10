from datetime import datetime, timedelta

from fastapi import status
from fastapi.testclient import TestClient
from pydantic import EmailStr
from pyotp import TOTP
from sqlalchemy.ext.asyncio import AsyncSession

from ecom.auth.crypto import decode_jwt_token, encode_payload
from ecom.auth.models import AccountModel
from ecom.auth.schemas import (
    AccessTokenPayloadSchema,
    LoginWithPasswordSchema,
    ScopeEnum,
)
from ecom.auth.usecases import login_with_password_usecase
from ecom.settings import settings


async def test_should_login_with_totp_successfully(
    client: TestClient,
    account_with_password: AccountModel,
    async_session: AsyncSession,
    password: str,
) -> None:
    schema = LoginWithPasswordSchema(
        username=EmailStr(account_with_password.username),
        password=password,
    )
    result = await login_with_password_usecase(
        schema=schema,
        session=async_session,
    )
    tmp_token = result.access_token
    totp = TOTP(account_with_password.totp_auth.secret).now()
    response = client.post(
        "/auth/totp-verify",
        json={"totp": totp},
        headers={"Authorization": f"Bearer {tmp_token}"},
    )
    assert response.status_code == status.HTTP_200_OK
    token = response.json().get("access_token")
    assert token is not None
    decoded = decode_jwt_token(
        token,
        settings.auth.full_jwt_secret,
        settings.auth.full_jwt_algorithm,
    )
    assert decoded.sub == str(account_with_password.id)
    assert decoded.scopes == ["full:access"]


async def test_should_return_401_when_logining_with_a_wrong_totp(
    client: TestClient,
    account_with_password: AccountModel,
    async_session: AsyncSession,
    password: str,
) -> None:
    schema = LoginWithPasswordSchema(
        username=EmailStr(account_with_password.username),
        password=password,
    )
    result = await login_with_password_usecase(
        schema=schema,
        session=async_session,
    )
    tmp_token = result.access_token
    response = client.post(
        "/auth/totp-verify",
        json={"totp": "wrong_totp"},
        headers={"Authorization": f"Bearer {tmp_token}"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_sigin_with_invalid_token(client: TestClient):
    response = client.post(
        "/auth/totp-verify",
        json={"totp": "wrong_totp"},
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_sigin_with_expired_token(
    client: TestClient,
    account_with_password: AccountModel,
):
    payload = AccessTokenPayloadSchema(
        sub=str(account_with_password.id),
        exp=datetime.utcnow() - timedelta(seconds=1),
        scopes=[ScopeEnum.totp_login],
    )
    expired_token = encode_payload(
        payload,
        key=settings.auth.tmp_jwt_secret,
        algorithm=settings.auth.tmp_jwt_algorithm,
    )

    totp = TOTP(account_with_password.totp_auth.secret).now()

    response = client.post(
        "/auth/totp-verify",
        json={"totp": totp},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_sigin_with_a_token_with_invalid_scopes(
    client: TestClient,
    account_with_password: AccountModel,
):
    payload = AccessTokenPayloadSchema(
        sub=str(account_with_password.id),
        exp=datetime.utcnow() + timedelta(seconds=30),
        scopes=[ScopeEnum.full_access],
    )
    token = encode_payload(
        payload,
        key=settings.auth.tmp_jwt_secret,
        algorithm=settings.auth.tmp_jwt_algorithm,
    )

    totp = TOTP(account_with_password.totp_auth.secret).now()

    response = client.post(
        "/auth/totp-verify",
        json={"totp": totp},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_should_not_signin_with_a_token_with_invalid_sub(
    client: TestClient,
    account_with_password: AccountModel,
):
    payload = AccessTokenPayloadSchema(
        sub="invalid_sub",
        exp=datetime.utcnow() + timedelta(seconds=30),
        scopes=[ScopeEnum.totp_login],
    )
    token = encode_payload(
        payload,
        key=settings.auth.tmp_jwt_secret,
        algorithm=settings.auth.tmp_jwt_algorithm,
    )

    totp = TOTP(account_with_password.totp_auth.secret).now()

    response = client.post(
        "/auth/totp-verify",
        json={"totp": totp},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
