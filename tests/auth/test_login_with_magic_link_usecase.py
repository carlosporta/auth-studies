from uuid import uuid4

from fastapi import status
from fastapi.testclient import TestClient
from pyotp import TOTP

from ecom.auth.models import AccountModel


async def test_should_login_with_a_magic_link_correctly(
    client: TestClient,
    account_with_magic_link: AccountModel,
):
    secret = account_with_magic_link.magic_link_auth.secret
    acc_id = account_with_magic_link.id
    totp = TOTP(secret).now()
    link = f"/auth/magic-link-verify?accountid={acc_id}&token={totp}"
    response = client.get(link)
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()


async def test_should_not_login_with_a_magic_link_with_wrong_totp(
    client: TestClient,
    account_with_magic_link: AccountModel,
):
    acc_id = account_with_magic_link.id
    totp = "123456"
    link = f"/auth/magic-link-verify?accountid={acc_id}&token={totp}"
    response = client.get(link)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_should_not_with_an_not_existing_account(client: TestClient):
    acc_id = str(uuid4())
    totp = "123456"
    link = f"/auth/magic-link-verify?accountid={acc_id}&token={totp}"
    response = client.get(link)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
