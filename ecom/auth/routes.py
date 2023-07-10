from typing import Annotated

import httpx
from fastapi import APIRouter, Header, HTTPException, status

from ecom.auth.exceptions import (
    AccountAlreadyExistsException,
    BadCredentialsException,
    ForbiddenException,
)
from ecom.auth.schemas import (
    AccountReadSchema,
    EncodedAccessTokenSchema,
    LoginWithPasswordSchema,
    LoginWithTOTPSchema,
    RegisterAccountWithCredentialsSchema,
    RegisterAccountWithGoogleOauthSchema,
    RegisterAccountWithMagicLinkSchema,
)
from ecom.auth.types import AccountId
from ecom.auth.usecases import (
    login_with_magic_link_usecase,
    login_with_password_usecase,
    login_with_totp_usecase,
    register_account_with_credentials_usecase,
    register_account_with_google_oauth_usecase,
    register_account_with_magic_link_usecase,
)
from ecom.db import DBSession
from ecom.settings import settings

router = APIRouter()


@router.post(
    "/register-with-credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=AccountReadSchema,
)
async def register_account(
    schema: RegisterAccountWithCredentialsSchema,
    session: DBSession,
) -> AccountReadSchema:
    try:
        acc = await register_account_with_credentials_usecase(schema, session)
        return acc
    except AccountAlreadyExistsException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.post(
    "/password-verify",
    status_code=status.HTTP_200_OK,
    response_model=EncodedAccessTokenSchema,
)
async def login_with_password(
    schema: LoginWithPasswordSchema,
    session: DBSession,
) -> EncodedAccessTokenSchema:
    try:
        jwt = await login_with_password_usecase(schema, session)
        return jwt
    except BadCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except ForbiddenException as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )


@router.post(
    "/totp-verify",
    status_code=status.HTTP_200_OK,
    response_model=EncodedAccessTokenSchema,
)
async def login_with_totp(
    schema: LoginWithTOTPSchema,
    authorization: Annotated[str, Header()],
    session: DBSession,
) -> EncodedAccessTokenSchema:
    try:
        return await login_with_totp_usecase(schema, authorization, session)
    except BadCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except ForbiddenException as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )


@router.post(
    "/register-with-magic-link",
    status_code=status.HTTP_201_CREATED,
    response_model=AccountReadSchema,
)
async def register_account_with_magic_link(
    schema: RegisterAccountWithMagicLinkSchema,
    session: DBSession,
) -> AccountReadSchema:
    try:
        acc = await register_account_with_magic_link_usecase(schema, session)
        return acc
    except AccountAlreadyExistsException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.get("/magic-link-verify")
async def verify_magic_link(
    accountid: AccountId,
    token: str,
    session: DBSession,
) -> EncodedAccessTokenSchema:
    try:
        return await login_with_magic_link_usecase(accountid, token, session)
    except BadCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


def authorize(code):
    link = settings.auth.google_oauth.authorization_uri
    data = {
        "code": code,
        "client_id": settings.auth.google_oauth.client_id,
        "client_secret": settings.auth.google_oauth.client_secret,
        "redirect_uri": settings.auth.google_oauth.redirect_uri,
        "grant_type": "authorization_code",
    }
    response = httpx.post(link, data=data)
    if response.status_code != status.HTTP_200_OK:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad credentials",
        )
    return response.json()["access_token"]


def get_username(access_token):
    link = settings.auth.google_oauth.user_email_uri
    headers = {"Authorization": f"Bearer {access_token}"}
    response = httpx.post(link, headers=headers)
    return response.json()["email"]


@router.get("/google-oauth")
async def google_oauth(code: str, session: DBSession) -> EncodedAccessTokenSchema:
    access_token = authorize(code)
    username = get_username(access_token)

    try:
        await register_account_with_google_oauth_usecase(
            RegisterAccountWithGoogleOauthSchema(
                username=username,
            ),
            session,
        )
    except AccountAlreadyExistsException:
        pass

    token = EncodedAccessTokenSchema(access_token=access_token)
    return token
