from datetime import datetime, timedelta

from jose import JWTError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ecom.auth.crypto import (
    decode_jwt_token,
    encode_payload,
    gen_magic_link_secret,
    gen_totp_secret,
    hash_password,
    verify_password,
    verify_totp,
)
from ecom.auth.exceptions import (
    AccountAlreadyExistsException,
    BadCredentialsException,
    ForbiddenException,
)
from ecom.auth.models import (
    AccountModel,
    MagicLinkAuthModel,
    PasswordAuthModel,
    TotpAuthModel,
)
from ecom.auth.schemas import (
    AccessTokenPayloadSchema,
    AccountReadSchema,
    EncodedAccessTokenSchema,
    LoginWithPasswordSchema,
    LoginWithTOTPSchema,
    RegisterAccountWithCredentialsSchema,
    RegisterAccountWithGoogleOauthSchema,
    RegisterAccountWithMagicLinkSchema,
    ScopeEnum,
)
from ecom.auth.types import AccountId
from ecom.settings import settings


async def register_account_with_credentials_usecase(
    schema: RegisterAccountWithCredentialsSchema,
    session: AsyncSession,
) -> AccountReadSchema:
    pwhash = hash_password(schema.password)
    account_data = schema.dict(exclude={"password", "password_confirmation"})
    pw_model = PasswordAuthModel(password_hash=pwhash)
    totp_model = TotpAuthModel(secret=gen_totp_secret())
    acc_model = AccountModel(
        **account_data,
        password_auth=pw_model,
        totp_auth=totp_model,
    )

    session.add(acc_model)

    try:
        await session.commit()
        await session.refresh(acc_model)
    except IntegrityError as e:
        await session.rollback()
        if "UNIQUE constraint failed: accounts.username" in str(e):
            raise AccountAlreadyExistsException()
        raise e

    return AccountReadSchema.from_orm(acc_model)


async def register_account_with_magic_link_usecase(
    schema: RegisterAccountWithMagicLinkSchema,
    session: AsyncSession,
) -> AccountReadSchema:
    magic_link_model = MagicLinkAuthModel(secret=gen_magic_link_secret())
    model = AccountModel(
        **schema.dict(),
        magic_link_auth=magic_link_model,
    )

    session.add(model)
    try:
        await session.commit()
        await session.refresh(model)
        return AccountReadSchema.from_orm(model)
    except IntegrityError as e:
        if "UNIQUE constraint failed: accounts.username" in str(e):
            raise AccountAlreadyExistsException()
        raise e


async def register_account_with_google_oauth_usecase(
    schema: RegisterAccountWithGoogleOauthSchema,
    session: AsyncSession,
) -> AccountReadSchema:
    model = AccountModel(
        **schema.dict(),
    )

    session.add(model)
    try:
        await session.commit()
        return AccountReadSchema.from_orm(model)
    except IntegrityError as e:
        if "UNIQUE constraint failed: accounts.username" in str(e):
            raise AccountAlreadyExistsException()
        raise e


async def login_with_password_usecase(
    schema: LoginWithPasswordSchema,
    session: AsyncSession,
) -> EncodedAccessTokenSchema:
    stmt = (
        select(AccountModel)
        .options(selectinload(AccountModel.password_auth))
        .where(AccountModel.username == schema.username)
    )
    result = await session.execute(stmt)
    model = result.scalars().first()
    if not model or model.password_auth is None:
        raise BadCredentialsException()

    if not verify_password(schema.password, model.password_auth.password_hash):
        raise BadCredentialsException()

    payload = AccessTokenPayloadSchema(
        sub=str(model.id),
        exp=datetime.utcnow()
        + timedelta(seconds=settings.auth.tmp_token_expiration_seconds),
        scopes=[ScopeEnum.totp_login],
    )
    jwt = encode_payload(
        payload,
        key=settings.auth.tmp_jwt_secret,
        algorithm=settings.auth.tmp_jwt_algorithm,
    )
    return EncodedAccessTokenSchema(access_token=jwt)


async def login_with_totp_usecase(
    schema: LoginWithTOTPSchema,
    bearer: str,
    session: AsyncSession,
) -> EncodedAccessTokenSchema:
    try:
        payload = decode_jwt_token(
            bearer.split(" ")[1],
            settings.auth.tmp_jwt_secret,
            settings.auth.tmp_jwt_algorithm,
        )
    except JWTError:
        raise BadCredentialsException()

    try:
        AccountId(payload.sub)
    except ValueError:
        raise BadCredentialsException()

    if not payload.scopes or ScopeEnum.totp_login not in payload.scopes:
        raise ForbiddenException()

    stmt = (
        select(AccountModel)
        .options(selectinload(AccountModel.totp_auth))
        .where(AccountModel.id == AccountId(payload.sub))
    )
    result = await session.execute(stmt)
    model = result.scalars().first()
    if not model or not verify_totp(schema.totp, model.totp_auth.secret):
        raise BadCredentialsException()

    payload = AccessTokenPayloadSchema(
        sub=str(model.id),
        exp=datetime.utcnow()
        + timedelta(seconds=settings.auth.full_jwt_expiration_seconds),
        scopes=[ScopeEnum.full_access],
    )
    jwt = encode_payload(
        payload,
        key=settings.auth.full_jwt_secret,
        algorithm=settings.auth.full_jwt_algorithm,
    )
    return EncodedAccessTokenSchema(access_token=jwt)


async def login_with_magic_link_usecase(
    account_id: AccountId,
    totp: str,
    session: AsyncSession,
) -> EncodedAccessTokenSchema:
    stmt = (
        select(AccountModel)
        .options(selectinload(AccountModel.magic_link_auth))
        .where(AccountModel.id == account_id)
    )
    result = await session.execute(stmt)
    model = result.scalars().first()

    if not model or not verify_totp(totp, model.magic_link_auth.secret):
        raise BadCredentialsException()

    payload = AccessTokenPayloadSchema(
        sub=str(model.id),
        exp=datetime.utcnow()
        + timedelta(seconds=settings.auth.full_jwt_expiration_seconds),
        scopes=[ScopeEnum.full_access],
    )
    jwt = encode_payload(
        payload,
        key=settings.auth.full_jwt_secret,
        algorithm=settings.auth.full_jwt_algorithm,
    )
    return EncodedAccessTokenSchema(access_token=jwt)
