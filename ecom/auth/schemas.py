from datetime import datetime
from enum import Enum

from pydantic import BaseModel, validator

from ecom.auth.types import AccountId, Password, Username


class RegisterAccountWithCredentialsSchema(BaseModel):
    username: Username
    password: Password
    password_confirmation: Password

    @validator("password_confirmation")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("passwords do not match")
        return v


class RegisterAccountWithMagicLinkSchema(BaseModel):
    username: Username


class RegisterAccountWithGoogleOauthSchema(BaseModel):
    username: Username


class AccountReadSchema(BaseModel):
    id: AccountId
    username: Username

    class Config:
        orm_mode = True


class EncodedAccessTokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginWithPasswordSchema(BaseModel):
    username: Username
    password: Password


class LoginWithTOTPSchema(BaseModel):
    totp: str


class ScopeEnum(str, Enum):
    totp_login = "totp:login"
    full_access = "full:access"


class AccessTokenPayloadSchema(BaseModel):
    sub: str
    exp: datetime
    scopes: list[ScopeEnum]
