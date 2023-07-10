from os import getenv
from secrets import token_urlsafe

from pydantic import BaseSettings


def getenv_or_raise(key: str) -> str:
    value = getenv(key)
    if not value:
        raise ValueError(f"Environment variable {key} is not set")
    return value


class GoogleOAuth2(BaseSettings):
    client_id: str = getenv_or_raise("GOOGLE_OAUTH_CLIENT_ID")
    client_secret: str = getenv_or_raise("GOOGLE_OAUTH_CLIENT_SECRET")
    redirect_uri: str = "http://127.0.0.1:8000/auth/google-oauth"
    authorization_uri: str = "https://oauth2.googleapis.com/token"
    user_email_uri: str = "https://openidconnect.googleapis.com/v1/userinfo"


class Auth(BaseSettings):
    tmp_jwt_secret: str = token_urlsafe(32)
    tmp_jwt_algorithm: str = "HS256"
    tmp_token_expiration_seconds: int = 60 * 3
    full_jwt_secret: str = token_urlsafe(32)
    full_jwt_expiration_seconds: int = 60 * 15
    full_jwt_algorithm: str = "HS256"
    encryption_key: str = getenv("ENCRYPTION_KEY", token_urlsafe(32))
    google_oauth: GoogleOAuth2 = GoogleOAuth2()


class Settings(BaseSettings):
    auth: Auth = Auth()


settings = Settings()
