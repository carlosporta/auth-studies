from jose import jwt
from passlib.context import CryptContext
from pyotp import TOTP, random_base32

from ecom.auth.schemas import AccessTokenPayloadSchema

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def gen_totp_secret():
    return random_base32()


def gen_magic_link_secret():
    return random_base32()


def verify_totp(totp: str, secret: str) -> bool:
    return TOTP(secret).verify(totp)


def encode_payload(
    payload: AccessTokenPayloadSchema,
    key: str,
    algorithm: str,
) -> str:
    return jwt.encode(
        payload.dict(),
        key=key,
        algorithm=algorithm,
    )


def decode_jwt_token(
    token: str,
    key: str,
    algorithm: str,
) -> AccessTokenPayloadSchema:
    decoded = jwt.decode(
        token,
        key=key,
        algorithms=[algorithm],
    )
    return AccessTokenPayloadSchema(**decoded)
