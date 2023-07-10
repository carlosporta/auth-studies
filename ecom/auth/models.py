from uuid import UUID, uuid4

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ecom.db import Base


class PasswordAuthModel(Base):
    __tablename__ = "password_auths"
    id: Mapped[int] = mapped_column(primary_key=True)
    auth_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.id"))
    password_hash: Mapped[str] = mapped_column()


class TotpAuthModel(Base):
    __tablename__ = "totp_auths"
    id: Mapped[int] = mapped_column(primary_key=True)
    auth_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.id"))
    secret: Mapped[str] = mapped_column()


class MagicLinkAuthModel(Base):
    __tablename__ = "magic_link_auths"
    id: Mapped[int] = mapped_column(primary_key=True)
    auth_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.id"))
    secret: Mapped[str] = mapped_column()


class AccountModel(Base):
    __tablename__ = "accounts"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(unique=True)
    password_auth: Mapped[PasswordAuthModel] = relationship(uselist=False)
    totp_auth: Mapped[TotpAuthModel] = relationship(uselist=False)
    magic_link_auth: Mapped[MagicLinkAuthModel] = relationship(uselist=False)
