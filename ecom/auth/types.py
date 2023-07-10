from typing import Annotated
from uuid import UUID

from pydantic import EmailStr, Field

AccountId = UUID
Password = Annotated[str, Field(min_length=4)]
Username = EmailStr
