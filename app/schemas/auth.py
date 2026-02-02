from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: UUID
    username: str
    created_at: datetime
    last_login: datetime | None

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str | None = None


class SessionOut(BaseModel):
    id: UUID
    user_id: UUID
    created_at: datetime
    expires_at: datetime
    is_active: bool

    class Config:
        from_attributes = True
