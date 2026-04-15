from datetime import datetime
from typing import Optional
from pydantic import BaseModel, field_validator

from app.domain.enums import UserRole


class RoleRead(BaseModel):
    id: int
    name: UserRole

    model_config = {"from_attributes": True}


class UserRead(BaseModel):
    id: int
    username: str
    role: RoleRead
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str
    password: str
    role_name: UserRole = UserRole.OPERATOR

    @field_validator("username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 4:
            raise ValueError("Password must be at least 4 characters")
        return v


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role_name: Optional[UserRole] = None

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) < 4:
            raise ValueError("Password must be at least 4 characters")
        return v
