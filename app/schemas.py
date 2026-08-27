"""Request and response models."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


class TenantRegistration(BaseModel):
    tenant_name: str = Field(min_length=2, max_length=160)
    tenant_slug: str = Field(min_length=3, max_length=64)
    industry: str = Field(default="", max_length=120)
    full_name: str = Field(min_length=2, max_length=160)
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("tenant_slug")
    @classmethod
    def check_slug(cls, value: str) -> str:
        value = value.strip().lower()
        if not SLUG_RE.match(value):
            raise ValueError(
                "The workspace identifier must use lower case letters, digits and hyphens only"
            )
        return value

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or "." not in value.split("@")[-1]:
            raise ValueError("A valid email address is required")
        return value


class LoginRequest(BaseModel):
    tenant_slug: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("tenant_slug")
    @classmethod
    def normalise_slug(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class UserCreate(BaseModel):
    email: str = Field(min_length=5, max_length=200)
    full_name: str = Field(default="", max_length=160)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst")

    @field_validator("role")
    @classmethod
    def check_role(cls, value: str) -> str:
        if value not in ("admin", "analyst", "viewer"):
            raise ValueError("The role must be admin, analyst or viewer")
        return value

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=160)
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)

    @field_validator("role")
    @classmethod
    def check_role(cls, value: str | None) -> str | None:
        if value is not None and value not in ("admin", "analyst", "viewer"):
            raise ValueError("The role must be admin, analyst or viewer")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, Any]
    tenant: dict[str, Any]
