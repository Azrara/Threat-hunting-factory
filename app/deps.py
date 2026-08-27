"""Shared FastAPI dependencies for authentication and tenant scoping."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import decode_access_token

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise CREDENTIALS_ERROR
    payload = decode_access_token(authorization.split(" ", 1)[1].strip())
    if not payload:
        raise CREDENTIALS_ERROR
    user = db.get(User, payload.get("sub", ""))
    if user is None or not user.is_active:
        raise CREDENTIALS_ERROR
    if user.tenant_id != payload.get("tid"):
        raise CREDENTIALS_ERROR
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")
    return user


def require_analyst(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the analyst or administrator role",
        )
    return user
