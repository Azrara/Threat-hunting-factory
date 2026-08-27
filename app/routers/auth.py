"""Authentication and tenant registration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import AuditLog, Tenant, User, utcnow
from ..schemas import LoginRequest, TenantRegistration, TokenResponse
from ..security import create_access_token, hash_password, verify_password
from ..serializers import tenant_payload, user_payload

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register_tenant(payload: TenantRegistration, db: Session = Depends(get_db)) -> TokenResponse:
    """Create a new workspace with its first administrator."""
    existing = db.scalar(select(Tenant).where(Tenant.slug == payload.tenant_slug))
    if existing is not None:
        raise HTTPException(status_code=409, detail="That workspace identifier is already taken")

    tenant = Tenant(slug=payload.tenant_slug, name=payload.tenant_name.strip(), industry=payload.industry.strip())
    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email=payload.email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role="admin",
    )
    db.add(user)
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="tenant.created", detail=tenant.slug))
    db.commit()
    db.refresh(user)
    db.refresh(tenant)

    token = create_access_token(user.id, tenant.id, user.role)
    return TokenResponse(access_token=token, user=user_payload(user), tenant=tenant_payload(tenant))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    tenant = db.scalar(select(Tenant).where(Tenant.slug == payload.tenant_slug))
    invalid = HTTPException(status_code=401, detail="Invalid workspace, email address or password")
    if tenant is None or not tenant.is_active:
        raise invalid
    user = db.scalar(
        select(User).where(User.tenant_id == tenant.id, func.lower(User.email) == payload.email)
    )
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise invalid

    user.last_login_at = utcnow()
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="user.login", detail=user.email))
    db.commit()

    token = create_access_token(user.id, tenant.id, user.role)
    return TokenResponse(access_token=token, user=user_payload(user), tenant=tenant_payload(tenant))


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    tenant = db.get(Tenant, user.tenant_id)
    return {"user": user_payload(user), "tenant": tenant_payload(tenant) if tenant else None}
