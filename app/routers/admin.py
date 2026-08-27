"""Workspace administration: users and audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, require_admin
from ..models import AuditLog, Tenant, User
from ..schemas import UserCreate, UserUpdate
from ..security import hash_password
from ..serializers import tenant_payload, user_payload

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users")
def list_users(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    users = db.scalars(
        select(User).where(User.tenant_id == user.tenant_id).order_by(User.created_at.asc())
    ).all()
    return {"items": [user_payload(item) for item in users], "total": len(users)}


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    existing = db.scalar(
        select(User).where(User.tenant_id == admin.tenant_id, func.lower(User.email) == payload.email)
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists in this workspace")
    user = User(
        tenant_id=admin.tenant_id,
        email=payload.email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id, action="user.created", detail=payload.email))
    db.commit()
    db.refresh(user)
    return user_payload(user)


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.tenant_id != admin.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.full_name is not None:
        target.full_name = payload.full_name.strip()
    if payload.role is not None:
        if target.id == admin.id and payload.role != "admin":
            raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
        target.role = payload.role
    if payload.is_active is not None:
        if target.id == admin.id and not payload.is_active:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
        target.is_active = payload.is_active
    if payload.password is not None:
        target.password_hash = hash_password(payload.password)
    db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id, action="user.updated", detail=target.email))
    db.commit()
    db.refresh(target)
    return user_payload(target)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> None:
    target = db.get(User, user_id)
    if target is None or target.tenant_id != admin.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id, action="user.deleted", detail=target.email))
    db.delete(target)
    db.commit()


@router.get("/audit")
def audit_trail(admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    entries = db.scalars(
        select(AuditLog)
        .where(AuditLog.tenant_id == admin.tenant_id)
        .order_by(AuditLog.created_at.desc())
        .limit(200)
    ).all()
    users = {item.id: item.email for item in db.scalars(select(User).where(User.tenant_id == admin.tenant_id)).all()}
    return {
        "items": [
            {
                "id": entry.id,
                "action": entry.action,
                "detail": entry.detail,
                "user": users.get(entry.user_id, entry.user_id),
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            }
            for entry in entries
        ]
    }


@router.get("/workspace")
def workspace(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    tenant = db.get(Tenant, user.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    user_count = db.scalar(select(func.count(User.id)).where(User.tenant_id == tenant.id)) or 0
    return {"tenant": tenant_payload(tenant), "user_count": user_count}
