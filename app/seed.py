"""Seed a demonstration workspace so the platform is usable immediately."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Tenant, User
from .security import hash_password

DEMO_TENANT_SLUG = "demo"
DEMO_USERS = (
    ("analyst@demo.local", "Alex Moreau", "admin", "HuntFactory2026"),
    ("viewer@demo.local", "Robin Keller", "viewer", "HuntFactory2026"),
)


def seed_demo(db: Session) -> Tenant:
    """Create the demo workspace once. Safe to call on every start up."""
    tenant = db.scalar(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))
    if tenant is None:
        tenant = Tenant(slug=DEMO_TENANT_SLUG, name="Demo Workspace", industry="Professional services")
        db.add(tenant)
        db.flush()
    for email, full_name, role, password in DEMO_USERS:
        existing = db.scalar(select(User).where(User.tenant_id == tenant.id, User.email == email))
        if existing is None:
            db.add(
                User(
                    tenant_id=tenant.id,
                    email=email,
                    full_name=full_name,
                    role=role,
                    password_hash=hash_password(password),
                )
            )
    db.commit()
    return tenant
