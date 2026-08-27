"""Report export endpoints."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..engine.catalog import get_hypothesis
from ..models import Hunt, Observation, Tenant, User
from ..reporting.pdf import build_report
from ..serializers import hunt_payload, observation_payload, tenant_payload

router = APIRouter(prefix="/api/hunts", tags=["reports"])


def _load(db: Session, user: User, hunt_id: str) -> tuple[Hunt, list[Observation], Tenant]:
    hunt = db.get(Hunt, hunt_id)
    if hunt is None or hunt.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Hunt not found")
    if hunt.status != "completed":
        raise HTTPException(status_code=409, detail="The report is available once the hunt has completed")
    observations = db.scalars(
        select(Observation).where(Observation.hunt_id == hunt.id).order_by(Observation.score.desc())
    ).all()
    tenant = db.get(Tenant, hunt.tenant_id)
    return hunt, list(observations), tenant


def _filename(hunt: Hunt, extension: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "-", hunt.title or hunt.hypothesis_id).strip("-").lower()[:60]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"threat-hunting-report-{stem or 'hunt'}-{stamp}.{extension}"


@router.get("/{hunt_id}/report.pdf")
def report_pdf(hunt_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    hunt, observations, tenant = _load(db, user, hunt_id)
    author = db.get(User, hunt.user_id)
    hypothesis = get_hypothesis(hunt.hypothesis_id)
    payload = {
        "hunt": hunt_payload(hunt, include_summary=True),
        "tenant": tenant_payload(tenant) if tenant else {"name": ""},
        "observations": [observation_payload(item) for item in observations],
        "hypothesis": hypothesis.to_dict() if hypothesis else {},
        "analyst": (author.full_name or author.email) if author else "",
    }
    pdf = build_report(payload)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_filename(hunt, "pdf")}"'},
    )


@router.get("/{hunt_id}/report.json")
def report_json(hunt_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    hunt, observations, tenant = _load(db, user, hunt_id)
    hypothesis = get_hypothesis(hunt.hypothesis_id)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant": tenant_payload(tenant) if tenant else None,
        "hunt": hunt_payload(hunt, include_summary=True),
        "hypothesis": hypothesis.to_dict() if hypothesis else None,
        "observations": [observation_payload(item) for item in observations],
    }
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{_filename(hunt, "json")}"'},
    )
