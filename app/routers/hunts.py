"""Hunt lifecycle: upload evidence, run the engine, read the results."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user, require_analyst
from ..engine.catalog import get_hypothesis
from ..hunt_service import schedule
from ..models import AuditLog, Hunt, Observation, User, new_id
from ..serializers import hunt_payload, observation_payload

router = APIRouter(prefix="/api/hunts", tags=["hunts"])

ALLOWED_SUFFIXES = {
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".log", ".txt", ".json", ".jsonl",
    ".ndjson", ".csv", ".tsv", ".xml", ".evtx", ".cef", ".leef", ".eve",
}
CHUNK = 1024 * 1024


def _fetch(db: Session, user: User, hunt_id: str) -> Hunt:
    hunt = db.get(Hunt, hunt_id)
    if hunt is None or hunt.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt


@router.post("", status_code=201)
async def create_hunt(
    hypothesis_id: str = Form(...),
    title: str = Form(default=""),
    file: UploadFile = File(...),
    user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    """Accept an evidence archive and queue the analysis."""
    hypothesis = get_hypothesis(hypothesis_id)
    if hypothesis is None:
        raise HTTPException(status_code=400, detail="Unknown hypothesis")

    filename = Path(file.filename or "evidence.zip").name
    suffix = Path(filename).suffix.lower()
    compound = "".join(Path(filename).suffixes[-2:]).lower()
    if suffix not in ALLOWED_SUFFIXES and compound not in (".tar.gz", ".tar.bz2", ".tar.xz"):
        raise HTTPException(
            status_code=400,
            detail="Upload an archive (zip, tar, tar.gz) or a single log file (log, json, csv, xml, evtx)",
        )

    hunt_id = new_id()
    target_dir = settings.upload_dir / user.tenant_id / hunt_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / filename

    written = 0
    try:
        with open(target, "wb") as sink:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > settings.max_archive_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"The archive exceeds the {settings.max_archive_bytes // (1024 * 1024)} MB limit",
                    )
                sink.write(chunk)
    except HTTPException:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise
    finally:
        await file.close()

    if written == 0:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="The uploaded file is empty")

    hunt = Hunt(
        id=hunt_id,
        tenant_id=user.tenant_id,
        user_id=user.id,
        hypothesis_id=hypothesis.id,
        hypothesis_name=hypothesis.name,
        hypothesis_category=hypothesis.family,
        title=(title.strip() or hypothesis.name)[:200],
        status="pending",
        stage="Queued",
        archive_name=filename,
        archive_path=str(target),
        archive_bytes=written,
    )
    db.add(hunt)
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="hunt.created", detail=hunt.id))
    db.commit()
    db.refresh(hunt)

    schedule(hunt.id)
    return hunt_payload(hunt)


@router.get("")
def list_hunts(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = select(Hunt).where(Hunt.tenant_id == user.tenant_id)
    if status_filter:
        query = query.where(Hunt.status == status_filter)
    total = len(db.scalars(query).all())
    hunts = db.scalars(query.order_by(Hunt.created_at.desc()).limit(limit).offset(offset)).all()
    return {"items": [hunt_payload(hunt) for hunt in hunts], "total": total}


@router.get("/{hunt_id}")
def get_hunt(hunt_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    hunt = _fetch(db, user, hunt_id)
    payload = hunt_payload(hunt, include_summary=True)
    hypothesis = get_hypothesis(hunt.hypothesis_id)
    payload["hypothesis"] = hypothesis.to_dict() if hypothesis else None
    return payload


@router.get("/{hunt_id}/observations")
def list_observations(
    hunt_id: str,
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    search: str | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    hunt = _fetch(db, user, hunt_id)
    query = select(Observation).where(Observation.hunt_id == hunt.id)
    if severity:
        query = query.where(Observation.severity == severity)
    if category:
        query = query.where(Observation.category == category)
    observations = db.scalars(query.order_by(Observation.score.desc())).all()
    if search:
        needle = search.lower()
        observations = [
            item
            for item in observations
            if needle in item.title.lower()
            or needle in item.description.lower()
            or needle in (item.entity or "").lower()
            or needle in item.rule_id.lower()
        ]
    return {
        "items": [observation_payload(item) for item in observations],
        "total": len(observations),
        "hunt": hunt_payload(hunt, include_summary=True),
    }


@router.delete("/{hunt_id}", status_code=204)
def delete_hunt(hunt_id: str, user: User = Depends(require_analyst), db: Session = Depends(get_db)) -> None:
    hunt = _fetch(db, user, hunt_id)
    if hunt.status == "running":
        raise HTTPException(status_code=409, detail="The hunt is still running")
    directory = settings.upload_dir / hunt.tenant_id / hunt.id
    shutil.rmtree(directory, ignore_errors=True)
    db.delete(hunt)
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="hunt.deleted", detail=hunt_id))
    db.commit()


@router.post("/{hunt_id}/rerun")
def rerun_hunt(hunt_id: str, user: User = Depends(require_analyst), db: Session = Depends(get_db)) -> dict:
    hunt = _fetch(db, user, hunt_id)
    if hunt.status == "running":
        raise HTTPException(status_code=409, detail="The hunt is already running")
    if not Path(hunt.archive_path).exists():
        raise HTTPException(status_code=410, detail="The evidence archive is no longer available")
    hunt.status = "pending"
    hunt.stage = "Queued"
    hunt.progress = 0
    hunt.error = ""
    db.commit()
    schedule(hunt.id)
    return hunt_payload(hunt)
