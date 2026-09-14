"""The collector: its runs, its sources and what it decided about each article."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai.collector.schedule import next_slot, run_now
from ..ai.config import ai_settings
from ..database import get_db
from ..deps import require_admin, require_analyst
from ..models import CollectedArticle, CollectorRun, FeedSource, User, utcnow
from ..schemas import FeedSourceIn
from ..serializers import collector_run_payload, feed_source_payload

router = APIRouter(prefix="/api/cti", tags=["cti"])

_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cti")
_RUNNING = threading.Event()


def _collect() -> None:
    try:
        run_now("manual", ai_settings)
    finally:
        _RUNNING.clear()


@router.get("/status")
def collector_status(
    _user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    last = db.scalar(select(CollectorRun).order_by(CollectorRun.started_at.desc()))
    reference = last.started_at if last is not None else utcnow()
    if reference.tzinfo is None:
        from datetime import timezone

        reference = reference.replace(tzinfo=timezone.utc)
    return {
        "enabled": ai_settings.collector_enabled,
        "running": _RUNNING.is_set() or (last is not None and last.status == "running"),
        "weekday": ai_settings.collector_weekday,
        "hour": ai_settings.collector_hour,
        "next_run_at": next_slot(
            reference, ai_settings.collector_weekday, ai_settings.collector_hour
        ).isoformat(),
        "last_run": collector_run_payload(last) if last is not None else None,
        "sources_active": db.query(FeedSource).filter_by(is_active=True).count(),
        "ceilings": {
            "articles": ai_settings.collector_max_articles,
            "candidates": ai_settings.collector_max_candidates,
            "model_calls": ai_settings.collector_max_model_calls,
        },
    }


@router.get("/runs")
def list_runs(
    limit: int = Query(default=20, ge=1, le=100),
    _user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(
        select(CollectorRun).order_by(CollectorRun.started_at.desc()).limit(limit)
    )
    return {"items": [collector_run_payload(row) for row in rows]}


@router.post("/run", status_code=202)
def trigger_run(_user: User = Depends(require_admin)) -> dict:
    """Collect now rather than waiting for the weekly slot."""
    if not ai_settings.collector_enabled:
        raise HTTPException(status_code=409, detail="The collector is switched off by configuration")
    if _RUNNING.is_set():
        raise HTTPException(status_code=409, detail="A collection is already running")
    _RUNNING.set()
    _EXECUTOR.submit(_collect)
    return {"status": "started"}


@router.get("/sources")
def list_sources(
    _user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(select(FeedSource).order_by(FeedSource.category, FeedSource.name))
    return {"items": [feed_source_payload(row) for row in rows]}


@router.patch("/sources/{source_id}")
def update_source(
    source_id: str,
    payload: FeedSourceIn,
    _user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    row = db.get(FeedSource, source_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown source")
    if payload.is_active is not None:
        row.is_active = payload.is_active
        if payload.is_active:
            row.consecutive_failures = 0
    db.commit()
    return feed_source_payload(row)


@router.get("/articles")
def list_articles(
    limit: int = Query(default=50, ge=1, le=200),
    decision: str | None = Query(default=None),
    _user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    statement = select(CollectedArticle).order_by(CollectedArticle.created_at.desc())
    if decision:
        statement = statement.where(CollectedArticle.decision == decision)
    rows = db.scalars(statement.limit(limit))
    return {
        "items": [
            {
                "id": row.id,
                "url": row.url,
                "title": row.title,
                "source_slug": row.source_slug,
                "decision": row.decision,
                "reason": row.reason,
                "relevance_score": row.relevance_score,
                "characters": row.characters,
                "candidates_created": row.candidates_created,
                "published_at": row.published_at.isoformat() if row.published_at else None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]
    }
