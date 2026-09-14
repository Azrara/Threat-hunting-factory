"""Hypothesis catalogue, data sources and the detection rule library."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from sqlalchemy.orm import Session

from .. import attack, hypotheses as hypothesis_service
from ..database import get_db
from ..deps import get_current_user, require_admin, require_analyst
from ..engine import catalog as engine_catalog
from ..engine.rules import rule_summary, statistics
from ..models import GeneratedHypothesis, User
from ..schemas import CandidateIn, ReviewIn
from ..serializers import generated_hypothesis_payload

router = APIRouter(prefix="/api", tags=["catalog"])


@router.get("/hypotheses")
def list_hypotheses(
    family: str | None = Query(default=None),
    search: str | None = Query(default=None),
    origin: str | None = Query(default=None),
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    hypothesis_service.refresh(db)
    items = engine_catalog.catalogue()
    if origin:
        items = [item for item in items if item["origin"] == origin]
    if family:
        items = [item for item in items if item["family"] == family]
    if search:
        needle = search.lower()
        items = [
            item
            for item in items
            if needle in item["name"].lower()
            or needle in item["summary"].lower()
            or any(needle in actor.lower() for actor in item["threat_actors"])
            or any(needle in tactic.lower() for tactic in item["mitre_tactics"])
        ]
    return {
        "items": items,
        "families": engine_catalog.FAMILY_LABELS,
        "total": len(items),
    }


# Registered before the identifier route so that "review" is not read as one.
@router.get("/hypotheses/review")
def review_queue(
    status: str = Query(default="review", pattern="^(review|published|rejected|all)$"),
    _user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    rows = hypothesis_service.queue(db, status)
    counts = {
        state: len(hypothesis_service.queue(db, state))
        for state in ("review", "published", "rejected")
    }
    return {
        "items": [generated_hypothesis_payload(row) for row in rows],
        "counts": counts,
        "total": len(rows),
        "attack_version": attack.version(),
    }


@router.post("/hypotheses/candidates", status_code=201)
def create_candidate(
    payload: CandidateIn,
    _user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Propose a hypothesis. The collector uses this path, and so can a person."""
    row = hypothesis_service.create(db, payload.to_candidate())
    return generated_hypothesis_payload(row)


@router.post("/hypotheses/review/{row_id}/publish")
def publish_candidate(
    row_id: str,
    payload: ReviewIn | None = None,
    user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    row = _candidate(db, row_id)
    if row.quality != "ready":
        raise HTTPException(
            status_code=409,
            detail="This candidate did not pass every check: " + "; ".join(row.gate_failures or []),
        )
    return generated_hypothesis_payload(
        hypothesis_service.publish(db, row, user, payload.note if payload else "")
    )


@router.post("/hypotheses/review/{row_id}/reject")
def reject_candidate(
    row_id: str,
    payload: ReviewIn | None = None,
    user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    row = _candidate(db, row_id)
    return generated_hypothesis_payload(
        hypothesis_service.reject(db, row, user, payload.note if payload else "")
    )


def _candidate(db: Session, row_id: str) -> GeneratedHypothesis:
    row = db.get(GeneratedHypothesis, row_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown candidate")
    return row


@router.get("/hypotheses/{hypothesis_id}")
def get_hypothesis(
    hypothesis_id: str,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    hypothesis_service.refresh(db)
    hypothesis = engine_catalog.get_hypothesis(hypothesis_id)
    if hypothesis is None:
        raise HTTPException(status_code=404, detail="Unknown hypothesis")
    payload = hypothesis.to_dict()
    payload["origin"] = "builtin" if hypothesis.id in engine_catalog.BUILTIN_IDS else "generated"
    if payload["origin"] == "generated":
        row = db.scalar(
            select(GeneratedHypothesis).where(
                GeneratedHypothesis.hypothesis_id == hypothesis_id
            )
        )
        if row is not None:
            payload["source"] = {
                "url": row.source_url,
                "title": row.source_title,
                "quote": row.source_quote,
                "published_at": row.source_published_at.isoformat() if row.source_published_at else None,
                "collected_at": row.created_at.isoformat() if row.created_at else None,
            }
            payload["detection_gap"] = not (row.rule_selectors or [])
    payload["rules"] = [
        {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "category": rule.category,
            "detection_type": rule.detection_type,
            "mitre_technique": rule.mitre_technique,
            "mitre_technique_id": rule.mitre_technique_id,
        }
        for rule in hypothesis.rules()
    ]
    return payload


@router.get("/data-sources")
def list_data_sources(_user: User = Depends(get_current_user)) -> dict:
    return {
        "items": [
            {
                "id": source.id,
                "name": source.name,
                "description": source.description,
                "formats": list(source.formats),
                "examples": list(source.examples),
                "collection_hint": source.collection_hint,
            }
            for source in engine_catalog.DATA_SOURCES.values()
        ]
    }


@router.get("/rules")
def list_rules(_user: User = Depends(get_current_user)) -> dict:
    return {"items": rule_summary(), "statistics": statistics()}
