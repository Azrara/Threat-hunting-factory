"""Hypothesis catalogue, data sources and the detection rule library."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..deps import get_current_user
from ..engine import catalog as engine_catalog
from ..engine.rules import rule_summary, statistics
from ..models import User

router = APIRouter(prefix="/api", tags=["catalog"])


@router.get("/hypotheses")
def list_hypotheses(
    family: str | None = Query(default=None),
    search: str | None = Query(default=None),
    _user: User = Depends(get_current_user),
) -> dict:
    items = engine_catalog.catalogue()
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


@router.get("/hypotheses/{hypothesis_id}")
def get_hypothesis(hypothesis_id: str, _user: User = Depends(get_current_user)) -> dict:
    hypothesis = engine_catalog.get_hypothesis(hypothesis_id)
    if hypothesis is None:
        raise HTTPException(status_code=404, detail="Unknown hypothesis")
    payload = hypothesis.to_dict()
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
