"""Conversion helpers between ORM objects and API payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Hunt, Observation, Tenant, User


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _epoch_iso(value: float | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def tenant_payload(tenant: Tenant) -> dict[str, Any]:
    return {
        "id": tenant.id,
        "slug": tenant.slug,
        "name": tenant.name,
        "industry": tenant.industry,
        "created_at": _iso(tenant.created_at),
    }


def user_payload(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": _iso(user.created_at),
        "last_login_at": _iso(user.last_login_at),
        "tenant_id": user.tenant_id,
    }


def hunt_payload(hunt: Hunt, include_summary: bool = False) -> dict[str, Any]:
    payload = {
        "id": hunt.id,
        "tenant_id": hunt.tenant_id,
        "user_id": hunt.user_id,
        "hypothesis_id": hunt.hypothesis_id,
        "hypothesis_name": hunt.hypothesis_name,
        "hypothesis_category": hunt.hypothesis_category,
        "title": hunt.title,
        "status": hunt.status,
        "progress": hunt.progress,
        "stage": hunt.stage,
        "error": hunt.error,
        "archive_name": hunt.archive_name,
        "archive_bytes": hunt.archive_bytes,
        "files_analysed": hunt.files_analysed,
        "events_parsed": hunt.events_parsed,
        "lines_read": hunt.lines_read,
        "rules_evaluated": hunt.rules_evaluated,
        "observation_count": hunt.observation_count,
        "risk_score": hunt.risk_score,
        "verdict": hunt.verdict,
        "duration_ms": hunt.duration_ms,
        "ai_status": hunt.ai_status,
        "ai_detail": hunt.ai_detail,
        "ai_observation_count": hunt.ai_observation_count,
        "ai_model": hunt.ai_model,
        "created_at": _iso(hunt.created_at),
        "started_at": _iso(hunt.started_at),
        "completed_at": _iso(hunt.completed_at),
    }
    if include_summary:
        payload["summary"] = hunt.summary or {}
        payload["coverage"] = hunt.coverage or {}
    return payload


def observation_payload(observation: Observation) -> dict[str, Any]:
    return {
        "id": observation.id,
        "hunt_id": observation.hunt_id,
        "rule_id": observation.rule_id,
        "title": observation.title,
        "description": observation.description,
        "severity": observation.severity,
        "confidence": observation.confidence,
        "score": observation.score,
        "category": observation.category,
        "detection_type": observation.detection_type,
        "origin": observation.origin,
        "ai_confidence": observation.ai_confidence,
        "ai_rationale": observation.ai_rationale,
        "benign_explanation": observation.benign_explanation,
        "model_name": observation.model_name,
        "risk": observation.risk,
        "impact": observation.impact,
        "recommendation": observation.recommendation,
        "mitre_tactic": observation.mitre_tactic,
        "mitre_technique": observation.mitre_technique,
        "mitre_technique_id": observation.mitre_technique_id,
        "entity": observation.entity,
        "data_source": observation.data_source,
        "source_files": observation.source_files or [],
        "evidence": observation.evidence or [],
        "fields": observation.fields or {},
        "metrics": observation.metrics or {},
        "references": observation.references or [],
        "event_count": observation.event_count,
        "first_seen": _iso(observation.first_seen),
        "last_seen": _iso(observation.last_seen),
        "created_at": _iso(observation.created_at),
    }


def generated_hypothesis_payload(row) -> dict:
    """One entry of the review queue, with everything a reviewer needs to decide."""
    from .engine.catalog import DATA_SOURCES
    from .engine.rules import RULES_BY_ID

    return {
        "id": row.id,
        "hypothesis_id": row.hypothesis_id,
        "name": row.name,
        "statement": row.statement,
        "family": row.family,
        "priority": row.priority,
        "mitre_technique_id": row.mitre_technique_id,
        "mitre_technique": row.mitre_technique,
        "mitre_tactic": row.mitre_tactic,
        "attack_url": (
            f"https://attack.mitre.org/techniques/{row.mitre_technique_id.replace('.', '/')}/"
            if row.mitre_technique_id else ""
        ),
        "required_data_sources": [
            {
                "id": source,
                "name": DATA_SOURCES[source].name if source in DATA_SOURCES else source,
            }
            for source in (row.required_data_sources or [])
        ],
        "rule_selectors": list(row.rule_selectors or []),
        "rule_count": len([r for r in (row.rule_selectors or []) if r in RULES_BY_ID]),
        "detection_gap": not (row.rule_selectors or []),
        "threat_actors": list(row.threat_actors or []),
        "source_url": row.source_url,
        "source_title": row.source_title,
        "source_quote": row.source_quote,
        "source_published_at": row.source_published_at.isoformat() if row.source_published_at else None,
        "status": row.status,
        "quality": row.quality,
        "gate_failures": list(row.gate_failures or []),
        "confidence": row.confidence,
        "model_name": row.model_name,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "review_note": row.review_note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def collector_run_payload(row) -> dict:
    return {
        "id": row.id,
        "trigger": row.trigger,
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "duration_ms": row.duration_ms,
        "sources_polled": row.sources_polled,
        "sources_failed": row.sources_failed,
        "articles_seen": row.articles_seen,
        "articles_fetched": row.articles_fetched,
        "articles_relevant": row.articles_relevant,
        "articles_extracted": row.articles_extracted,
        "candidates_created": row.candidates_created,
        "duplicates_merged": row.duplicates_merged,
        "model_calls": row.model_calls,
        "model_name": row.model_name,
        "rotated_feeds": list(row.rotated_feeds or []),
        "warnings": list(row.warnings or []),
        "error": (row.error or "").strip().splitlines()[-1] if row.error else "",
    }


def feed_source_payload(row) -> dict:
    return {
        "id": row.id,
        "slug": row.slug,
        "name": row.name,
        "url": row.url,
        "kind": row.kind,
        "category": row.category,
        "is_active": row.is_active,
        "last_fetched_at": row.last_fetched_at.isoformat() if row.last_fetched_at else None,
        "last_status": row.last_status,
        "consecutive_failures": row.consecutive_failures,
        "oldest_item_at": row.oldest_item_at.isoformat() if row.oldest_item_at else None,
    }
