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
