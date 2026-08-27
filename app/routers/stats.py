"""Workspace statistics for the home dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..engine.catalog import HYPOTHESES_BY_ID
from ..engine.rules import statistics as rule_statistics
from ..models import Hunt, Observation, User
from ..serializers import hunt_payload

router = APIRouter(prefix="/api/stats", tags=["stats"])

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@router.get("/overview")
def overview(
    days: int = Query(default=90, ge=1, le=730),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    tenant_id = user.tenant_id
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    hunts = db.scalars(
        select(Hunt).where(Hunt.tenant_id == tenant_id).order_by(Hunt.created_at.desc())
    ).all()
    recent = [hunt for hunt in hunts if hunt.created_at and hunt.created_at >= since]

    status_counts = Counter(hunt.status for hunt in hunts)
    family_counts = Counter(hunt.hypothesis_category for hunt in hunts if hunt.hypothesis_category)
    hypothesis_counts = Counter(hunt.hypothesis_id for hunt in hunts)

    severity_rows = db.execute(
        select(Observation.severity, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id)
        .group_by(Observation.severity)
    ).all()
    severity_counts = {severity: count for severity, count in severity_rows}

    category_rows = db.execute(
        select(Observation.category, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id)
        .group_by(Observation.category)
        .order_by(func.count(Observation.id).desc())
        .limit(12)
    ).all()

    technique_rows = db.execute(
        select(
            Observation.mitre_technique_id,
            Observation.mitre_technique,
            Observation.mitre_tactic,
            func.count(Observation.id),
        )
        .where(Observation.tenant_id == tenant_id, Observation.mitre_technique_id != "")
        .group_by(Observation.mitre_technique_id, Observation.mitre_technique, Observation.mitre_tactic)
        .order_by(func.count(Observation.id).desc())
        .limit(12)
    ).all()

    tactic_rows = db.execute(
        select(Observation.mitre_tactic, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id, Observation.mitre_tactic != "")
        .group_by(Observation.mitre_tactic)
        .order_by(func.count(Observation.id).desc())
    ).all()

    detection_rows = db.execute(
        select(Observation.detection_type, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id)
        .group_by(Observation.detection_type)
    ).all()

    entity_rows = db.execute(
        select(Observation.entity, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id, Observation.entity != "")
        .group_by(Observation.entity)
        .order_by(func.count(Observation.id).desc())
        .limit(10)
    ).all()

    rule_rows = db.execute(
        select(Observation.rule_id, Observation.title, func.count(Observation.id))
        .where(Observation.tenant_id == tenant_id)
        .group_by(Observation.rule_id, Observation.title)
        .order_by(func.count(Observation.id).desc())
        .limit(10)
    ).all()

    timeline: dict[str, dict[str, int]] = defaultdict(lambda: {"hunts": 0, "observations": 0, "critical": 0})
    for hunt in recent:
        key = hunt.created_at.date().isoformat()
        timeline[key]["hunts"] += 1
        timeline[key]["observations"] += hunt.observation_count
        summary = hunt.summary or {}
        timeline[key]["critical"] += int((summary.get("severities") or {}).get("critical", 0))

    completed = [hunt for hunt in hunts if hunt.status == "completed"]
    data_source_totals: Counter = Counter()
    for hunt in completed:
        for source, count in ((hunt.summary or {}).get("data_sources") or {}).items():
            data_source_totals[source] += count

    return {
        "totals": {
            "hunts": len(hunts),
            "hunts_in_period": len(recent),
            "completed": status_counts.get("completed", 0),
            "running": status_counts.get("running", 0) + status_counts.get("pending", 0),
            "failed": status_counts.get("failed", 0),
            "observations": sum(severity_counts.values()),
            "events_analysed": sum(hunt.events_parsed for hunt in hunts),
            "files_analysed": sum(hunt.files_analysed for hunt in hunts),
            "hypotheses_used": len(hypothesis_counts),
            "hypotheses_available": len(HYPOTHESES_BY_ID),
            "average_risk_score": round(
                sum(hunt.risk_score for hunt in completed) / len(completed), 1
            ) if completed else 0.0,
            "highest_risk_score": max((hunt.risk_score for hunt in completed), default=0.0),
        },
        "severity": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
        "status": dict(status_counts),
        "families": dict(family_counts),
        "categories": [{"name": name or "general", "count": count} for name, count in category_rows],
        "techniques": [
            {"id": tid, "name": name, "tactic": tactic, "count": count}
            for tid, name, tactic, count in technique_rows
        ],
        "tactics": [{"name": name, "count": count} for name, count in tactic_rows],
        "detection_types": [{"name": name, "count": count} for name, count in detection_rows],
        "top_entities": [{"name": name, "count": count} for name, count in entity_rows],
        "top_rules": [{"id": rid, "title": title, "count": count} for rid, title, count in rule_rows],
        "top_hypotheses": [
            {
                "id": hypothesis_id,
                "name": HYPOTHESES_BY_ID[hypothesis_id].name if hypothesis_id in HYPOTHESES_BY_ID else hypothesis_id,
                "family": HYPOTHESES_BY_ID[hypothesis_id].family if hypothesis_id in HYPOTHESES_BY_ID else "",
                "count": count,
            }
            for hypothesis_id, count in hypothesis_counts.most_common(8)
        ],
        "timeline": [
            {"date": key, **value} for key, value in sorted(timeline.items())
        ],
        "data_sources": [
            {"name": name, "events": count} for name, count in data_source_totals.most_common(12)
        ],
        "recent_hunts": [hunt_payload(hunt) for hunt in hunts[:8]],
        "engine": rule_statistics(),
    }
