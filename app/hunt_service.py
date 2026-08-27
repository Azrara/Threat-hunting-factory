"""Hunt execution service: schedules, runs and persists analyses."""

from __future__ import annotations

import shutil
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .engine.catalog import get_hypothesis
from .engine.runner import HuntOutcome, run_hunt
from .models import Hunt, Observation, utcnow

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hunt")
_LOCK = threading.Lock()


def workdir_for(hunt: Hunt) -> Path:
    return settings.upload_dir / hunt.tenant_id / hunt.id / "extracted"


def schedule(hunt_id: str) -> None:
    """Queue a hunt for background execution."""
    _EXECUTOR.submit(_run_safely, hunt_id)


def _run_safely(hunt_id: str) -> None:
    db = SessionLocal()
    try:
        execute(db, hunt_id)
    except Exception:
        try:
            hunt = db.get(Hunt, hunt_id)
            if hunt is not None:
                hunt.status = "failed"
                hunt.error = traceback.format_exc(limit=4)[-1500:]
                hunt.stage = "Failed"
                hunt.completed_at = utcnow()
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def execute(db: Session, hunt_id: str) -> Hunt:
    """Run one hunt to completion and persist the observations."""
    hunt = db.get(Hunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Unknown hunt {hunt_id}")
    hypothesis = get_hypothesis(hunt.hypothesis_id)
    if hypothesis is None:
        hunt.status = "failed"
        hunt.error = f"Unknown hypothesis {hunt.hypothesis_id}"
        hunt.completed_at = utcnow()
        db.commit()
        return hunt

    hunt.status = "running"
    hunt.stage = "Starting"
    hunt.progress = 1
    hunt.started_at = utcnow()
    hunt.error = ""
    db.commit()

    last_reported = {"value": 0}

    def progress(fraction: float, stage: str) -> None:
        percent = int(max(0.0, min(1.0, fraction)) * 100)
        if percent - last_reported["value"] >= 2 or stage != hunt.stage:
            last_reported["value"] = percent
            hunt.progress = percent
            hunt.stage = stage[:120]
            try:
                db.commit()
            except Exception:
                db.rollback()

    workdir = workdir_for(hunt)
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        outcome = run_hunt(Path(hunt.archive_path), workdir, hypothesis, progress)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    _persist(db, hunt, outcome)
    return hunt


def _persist(db: Session, hunt: Hunt, outcome: HuntOutcome) -> None:
    db.query(Observation).filter(Observation.hunt_id == hunt.id).delete()
    for finding in outcome.findings:
        db.add(
            Observation(
                hunt_id=hunt.id,
                tenant_id=hunt.tenant_id,
                rule_id=finding.rule_id,
                title=finding.title[:240],
                description=finding.description,
                severity=finding.severity,
                confidence=finding.confidence,
                score=finding.score,
                category=finding.category,
                detection_type=finding.detection_type,
                risk=finding.risk,
                impact=finding.impact,
                recommendation=finding.recommendation,
                mitre_tactic=finding.mitre_tactic,
                mitre_technique=finding.mitre_technique,
                mitre_technique_id=finding.mitre_technique_id,
                entity=(finding.entity or "")[:200],
                data_source=finding.data_source[:120],
                source_files=finding.source_files,
                evidence=finding.evidence,
                fields=finding.fields,
                metrics=finding.metrics,
                references=list(finding.references),
                event_count=finding.event_count,
                first_seen=_to_datetime(finding.first_seen),
                last_seen=_to_datetime(finding.last_seen),
            )
        )
    hunt.status = "completed"
    hunt.stage = "Completed"
    hunt.progress = 100
    hunt.files_analysed = len(outcome.files)
    hunt.events_parsed = outcome.events_parsed
    hunt.lines_read = outcome.lines_read
    hunt.rules_evaluated = outcome.rules_evaluated
    hunt.observation_count = len(outcome.findings)
    hunt.risk_score = outcome.risk_score
    hunt.verdict = outcome.verdict
    hunt.duration_ms = outcome.duration_ms
    hunt.summary = outcome.summary()
    hunt.coverage = outcome.coverage
    hunt.completed_at = utcnow()
    db.commit()


def _to_datetime(epoch: float | None) -> datetime | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None
