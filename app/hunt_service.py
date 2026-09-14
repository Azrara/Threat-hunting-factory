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
from . import hypotheses as hypothesis_service
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


def schedule_ai(hunt_id: str) -> None:
    """Queue model adjudication for a hunt that has already completed."""
    _EXECUTOR.submit(_enrich_safely, hunt_id)


def _enrich_safely(hunt_id: str) -> None:
    db = SessionLocal()
    try:
        reanalyse(db, hunt_id)
    except Exception:
        try:
            hunt = db.get(Hunt, hunt_id)
            if hunt is not None:
                hunt.ai_status = "failed"
                hunt.ai_detail = traceback.format_exc(limit=2)[-380:]
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def reanalyse(db: Session, hunt_id: str) -> Hunt:
    """Re-parse the evidence and adjudicate its behavioural candidates again."""
    from .engine.behaviour import analyse_behaviour
    from .engine.runner import parse_evidence

    hunt = db.get(Hunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Unknown hunt {hunt_id}")
    outcome = HuntOutcome()
    workdir = workdir_for(hunt)
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        context, outcome = parse_evidence(Path(hunt.archive_path), workdir)
        _, outcome.behaviour_candidates = analyse_behaviour(context.events)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    # Existing observations carry the rule findings this run needs for corroboration.
    outcome.findings = [
        _finding_from_row(row)
        for row in db.query(Observation).filter(
            Observation.hunt_id == hunt.id, Observation.origin == "rule"
        )
    ]
    return enrich_with_model(db, hunt, outcome)


def _finding_from_row(row: Observation):
    from .engine.rules.base import Finding

    return Finding(
        rule_id=row.rule_id, title=row.title, description="", severity=row.severity,
        origin=row.origin, entity=row.entity or "",
    )


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
    hypothesis_service.refresh(db)
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
    # The report is complete and readable at this point. Model adjudication runs
    # afterwards and updates the hunt as it goes, so a slow model, or no model at
    # all, never delays the deterministic result.
    enrich_with_model(db, hunt, outcome)
    return hunt


def _observation_from(hunt: Hunt, finding) -> Observation:
    return Observation(
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
        origin=finding.origin,
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
        ai_confidence=finding.ai_confidence,
        ai_rationale=finding.ai_rationale,
        benign_explanation=finding.benign_explanation,
        model_name=finding.model_name,
        prompt_version=finding.prompt_version,
    )


def enrich_with_model(db: Session, hunt: Hunt, outcome: HuntOutcome) -> Hunt:
    """Have a local model adjudicate the behavioural candidates. Never raises."""
    from .ai.analyst import adjudicate, corroborating_rules
    from .ai.client import OllamaClient
    from .ai.config import ai_settings
    from .ai.status import build_status

    if not ai_settings.enabled:
        return _ai_state(db, hunt, "unavailable", "The model layer is switched off")
    if not outcome.behaviour_candidates:
        return _ai_state(db, hunt, "skipped", "No behavioural candidate to adjudicate")

    status = build_status(ai_settings)
    if not status.get("reachable"):
        return _ai_state(db, hunt, "unavailable", status.get("degraded_reason", "")[:400])
    selection = status.get("model") or {}
    if not selection.get("usable"):
        return _ai_state(db, hunt, "unavailable", selection.get("reason", "")[:400])

    model = str(selection["tag"])
    _ai_state(db, hunt, "running", f"Adjudicating with {model}")
    client = OllamaClient(ai_settings)
    try:
        result = adjudicate(
            client, model, outcome.behaviour_candidates,
            corroborating_rules(outcome.findings),
            max_calls=ai_settings.max_calls_per_hunt,
        )
    except Exception as error:  # noqa: BLE001 - a completed hunt is never lost to this
        client.close()
        return _ai_state(db, hunt, "failed", f"{type(error).__name__}: {error}"[:400])
    client.close()

    db.query(Observation).filter(
        Observation.hunt_id == hunt.id, Observation.origin == "ai"
    ).delete()
    for finding in result.findings:
        db.add(_observation_from(hunt, finding))

    # An adjudicated candidate is reported once. The model assessment carries the
    # profiler's own measurements in its metrics, so keeping both would print the
    # same entity twice with the second copy saying strictly less. A candidate the
    # guards rejected keeps its deterministic observation, which is the point of
    # having one.
    adjudicated = {finding.entity for finding in result.findings if finding.entity}
    if adjudicated:
        db.query(Observation).filter(
            Observation.hunt_id == hunt.id,
            Observation.origin == "anomaly",
            Observation.entity.in_(adjudicated),
        ).delete(synchronize_session=False)

    hunt.ai_observation_count = len(result.findings)
    hunt.ai_model = model
    db.flush()
    hunt.observation_count = (
        db.query(Observation).filter(Observation.hunt_id == hunt.id).count()
    )
    detail = (
        f"{result.suspicious} judged suspicious, {result.dismissed} examined and dismissed, "
        f"{result.model_calls} model calls"
    )
    if result.error:
        detail = f"{detail}. The model stopped answering: {result.error}"
    hunt.ai_status = "completed" if not result.error else "failed"
    hunt.ai_detail = detail[:400]
    db.commit()
    return hunt


def _ai_state(db: Session, hunt: Hunt, status: str, detail: str = "") -> Hunt:
    hunt.ai_status = status
    hunt.ai_detail = detail[:400]
    try:
        db.commit()
    except Exception:
        db.rollback()
    return hunt


def _persist(db: Session, hunt: Hunt, outcome: HuntOutcome) -> None:
    db.query(Observation).filter(Observation.hunt_id == hunt.id).delete()
    for finding in outcome.findings:
        db.add(_observation_from(hunt, finding))
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
    hunt.ai_status = "pending"
    hunt.ai_observation_count = 0
    db.commit()


def _to_datetime(epoch: float | None) -> datetime | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None
