"""Running the collector once a week, unattended.

The schedule is deliberately coarse: a weekday and an hour. Anything finer would
imply a precision the job does not have, since one run reads twenty websites at a
polite pace and takes as long as it takes.

The due calculation is a pure function so that it can be tested without waiting a
week, and the thread around it does nothing but sleep and call it.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ...database import SessionLocal
from ...models import CollectorRun
from ..config import AiSettings, ai_settings
from .http import PoliteClient
from .runner import RunContext
from .runner import run as run_collection

logger = logging.getLogger("thf.collector")

CHECK_INTERVAL_SECONDS = 600
BOOTED_AT = datetime.now(timezone.utc)
_THREAD: threading.Thread | None = None
_STOP = threading.Event()


def next_slot(after: datetime, weekday: int, hour: int) -> datetime:
    """The first scheduled moment strictly after ``after``."""
    moment = after.astimezone(timezone.utc)
    candidate = moment.replace(hour=hour, minute=0, second=0, microsecond=0)
    days_ahead = (weekday - candidate.weekday()) % 7
    candidate += timedelta(days=days_ahead)
    if candidate <= moment:
        candidate += timedelta(days=7)
    return candidate


def is_due(
    now: datetime,
    last_started: datetime | None,
    settings: AiSettings,
    booted_at: datetime | None = None,
) -> bool:
    """True when a run should start.

    A fresh installation has no previous run, and counting from nothing would mean
    either never collecting or collecting the moment the application starts. Both
    are wrong, so the reference is the moment this process booted: the first run
    happens at the first scheduled slot after start up.
    """
    if not settings.collector_enabled:
        return False
    reference = last_started or booted_at or now
    return now >= next_slot(reference, settings.collector_weekday, settings.collector_hour)


def last_started(db) -> datetime | None:
    row = db.scalar(select(CollectorRun).order_by(CollectorRun.started_at.desc()))
    if row is None or row.started_at is None:
        return None
    stamp = row.started_at
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def run_now(trigger: str = "manual", settings: AiSettings | None = None) -> CollectorRun:
    """Execute one collection against the real network and the local model.

    The record is detached from its session before it is returned, so a caller can
    read what happened after the session is gone. Returning a live row and closing
    the session under it leaves the caller holding something that raises on every
    attribute it touches.
    """
    settings = settings or ai_settings
    db = SessionLocal()
    try:
        with PoliteClient(respect_robots=settings.collector_respect_robots) as http:
            record = run_collection(RunContext(db=db, http=http, settings=settings), trigger)
            db.refresh(record)
            db.expunge(record)
            return record
    finally:
        db.close()


def _loop(settings: AiSettings) -> None:
    # A fresh process has no idea when the last run was until it reads the
    # database, so the first check happens after one interval rather than at once.
    while not _STOP.wait(CHECK_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            due = is_due(datetime.now(timezone.utc), last_started(db), settings, BOOTED_AT)
        except Exception:  # noqa: BLE001 - a scheduler that dies is worse than a late run
            logger.exception("The collector schedule could not be evaluated")
            due = False
        finally:
            db.close()
        if not due:
            continue
        try:
            record = run_now("schedule", settings)
            logger.info(
                "Collector run %s finished: %s candidates from %s articles",
                record.status, record.candidates_created, record.articles_fetched,
            )
        except Exception:  # noqa: BLE001
            logger.exception("The collector run failed")


def start(settings: AiSettings | None = None) -> bool:
    """Start the weekly thread. Returns whether it was started."""
    global _THREAD
    settings = settings or ai_settings
    if not settings.collector_enabled:
        return False
    if _THREAD is not None and _THREAD.is_alive():
        return False
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, args=(settings,), name="cti-collector", daemon=True)
    _THREAD.start()
    return True


def stop() -> None:
    _STOP.set()
