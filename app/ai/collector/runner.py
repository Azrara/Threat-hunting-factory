"""One run of the collector: read the feeds, keep what matters, propose hypotheses.

A run is unattended, so it is built to survive the things that go wrong on other
people's websites. A feed that fails does not stop the run, an article that will
not parse does not stop the source, and a model that is unreachable stops the
extraction while everything already collected is still recorded. Every outcome,
including the failures, lands in the run record.

It is also idempotent. An article is keyed by its canonical address, so running
twice in the same week reads the feeds again and creates nothing new.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import hypotheses as hypothesis_service
from ...models import CollectedArticle, CollectorRun, FeedSource, utcnow
from ..client import OllamaClient, OllamaError
from ..config import AiSettings, ai_settings
from ..status import build_status
from . import feeds, relevance
from .fetch import Article, read
from .http import FetchError, Forbidden, NotModified, PoliteClient, canonical
from .sources import load_sources

MAX_REASON_LENGTH = 380
# A run that never finished, older than this, was killed rather than is running.
STALE_RUN_HOURS = 6


@dataclass
class RunContext:
    """Everything one run needs, so that a test can supply its own."""

    db: Session
    http: PoliteClient
    model_client: OllamaClient | None = None
    model: str = ""
    settings: AiSettings | None = None

    def __post_init__(self) -> None:
        self.settings = self.settings or ai_settings


def ensure_sources(db: Session, settings: AiSettings | None = None) -> list[FeedSource]:
    """Create the shipped source list on first use, without touching what exists."""
    settings = settings or ai_settings
    known = {row.slug: row for row in db.scalars(select(FeedSource))}
    if not settings.collector_seed_sources:
        return list(known.values())
    for entry in load_sources():
        if entry["slug"] in known:
            continue
        row = FeedSource(
            slug=entry["slug"], name=entry["name"], url=entry["url"],
            kind=entry.get("kind", "rss"), category=entry.get("category", "vendor"),
        )
        db.add(row)
        known[row.slug] = row
    db.commit()
    return [row for row in known.values()]


def previous_run_at(db: Session, settings: AiSettings) -> datetime:
    """When the last completed run started, or a bounded window before now."""
    return _previous_run(db, settings)[0]


def _previous_run(db: Session, settings: AiSettings) -> tuple[datetime, bool]:
    """The window start, and whether this would be the first run.

    The two are needed together because a first run cannot have missed anything:
    there is no earlier run for an article to have scrolled past.
    """
    last = db.scalar(
        select(CollectorRun)
        .where(CollectorRun.status == "completed")
        .order_by(CollectorRun.started_at.desc())
    )
    if last is not None and last.started_at is not None:
        stamp = last.started_at
        return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)), False
    return datetime.now(timezone.utc) - timedelta(days=settings.collector_first_run_days), True


def close_stale_runs(db: Session) -> int:
    """Mark runs that were interrupted, so a crash does not block the next one."""
    cutoff = utcnow() - timedelta(hours=STALE_RUN_HOURS)
    stale = list(db.scalars(select(CollectorRun).where(CollectorRun.status == "running")))
    closed = 0
    for row in stale:
        started = row.started_at
        if started is not None and started.replace(tzinfo=None) > cutoff.replace(tzinfo=None):
            continue
        row.status = "failed"
        row.error = "The run did not finish and was closed by a later one"
        row.finished_at = utcnow()
        closed += 1
    if closed:
        db.commit()
    return closed


def resolve_model(context: RunContext) -> tuple[OllamaClient | None, str, str]:
    """The model to extract with, or a reason there is none."""
    if context.model_client is not None:
        return context.model_client, context.model, ""
    status = build_status(context.settings)
    if not status.get("reachable"):
        return None, "", status.get("degraded_reason") or "no model server"
    selection = status.get("model") or {}
    if not selection.get("usable"):
        return None, "", selection.get("reason") or "no usable model"
    return OllamaClient(context.settings), str(selection["tag"]), ""


def run(context: RunContext, trigger: str = "schedule") -> CollectorRun:
    """Execute one collection. Never raises: the record carries what happened."""
    db = context.db
    settings = context.settings
    close_stale_runs(db)

    record = CollectorRun(trigger=trigger, status="running")
    db.add(record)
    db.commit()
    db.refresh(record)
    started = time.perf_counter()

    owned_client = False
    model_client, model, model_problem = None, "", ""
    try:
        model_client, model, model_problem = resolve_model(context)
        owned_client = model_client is not None and context.model_client is None
        record.model_name = model
        if model_problem:
            record.warnings = [f"No extraction this run: {model_problem}"]

        since, first_run = _previous_run(db, settings)
        sources = [row for row in ensure_sources(db, settings) if row.is_active]
        pending: list[tuple[FeedSource, feeds.FeedItem]] = []

        for source in sources:
            record.sources_polled += 1
            try:
                items, rotated = poll(context, source, since)
            except Exception as error:  # noqa: BLE001 - one bad feed is not a failed run
                record.sources_failed += 1
                source.consecutive_failures += 1
                source.last_status = f"{type(error).__name__}: {error}"[:200]
                db.commit()
                continue
            # A first run has no earlier run to have missed anything between.
            if rotated and not first_run:
                record.rotated_feeds = [*record.rotated_feeds, source.slug]
            pending.extend((source, item) for item in items)
        record.articles_seen = len(pending)
        db.commit()

        _process(context, record, pending, model_client, model)
        record.status = "completed"
    except Exception:  # noqa: BLE001 - a run always ends with a record
        record.status = "failed"
        record.error = traceback.format_exc(limit=4)[-2000:]
    finally:
        if owned_client and model_client is not None:
            model_client.close()
        record.finished_at = utcnow()
        record.duration_ms = int((time.perf_counter() - started) * 1000)
        db.commit()
    return record


def poll(
    context: RunContext,
    source: FeedSource,
    since: datetime,
) -> tuple[list[feeds.FeedItem], bool]:
    """Read one feed and return what is new, plus whether it has rotated."""
    try:
        response = context.http.get(source.url, source.etag, source.last_modified)
    except NotModified:
        source.last_fetched_at = utcnow()
        source.last_status = "not modified"
        source.consecutive_failures = 0
        context.db.commit()
        return [], False

    feed = feeds.parse(response.content)
    source.etag = response.etag[:400]
    source.last_modified = response.last_modified[:120]
    source.last_fetched_at = utcnow()
    source.last_status = f"{len(feed.items)} items"
    source.consecutive_failures = 0
    oldest = feed.oldest
    source.oldest_item_at = oldest.replace(tzinfo=None) if oldest else None
    context.db.commit()

    return feeds.items_since(feed, since), feeds.has_rotated(feed, since)


def _process(
    context: RunContext,
    record: CollectorRun,
    pending: list[tuple[FeedSource, feeds.FeedItem]],
    model_client: OllamaClient | None,
    model: str,
) -> None:
    db = context.db
    settings = context.settings
    # Newest first, so that a run which hits its ceiling keeps the recent work.
    pending.sort(key=lambda pair: pair[1].published_at or datetime.min.replace(tzinfo=timezone.utc),
                 reverse=True)

    for source, item in pending:
        if record.articles_fetched >= settings.collector_max_articles:
            _warn(record, "The article ceiling for one run was reached")
            break
        if record.candidates_created >= settings.collector_max_candidates:
            _warn(record, "The candidate ceiling for one run was reached")
            break

        key = canonical(item.url)
        if db.scalar(select(CollectedArticle).where(CollectedArticle.canonical_url == key)):
            continue  # seen in an earlier run, or earlier in this one

        entry = CollectedArticle(
            url=item.url[:1000], canonical_url=key[:1000], title=item.title[:400],
            source_slug=source.slug, run_id=record.id,
            published_at=item.published_at.replace(tzinfo=None) if item.published_at else None,
        )
        db.add(entry)

        article = _read_article(context, item, entry)
        if article is None:
            db.commit()
            continue
        record.articles_fetched += 1
        entry.characters = article.characters
        entry.title = (article.title or item.title)[:400]

        verdict = relevance.score(article.text, entry.title)
        entry.relevance_score = verdict.score
        if not verdict.keep:
            entry.decision = "irrelevant"
            entry.reason = verdict.summary()[:MAX_REASON_LENGTH]
            db.commit()
            continue
        record.articles_relevant += 1

        if model_client is None:
            entry.decision = "fetched"
            entry.reason = "kept for a later run: no model was available"[:MAX_REASON_LENGTH]
            db.commit()
            continue
        if record.model_calls >= settings.collector_max_model_calls:
            entry.decision = "fetched"
            entry.reason = "kept for a later run: the model call budget was spent"
            _warn(record, "The model call budget for one run was spent")
            db.commit()
            continue

        _extract_into(context, record, entry, article, item, model_client, model)
        db.commit()


def _read_article(
    context: RunContext,
    item: feeds.FeedItem,
    entry: CollectedArticle,
) -> Article | None:
    try:
        response = context.http.get(item.url)
    except Forbidden as error:
        entry.decision = "skipped"
        entry.reason = str(error)[:MAX_REASON_LENGTH]
        return None
    except FetchError as error:
        entry.decision = "failed"
        entry.reason = str(error)[:MAX_REASON_LENGTH]
        return None
    try:
        article = read(response.content, response.content_type, item.url)
    except Exception as error:  # noqa: BLE001 - an unreadable page is not a failed run
        entry.decision = "failed"
        entry.reason = f"could not be read: {type(error).__name__}: {error}"[:MAX_REASON_LENGTH]
        return None
    import hashlib

    entry.content_hash = hashlib.sha256(article.text.encode("utf-8")).hexdigest()
    return article


def _extract_into(
    context: RunContext,
    record: CollectorRun,
    entry: CollectedArticle,
    article: Article,
    item: feeds.FeedItem,
    model_client: OllamaClient,
    model: str,
) -> None:
    from .extract import extract

    try:
        result = extract(model_client, model, article, item.url, record.id)
    except OllamaError as error:
        entry.decision = "failed"
        entry.reason = f"extraction failed: {error}"[:MAX_REASON_LENGTH]
        _warn(record, f"The model stopped answering: {error}")
        return

    record.model_calls += result.model_calls
    if result.error:
        _warn(record, f"The model stopped answering: {result.error}")

    created = 0
    for candidate in result.candidates:
        # One article can propose several hypotheses, so the ceiling is checked here
        # as well as between articles.
        if record.candidates_created >= context.settings.collector_max_candidates:
            _warn(record, "The candidate ceiling for one run was reached")
            break
        candidate.model_name = model
        candidate.source_published_at = (
            item.published_at.replace(tzinfo=None) if item.published_at else None
        )
        before = hypothesis_service.existing_candidates(context.db)
        row = hypothesis_service.create(context.db, candidate)
        if any(existing.id == row.id for existing in before):
            record.duplicates_merged += 1
            continue
        created += 1
        record.candidates_created += 1

    entry.candidates_created = created
    entry.decision = "extracted" if created else "irrelevant"
    if not created:
        entry.reason = (
            "; ".join(result.dropped)[:MAX_REASON_LENGTH]
            or "the model proposed nothing that passed grounding"
        )
    record.articles_extracted += 1


def _warn(record: CollectorRun, message: str) -> None:
    if message not in record.warnings:
        record.warnings = [*record.warnings, message][:20]
