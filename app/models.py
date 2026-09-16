"""SQLAlchemy ORM models for the multi tenant threat hunting platform."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    industry: Mapped[str] = mapped_column(String(120), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    hunts: Mapped[list["Hunt"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(200), index=True)
    full_name: Mapped[str] = mapped_column(String(160), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32), default="analyst")  # admin, analyst, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class Hunt(Base):
    """One execution of a hypothesis against an uploaded evidence archive."""

    __tablename__ = "hunts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(80), index=True)
    hypothesis_name: Mapped[str] = mapped_column(String(200), default="")
    hypothesis_category: Mapped[str] = mapped_column(String(80), default="")
    title: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    # pending, running, completed, failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(120), default="Queued")
    error: Mapped[str] = mapped_column(Text, default="")

    archive_name: Mapped[str] = mapped_column(String(255), default="")
    archive_path: Mapped[str] = mapped_column(String(500), default="")
    archive_bytes: Mapped[int] = mapped_column(Integer, default=0)

    files_analysed: Mapped[int] = mapped_column(Integer, default=0)
    events_parsed: Mapped[int] = mapped_column(Integer, default=0)
    lines_read: Mapped[int] = mapped_column(Integer, default=0)
    rules_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(40), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)

    # The model stage runs after the hunt is already complete and readable.
    # unavailable, pending, running, completed, failed, skipped
    ai_status: Mapped[str] = mapped_column(String(16), default="unavailable")
    ai_detail: Mapped[str] = mapped_column(String(400), default="")
    ai_observation_count: Mapped[int] = mapped_column(Integer, default=0)
    ai_model: Mapped[str] = mapped_column(String(120), default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="hunts")
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="hunt", cascade="all, delete-orphan"
    )


class Observation(Base):
    """A single finding produced by the detection engine."""

    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    hunt_id: Mapped[str] = mapped_column(ForeignKey("hunts.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)

    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # critical, high, medium, low, info
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    category: Mapped[str] = mapped_column(String(80), default="")
    detection_type: Mapped[str] = mapped_column(String(40), default="pattern")

    risk: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")

    mitre_tactic: Mapped[str] = mapped_column(String(120), default="")
    mitre_technique: Mapped[str] = mapped_column(String(120), default="")
    mitre_technique_id: Mapped[str] = mapped_column(String(32), default="")

    entity: Mapped[str] = mapped_column(String(200), default="")
    data_source: Mapped[str] = mapped_column(String(120), default="")
    source_files: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)  # raw log excerpts
    fields: Mapped[dict] = mapped_column(JSON, default=dict)  # extracted key values
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)  # statistical detail
    references: Mapped[list] = mapped_column(JSON, default=list)

    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Where the observation came from, so a reader can always tell what the engine
    # proved from what a model suggested.
    # rule: a detection rule matched
    # anomaly: the behavioural profiler, deterministic and with no model
    # ai: a local model adjudicated a behavioural candidate
    origin: Mapped[str] = mapped_column(String(16), default="rule", index=True)
    ai_confidence: Mapped[str] = mapped_column(String(16), default="")
    ai_rationale: Mapped[str] = mapped_column(Text, default="")
    benign_explanation: Mapped[str] = mapped_column(Text, default="")
    model_name: Mapped[str] = mapped_column(String(120), default="")
    prompt_version: Mapped[str] = mapped_column(String(40), default="")

    hunt: Mapped[Hunt] = relationship(back_populates="observations")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), default="")
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class GeneratedHypothesis(Base):
    """A hypothesis derived from public reporting, waiting for or past review.

    These are deliberately not scoped to a tenant. They come from public threat
    intelligence, never from client evidence, so there is nothing to isolate and
    collecting them once for the platform costs a fraction of collecting them once
    per client.
    """

    __tablename__ = "generated_hypotheses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # The identifier the rest of the platform uses, stable across republishing.
    hypothesis_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)

    name: Mapped[str] = mapped_column(String(200))
    statement: Mapped[str] = mapped_column(Text)
    family: Mapped[str] = mapped_column(String(32), default="technique")
    priority: Mapped[str] = mapped_column(String(16), default="medium")

    mitre_technique_id: Mapped[str] = mapped_column(String(32), index=True, default="")
    mitre_technique: Mapped[str] = mapped_column(String(160), default="")
    mitre_tactic: Mapped[str] = mapped_column(String(80), default="")

    required_data_sources: Mapped[list] = mapped_column(JSON, default=list)
    optional_data_sources: Mapped[list] = mapped_column(JSON, default=list)
    rule_selectors: Mapped[list] = mapped_column(JSON, default=list)
    threat_actors: Mapped[list] = mapped_column(JSON, default=list)

    source_url: Mapped[str] = mapped_column(String(1000), default="")
    source_title: Mapped[str] = mapped_column(String(400), default="")
    source_quote: Mapped[str] = mapped_column(Text, default="")
    source_published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # review, published, rejected
    status: Mapped[str] = mapped_column(String(16), default="review", index=True)
    # ready when every gate passed, needs_attention otherwise
    quality: Mapped[str] = mapped_column(String(24), default="ready", index=True)
    gate_failures: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")

    model_name: Mapped[str] = mapped_column(String(120), default="")
    prompt_version: Mapped[str] = mapped_column(String(32), default="")
    collector_run_id: Mapped[str] = mapped_column(String(32), default="", index=True)

    reviewed_by: Mapped[str] = mapped_column(String(32), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    review_note: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class FeedSource(Base):
    """One publication the collector reads: a vendor blog, an advisory feed, a journal."""

    __tablename__ = "feed_sources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(1000))
    kind: Mapped[str] = mapped_column(String(24), default="rss")  # rss, atom, arxiv
    category: Mapped[str] = mapped_column(String(40), default="vendor")  # vendor, advisory, research
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Conditional GET state, so a feed that has not changed costs one request.
    etag: Mapped[str] = mapped_column(String(400), default="")
    last_modified: Mapped[str] = mapped_column(String(120), default="")
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(200), default="")
    # The oldest item the feed still offers. When this is newer than the previous
    # run, items published in between have rotated out of the feed unseen.
    oldest_item_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CollectedArticle(Base):
    """An article the collector has seen, so that it is never processed twice."""

    __tablename__ = "collected_articles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    url: Mapped[str] = mapped_column(String(1000))
    canonical_url: Mapped[str] = mapped_column(String(1000), unique=True, index=True)
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    title: Mapped[str] = mapped_column(String(400), default="")
    source_slug: Mapped[str] = mapped_column(String(80), default="", index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # A decision is final when nothing a later run does would change it.
    #   extracted  the model read it and proposed what it proposed
    #   irrelevant it was read and judged not worth the model's time
    #   skipped    robots.txt asked us not to read it
    # These two are not final, and a later run reconsiders them:
    #   fetched    read and deliberately deferred, usually for want of a model
    #   failed     could not be read this time
    decision: Mapped[str] = mapped_column(String(24), default="fetched", index=True)
    reason: Mapped[str] = mapped_column(String(400), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    relevance_score: Mapped[float] = mapped_column(Float, default=0.0)
    characters: Mapped[int] = mapped_column(Integer, default=0)
    candidates_created: Mapped[int] = mapped_column(Integer, default=0)
    run_id: Mapped[str] = mapped_column(String(32), default="", index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class CollectorRun(Base):
    """One execution of the collector, and everything it did."""

    __tablename__ = "collector_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    trigger: Mapped[str] = mapped_column(String(24), default="schedule")  # schedule, manual, cli
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    # running, completed, failed

    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    sources_polled: Mapped[int] = mapped_column(Integer, default=0)
    sources_failed: Mapped[int] = mapped_column(Integer, default=0)
    articles_seen: Mapped[int] = mapped_column(Integer, default=0)
    articles_skipped: Mapped[int] = mapped_column(Integer, default=0)
    articles_fetched: Mapped[int] = mapped_column(Integer, default=0)
    articles_relevant: Mapped[int] = mapped_column(Integer, default=0)
    articles_extracted: Mapped[int] = mapped_column(Integer, default=0)
    candidates_created: Mapped[int] = mapped_column(Integer, default=0)
    duplicates_merged: Mapped[int] = mapped_column(Integer, default=0)
    model_calls: Mapped[int] = mapped_column(Integer, default=0)

    model_name: Mapped[str] = mapped_column(String(120), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    # Feeds whose oldest available item is newer than the previous run: the
    # observable symptom of articles rotating out between two weekly runs.
    rotated_feeds: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
