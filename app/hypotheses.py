"""Generated hypotheses: the quality gate, the review queue and the catalogue.

A hypothesis derived from an article is only worth having if it is executable. The
work here is turning five extracted fields into something the hunt engine can run:
the technique is validated against ATT&CK, the tactic is read from ATT&CK rather
than believed, the data sources are mapped onto the fixed set the platform can
ingest, and the detections are selected from the rule library by matching on the
technique. Only the statement and the technique ever come from a model.

Nothing publishes itself. Every candidate waits in a review queue, and the gates
below decide whether it arrives marked ready or marked with the reason it is not.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import attack
from .engine.catalog import DATA_SOURCES, Hypothesis, register_generated
from .engine.rules import RULES_BY_ID
from .models import GeneratedHypothesis, User, utcnow

MAX_STATEMENT_LENGTH = 400
MIN_STATEMENT_LENGTH = 30
SEVERITY_TO_PRIORITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "medium"}
PRIORITY_ORDER = ("critical", "high", "medium")
# The registry is process wide, so a deployment running several workers refreshes
# it independently in each one. This is the window in which they can disagree.
REFRESH_SECONDS = 5.0

_LOCK = threading.Lock()
_REFRESHED_AT = 0.0


# ---------------------------------------------------------------------------
# mapping a technique onto the detection library
# ---------------------------------------------------------------------------


def _technique_index() -> dict[str, set[str]]:
    """Resolved technique identifier to the rules that detect it.

    Rules are indexed under the identifier ATT&CK currently uses, so a rule written
    against an identifier that has since been revoked still meets a hypothesis that
    names the replacement.
    """
    index: dict[str, set[str]] = {}
    for rule in RULES_BY_ID.values():
        if not rule.mitre_technique_id:
            continue
        technique = attack.resolve(rule.mitre_technique_id)
        key = technique.id if technique else rule.mitre_technique_id.upper()
        index.setdefault(key, set()).add(rule.id)
    return index


_INDEX: dict[str, set[str]] | None = None


def technique_index() -> dict[str, set[str]]:
    global _INDEX
    if _INDEX is None:
        _INDEX = _technique_index()
    return _INDEX


def rules_for_technique(technique_id: str) -> tuple[str, ...]:
    """Every rule that detects the technique, or any of its sub techniques.

    A hypothesis about ``T1071`` should run the rules written for ``T1071.001`` as
    well, and a hypothesis about ``T1071.001`` should run the rules written for the
    parent, because a detection is rarely tagged at exactly the depth the article
    describes.
    """
    technique = attack.resolve(technique_id)
    if technique is None:
        return ()
    index = technique_index()
    parent = attack.parent_of(technique.id)
    selected: set[str] = set(index.get(technique.id, ()))
    selected |= set(index.get(parent, ()))
    for key, rules in index.items():
        if attack.parent_of(key) == parent:
            selected |= rules
    return tuple(sorted(selected))


def priority_for(rule_ids: tuple[str, ...]) -> str:
    """The priority of a hypothesis follows the worst thing its rules detect."""
    severities = {RULES_BY_ID[rule_id].severity for rule_id in rule_ids if rule_id in RULES_BY_ID}
    for severity in ("critical", "high", "medium", "low"):
        if severity in severities:
            return SEVERITY_TO_PRIORITY[severity]
    return "medium"


# ---------------------------------------------------------------------------
# candidates
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    """What an agent, or a person, proposes. Only two fields are ever model written."""

    statement: str
    technique_id: str
    data_sources: tuple[str, ...] = ()
    source_url: str = ""
    source_title: str = ""
    source_quote: str = ""
    source_published_at: datetime | None = None
    threat_actors: tuple[str, ...] = ()
    confidence: str = "medium"
    model_name: str = ""
    prompt_version: str = ""
    collector_run_id: str = ""


@dataclass
class Assessment:
    """The outcome of the gates, and everything derived along the way."""

    failures: list[str] = field(default_factory=list)
    technique: attack.Technique | None = None
    data_sources: tuple[str, ...] = ()
    rule_selectors: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return not self.failures

    @property
    def detection_gap(self) -> bool:
        """No rule covers this technique. Not a failure: it is useful to know."""
        return not self.rule_selectors


_SENTENCE_END = re.compile(r"[.!?]")


def assess(candidate: Candidate, existing: list[GeneratedHypothesis] | None = None) -> Assessment:
    """Run every gate. A failure is a reason shown to the reviewer, never a silent drop."""
    assessment = Assessment()
    statement = candidate.statement.strip()

    if not statement:
        assessment.failures.append("The statement is empty")
    elif len(statement) < MIN_STATEMENT_LENGTH:
        assessment.failures.append("The statement is too short to describe a scenario")
    elif len(statement) > MAX_STATEMENT_LENGTH:
        assessment.failures.append("The statement is longer than one sentence should be")
    elif len(_SENTENCE_END.findall(statement.rstrip("."))) > 1:
        assessment.failures.append("The statement is more than one sentence")

    technique = attack.resolve(candidate.technique_id)
    if technique is None:
        assessment.failures.append(
            f"{candidate.technique_id or 'The technique'} is not in ATT&CK {attack.version()}"
        )
    else:
        assessment.technique = technique

    known = tuple(source for source in candidate.data_sources if source in DATA_SOURCES)
    unknown = [source for source in candidate.data_sources if source not in DATA_SOURCES]
    if unknown:
        assessment.failures.append(f"Unknown data sources: {', '.join(sorted(unknown))}")
    if not known:
        assessment.failures.append("No data source the platform can ingest was identified")
    assessment.data_sources = known

    url = candidate.source_url.strip()
    if not url:
        assessment.failures.append("The source article is not referenced")
    elif not url.lower().startswith(("http://", "https://")):
        assessment.failures.append("The source reference is not a usable link")

    if not candidate.source_quote.strip():
        assessment.failures.append("No passage from the article supports the statement")

    if technique is not None:
        assessment.rule_selectors = rules_for_technique(technique.id)
        duplicate = _duplicate_of(statement, technique.id, known, existing or [])
        if duplicate:
            assessment.failures.append(f"Already covered by {duplicate}")

    return assessment


def _duplicate_of(
    statement: str,
    technique_id: str,
    data_sources: tuple[str, ...],
    existing: list[GeneratedHypothesis],
) -> str:
    """Same technique over the same telemetry is the same hunt.

    This is the deterministic half of deduplication. Comparing meaning rather than
    identifiers needs embeddings and arrives with the collector.
    """
    normalised = _normalise(statement)
    wanted = set(data_sources)
    for row in existing:
        if row.status == "rejected":
            continue
        if _normalise(row.statement) == normalised:
            return row.hypothesis_id
        if row.mitre_technique_id == technique_id and set(row.required_data_sources or []) == wanted:
            return row.hypothesis_id
    return ""


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", "", value.lower()).strip()


def hypothesis_id_for(statement: str, technique_id: str) -> str:
    digest = hashlib.sha256(f"{technique_id}|{_normalise(statement)}".encode()).hexdigest()[:8]
    return f"gen-{technique_id.lower().replace('.', '-')}-{digest}"


def name_for(technique: attack.Technique, actors: tuple[str, ...]) -> str:
    if actors:
        return f"{actors[0]} activity using {technique.name}"
    return f"{technique.name} in the estate"


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


def existing_candidates(db: Session) -> list[GeneratedHypothesis]:
    return list(db.scalars(select(GeneratedHypothesis)))


def create(db: Session, candidate: Candidate) -> GeneratedHypothesis:
    """Store a candidate in the review queue, marked with what it passed or failed."""
    assessment = assess(candidate, existing_candidates(db))
    technique = assessment.technique
    technique_id = technique.id if technique else candidate.technique_id.strip().upper()
    statement = candidate.statement.strip()

    row = GeneratedHypothesis(
        hypothesis_id=hypothesis_id_for(statement, technique_id),
        name=name_for(technique, candidate.threat_actors) if technique else statement[:120],
        statement=statement,
        family="cti" if candidate.threat_actors else "technique",
        priority=priority_for(assessment.rule_selectors),
        mitre_technique_id=technique_id,
        mitre_technique=technique.name if technique else "",
        # Read from ATT&CK, never taken from the model.
        mitre_tactic=technique.tactic if technique else "",
        required_data_sources=list(assessment.data_sources),
        optional_data_sources=[],
        rule_selectors=list(assessment.rule_selectors),
        threat_actors=list(candidate.threat_actors),
        source_url=candidate.source_url.strip()[:1000],
        source_title=candidate.source_title.strip()[:400],
        source_quote=candidate.source_quote.strip()[:4000],
        source_published_at=candidate.source_published_at,
        status="review",
        quality="ready" if assessment.ready else "needs_attention",
        gate_failures=list(assessment.failures),
        confidence=candidate.confidence,
        model_name=candidate.model_name[:120],
        prompt_version=candidate.prompt_version[:32],
        collector_run_id=candidate.collector_run_id[:32],
    )
    existing = db.scalar(
        select(GeneratedHypothesis).where(GeneratedHypothesis.hypothesis_id == row.hypothesis_id)
    )
    if existing is not None:
        return existing  # the same article proposed twice creates nothing new
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def publish(db: Session, row: GeneratedHypothesis, user: User, note: str = "") -> GeneratedHypothesis:
    row.status = "published"
    row.reviewed_by = user.id
    row.reviewed_at = utcnow()
    row.review_note = note[:2000]
    db.commit()
    refresh(db, force=True)
    return row


def reject(db: Session, row: GeneratedHypothesis, user: User, note: str = "") -> GeneratedHypothesis:
    row.status = "rejected"
    row.reviewed_by = user.id
    row.reviewed_at = utcnow()
    row.review_note = note[:2000]
    db.commit()
    refresh(db, force=True)
    return row


# ---------------------------------------------------------------------------
# the catalogue
# ---------------------------------------------------------------------------


def to_hypothesis(row: GeneratedHypothesis) -> Hypothesis:
    """Turn a stored row into something the hunt engine can run."""
    selectors = tuple(row.rule_selectors or ())
    gap = not selectors
    narrative = row.statement
    if row.source_title or row.source_url:
        narrative = f"{row.statement}\n\nReported by {row.source_title or row.source_url}."
    rationale = row.source_quote or row.statement
    method = (
        "Detections selected from the library by matching the ATT&CK technique."
        if not gap
        else "No rule in the library covers this technique yet, so this hunt relies on "
             "behavioural profiling alone, which needs no signature. The gap is the "
             "point: it names a technique the detection library cannot yet see."
    )
    return Hypothesis(
        id=row.hypothesis_id,
        name=row.name,
        family=row.family or "technique",
        summary=row.statement,
        narrative=narrative,
        rationale=rationale,
        priority=row.priority or "medium",
        threat_actors=tuple(row.threat_actors or ()),
        mitre_tactics=(row.mitre_tactic,) if row.mitre_tactic else (),
        required_data_sources=tuple(row.required_data_sources or ()),
        optional_data_sources=tuple(row.optional_data_sources or ()),
        # A technique with no rule runs no rule. Falling back to the whole
        # statistical library would fill the report with observations that have
        # nothing to do with the hypothesis being tested.
        rule_selectors=selectors,
        expected_findings=(),
        method=method,
    )


def published(db: Session) -> list[GeneratedHypothesis]:
    return list(
        db.scalars(
            select(GeneratedHypothesis)
            .where(GeneratedHypothesis.status == "published")
            .order_by(GeneratedHypothesis.created_at)
        )
    )


def refresh(db: Session, force: bool = False) -> None:
    """Load published hypotheses into the engine registry."""
    global _REFRESHED_AT
    now = time.monotonic()
    with _LOCK:
        if not force and now - _REFRESHED_AT < REFRESH_SECONDS:
            return
        _REFRESHED_AT = now
    register_generated(to_hypothesis(row) for row in published(db))


def queue(db: Session, status: str = "review") -> list[GeneratedHypothesis]:
    statement = select(GeneratedHypothesis).order_by(GeneratedHypothesis.created_at.desc())
    if status != "all":
        statement = statement.where(GeneratedHypothesis.status == status)
    return list(db.scalars(statement))
