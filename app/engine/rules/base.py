"""Rule primitives: conditions, rule types and the finding container.

The engine supports four detection styles:

``pattern``      single event matching on normalised fields or raw text
``threshold``    grouped counting inside a sliding time window
``sequence``     ordered stages that must occur for the same entity
``statistical``  whole dataset mathematics such as entropy or spectral analysis
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..event import Event
from ..stats_math import shannon_entropy

SEVERITY_SCORE = {"critical": 95.0, "high": 75.0, "medium": 50.0, "low": 25.0, "info": 10.0}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.85, "low": 0.65}


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str = "medium"
    confidence: str = "medium"
    category: str = ""
    detection_type: str = "pattern"
    # Where this came from, so a reader can always separate what the engine proved
    # from what a model suggested.  rule, anomaly or ai.
    origin: str = "rule"
    risk: str = ""
    impact: str = ""
    recommendation: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    entity: str = ""
    data_source: str = ""
    source_files: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    fields: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    event_count: int = 1
    first_seen: float | None = None
    last_seen: float | None = None
    # Set only on findings a model produced.
    ai_confidence: str = ""
    ai_rationale: str = ""
    benign_explanation: str = ""
    model_name: str = ""
    prompt_version: str = ""

    @property
    def score(self) -> float:
        return round(SEVERITY_SCORE.get(self.severity, 40.0) * CONFIDENCE_WEIGHT.get(self.confidence, 0.85), 2)


# ---------------------------------------------------------------------------
# conditions
# ---------------------------------------------------------------------------

TEXT_FIELD = "_text"
RAW_FIELD = "_raw"
SOURCE_FIELD = "_data_source"
FORMAT_FIELD = "_log_format"


def field_value(event: Event, name: str) -> Any:
    if name == TEXT_FIELD:
        return event.searchable
    if name == RAW_FIELD:
        return event.raw
    if name == SOURCE_FIELD:
        return event.data_source
    if name == FORMAT_FIELD:
        return event.log_format
    return event.get(name)


@dataclass
class Cond:
    """A single field test. ``value`` semantics depend on ``op``."""

    field: str
    op: str = "icontains"
    value: Any = None

    def __post_init__(self) -> None:
        if self.op == "regex" and isinstance(self.value, str):
            self.value = re.compile(self.value, re.IGNORECASE)
        if self.op in ("in", "not_in", "any_contains", "any_regex") and isinstance(self.value, (list, tuple, set)):
            if self.op == "any_regex":
                self.value = [re.compile(item, re.IGNORECASE) if isinstance(item, str) else item for item in self.value]
            elif self.op in ("in", "not_in"):
                self.value = {str(item).lower() for item in self.value}
            else:
                self.value = [str(item).lower() for item in self.value]

    def test(self, event: Event) -> bool:
        raw = field_value(event, self.field)
        op = self.op
        if op == "exists":
            return raw is not None and raw != ""
        if op == "missing":
            return raw is None or raw == ""
        if raw is None:
            return False
        if isinstance(raw, (list, tuple)):
            raw = " ".join(str(item) for item in raw)
        text = str(raw)
        lowered = text.lower()
        value = self.value

        if op == "eq":
            return lowered == str(value).lower()
        if op == "ne":
            return lowered != str(value).lower()
        if op == "contains":
            return str(value) in text
        if op == "icontains":
            return str(value).lower() in lowered
        if op == "not_contains":
            return str(value).lower() not in lowered
        if op == "startswith":
            return lowered.startswith(str(value).lower())
        if op == "endswith":
            return lowered.endswith(str(value).lower())
        if op == "regex":
            return bool(value.search(text))
        if op == "any_regex":
            return any(pattern.search(text) for pattern in value)
        if op == "in":
            return lowered in value
        if op == "not_in":
            return lowered not in value
        if op == "any_contains":
            return any(item in lowered for item in value)
        if op == "all_contains":
            return all(item in lowered for item in value)
        if op in ("gt", "gte", "lt", "lte"):
            try:
                number = float(text)
                threshold = float(value)
            except (TypeError, ValueError):
                return False
            if op == "gt":
                return number > threshold
            if op == "gte":
                return number >= threshold
            if op == "lt":
                return number < threshold
            return number <= threshold
        if op == "len_gt":
            return len(text) > int(value)
        if op == "len_lt":
            return len(text) < int(value)
        if op == "entropy_gt":
            return shannon_entropy(text) > float(value)
        if op == "cidr":
            return _in_networks(text, value)
        if op == "not_cidr":
            return not _in_networks(text, value)
        if op == "private_ip":
            return _is_private(text) is True
        if op == "public_ip":
            return _is_private(text) is False
        return False


def _in_networks(text: str, networks: Iterable[str]) -> bool:
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    for network in networks if isinstance(networks, (list, tuple, set)) else [networks]:
        try:
            if address in ipaddress.ip_network(str(network), strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_private(text: str) -> bool | None:
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return address.is_private or address.is_loopback or address.is_link_local


@dataclass
class Selector:
    """Boolean combination of conditions."""

    all_of: Sequence[Cond] = field(default_factory=tuple)
    any_of: Sequence[Cond] = field(default_factory=tuple)
    none_of: Sequence[Cond] = field(default_factory=tuple)

    def test(self, event: Event) -> bool:
        for cond in self.all_of:
            if not cond.test(event):
                return False
        if self.any_of and not any(cond.test(event) for cond in self.any_of):
            return False
        for cond in self.none_of:
            if cond.test(event):
                return False
        return True


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """Metadata shared by every detection, plus the reporting narrative."""

    id: str
    name: str
    description: str
    severity: str = "medium"
    confidence: str = "medium"
    category: str = "general"
    detection_type: str = "pattern"
    data_sources: tuple[str, ...] = ()
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    risk: str = ""
    impact: str = ""
    recommendation: str = ""
    references: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    event_codes: tuple[str, ...] = ()
    max_findings: int = 25

    def base_finding(self, **overrides: Any) -> Finding:
        payload: dict[str, Any] = {
            "rule_id": self.id,
            "title": self.name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "detection_type": self.detection_type,
            "risk": self.risk,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "references": list(self.references),
        }
        payload.update(overrides)
        return Finding(**payload)


@dataclass
class PatternRule(Rule):
    """Matches individual events and groups identical hits together."""

    selector: Selector = field(default_factory=Selector)
    group_by: tuple[str, ...] = ("host.name", "user.name")
    detail_fields: tuple[str, ...] = ()
    detection_type: str = "pattern"

    def matches(self, event: Event) -> bool:
        return self.selector.test(event)


@dataclass
class ThresholdRule(Rule):
    """Counts matching events per group inside a sliding window."""

    selector: Selector = field(default_factory=Selector)
    group_by: tuple[str, ...] = ("source.ip",)
    distinct_field: str | None = None
    min_count: int = 10
    window_seconds: int = 300
    detection_type: str = "threshold"


@dataclass
class SequenceRule(Rule):
    """Requires several stages to occur for the same entity, in order."""

    stages: tuple[tuple[str, Selector], ...] = ()
    group_by: tuple[str, ...] = ("host.name",)
    window_seconds: int = 3600
    detection_type: str = "sequence"


@dataclass
class StatisticalRule(Rule):
    """Runs an arbitrary analysis function over the whole event set."""

    analyse: Callable[[Any, "StatisticalRule"], list[Finding]] | None = None
    detection_type: str = "statistical"

    def run(self, context: Any) -> list[Finding]:
        if self.analyse is None:
            return []
        return self.analyse(context, self)


def render(template: str, event: Event, extra: dict[str, Any] | None = None) -> str:
    """Fill ``{field.name}`` placeholders from an event or a mapping."""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if extra and key in extra:
            return str(extra[key])
        value = field_value(event, key) if event is not None else None
        return str(value) if value not in (None, "") else "unknown"

    return re.sub(r"\{([A-Za-z0-9_.]+)\}", replace, template)


def evidence_from(event: Event) -> dict[str, Any]:
    return {
        "source_file": event.source_file,
        "line_no": event.line_no,
        "timestamp": event.datetime_utc.isoformat() if event.datetime_utc else None,
        "log_format": event.log_format,
        "excerpt": event.excerpt(),
    }
