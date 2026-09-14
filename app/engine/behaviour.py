"""Behavioural profiling: observations the rule library does not describe.

A detection rule answers a question somebody already thought to ask. This module
answers a different one: which entity in this evidence does not behave like its
peers, whatever the reason. It builds a feature vector for every host, account,
process, address, destination and client, compares each entity only against
entities of the same kind, and reports the ones that stand out on several
independent features at once.

Three design choices carry the quality of the result.

**Peer groups, never one global distribution.** A domain controller does not
behave like a laptop and a service account does not behave like a person. Mixing
them manufactures outliers, so every feature is scored inside its own kind.

**Agreement, not magnitude.** One extreme number is usually a measurement
artefact. An entity that is simultaneously unusual in volume, in timing and in
diversity is usually worth a look. The candidate rule is therefore agreement
across independent features, with a single very extreme feature as the only
exception.

**Sequence surprise.** A first order Markov model over per entity event type
sequences scores how improbable an entity's own order of operations is. That
catches the right events in the wrong order, which no fixed rule expresses.

Everything here is deterministic and needs no model server. It is the part of the
behavioural analyst that runs on any host, and it is also what reduces a corpus of
half a million events to a few hundred candidates that a model could later
adjudicate. See ``docs/ai-agents-design.md``.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .event import Event
from .rules.base import Finding, evidence_from
from .stats_math import modified_zscores, normalised_entropy, percentile

# -- bounds -----------------------------------------------------------------
# A hunt runs on modest hardware, so every unbounded structure gets a ceiling.
MAX_ENTITIES_PER_KIND = 20000
MAX_SAMPLE_EVENTS = 3
# An entity seen a handful of times has no behaviour to profile, and letting those
# into the population drags the median down until every genuinely active entity
# looks like an outlier. The floor is what makes the peer median mean something.
MIN_EVENTS_PER_ENTITY = 10
MIN_PEER_GROUP = 8
# Robust statistics need a population. Below this the median absolute deviation
# is meaningless and every entity looks like an outlier.
MIN_FEATURE_POPULATION = 8
OUTLIER_Z = 3.5
EXTREME_Z = 8.0
MIN_AGREEING_FAMILIES = 3
# A feature whose values are nearly all identical produces meaningless z scores:
# the deviation collapses towards zero and the ratio explodes. Anything past this
# ceiling is a degenerate distribution rather than a strong signal.
MAX_SANE_Z = 1000.0
# Seven distinct accounts against a peer median of six is a z score of nine and a
# difference of one. Statistical distance is not practical distance, so an outlier
# must also stand clear of its peers by a margin a reader would call a difference.
MIN_RATIO_OVER_PEER = 1.5
MAX_FINDINGS_PER_KIND = 8
# A candidate carried by one family alone is a weaker claim, and several entities
# usually share the same cause. Report the strongest few and stop.
MAX_SINGLE_FAMILY_PER_KIND = 2
MAX_TRANSITIONS_PER_ENTITY = 256
MAX_FINDINGS = 25
# Shannon entropy over every command line in a large corpus costs more than it is
# worth, so distinct values are memoised and the total work is capped.
ENTROPY_BUDGET = 40000
ENTROPY_KEY_LENGTH = 256
BURST_BUCKET_SECONDS = 300.0
BUSINESS_HOURS = range(7, 20)


@dataclass
class EntityKind:
    """One population of comparable entities."""

    key: str
    label: str
    fields: tuple[str, ...]


ENTITY_KINDS: tuple[EntityKind, ...] = (
    EntityKind("host", "host", ("host.name",)),
    EntityKind("account", "account", ("user.name",)),
    EntityKind("process", "process image", ("process.name",)),
    EntityKind("source", "source address", ("source.ip",)),
    EntityKind("destination", "destination", ("destination.domain", "destination.ip")),
    EntityKind("client", "client software", ("user_agent.original",)),
)

# Features where only an unusually HIGH value is interesting. A host with fewer
# distinct destinations than its peers is not a finding.
HIGH_ONLY = {
    "events",
    "events_per_active_hour",
    "off_hours_ratio",
    "weekend_ratio",
    "burst_ratio",
    "distinct_destinations",
    "distinct_ports",
    "distinct_accounts",
    "distinct_hosts",
    "distinct_processes",
    "distinct_parents",
    "failure_ratio",
    "mean_command_entropy",
    "max_command_entropy",
    "bytes_out",
    "out_in_ratio",
    "interval_regularity",
    "sequence_surprise",
}

# Features inside one family measure the same underlying thing. Counting them
# separately would turn one observation into three and break the premise that
# agreement means independent evidence, so agreement is counted in families.
FEATURE_FAMILIES = {
    "events": "volume",
    "events_per_active_hour": "volume",
    "burst_ratio": "volume",
    "off_hours_ratio": "timing",
    "weekend_ratio": "timing",
    "interval_regularity": "timing",
    "distinct_destinations": "diversity",
    "distinct_ports": "diversity",
    "distinct_accounts": "diversity",
    "distinct_hosts": "diversity",
    "distinct_processes": "diversity",
    "distinct_parents": "diversity",
    "mean_command_entropy": "content",
    "max_command_entropy": "content",
    "bytes_out": "volumetrics",
    "out_in_ratio": "volumetrics",
    "failure_ratio": "outcome",
    "sequence_surprise": "sequence",
}

# Being statistically extreme is not the same as meaning anything. A sequence
# surprise of 0.01 bits against a peer median of 0.00 is a real z score and an
# empty observation. Below these values a feature cannot carry a finding, whatever
# the distribution says.
FEATURE_FLOORS = {
    "events": 20.0,
    "events_per_active_hour": 5.0,
    "burst_ratio": 3.0,
    "off_hours_ratio": 0.3,
    "weekend_ratio": 0.3,
    "interval_regularity": 0.7,
    "distinct_destinations": 5.0,
    "distinct_ports": 5.0,
    "distinct_accounts": 5.0,
    "distinct_hosts": 5.0,
    "distinct_processes": 5.0,
    "distinct_parents": 4.0,
    "failure_ratio": 0.5,
    "mean_command_entropy": 0.6,
    "max_command_entropy": 0.6,
    "out_in_ratio": 2.0,
    "sequence_surprise": 1.0,
}

FEATURE_LABELS = {
    "events": "event volume",
    "events_per_active_hour": "events per active hour",
    "off_hours_ratio": "share of activity outside business hours",
    "weekend_ratio": "share of activity at the weekend",
    "burst_ratio": "burstiness",
    "distinct_destinations": "number of distinct destinations",
    "distinct_ports": "number of distinct ports",
    "distinct_accounts": "number of distinct accounts",
    "distinct_hosts": "number of distinct hosts",
    "distinct_processes": "number of distinct processes",
    "distinct_parents": "number of distinct parent processes",
    "failure_ratio": "share of failed outcomes",
    "mean_command_entropy": "average command line entropy",
    "max_command_entropy": "peak command line entropy",
    "bytes_out": "bytes sent",
    "out_in_ratio": "ratio of bytes sent to bytes received",
    "interval_regularity": "regularity of the interval between events",
    "sequence_surprise": "improbability of its own sequence of actions",
}


# ---------------------------------------------------------------------------
# accumulation
# ---------------------------------------------------------------------------


@dataclass
class _Accumulator:
    """Running state for one entity. Keeps counts, never the events themselves."""

    kind: str
    value: str
    events: int = 0
    hours: set[int] = field(default_factory=set)
    off_hours: int = 0
    weekend: int = 0
    stamped: int = 0
    failures: int = 0
    outcomes: int = 0
    buckets: Counter = field(default_factory=Counter)
    distinct: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    bytes_out: float = 0.0
    bytes_in: float = 0.0
    entropy_sum: float = 0.0
    entropy_max: float = 0.0
    entropy_count: int = 0
    timestamps: list[float] = field(default_factory=list)
    transitions: Counter = field(default_factory=Counter)
    last_type: str = ""

    first_seen: float | None = None
    last_seen: float | None = None
    samples: list[Event] = field(default_factory=list)

    def note(self, event: Event, event_type: str, stamp: float | None,
             hour: int, off_hours: bool, weekend: bool, bucket: int) -> None:
        """Record one event.

        The calendar arithmetic is done once per event by the caller and handed in,
        because an event belongs to several entities at once and converting its
        timestamp separately for each of them was the single most expensive thing
        this profiler did.
        """
        self.events += 1
        if self.last_type:
            # The sequence of actions is learned here rather than in a second pass
            # over the corpus. Per entity there are at most a few hundred distinct
            # transitions, so this stays bounded while the event count does not.
            if len(self.transitions) < MAX_TRANSITIONS_PER_ENTITY:
                self.transitions[(self.last_type, event_type)] += 1
        self.last_type = event_type
        if len(self.samples) < MAX_SAMPLE_EVENTS:
            self.samples.append(event)
        if stamp is None:
            return
        self.stamped += 1
        self.first_seen = stamp if self.first_seen is None else min(self.first_seen, stamp)
        self.last_seen = stamp if self.last_seen is None else max(self.last_seen, stamp)
        if hour >= 0:
            self.hours.add(hour)
            if off_hours:
                self.off_hours += 1
            if weekend:
                self.weekend += 1
        self.buckets[bucket] += 1
        # Regularity needs the ordered series, and the series is the only per
        # entity list kept, so it is capped.
        if len(self.timestamps) < 4096:
            self.timestamps.append(stamp)


def _distinct_add(acc: _Accumulator, name: str, value: str) -> None:
    bucket = acc.distinct[name]
    # A single entity talking to a million destinations must not cost a million
    # strings. The cap is far above any threshold the scoring cares about.
    if len(bucket) < 4096:
        bucket.add(value)


class _EntropyCache:
    """Memoised normalised entropy under a total work budget."""

    def __init__(self, budget: int = ENTROPY_BUDGET) -> None:
        self.budget = budget
        self.values: dict[str, float] = {}

    def score(self, text: str) -> float | None:
        key = text[:ENTROPY_KEY_LENGTH]
        cached = self.values.get(key)
        if cached is not None:
            return cached
        if self.budget <= 0:
            return None
        self.budget -= 1
        value = normalised_entropy(key)
        if len(self.values) < ENTROPY_BUDGET:
            self.values[key] = value
        return value


def _event_type(event: Event) -> str:
    """A stable, coarse label for what kind of thing happened."""
    code = event.get_str("event.code") or event.get_str("event.action")
    if not code:
        code = event.get_str("http.request.method") or "event"
    return f"{event.data_source}:{code.lower()[:40]}"


# ---------------------------------------------------------------------------
# sequence surprise
# ---------------------------------------------------------------------------


def _sequence_surprise(accumulators: dict[str, _Accumulator]) -> dict[str, float]:
    """Mean negative log probability of each entity's own transitions, per kind.

    The transition counts were gathered during the single pass over the evidence,
    so this works on a few thousand small counters rather than on the corpus. Each
    kind is scored against its own transition table: how surprising a sequence is
    for a host is a different question from how surprising it is for an account.
    """
    transitions: Counter = Counter()
    origins: Counter = Counter()
    vocabulary: set[str] = set()
    for acc in accumulators.values():
        for (before, after), count in acc.transitions.items():
            transitions[(before, after)] += count
            origins[before] += count
            vocabulary.add(before)
            vocabulary.add(after)

    size = len(vocabulary)
    if size < 2 or not transitions:
        return {}

    scores: dict[str, float] = {}
    for value, acc in accumulators.items():
        steps = sum(acc.transitions.values())
        if steps < 2:
            continue
        total = 0.0
        for (before, after), count in acc.transitions.items():
            # Laplace smoothing: an unseen transition is improbable, not impossible.
            probability = (transitions[(before, after)] + 1) / (origins[before] + size)
            total += count * -math.log2(probability)
        scores[value] = total / steps
    return scores


def _interval_regularity(stamps: list[float]) -> float | None:
    """1.0 for a perfect metronome, near 0 for irregular human activity."""
    if len(stamps) < 6:
        return None
    ordered = sorted(stamps)
    gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b > a]
    if len(gaps) < 5:
        return None
    median = percentile(gaps, 50)
    if median <= 0:
        return None
    deviations = [abs(gap - median) for gap in gaps]
    spread = percentile(deviations, 50) / median
    return max(0.0, 1.0 - min(spread, 1.0))


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------


@dataclass
class EntityProfile:
    kind: str
    label: str
    value: str
    events: int
    features: dict[str, float]
    samples: list[Event]
    first_seen: float | None
    last_seen: float | None


@dataclass
class FeatureOutlier:
    name: str
    label: str
    value: float
    peer_median: float
    zscore: float

    @property
    def family(self) -> str:
        return FEATURE_FAMILIES.get(self.name, self.name)


@dataclass
class BehaviourCandidate:
    profile: EntityProfile
    outliers: list[FeatureOutlier]
    score: float

    @property
    def families(self) -> list[str]:
        seen: list[str] = []
        for outlier in self.outliers:
            if outlier.family not in seen:
                seen.append(outlier.family)
        return seen

    @property
    def agreement(self) -> int:
        """How many independent kinds of evidence agree, not how many numbers."""
        return len(self.families)


def _entity_values(event: Event, kind: EntityKind) -> str:
    for name in kind.fields:
        value = event.get_str(name)
        if value:
            return value[:200]
    return ""


def _entity_map(
    host: str, account: str, process: str, source: str, destination: str, client: str
) -> dict[str, str]:
    """The entity value per kind, from values already read once from the event.

    Reading each field once and handing the results to every consumer is what keeps
    the profiler linear in practice. Calling ``_entity_values`` per kind would read
    the same fields again for every kind, on every record.
    """
    return {
        "host": host[:200],
        "account": account[:200],
        "process": process[:200],
        "source": source[:200],
        "destination": destination[:200],
        "client": client[:200],
    }


def build_profiles(events: list[Event]) -> dict[str, list[EntityProfile]]:
    """One pass over the evidence, one feature vector per entity."""
    if not events:
        return {}

    ordered = sorted(events, key=lambda event: event.timestamp or 0.0)
    accumulators: dict[str, dict[str, _Accumulator]] = {kind.key: {} for kind in ENTITY_KINDS}
    entropy = _EntropyCache()

    for event in ordered:
        event_type = _event_type(event)
        stamp = event.timestamp
        hour, off_hours, weekend, time_bucket = -1, False, False, 0
        if stamp:
            moment = event.datetime_utc
            if moment is not None:
                hour = moment.hour
                off_hours = hour not in BUSINESS_HOURS
                weekend = moment.weekday() >= 5
            time_bucket = int(stamp // BURST_BUCKET_SECONDS)
        command = event.get_str("process.command_line")
        entropy_value = entropy.score(command) if len(command) >= 12 else None
        outcome = event.get_str("event.outcome").lower()
        destination = event.get_str("destination.domain") or event.get_str("destination.ip")
        port = event.get_str("destination.port")
        account = event.get_str("user.name")
        host = event.get_str("host.name")
        process = event.get_str("process.name")
        parent = event.get_str("process.parent.name")
        if not (host or account or process or destination):
            # Nothing this profiler can attribute the record to. Skipping here saves
            # the remaining field reads on records that carry no entity at all.
            if not (event.get_str("source.ip") or event.get_str("user_agent.original")):
                continue
        bytes_out = event.get_float("network.bytes_out")
        bytes_in = event.get_float("network.bytes_in")
        entities = _entity_map(
            host, account, process, event.get_str("source.ip"), destination,
            event.get_str("user_agent.original"),
        )

        for kind in ENTITY_KINDS:
            value = entities[kind.key]
            if not value:
                continue
            bucket = accumulators[kind.key]
            acc = bucket.get(value)
            if acc is None:
                if len(bucket) >= MAX_ENTITIES_PER_KIND:
                    continue
                acc = _Accumulator(kind.key, value)
                bucket[value] = acc
            acc.note(event, event_type, stamp, hour, off_hours, weekend, time_bucket)

            if destination:
                _distinct_add(acc, "destinations", destination[:120])
            if port:
                _distinct_add(acc, "ports", port[:12])
            if account and kind.key != "account":
                _distinct_add(acc, "accounts", account[:120])
            if host and kind.key != "host":
                _distinct_add(acc, "hosts", host[:120])
            if process and kind.key != "process":
                _distinct_add(acc, "processes", process[:120])
            if parent:
                _distinct_add(acc, "parents", parent[:120])
            if outcome:
                acc.outcomes += 1
                if outcome in ("failure", "failed", "fail", "denied", "error"):
                    acc.failures += 1
            if entropy_value is not None:
                acc.entropy_sum += entropy_value
                acc.entropy_max = max(acc.entropy_max, entropy_value)
                acc.entropy_count += 1
            if bytes_out:
                acc.bytes_out += max(0.0, bytes_out)
            if bytes_in:
                acc.bytes_in += max(0.0, bytes_in)

    profiles: dict[str, list[EntityProfile]] = {}
    labels = {kind.key: kind.label for kind in ENTITY_KINDS}
    for key, bucket in accumulators.items():
        surprise = _sequence_surprise(bucket)
        collected = [
            _to_profile(acc, labels[key], surprise.get(acc.value))
            for acc in bucket.values()
            if acc.events >= MIN_EVENTS_PER_ENTITY
        ]
        if collected:
            profiles[key] = collected
    return profiles


def _to_profile(acc: _Accumulator, label: str, surprise: float | None) -> EntityProfile:
    features: dict[str, float] = {"events": float(acc.events)}
    active_hours = len(acc.hours) or 1
    if acc.stamped:
        features["events_per_active_hour"] = acc.events / active_hours
        features["off_hours_ratio"] = acc.off_hours / acc.stamped
        features["weekend_ratio"] = acc.weekend / acc.stamped
        if acc.buckets:
            counts = list(acc.buckets.values())
            mean = sum(counts) / len(counts)
            if mean > 0:
                features["burst_ratio"] = max(counts) / mean
    for name, target in (
        ("destinations", "distinct_destinations"),
        ("ports", "distinct_ports"),
        ("accounts", "distinct_accounts"),
        ("hosts", "distinct_hosts"),
        ("processes", "distinct_processes"),
        ("parents", "distinct_parents"),
    ):
        values = acc.distinct.get(name)
        if values:
            features[target] = float(len([item for item in values if item]))
    if acc.outcomes:
        features["failure_ratio"] = acc.failures / acc.outcomes
    if acc.entropy_count:
        features["mean_command_entropy"] = acc.entropy_sum / acc.entropy_count
        features["max_command_entropy"] = acc.entropy_max
    if acc.bytes_out:
        features["bytes_out"] = acc.bytes_out
        features["out_in_ratio"] = acc.bytes_out / acc.bytes_in if acc.bytes_in else float(acc.bytes_out)
    regularity = _interval_regularity(acc.timestamps)
    if regularity is not None:
        features["interval_regularity"] = regularity
    if surprise is not None:
        features["sequence_surprise"] = surprise

    return EntityProfile(
        kind=acc.kind,
        label=label,
        value=acc.value,
        events=acc.events,
        features=features,
        samples=list(acc.samples),
        first_seen=acc.first_seen,
        last_seen=acc.last_seen,
    )


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def score_profiles(profiles: Iterable[EntityProfile]) -> list[BehaviourCandidate]:
    """Score one peer group. Returns candidates ordered by strength."""
    population = [profile for profile in profiles]
    if len(population) < MIN_PEER_GROUP:
        return []

    names: set[str] = set()
    for profile in population:
        names.update(profile.features)

    outliers_by_entity: dict[int, list[FeatureOutlier]] = defaultdict(list)
    for name in sorted(names):
        present = [(index, profile) for index, profile in enumerate(population) if name in profile.features]
        if len(present) < MIN_FEATURE_POPULATION:
            continue
        values = [profile.features[name] for _, profile in present]
        scores = _usable_scores(values)
        if scores is None:
            continue
        median = percentile(values, 50)
        for (index, _profile), value, score in zip(present, values, scores):
            if abs(score) < OUTLIER_Z:
                continue
            if name in HIGH_ONLY and score < 0:
                continue
            if name in HIGH_ONLY:
                if value < FEATURE_FLOORS.get(name, 0.0):
                    continue
                if median > 0 and value < median * MIN_RATIO_OVER_PEER:
                    continue
            outliers_by_entity[index].append(
                FeatureOutlier(
                    name=name,
                    label=FEATURE_LABELS.get(name, name.replace("_", " ")),
                    value=round(value, 4),
                    peer_median=round(median, 4),
                    zscore=round(score, 2),
                )
            )

    candidates: list[BehaviourCandidate] = []
    for index, outliers in outliers_by_entity.items():
        strongest = max(abs(item.zscore) for item in outliers)
        candidate = BehaviourCandidate(
            profile=population[index],
            outliers=sorted(outliers, key=lambda item: -abs(item.zscore)),
            score=0.0,
        )
        # Agreement across independent families, or one measurement so extreme
        # that it stands on its own.
        if candidate.agreement < MIN_AGREEING_FAMILIES and strongest < EXTREME_Z:
            continue
        # One score per family, taking its strongest member, so a family with
        # three correlated members does not count three times here either.
        best_per_family: dict[str, float] = {}
        for item in outliers:
            best_per_family[item.family] = max(
                best_per_family.get(item.family, 0.0), min(abs(item.zscore), 12.0)
            )
        candidate.score = round(sum(best_per_family.values()), 2)
        candidates.append(candidate)
    return sorted(candidates, key=lambda candidate: (-candidate.agreement, -candidate.score))


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


RISK_BY_KIND = {
    "host": "A host that stops resembling its peers is either newly repurposed or newly controlled by "
            "somebody else. Compromised systems diverge from their own baseline before any signature fires.",
    "account": "An account behaving unlike every comparable account is the earliest visible symptom of "
               "credential misuse, and it precedes the actions a signature would catch.",
    "process": "A process image whose behaviour differs from every other image in the estate is either "
               "unmanaged software or an attacker tool wearing a familiar name.",
    "source": "A source address that stands apart from its peers is usually automation. Automation that "
              "nobody scheduled is tooling.",
    "destination": "A destination that no other entity treats the same way is a candidate command and "
                   "control channel or an unsanctioned data path.",
    "client": "Client software that behaves unlike every other client is frequently a script or an "
              "implant presenting a borrowed user agent.",
}

IMPACT_BY_KIND = {
    "host": "If the divergence is attacker driven, the host is a foothold from which the rest of the "
            "estate is reachable.",
    "account": "Misused credentials give an intruder legitimate access, which survives most containment "
               "that focuses on malware.",
    "process": "An unmanaged or malicious binary executing at scale provides durable execution across "
               "the estate.",
    "source": "Unattended automation from one address supports enumeration, brute force and collection "
              "at a speed no analyst will match.",
    "destination": "An unsanctioned channel carries command traffic inbound and data outbound, often for "
                   "as long as it stays unnoticed.",
    "client": "A borrowed user agent hides the real client, which delays attribution during an incident.",
}


def _behaviour_finding(candidate: BehaviourCandidate) -> Finding:
    profile = candidate.profile
    strongest_per_family: dict[str, FeatureOutlier] = {}
    for item in candidate.outliers:
        current = strongest_per_family.get(item.family)
        if current is None or abs(item.zscore) > abs(current.zscore):
            strongest_per_family[item.family] = item
    highlighted = sorted(strongest_per_family.values(), key=lambda item: -abs(item.zscore))
    reasons = ", ".join(
        f"{item.label} of {_format_number(item.value)} against a peer median of "
        f"{_format_number(item.peer_median)}"
        for item in highlighted[:4]
    )
    plural = "kinds of measurement" if candidate.agreement != 1 else "kind of measurement"
    description = (
        f"The {profile.label} {profile.value} does not behave like the other {profile.label}s in this "
        f"evidence. It stands out on {candidate.agreement} independent {plural} at once "
        f"({', '.join(candidate.families)}): {reasons}. "
        "Each comparison is made only against entities of the same kind, using median absolute deviation "
        "so that a handful of extreme values cannot move the baseline. No detection rule describes this "
        "behaviour, which is the reason it is reported: it is a deviation from the population, not a "
        "match against a known technique."
    )
    # Capped at medium by design: a deviation from a population is a lead, not a
    # confirmed intrusion, and only a rule or a corroborating signal earns more.
    severity = "medium" if candidate.agreement >= 4 else "low"

    samples = profile.samples
    return Finding(
        rule_id=f"behaviour-{profile.kind}",
        title=f"Behavioural outlier: the {profile.label} {profile.value}",
        description=description,
        severity=severity,
        confidence="low",
        category="anomaly",
        detection_type="behavioural",
        origin="anomaly",
        risk=RISK_BY_KIND.get(profile.kind, ""),
        impact=IMPACT_BY_KIND.get(profile.kind, ""),
        recommendation=(
            f"Establish what the {profile.label} {profile.value} is for and who owns it, then compare the "
            "behaviour above against that expectation. A documented service account, scanner or backup job "
            "explains most of these. If no owner claims it, treat the listed features as the starting "
            "point of an investigation and pull the full activity for the period shown. Record the "
            "conclusion so the next hunt does not repeat the work."
        ),
        mitre_tactic="Discovery",
        mitre_technique="Behavioural outlier",
        mitre_technique_id="",
        entity=profile.value,
        data_source=samples[0].data_source if samples else "",
        source_files=sorted({event.source_file for event in samples})[:10],
        evidence=[evidence_from(event) for event in samples],
        fields={"entity_kind": profile.label, "events": profile.events},
        metrics={
            "peer_group": profile.label,
            "agreeing_families": candidate.agreement,
            "families": candidate.families,
            "anomaly_score": candidate.score,
            "event_count": profile.events,
            "outliers": [
                {
                    "feature": item.name,
                    "label": item.label,
                    "value": item.value,
                    "peer_median": item.peer_median,
                    "modified_zscore": item.zscore,
                }
                for item in candidate.outliers
            ],
        },
        references=[
            "https://www.itl.nist.gov/div898/handbook/eda/section3/eda35h.htm",
            "https://attack.mitre.org/",
        ],
        event_count=profile.events,
        first_seen=profile.first_seen,
        last_seen=profile.last_seen,
    )


def _usable_scores(values: list[float]) -> list[float] | None:
    """Robust z scores for one feature, or None when the distribution is degenerate.

    Counting distinct values is the wrong test here. A feature where most entities
    sit at 2 and one sits at 120 has only two distinct values and is exactly the
    signal worth reporting. The pathology to reject is different: when almost every
    value is identical and the few differences are floating point noise, the
    deviation collapses towards zero and the ratio explodes into the billions. That
    is what the ceiling catches, and nothing else.
    """
    if max(values) == min(values):
        return None
    scores = modified_zscores(values)
    if max(abs(score) for score in scores) > MAX_SANE_Z:
        return None
    return scores


def _format_number(value: float) -> str:
    if value >= 1000:
        return f"{value:,.0f}"
    if value == int(value):
        return str(int(value))
    return f"{value:.2f}"


def _limit_single_family(candidates: list[BehaviourCandidate]) -> list[BehaviourCandidate]:
    """Keep every corroborated candidate, but only the strongest few single family ones."""
    kept: list[BehaviourCandidate] = []
    singles = 0
    for candidate in candidates:
        if candidate.agreement >= MIN_AGREEING_FAMILIES:
            kept.append(candidate)
            continue
        if singles < MAX_SINGLE_FAMILY_PER_KIND:
            singles += 1
            kept.append(candidate)
    return kept


def analyse_behaviour(
    events: list[Event],
    max_findings: int = MAX_FINDINGS,
) -> tuple[list[Finding], list[BehaviourCandidate]]:
    """Profile the evidence and report the entities that stand apart.

    Returns the findings and the candidates behind them. The candidates are what a
    model would later adjudicate, which is why they are returned rather than
    discarded.
    """
    profiles = build_profiles(events)
    findings: list[Finding] = []
    candidates: list[BehaviourCandidate] = []
    for kind in ENTITY_KINDS:
        group = profiles.get(kind.key)
        if not group:
            continue
        scored = _limit_single_family(score_profiles(group))[:MAX_FINDINGS_PER_KIND]
        candidates.extend(scored)
        findings.extend(_behaviour_finding(candidate) for candidate in scored)
    ranked = sorted(
        zip(findings, candidates),
        key=lambda pair: (-pair[1].agreement, -pair[1].score),
    )[:max_findings]
    return [finding for finding, _ in ranked], [candidate for _, candidate in ranked]
