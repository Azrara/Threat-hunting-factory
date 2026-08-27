"""Detection execution: one pass over the events, then the aggregations."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .event import Event
from .rules.base import (
    Finding,
    PatternRule,
    Rule,
    SequenceRule,
    StatisticalRule,
    ThresholdRule,
    evidence_from,
    field_value,
    render,
)

MAX_EVIDENCE_PER_FINDING = 6


@dataclass
class HuntContext:
    """Everything an analysis function needs about the parsed evidence."""

    events: list[Event] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    data_sources: Counter = field(default_factory=Counter)
    formats: Counter = field(default_factory=Counter)
    parse_errors: int = 0
    lines_read: int = 0
    _index: dict[str, list[Event]] = field(default_factory=dict, repr=False)

    def by_source(self, *names: str) -> list[Event]:
        key = "|".join(sorted(names))
        if key not in self._index:
            wanted = set(names)
            self._index[key] = [event for event in self.events if event.data_source in wanted]
        return self._index[key]

    def with_field(self, name: str) -> list[Event]:
        key = f"field::{name}"
        if key not in self._index:
            self._index[key] = [event for event in self.events if event.get(name)]
        return self._index[key]

    def timespan(self) -> tuple[float | None, float | None]:
        stamps = [event.timestamp for event in self.events if event.timestamp]
        if not stamps:
            return None, None
        return min(stamps), max(stamps)


def group_key(event: Event, keys: tuple[str, ...]) -> str:
    parts = []
    for key in keys:
        value = field_value(event, key)
        if value not in (None, ""):
            parts.append(f"{str(value)[:120]}")
    return " | ".join(parts) if parts else "global"


class DetectionEngine:
    """Runs a rule set against a hunt context."""

    def __init__(self, rules: list[Rule], max_findings_per_rule: int = 50) -> None:
        self.rules = rules
        self.max_findings_per_rule = max_findings_per_rule
        self._prepare()

    # -- indexing ---------------------------------------------------------
    def _prepare(self) -> None:
        self.single_event_rules: list[Rule] = []
        self.statistical_rules: list[StatisticalRule] = []
        self.keyword_index: dict[str, set[str]] = defaultdict(set)
        self.code_index: dict[str, set[str]] = defaultdict(set)
        self.always_rules: set[str] = set()
        self.by_id: dict[str, Rule] = {}
        self.stage_selectors: dict[str, list] = {}

        keywords: set[str] = set()
        for rule in self.rules:
            self.by_id[rule.id] = rule
            if isinstance(rule, StatisticalRule):
                self.statistical_rules.append(rule)
                continue
            self.single_event_rules.append(rule)
            registered = False
            for keyword in rule.keywords:
                cleaned = keyword.lower().strip()
                if cleaned:
                    self.keyword_index[cleaned].add(rule.id)
                    keywords.add(cleaned)
                    registered = True
            for code in rule.event_codes:
                self.code_index[str(code)].add(rule.id)
                registered = True
            if not registered:
                self.always_rules.add(rule.id)
        if keywords:
            ordered = sorted(keywords, key=len, reverse=True)
            self.keyword_regex: re.Pattern[str] | None = re.compile(
                "|".join(re.escape(word) for word in ordered)
            )
        else:
            self.keyword_regex = None

    # -- execution --------------------------------------------------------
    def run(self, context: HuntContext, progress=None) -> list[Finding]:
        buckets = self._collect(context, progress)
        findings: list[Finding] = []
        findings.extend(self._pattern_findings(buckets))
        findings.extend(self._threshold_findings(buckets))
        findings.extend(self._sequence_findings(buckets, context))
        if progress:
            progress(0.85, "Running statistical models")
        findings.extend(self._statistical_findings(context))
        findings.sort(key=lambda item: (-item.score, item.rule_id))
        return findings

    def _collect(self, context: HuntContext, progress=None) -> dict[str, list[Event]]:
        buckets: dict[str, list[Event]] = defaultdict(list)
        total = max(1, len(context.events))
        step = max(1, total // 20)
        for index, event in enumerate(context.events):
            if progress and index % step == 0:
                progress(0.45 + 0.35 * (index / total), "Evaluating detection rules")
            candidates: set[str] = set(self.always_rules)
            code = event.get_str("event.code")
            if code:
                candidates |= self.code_index.get(code, set())
                if code.isdigit():
                    candidates |= self.code_index.get(str(int(code)), set())
            if self.keyword_regex is not None:
                text = event.searchable
                for match in self.keyword_regex.finditer(text):
                    candidates |= self.keyword_index[match.group(0)]
            if not candidates:
                continue
            for rule_id in candidates:
                rule = self.by_id.get(rule_id)
                if rule is None:
                    continue
                if rule.data_sources and event.data_source not in rule.data_sources:
                    continue
                if isinstance(rule, SequenceRule):
                    for stage_index, (_label, selector) in enumerate(rule.stages):
                        try:
                            if selector.test(event):
                                buckets[f"{rule.id}::stage{stage_index}"].append(event)
                        except Exception:
                            continue
                    continue
                selector = getattr(rule, "selector", None)
                if selector is None:
                    continue
                try:
                    if selector.test(event):
                        buckets[rule.id].append(event)
                except Exception:
                    continue
        return buckets

    # -- pattern ----------------------------------------------------------
    def _pattern_findings(self, buckets: dict[str, list[Event]]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.single_event_rules:
            if not isinstance(rule, PatternRule):
                continue
            matched = buckets.get(rule.id) or []
            if not matched:
                continue
            groups: dict[str, list[Event]] = defaultdict(list)
            for event in matched:
                groups[group_key(event, rule.group_by)].append(event)
            limit = min(rule.max_findings, self.max_findings_per_rule)
            for key, events in sorted(groups.items(), key=lambda item: -len(item[1]))[:limit]:
                findings.append(self._build_pattern_finding(rule, key, events))
        return findings

    def _build_pattern_finding(self, rule: PatternRule, key: str, events: list[Event]) -> Finding:
        sample = events[0]
        stamps = [event.timestamp for event in events if event.timestamp]
        details: dict[str, Any] = {}
        for name in rule.detail_fields or (
            "user.name", "host.name", "process.name", "process.command_line",
            "source.ip", "destination.ip", "url.original", "file.path",
        ):
            value = field_value(sample, name)
            if value not in (None, ""):
                details[name] = str(value)[:400]
        if key and key != "global":
            details["group"] = key
        finding = rule.base_finding(
            title=render(rule.name, sample),
            description=render(rule.description, sample),
            entity=sample.entity(),
            data_source=sample.data_source,
            source_files=sorted({event.source_file for event in events})[:10],
            evidence=[evidence_from(event) for event in events[:MAX_EVIDENCE_PER_FINDING]],
            fields=details,
            event_count=len(events),
            first_seen=min(stamps) if stamps else None,
            last_seen=max(stamps) if stamps else None,
        )
        return finding

    # -- threshold --------------------------------------------------------
    def _threshold_findings(self, buckets: dict[str, list[Event]]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.single_event_rules:
            if not isinstance(rule, ThresholdRule):
                continue
            matched = buckets.get(rule.id) or []
            if len(matched) < rule.min_count:
                continue
            groups: dict[str, list[Event]] = defaultdict(list)
            for event in matched:
                groups[group_key(event, rule.group_by)].append(event)
            limit = min(rule.max_findings, self.max_findings_per_rule)
            produced = 0
            for key, events in sorted(groups.items(), key=lambda item: -len(item[1])):
                if produced >= limit:
                    break
                window = self._best_window(rule, events)
                if window is None:
                    continue
                window_events, count, span = window
                metrics = {
                    "matched_events": len(events),
                    "window_seconds": rule.window_seconds,
                    "peak_in_window": count,
                    "threshold": rule.min_count,
                    "observed_span_seconds": round(span, 1),
                }
                if rule.distinct_field:
                    distinct = {
                        str(field_value(event, rule.distinct_field))
                        for event in window_events
                        if field_value(event, rule.distinct_field)
                    }
                    metrics["distinct_values"] = len(distinct)
                    metrics["distinct_field"] = rule.distinct_field
                    metrics["sample_values"] = sorted(distinct)[:15]
                sample = window_events[0]
                stamps = [event.timestamp for event in window_events if event.timestamp]
                findings.append(
                    rule.base_finding(
                        title=render(rule.name, sample, {"count": count}),
                        description=render(rule.description, sample, {"count": count, "window": rule.window_seconds}),
                        entity=key if key != "global" else sample.entity(),
                        data_source=sample.data_source,
                        source_files=sorted({event.source_file for event in window_events})[:10],
                        evidence=[evidence_from(event) for event in window_events[:MAX_EVIDENCE_PER_FINDING]],
                        fields={"group": key, "event_count": count},
                        metrics=metrics,
                        event_count=count,
                        first_seen=min(stamps) if stamps else None,
                        last_seen=max(stamps) if stamps else None,
                    )
                )
                produced += 1
        return findings

    def _best_window(self, rule: ThresholdRule, events: list[Event]) -> tuple[list[Event], int, float] | None:
        """Return the densest window that satisfies the rule threshold."""
        stamped = sorted((event for event in events if event.timestamp), key=lambda e: e.timestamp or 0.0)
        if not stamped:
            # Without timestamps fall back to the raw count.
            if rule.distinct_field:
                distinct = {
                    str(field_value(event, rule.distinct_field))
                    for event in events
                    if field_value(event, rule.distinct_field)
                }
                if len(distinct) >= rule.min_count:
                    return events, len(distinct), 0.0
                return None
            if len(events) >= rule.min_count:
                return events, len(events), 0.0
            return None

        best: tuple[list[Event], int, float] | None = None
        start = 0
        for end in range(len(stamped)):
            while (stamped[end].timestamp or 0.0) - (stamped[start].timestamp or 0.0) > rule.window_seconds:
                start += 1
            window = stamped[start : end + 1]
            if rule.distinct_field:
                distinct = {
                    str(field_value(event, rule.distinct_field))
                    for event in window
                    if field_value(event, rule.distinct_field)
                }
                count = len(distinct)
            else:
                count = len(window)
            if count >= rule.min_count and (best is None or count > best[1]):
                span = (window[-1].timestamp or 0.0) - (window[0].timestamp or 0.0)
                best = (window, count, span)
        return best

    # -- sequence ---------------------------------------------------------
    def _sequence_findings(self, buckets: dict[str, list[Event]], context: HuntContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.single_event_rules:
            if not isinstance(rule, SequenceRule):
                continue
            stage_events: list[list[Event]] = []
            for stage_index in range(len(rule.stages)):
                stage_events.append(buckets.get(f"{rule.id}::stage{stage_index}") or [])
            if any(not events for events in stage_events):
                continue
            grouped: dict[str, list[list[Event]]] = defaultdict(lambda: [[] for _ in rule.stages])
            for stage_index, events in enumerate(stage_events):
                for event in events:
                    grouped[group_key(event, rule.group_by)][stage_index].append(event)
            limit = min(rule.max_findings, self.max_findings_per_rule)
            for key, stages in grouped.items():
                if len(findings) >= limit:
                    break
                chain = self._match_chain(rule, stages)
                if not chain:
                    continue
                stamps = [event.timestamp for event in chain if event.timestamp]
                sample = chain[-1]
                findings.append(
                    rule.base_finding(
                        title=render(rule.name, sample),
                        description=render(rule.description, sample),
                        entity=key if key != "global" else sample.entity(),
                        data_source=sample.data_source,
                        source_files=sorted({event.source_file for event in chain})[:10],
                        evidence=[evidence_from(event) for event in chain[:MAX_EVIDENCE_PER_FINDING]],
                        fields={
                            "group": key,
                            "stages": ", ".join(label for label, _ in rule.stages),
                        },
                        metrics={
                            "stage_count": len(rule.stages),
                            "window_seconds": rule.window_seconds,
                            "elapsed_seconds": round((max(stamps) - min(stamps)), 1) if len(stamps) > 1 else 0.0,
                        },
                        event_count=len(chain),
                        first_seen=min(stamps) if stamps else None,
                        last_seen=max(stamps) if stamps else None,
                    )
                )
        return findings

    def _match_chain(self, rule: SequenceRule, stages: list[list[Event]]) -> list[Event]:
        """Greedy ordered match across the stages of a sequence rule."""
        undated = all(event.timestamp is None for stage in stages for event in stage)
        chain: list[Event] = []
        cursor: float | None = None
        for events in stages:
            ordered = sorted(events, key=lambda e: e.timestamp if e.timestamp is not None else 0.0)
            picked: Event | None = None
            for event in ordered:
                stamp = event.timestamp
                if stamp is None:
                    continue
                if cursor is not None and stamp < cursor:
                    continue
                anchor = chain[0].timestamp if chain and chain[0].timestamp is not None else None
                if anchor is not None and stamp - anchor > rule.window_seconds:
                    continue
                picked = event
                break
            if picked is None and undated and events:
                # Sources without usable timestamps still correlate on the entity.
                picked = events[0]
            if picked is None:
                return []
            chain.append(picked)
            if picked.timestamp is not None:
                cursor = picked.timestamp
        return chain

    # -- statistical ------------------------------------------------------
    def _statistical_findings(self, context: HuntContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.statistical_rules:
            try:
                produced = rule.run(context)
            except Exception:
                produced = []
            for finding in produced[: min(rule.max_findings, self.max_findings_per_rule)]:
                findings.append(finding)
        return findings
