"""Hunt orchestration: extract, parse, detect, score."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import settings
from .behaviour import BehaviourCandidate, analyse_behaviour
from .catalog import DATA_SOURCES, Hypothesis
from .executor import DetectionEngine, HuntContext
from .ingest import collect_log_files, extract_archive, read_lines, sample_lines
from .parsers import select_parser
from .rules.base import Finding

ProgressCallback = Callable[[float, str], None]

# Maps the data source label produced by the parsers onto the catalogue entries.
SOURCE_ALIGNMENT = {
    "windows_security": "windows_security",
    "windows_event": "windows_security",
    "sysmon": "sysmon",
    "powershell": "powershell",
    "linux_auth": "linux_auth",
    "web": "web_server",
    "dns": "dns",
    "network_flow": "network_flow",
    "aws_cloudtrail": "aws_cloudtrail",
    "o365_audit": "m365_audit",
    "ids": "ids",
    "security_appliance": "network_flow",
    "tls": "network_flow",
    "syslog": "linux_auth",
    "endpoint": "edr",
    "entra_signin": "entra_signin",
    "k8s_audit": "k8s_audit",
    "idp": "idp",
}

SEVERITY_WEIGHT = {"critical": 30.0, "high": 16.0, "medium": 7.0, "low": 2.5, "info": 1.0}


@dataclass
class FileReport:
    name: str
    path: str
    size_bytes: int
    log_format: str
    data_source: str
    confidence: float
    events: int
    lines: int


@dataclass
class HuntOutcome:
    findings: list[Finding] = field(default_factory=list)
    files: list[FileReport] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    events_parsed: int = 0
    lines_read: int = 0
    rules_evaluated: int = 0
    duration_ms: int = 0
    formats: dict[str, int] = field(default_factory=dict)
    data_sources: dict[str, int] = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    risk_score: float = 0.0
    verdict: str = "No significant findings"
    timespan: dict = field(default_factory=dict)
    # Kept rather than discarded: these are what a model would later adjudicate.
    behaviour_candidates: list[BehaviourCandidate] = field(default_factory=list)

    def summary(self) -> dict:
        severities = Counter(finding.severity for finding in self.findings)
        categories = Counter(finding.category for finding in self.findings)
        techniques = Counter(
            f"{finding.mitre_technique_id} {finding.mitre_technique}".strip()
            for finding in self.findings
            if finding.mitre_technique_id
        )
        detection_types = Counter(finding.detection_type for finding in self.findings)
        return {
            "severities": dict(severities),
            "categories": dict(categories),
            "top_techniques": techniques.most_common(10),
            "detection_types": dict(detection_types),
            "files": [file.__dict__ for file in self.files],
            "skipped": self.skipped[:50],
            "warnings": self.warnings[:20],
            "formats": self.formats,
            "data_sources": self.data_sources,
            "timespan": self.timespan,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "entities": Counter(finding.entity for finding in self.findings if finding.entity).most_common(10),
        }


def parse_evidence(
    archive_path: Path,
    workdir: Path,
    progress: ProgressCallback | None = None,
    max_events: int | None = None,
) -> tuple[HuntContext, HuntOutcome]:
    """Extract an archive and normalise every log file it contains."""
    outcome = HuntOutcome()
    context = HuntContext()
    max_events = max_events or settings.max_events

    if progress:
        progress(0.05, "Extracting evidence archive")
    extraction = extract_archive(archive_path, workdir, settings.max_uncompressed_bytes)
    outcome.warnings.extend(extraction.warnings)
    outcome.skipped.extend(extraction.skipped)

    if progress:
        progress(0.12, "Identifying log files")
    files, skipped = collect_log_files(workdir)
    outcome.skipped.extend(skipped)
    if not files:
        outcome.warnings.append("The archive contained no readable log files")
        return context, outcome

    total_files = len(files)
    for index, path in enumerate(files):
        if progress:
            progress(0.12 + 0.3 * (index / total_files), f"Parsing {path.name}")
        try:
            sample = sample_lines(path, 60)
        except Exception:
            outcome.skipped.append(f"{path.name} (unreadable)")
            continue
        if not any(line.strip() for line in sample):
            outcome.skipped.append(f"{path.name} (empty)")
            continue
        parser, confidence, _scores = select_parser(sample, path.name)
        relative = str(path.relative_to(workdir)) if workdir in path.parents or path.parent == workdir else path.name
        file_events = 0
        file_lines = 0
        source_counter: Counter = Counter()
        try:
            for line_index, _line in enumerate(read_lines(path)):
                file_lines = line_index + 1
        except Exception:
            file_lines = 0
        try:
            for event in parser.parse(read_lines(path), relative):
                if len(context.events) >= max_events:
                    outcome.warnings.append(
                        f"Event limit of {max_events} reached, later records were not analysed"
                    )
                    break
                context.events.append(event)
                source_counter[event.data_source] += 1
                context.data_sources[event.data_source] += 1
                context.formats[event.log_format] += 1
                file_events += 1
        except Exception as error:  # a single malformed file must not stop the hunt
            outcome.warnings.append(f"{path.name}: parsing stopped early ({type(error).__name__})")
        outcome.files.append(
            FileReport(
                name=path.name,
                path=relative,
                size_bytes=path.stat().st_size if path.exists() else 0,
                log_format=parser.name,
                data_source=(source_counter.most_common(1)[0][0] if source_counter else parser.data_source),
                confidence=round(confidence, 3),
                events=file_events,
                lines=file_lines,
            )
        )
        outcome.lines_read += file_lines
        if len(context.events) >= max_events:
            break

    context.files = [file.path for file in outcome.files]
    context.lines_read = outcome.lines_read
    outcome.events_parsed = len(context.events)
    outcome.formats = dict(context.formats)
    outcome.data_sources = dict(context.data_sources)
    start, end = context.timespan()
    outcome.timespan = {
        "start": start,
        "end": end,
        "duration_seconds": round(end - start, 1) if start and end else 0.0,
    }
    return context, outcome


def evaluate_coverage(hypothesis: Hypothesis, observed: dict[str, int]) -> dict:
    """Report which of the data sources the hypothesis wants are actually present."""
    aligned: Counter = Counter()
    for source, count in observed.items():
        mapped = SOURCE_ALIGNMENT.get(source)
        if mapped:
            aligned[mapped] += count
    required = list(hypothesis.required_data_sources)
    optional = list(hypothesis.optional_data_sources)
    satisfied = [source for source in required if aligned.get(source)]
    missing = [source for source in required if not aligned.get(source)]
    optional_present = [source for source in optional if aligned.get(source)]
    ratio = (len(satisfied) / len(required)) if required else 1.0
    return {
        "required": [{"id": source, "name": DATA_SOURCES[source].name if source in DATA_SOURCES else source,
                      "present": source in satisfied, "events": aligned.get(source, 0)} for source in required],
        "optional": [{"id": source, "name": DATA_SOURCES[source].name if source in DATA_SOURCES else source,
                      "present": source in optional_present, "events": aligned.get(source, 0)} for source in optional],
        "satisfied": satisfied,
        "missing": missing,
        "coverage_ratio": round(ratio, 3),
        "observed": dict(aligned),
        "unmapped_sources": sorted({source for source in observed if source not in SOURCE_ALIGNMENT}),
    }


def score_hunt(findings: list[Finding]) -> tuple[float, str]:
    """Aggregate the findings into a single risk score and a plain verdict."""
    if not findings:
        return 0.0, "No significant findings"
    score = 0.0
    for finding in findings:
        weight = SEVERITY_WEIGHT.get(finding.severity, 5.0)
        confidence = {"high": 1.0, "medium": 0.8, "low": 0.55}.get(finding.confidence, 0.8)
        score += weight * confidence
    # Compress with diminishing returns so a noisy rule cannot saturate the score.
    normalised = 100.0 * (1.0 - pow(2.718281828, -score / 90.0))
    normalised = round(min(normalised, 100.0), 1)
    if normalised >= 75:
        verdict = "Critical, active intrusion indicators"
    elif normalised >= 50:
        verdict = "High, credible attack activity"
    elif normalised >= 25:
        verdict = "Medium, suspicious activity to validate"
    elif normalised > 0:
        verdict = "Low, minor anomalies only"
    else:
        verdict = "No significant findings"
    return normalised, verdict


def _profile_behaviour(
    context: HuntContext,
    outcome: HuntOutcome,
    progress: ProgressCallback | None,
) -> list[Finding]:
    """Report entities that do not behave like their peers.

    This runs after the rules and is independent of them: it finds activity no rule
    describes. It is bounded and can be switched off, because it costs roughly a
    third of the rule engine's time on the same evidence.
    """
    if not settings.behaviour_enabled:
        return []
    if len(context.events) > settings.behaviour_max_events:
        outcome.warnings.append(
            f"Behavioural profiling skipped: {len(context.events):,} events exceed the "
            f"limit of {settings.behaviour_max_events:,}"
        )
        return []
    if progress:
        progress(0.88, "Profiling entity behaviour")
    try:
        findings, candidates = analyse_behaviour(context.events)
    except Exception as error:  # profiling must never lose a completed rule run
        outcome.warnings.append(f"Behavioural profiling stopped early ({type(error).__name__})")
        return []
    outcome.behaviour_candidates = candidates
    return findings


def run_hunt(
    archive_path: Path,
    workdir: Path,
    hypothesis: Hypothesis,
    progress: ProgressCallback | None = None,
) -> HuntOutcome:
    """Run one hypothesis against one evidence archive."""
    started = time.perf_counter()
    context, outcome = parse_evidence(archive_path, workdir, progress)
    rules = hypothesis.rules()
    outcome.rules_evaluated = len(rules)
    if context.events:
        if progress:
            progress(0.45, "Evaluating detection rules")
        engine = DetectionEngine(rules, max_findings_per_rule=settings.max_observations_per_rule)
        outcome.findings = engine.run(context, progress)
        outcome.findings.extend(_profile_behaviour(context, outcome, progress))
    if progress:
        progress(0.92, "Scoring observations")
    outcome.coverage = evaluate_coverage(hypothesis, outcome.data_sources)
    outcome.risk_score, outcome.verdict = score_hunt(outcome.findings)
    outcome.duration_ms = int((time.perf_counter() - started) * 1000)
    if progress:
        progress(1.0, "Completed")
    return outcome
