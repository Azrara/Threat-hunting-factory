"""Deciding whether an article is worth reading, without asking a model.

This is the step that makes a weekly run affordable. Roughly three hundred items
arrive from the feeds; without a filter, every one of them would be chunked and
sent to the model, which is thousands of calls and most of a day on a processor.
Scoring on vocabulary costs microseconds and removes the press releases, the
product announcements and the conference recaps before any of that happens.

The scoring is deliberately readable rather than clever. A reviewer can see why an
article was kept, and the thresholds can be argued with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MIN_CHARACTERS = 1200
MIN_SCORE = 6.0

# An explicit technique identifier is the strongest single signal that an article
# describes adversary behaviour rather than a product.
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

BEHAVIOUR_TERMS = (
    "adversary", "adversaries", "threat actor", "attacker", "intrusion", "campaign",
    "initial access", "lateral movement", "privilege escalation", "persistence",
    "command and control", "exfiltration", "defense evasion", "defence evasion",
    "credential access", "reconnaissance", "payload", "implant", "backdoor",
    "ransomware", "webshell", "web shell", "living off the land", "malware",
    "dropper", "loader", "beacon", "c2", "tradecraft", "kill chain",
)
TELEMETRY_TERMS = (
    "sysmon", "event id", "event code", "process creation", "command line",
    "powershell", "scheduled task", "registry key", "auditd", "syslog", "netflow",
    "proxy log", "dns query", "edr", "siem", "windows event", "cloudtrail",
    "authentication log", "access log", "packet capture", "detection rule",
    "sigma rule", "yara", "log source", "telemetry", "hunting query",
)
ARTEFACT_TERMS = (
    "rundll32", "regsvr32", "mshta", "wmic", "certutil", "bitsadmin", "psexec",
    "mimikatz", "cobalt strike", "impacket", "sha256", "md5", "ioc", "indicator",
    "mutex", "registry run key", "base64", "obfuscat",
)
# Words that mark a page as marketing or housekeeping rather than reporting.
NOISE_TERMS = (
    "we are pleased to announce", "register now", "join us", "webinar",
    "magic quadrant", "press release", "now generally available", "pricing",
    "is hiring", "our booth", "free trial", "sign up today", "gartner",
)


@dataclass
class Verdict:
    score: float
    keep: bool
    reasons: list[str]

    def summary(self) -> str:
        return "; ".join(self.reasons)


def _count(text: str, terms: tuple[str, ...]) -> tuple[int, list[str]]:
    found = [term for term in terms if term in text]
    return len(found), found[:6]


def score(text: str, title: str = "") -> Verdict:
    """Score an article on whether it describes attacker behaviour observably."""
    reasons: list[str] = []
    if len(text) < MIN_CHARACTERS:
        return Verdict(0.0, False, [f"only {len(text)} characters of text"])

    body = f"{title}\n{text}".lower()
    total = 0.0

    identifiers = set(TECHNIQUE_ID_RE.findall(body.upper()))
    if identifiers:
        total += min(len(identifiers), 6) * 1.5
        reasons.append(f"{len(identifiers)} ATT&CK identifiers")

    behaviour, sample = _count(body, BEHAVIOUR_TERMS)
    if behaviour:
        total += min(behaviour, 8) * 1.0
        reasons.append(f"attacker vocabulary ({', '.join(sample)})")

    telemetry, sample = _count(body, TELEMETRY_TERMS)
    if telemetry:
        total += min(telemetry, 8) * 1.25
        reasons.append(f"telemetry vocabulary ({', '.join(sample)})")

    artefacts, sample = _count(body, ARTEFACT_TERMS)
    if artefacts:
        total += min(artefacts, 6) * 0.75
        reasons.append(f"concrete artefacts ({', '.join(sample)})")

    noise, sample = _count(body, NOISE_TERMS)
    if noise:
        total -= noise * 3.0
        reasons.append(f"marketing language ({', '.join(sample)})")

    # An article that names techniques but never says where they would be visible
    # cannot produce a hypothesis with a data source, which is a publication gate.
    if not telemetry and not identifiers:
        total -= 3.0
        reasons.append("no telemetry and no technique identifier")

    total = round(total, 2)
    return Verdict(total, total >= MIN_SCORE, reasons)
