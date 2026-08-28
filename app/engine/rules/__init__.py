"""Detection rule registry.

Every rule in the library is registered here. Hypotheses reference rules by
identifier or by tag, so the catalogue and the engine stay decoupled.
"""

from __future__ import annotations

from .base import Finding, PatternRule, Rule, SequenceRule, StatisticalRule, ThresholdRule
from . import (
    cloud, database, directory, kubernetes, linux, macos, malware, network, saas,
    statistical, web, windows,
)

ALL_RULES: list[Rule] = [
    *windows.RULES,
    *directory.RULES,
    *linux.RULES,
    *macos.RULES,
    *web.RULES,
    *network.RULES,
    *cloud.RULES,
    *saas.RULES,
    *kubernetes.RULES,
    *database.RULES,
    *malware.RULES,
    *statistical.RULES,
]

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}

if len(RULES_BY_ID) != len(ALL_RULES):
    seen: set[str] = set()
    duplicates = sorted({rule.id for rule in ALL_RULES if rule.id in seen or seen.add(rule.id)})
    raise RuntimeError(f"Duplicate detection rule identifiers: {duplicates}")


def rules_for(identifiers) -> list[Rule]:
    """Resolve rule identifiers, wildcard prefixes and category names."""
    selected: dict[str, Rule] = {}
    for identifier in identifiers or ():
        if identifier == "*":
            return list(ALL_RULES)
        if identifier.endswith("*"):
            prefix = identifier[:-1]
            for rule in ALL_RULES:
                if rule.id.startswith(prefix):
                    selected[rule.id] = rule
            continue
        rule = RULES_BY_ID.get(identifier)
        if rule is not None:
            selected[rule.id] = rule
            continue
        for candidate in ALL_RULES:
            if candidate.category == identifier:
                selected[candidate.id] = candidate
    return list(selected.values())


def rule_summary() -> list[dict]:
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "category": rule.category,
            "detection_type": rule.detection_type,
            "mitre_tactic": rule.mitre_tactic,
            "mitre_technique": rule.mitre_technique,
            "mitre_technique_id": rule.mitre_technique_id,
            "data_sources": list(rule.data_sources),
        }
        for rule in ALL_RULES
    ]


def statistics() -> dict:
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    techniques: set[str] = set()
    for rule in ALL_RULES:
        by_type[rule.detection_type] = by_type.get(rule.detection_type, 0) + 1
        by_category[rule.category] = by_category.get(rule.category, 0) + 1
        by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1
        if rule.mitre_technique_id:
            techniques.add(rule.mitre_technique_id)
    return {
        "total": len(ALL_RULES),
        "by_type": by_type,
        "by_category": by_category,
        "by_severity": by_severity,
        "mitre_techniques": len(techniques),
    }


__all__ = [
    "ALL_RULES",
    "RULES_BY_ID",
    "Finding",
    "PatternRule",
    "Rule",
    "SequenceRule",
    "StatisticalRule",
    "ThresholdRule",
    "rules_for",
    "rule_summary",
    "statistics",
]
