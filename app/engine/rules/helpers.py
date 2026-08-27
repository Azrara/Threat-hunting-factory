"""Compact builders used by the rule library."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .base import (
    Cond,
    PatternRule,
    Selector,
    SequenceRule,
    StatisticalRule,
    ThresholdRule,
)


def C(field: str, op: str = "icontains", value: Any = None) -> Cond:
    return Cond(field, op, value)


def text_any(*values: str) -> Cond:
    return Cond("_text", "any_contains", list(values))


def _selector(all_of: Sequence[Cond] = (), any_of: Sequence[Cond] = (), none_of: Sequence[Cond] = ()) -> Selector:
    return Selector(all_of=tuple(all_of), any_of=tuple(any_of), none_of=tuple(none_of))


def _common(kwargs: dict[str, Any]) -> dict[str, Any]:
    kwargs.setdefault("severity", "medium")
    kwargs.setdefault("confidence", "medium")
    kwargs.setdefault("category", "general")
    kwargs["data_sources"] = tuple(kwargs.get("data_sources") or ())
    kwargs["references"] = tuple(kwargs.get("references") or ())
    kwargs["keywords"] = tuple(k.lower() for k in (kwargs.get("keywords") or ()))
    kwargs["event_codes"] = tuple(str(code) for code in (kwargs.get("event_codes") or ()))
    return kwargs


def pattern_rule(
    rule_id: str,
    name: str,
    description: str,
    *,
    all_of: Sequence[Cond] = (),
    any_of: Sequence[Cond] = (),
    none_of: Sequence[Cond] = (),
    group_by: tuple[str, ...] = ("host.name", "user.name"),
    detail_fields: tuple[str, ...] = (),
    **kwargs: Any,
) -> PatternRule:
    kwargs = _common(kwargs)
    return PatternRule(
        id=rule_id,
        name=name,
        description=description,
        selector=_selector(all_of, any_of, none_of),
        group_by=group_by,
        detail_fields=detail_fields,
        **kwargs,
    )


def threshold_rule(
    rule_id: str,
    name: str,
    description: str,
    *,
    all_of: Sequence[Cond] = (),
    any_of: Sequence[Cond] = (),
    none_of: Sequence[Cond] = (),
    group_by: tuple[str, ...] = ("source.ip",),
    distinct_field: str | None = None,
    min_count: int = 10,
    window_seconds: int = 300,
    **kwargs: Any,
) -> ThresholdRule:
    kwargs = _common(kwargs)
    return ThresholdRule(
        id=rule_id,
        name=name,
        description=description,
        selector=_selector(all_of, any_of, none_of),
        group_by=group_by,
        distinct_field=distinct_field,
        min_count=min_count,
        window_seconds=window_seconds,
        **kwargs,
    )


def sequence_rule(
    rule_id: str,
    name: str,
    description: str,
    *,
    stages: Sequence[tuple[str, Selector]],
    group_by: tuple[str, ...] = ("host.name",),
    window_seconds: int = 3600,
    **kwargs: Any,
) -> SequenceRule:
    kwargs = _common(kwargs)
    return SequenceRule(
        id=rule_id,
        name=name,
        description=description,
        stages=tuple(stages),
        group_by=group_by,
        window_seconds=window_seconds,
        **kwargs,
    )


def stage(label: str, all_of: Sequence[Cond] = (), any_of: Sequence[Cond] = (), none_of: Sequence[Cond] = ()):
    return (label, _selector(all_of, any_of, none_of))


def statistical_rule(rule_id: str, name: str, description: str, *, analyse, **kwargs: Any) -> StatisticalRule:
    kwargs = _common(kwargs)
    return StatisticalRule(id=rule_id, name=name, description=description, analyse=analyse, **kwargs)
