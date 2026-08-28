"""Regular expression safety.

Every detection pattern runs against attacker influenced text: the records in
an uploaded archive. A pattern whose cost grows faster than the length of the
record turns a single crafted log line into a denial of service against the
analysis engine, so the whole library is measured rather than reviewed.
"""

from __future__ import annotations

import re
import time

import pytest

from app.engine.event import MAX_FIELD_LENGTH, Event
from app.engine.parsers import assign
from app.engine.rules import ALL_RULES
from app.engine.rules.base import SequenceRule

LITERAL = re.compile(r"[A-Za-z0-9_/\\.:-]{3,}")
CLASS_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789/\\.-_+=%$ \t\"'"
SMALL, LARGE = 2000, 8000


def module_patterns():
    """Every regular expression compiled at import time in the parsing layer.

    The parser patterns run against the same untrusted text as the rules. The
    first version of this file only covered rule patterns, and a catastrophic
    pattern in the syslog parser went unnoticed until a long line hung the
    engine, so the sweep now includes them.
    """
    import app.engine.event as event_module
    import app.engine.fieldmap as fieldmap_module
    import app.engine.parsers as parsers_module
    import app.engine.timeparse as timeparse_module

    for module in (parsers_module, timeparse_module, event_module, fieldmap_module):
        for name in dir(module):
            value = getattr(module, name)
            if isinstance(value, re.Pattern):
                yield f"{module.__name__.split('.')[-1]}.{name}", value


def all_patterns():
    seen: set[str] = set()
    for rule in ALL_RULES:
        selectors = ([selector for _, selector in rule.stages]
                     if isinstance(rule, SequenceRule)
                     else ([rule.selector] if hasattr(rule, "selector") else []))
        for selector in selectors:
            for group in (selector.all_of, selector.any_of, selector.none_of):
                for cond in group:
                    compiled = []
                    if cond.op == "regex":
                        compiled = [cond.value]
                    elif cond.op == "any_regex":
                        compiled = list(cond.value)
                    for pattern in compiled:
                        if pattern.pattern not in seen:
                            seen.add(pattern.pattern)
                            yield rule.id, pattern


PATTERNS = list(all_patterns())
MODULE_PATTERNS = list(module_patterns())


def adversarial_inputs(pattern: re.Pattern[str], size: int) -> list[str]:
    """Strings built from the pattern's own alphabet, maximising partial matches."""
    payloads = []
    for literal in set(LITERAL.findall(pattern.pattern)):
        literal = literal.replace("\\", "")
        if 3 <= len(literal) <= 40:
            payloads.append((literal * (size // len(literal) + 1))[:size])
    for char in "a0/\\.-_ ":
        payloads.append(char * size)
    payloads.append((CLASS_CHARS * (size // len(CLASS_CHARS) + 1))[:size])
    return payloads[:14]


def worst_case(pattern: re.Pattern[str], size: int) -> float:
    slowest = 0.0
    for payload in adversarial_inputs(pattern, size):
        started = time.perf_counter()
        try:
            pattern.search(payload)
        except Exception:  # pragma: no cover - a pattern must never raise
            pytest.fail(f"pattern raised on adversarial input: {pattern.pattern}")
        slowest = max(slowest, time.perf_counter() - started)
    return slowest


class TestPatternScaling:
    @pytest.mark.parametrize("rule_id,pattern", PATTERNS,
                             ids=[f"{rule_id}:{index}" for index, (rule_id, _) in enumerate(PATTERNS)])
    def test_cost_grows_linearly(self, rule_id, pattern):
        """Quadrupling the input must not multiply the cost by much more than four."""
        small = worst_case(pattern, SMALL)
        if small < 0.0004:
            return  # too fast to measure a meaningful ratio
        large = worst_case(pattern, LARGE)
        ratio = large / small
        assert not (large > 0.02 and ratio > 6.0), (
            f"{rule_id} scales superlinearly: {small * 1000:.1f} ms at {SMALL} characters, "
            f"{large * 1000:.1f} ms at {LARGE}, growth {ratio:.1f}x for a 4x input. "
            f"Bound the quantifiers in: {pattern.pattern[:120]}"
        )

    @pytest.mark.parametrize("name,pattern", MODULE_PATTERNS, ids=[n for n, _ in MODULE_PATTERNS])
    def test_parser_patterns_scale_linearly(self, name, pattern):
        small = worst_case(pattern, SMALL)
        if small < 0.0004:
            return
        large = worst_case(pattern, LARGE)
        ratio = large / small
        assert not (large > 0.02 and ratio > 6.0), (
            f"{name} scales superlinearly: {small * 1000:.1f} ms at {SMALL} characters, "
            f"{large * 1000:.1f} ms at {LARGE}, growth {ratio:.1f}x for a 4x input. "
            f"Bound the quantifiers in: {pattern.pattern[:120]}"
        )

    def test_the_library_survives_a_pathological_record(self):
        """The whole library against one very long hostile line, end to end."""
        from app.engine.executor import DetectionEngine, HuntContext
        from app.engine.parsers import enrich

        hostile = (
            "a" * 4000 + " " + "../" * 400 + " " + "%2e" * 400 + " "
            + "union select " * 200 + " " + "/" * 2000
        )
        event = enrich(Event(raw=hostile, source_file="hostile.log", data_source="generic"))
        engine = DetectionEngine(list(ALL_RULES))
        started = time.perf_counter()
        engine.run(HuntContext(events=[event] * 200))
        elapsed = time.perf_counter() - started
        assert elapsed < 20, f"200 pathological records took {elapsed:.1f} seconds"


class TestInputBounds:
    def test_field_values_are_capped(self):
        event = Event()
        event.set("process.command_line", "x" * 100_000)
        assert len(event.get_str("process.command_line")) == MAX_FIELD_LENGTH

    def test_raw_field_values_are_capped(self):
        event = Event()
        assign(event, "CommandLine", "y" * 100_000)
        assert len(event.extra["CommandLine"]) == MAX_FIELD_LENGTH
        assert len(event.get_str("process.command_line")) == MAX_FIELD_LENGTH

    def test_short_values_are_untouched(self):
        event = Event()
        event.set("user.name", "  jdoe  ")
        assert event.get_str("user.name") == "jdoe"


class TestPathologicalArchives:
    """Shapes of evidence that are legal but hostile to a naive parser."""

    def _archive(self, tmp_path, name, members):
        import zipfile

        target = tmp_path / name
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            for filename, content in members.items():
                archive.writestr(filename, content)
        return target

    def _run(self, archive, tmp_path, budget):
        from app.engine.catalog import get_hypothesis
        from app.engine.runner import run_hunt

        started = time.perf_counter()
        outcome = run_hunt(archive, tmp_path / "work", get_hypothesis("math-full-spectrum"))
        elapsed = time.perf_counter() - started
        assert elapsed < budget, f"analysis took {elapsed:.1f} seconds, budget {budget}"
        return outcome

    def test_one_enormous_line(self, tmp_path):
        """A single very long line used to hang the engine indefinitely."""
        archive = self._archive(tmp_path, "bigline.zip", {"huge.log": "A" * (8 * 1024 * 1024)})
        self._run(archive, tmp_path, budget=40)

    def test_deeply_nested_json(self, tmp_path):
        document = '{"a":' * 2000 + "1" + "}" * 2000
        archive = self._archive(tmp_path, "deep.zip", {"deep.json": "\n".join([document] * 50)})
        self._run(archive, tmp_path, budget=40)

    def test_records_with_thousands_of_fields(self, tmp_path):
        import json as json_module

        record = json_module.dumps({f"field_{index}": "v" * 20 for index in range(5000)})
        archive = self._archive(tmp_path, "wide.zip", {"wide.json": "\n".join([record] * 200)})
        self._run(archive, tmp_path, budget=40)

    def test_thousands_of_small_files(self, tmp_path):
        members = {
            f"logs/f{index}.log": "Mar 11 08:15:22 srv sshd[1]: Failed password\n"
            for index in range(2000)
        }
        archive = self._archive(tmp_path, "many.zip", members)
        outcome = self._run(archive, tmp_path, budget=40)
        assert outcome.events_parsed == 2000

    def test_a_hostile_sudo_line(self, tmp_path):
        """The syslog helper was catastrophic on a long line without a match."""
        from app.engine.parsers import _parse_unix_message
        from app.engine.event import Event

        started = time.perf_counter()
        for _ in range(50):
            _parse_unix_message(Event(), "a" * 40000)
        elapsed = time.perf_counter() - started
        assert elapsed < 10, f"50 hostile messages took {elapsed:.1f} seconds"
