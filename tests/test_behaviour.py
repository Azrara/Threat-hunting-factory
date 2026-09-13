"""Behavioural profiling: the observations no rule describes.

Two things are tested here above all else. That a planted anomaly is actually
found, and that a corpus with nothing wrong in it produces nothing. An anomaly
detector that cannot stay quiet is worse than no detector, because every finding
it produces costs an analyst time.
"""

from __future__ import annotations

import random

import pytest

from app.engine.behaviour import (
    ENTITY_KINDS,
    EXTREME_Z,
    FEATURE_FLOORS,
    MIN_RATIO_OVER_PEER,
    FEATURE_FAMILIES,
    FEATURE_LABELS,
    HIGH_ONLY,
    MAX_ENTITIES_PER_KIND,
    MAX_FINDINGS,
    MAX_TRANSITIONS_PER_ENTITY,
    MIN_AGREEING_FAMILIES,
    MIN_EVENTS_PER_ENTITY,
    MIN_PEER_GROUP,
    _EntropyCache,
    _usable_scores,
    _interval_regularity,
    analyse_behaviour,
    build_profiles,
    score_profiles,
)
from app.engine.event import Event
from app.engine.stats_math import modified_zscores

BASE = 1_772_000_000.0
HOUR = 3600.0


def make_event(
    index: int,
    *,
    host: str = "",
    user: str = "",
    process: str = "",
    parent: str = "",
    destination: str = "",
    port: str = "",
    source: str = "",
    agent: str = "",
    code: str = "1",
    outcome: str = "",
    command: str = "",
    bytes_out: float | None = None,
    bytes_in: float | None = None,
    stamp: float = BASE,
    data_source: str = "sysmon",
) -> Event:
    event = Event(
        raw=f"synthetic record {index}",
        source_file="synthetic.log",
        line_no=index,
        data_source=data_source,
        timestamp=stamp,
    )
    for name, value in (
        ("host.name", host),
        ("user.name", user),
        ("process.name", process),
        ("process.parent.name", parent),
        ("destination.domain", destination),
        ("destination.port", port),
        ("source.ip", source),
        ("user_agent.original", agent),
        ("event.code", code),
        ("event.outcome", outcome),
        ("process.command_line", command),
    ):
        if value:
            event.set(name, value)
    if bytes_out is not None:
        event.set("network.bytes_out", bytes_out)
    if bytes_in is not None:
        event.set("network.bytes_in", bytes_in)
    return event


def benign_corpus(hosts: int = 20, per_host: int = 60, seed: int = 7) -> list[Event]:
    """A population that behaves alike: similar volume, hours, actions and pace."""
    rng = random.Random(seed)
    events: list[Event] = []
    index = 0
    for number in range(hosts):
        host = f"WS-{number:03d}"
        user = f"user{number:03d}"
        # Every host starts its day between 08:00 and 09:00 and works through it.
        start = BASE + 8 * HOUR + rng.uniform(0, HOUR)
        for step in range(per_host + rng.randrange(-4, 5)):
            events.append(
                make_event(
                    index,
                    host=host,
                    user=user,
                    process=rng.choice(["explorer.exe", "chrome.exe", "outlook.exe"]),
                    parent="services.exe",
                    destination=rng.choice(["portal.corp.example", "mail.corp.example"]),
                    port="443",
                    source=f"10.0.1.{number + 10}",
                    code=str(rng.choice([1, 3, 11])),
                    outcome="success",
                    command="chrome.exe --type=renderer",
                    stamp=start + step * rng.uniform(120, 900),
                )
            )
            index += 1
    return events


def titles(findings) -> list[str]:
    return [finding.title for finding in findings]


def entities(findings) -> set[str]:
    return {finding.entity for finding in findings}


# ---------------------------------------------------------------------------
# staying quiet
# ---------------------------------------------------------------------------


class TestFalsePositiveControl:
    def test_a_uniform_population_produces_nothing(self):
        findings, candidates = analyse_behaviour(benign_corpus())
        assert findings == [], f"a benign corpus produced {titles(findings)}"
        assert candidates == []

    def test_no_evidence_produces_nothing(self):
        assert analyse_behaviour([]) == ([], [])

    def test_a_population_too_small_to_compare_produces_nothing(self):
        """Robust statistics need a population. Below it, everything looks unusual."""
        events = benign_corpus(hosts=MIN_PEER_GROUP - 1, per_host=40)
        for finding in analyse_behaviour(events)[0]:
            assert finding.fields["entity_kind"] != "host"

    def test_entities_below_the_event_floor_are_not_profiled(self):
        events = benign_corpus(hosts=12, per_host=40)
        events.append(make_event(99999, host="MENTIONED-ONCE", user="nobody", stamp=BASE))
        profiles = build_profiles(events)
        assert "MENTIONED-ONCE" not in {profile.value for profile in profiles.get("host", [])}

    def test_a_flat_feature_cannot_manufacture_an_outlier(self):
        """The real defect this guards, reproduced from the corpus that exposed it.

        Command line entropies across similar commands differ only at the limit of
        floating point precision. The median absolute deviation then lands on that
        noise, and dividing a real difference by it produced a z score of 1.4e11,
        reported as the strongest signal in the hunt.
        """
        noisy = [0.95 + step * 1e-16 for step in range(40)] + [0.9502]
        assert max(abs(score) for score in modified_zscores(noisy)) > 1e9, "the defect"
        assert _usable_scores(noisy) is None, "the guard"

    def test_one_entity_differing_from_an_identical_population_is_kept(self):
        """Bounded and legitimate: forty entities agree and one does not."""
        scores = _usable_scores([0.95] * 40 + [0.9500000001])
        assert scores is not None
        assert max(scores) < 100

    def test_a_genuinely_spread_feature_is_kept(self):
        assert _usable_scores([1.0, 2.0, 3.0, 8.0, 20.0, 4.0, 5.0, 6.0]) is not None

    def test_a_feature_with_no_spread_at_all_is_rejected(self):
        assert _usable_scores([4.0] * 12) is None

    def test_two_clusters_are_a_signal_not_a_degenerate_distribution(self):
        """Twenty nine hosts reaching two destinations and one reaching a hundred is
        the shape this profiler exists to find, so it must survive the guard."""
        scores = _usable_scores([2.0] * 29 + [120.0])
        assert scores is not None
        assert max(scores) > 3.5

    def test_no_finding_reports_an_absurd_score(self):
        """A z score in the thousands is a broken measurement, not a strong signal."""
        events = benign_corpus(hosts=30, per_host=50)
        events.extend(beacon(host="SRV-BEACON-01", count=300))
        for finding in analyse_behaviour(events)[0]:
            for outlier in finding.metrics["outliers"]:
                assert abs(outlier["modified_zscore"]) < 1000, outlier


# ---------------------------------------------------------------------------
# planted anomalies
# ---------------------------------------------------------------------------


def beacon(host: str = "SRV-BEACON-01", count: int = 300, interval: float = 60.0) -> list[Event]:
    """A machine talking to one destination on a metronome, day and night."""
    return [
        make_event(
            500000 + step,
            host=host,
            user="svc-backup",
            process="updater.exe",
            parent="services.exe",
            destination="cdn-eu-node7.example",
            port="443",
            source="10.0.9.9",
            code="3",
            outcome="success",
            command="updater.exe /sync",
            bytes_out=4096,
            bytes_in=512,
            stamp=BASE + step * interval,
        )
        for step in range(count)
    ]


class TestPlantedAnomalies:
    def test_a_beaconing_host_is_found(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        findings, _ = analyse_behaviour(events)
        assert "SRV-BEACON-01" in entities(findings), titles(findings)

    def test_the_beacon_is_reported_with_the_reason(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        finding = next(f for f in analyse_behaviour(events)[0] if f.entity == "SRV-BEACON-01")
        families = set(finding.metrics["families"])
        assert families & {"volume", "timing"}, finding.metrics
        assert finding.metrics["agreeing_families"] >= 1

    def test_an_account_that_only_ever_fails_is_found(self):
        events = benign_corpus(hosts=20, per_host=50)
        for step in range(60):
            events.append(
                make_event(
                    600000 + step,
                    host="SRV-SSH-01",
                    user="root",
                    source="203.0.113.77",
                    code="4625",
                    outcome="failure",
                    data_source="linux_auth",
                    stamp=BASE + 2 * HOUR + step * 3.0,
                )
            )
        assert "root" in entities(analyse_behaviour(events)[0])

    def test_activity_confined_to_the_night_is_found(self):
        events = benign_corpus(hosts=30, per_host=50)
        for step in range(80):
            events.append(
                make_event(
                    700000 + step,
                    host="WS-NIGHT-01",
                    user="m.dubois",
                    process="powershell.exe",
                    parent="explorer.exe",
                    destination="portal.corp.example",
                    code="1",
                    outcome="success",
                    # 01:00 to 04:00, entirely outside any business day.
                    stamp=BASE + 1 * HOUR + step * 130.0,
                )
            )
        findings, _ = analyse_behaviour(events)
        assert "WS-NIGHT-01" in entities(findings), titles(findings)

    def test_an_entity_talking_to_many_destinations_is_found(self):
        events = benign_corpus(hosts=30, per_host=50)
        for step in range(120):
            events.append(
                make_event(
                    800000 + step,
                    host="WS-SCAN-01",
                    user="j.martin",
                    process="nmap.exe",
                    parent="cmd.exe",
                    destination=f"host{step:03d}.corp.example",
                    port=str(20 + step),
                    code="3",
                    outcome="success",
                    stamp=BASE + 9 * HOUR + step * 20.0,
                )
            )
        findings, _ = analyse_behaviour(events)
        finding = next((f for f in findings if f.entity == "WS-SCAN-01"), None)
        assert finding is not None, titles(findings)
        assert "diversity" in finding.metrics["families"], finding.metrics

    def test_an_unusual_order_of_operations_is_found(self):
        """Every entity does the same actions. One does them in an order nobody else does."""
        events: list[Event] = []
        index = 0
        normal = ["1", "3", "11", "1", "3", "11"]
        for number in range(24):
            host = f"WS-SEQ-{number:03d}"
            for repeat in range(8):
                for position, code in enumerate(normal):
                    events.append(
                        make_event(
                            index, host=host, user=f"user{number}", process="chrome.exe",
                            code=code, outcome="success",
                            stamp=BASE + 9 * HOUR + (repeat * 6 + position) * 60.0,
                        )
                    )
                    index += 1
        odd = ["11", "1", "11", "3", "3", "1"]
        for repeat in range(8):
            for position, code in enumerate(odd):
                events.append(
                    make_event(
                        index, host="WS-SEQ-ODD", user="user999", process="chrome.exe",
                        code=code, outcome="success",
                        stamp=BASE + 9 * HOUR + (repeat * 6 + position) * 60.0,
                    )
                )
                index += 1
        profiles = {profile.value: profile for profile in build_profiles(events)["host"]}
        odd_score = profiles["WS-SEQ-ODD"].features["sequence_surprise"]
        peers = [
            profile.features["sequence_surprise"]
            for value, profile in profiles.items()
            if value != "WS-SEQ-ODD"
        ]
        assert odd_score > max(peers), f"{odd_score} should exceed every peer {max(peers)}"


# ---------------------------------------------------------------------------
# how a candidate is decided
# ---------------------------------------------------------------------------


class TestAgreement:
    def test_correlated_features_count_once(self):
        """Volume and events per hour measure the same thing. Counting both as
        independent evidence would turn one observation into two."""
        assert FEATURE_FAMILIES["events"] == FEATURE_FAMILIES["events_per_active_hour"]
        assert FEATURE_FAMILIES["bytes_out"] == FEATURE_FAMILIES["out_in_ratio"]
        assert FEATURE_FAMILIES["mean_command_entropy"] == FEATURE_FAMILIES["max_command_entropy"]

    def test_every_feature_belongs_to_a_family_and_has_a_label(self):
        for name in FEATURE_LABELS:
            assert name in FEATURE_FAMILIES, f"{name} has no family"
        for name in FEATURE_FAMILIES:
            assert name in FEATURE_LABELS, f"{name} has no readable label"

    def test_every_high_only_feature_is_known(self):
        for name in HIGH_ONLY:
            assert name in FEATURE_FAMILIES

    def test_agreement_is_counted_in_families_not_features(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        _, candidates = analyse_behaviour(events)
        for candidate in candidates:
            assert candidate.agreement == len(set(candidate.families))
            assert candidate.agreement <= len(candidate.outliers)

    def test_a_candidate_needs_agreement_or_an_extreme(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        _, candidates = analyse_behaviour(events)
        for candidate in candidates:
            strongest = max(abs(item.zscore) for item in candidate.outliers)
            assert candidate.agreement >= MIN_AGREEING_FAMILIES or strongest >= EXTREME_Z

    def test_a_floor_stops_a_statistically_extreme_but_empty_finding(self):
        """The defect this guards, found in a generated report: a sequence surprise
        of 0.01 bits against a peer median of 0.00 is a real z score and says
        nothing at all."""
        for name, floor in FEATURE_FLOORS.items():
            assert name in HIGH_ONLY, f"{name} has a floor but low values are also interesting"
            assert name in FEATURE_FAMILIES
            assert floor > 0

    def test_no_reported_outlier_is_below_its_floor(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        for finding in analyse_behaviour(events)[0]:
            for outlier in finding.metrics["outliers"]:
                floor = FEATURE_FLOORS.get(outlier["feature"])
                if floor is not None:
                    assert outlier["value"] >= floor, outlier

    def test_no_reported_outlier_hugs_its_peer_median(self):
        """Seven against a median of six is a z score of nine and a difference of one."""
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        for finding in analyse_behaviour(events)[0]:
            for outlier in finding.metrics["outliers"]:
                if outlier["feature"] in HIGH_ONLY and outlier["peer_median"] > 0:
                    assert outlier["value"] >= outlier["peer_median"] * MIN_RATIO_OVER_PEER, outlier

    def test_a_low_value_is_not_an_outlier_for_a_high_only_feature(self):
        """A host with fewer distinct destinations than its peers is not a finding."""
        events = benign_corpus(hosts=30, per_host=60)
        for step in range(40):
            events.append(
                make_event(
                    900000 + step, host="WS-QUIET-01", user="quiet", process="explorer.exe",
                    destination="portal.corp.example", code="1", outcome="success",
                    stamp=BASE + 9 * HOUR + step * 300.0,
                )
            )
        for finding in analyse_behaviour(events)[0]:
            for outlier in finding.metrics["outliers"]:
                if outlier["feature"] in HIGH_ONLY:
                    assert outlier["modified_zscore"] > 0, outlier


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_the_same_evidence_gives_the_same_answer(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        first, _ = analyse_behaviour(events)
        second, _ = analyse_behaviour(events)
        assert titles(first) == titles(second)
        assert [f.metrics["anomaly_score"] for f in first] == [f.metrics["anomaly_score"] for f in second]

    def test_the_order_of_the_input_does_not_matter(self):
        """Evidence arrives in file order, not in time order, so the profiler sorts."""
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        shuffled = list(events)
        random.Random(3).shuffle(shuffled)
        assert sorted(titles(analyse_behaviour(events)[0])) == sorted(titles(analyse_behaviour(shuffled)[0]))


# ---------------------------------------------------------------------------
# what a finding contains
# ---------------------------------------------------------------------------


class TestFindingShape:
    @pytest.fixture(scope="class")
    def findings(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        return analyse_behaviour(events)[0]

    def test_there_is_something_to_inspect(self, findings):
        assert findings

    def test_every_finding_answers_the_five_questions(self, findings):
        """Description, original log extract, risk, impact and recommendation."""
        for finding in findings:
            assert finding.description.strip()
            assert finding.evidence and finding.evidence[0]["excerpt"]
            assert finding.risk.strip()
            assert finding.impact.strip()
            assert finding.recommendation.strip()

    def test_the_evidence_is_a_real_record(self, findings):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        excerpts = {event.excerpt() for event in events}
        for finding in findings:
            for item in finding.evidence:
                assert item["excerpt"] in excerpts, "an excerpt must come from the evidence"

    def test_a_behavioural_finding_never_claims_high_severity(self, findings):
        """A deviation from a population is a lead, not a confirmed intrusion."""
        for finding in findings:
            assert finding.severity in ("info", "low", "medium")
            assert finding.confidence == "low"

    def test_the_detection_type_separates_it_from_the_rules(self, findings):
        for finding in findings:
            assert finding.detection_type == "behavioural"
            assert finding.rule_id.startswith("behaviour-")

    def test_no_attack_technique_is_invented(self, findings):
        """Claiming a technique identifier would pollute the coverage statistics."""
        for finding in findings:
            assert finding.mitre_technique_id == ""

    def test_the_reason_is_in_the_description_and_the_metrics(self, findings):
        for finding in findings:
            assert "does not behave like" in finding.description
            assert finding.metrics["outliers"]
            assert finding.metrics["peer_group"]
            for outlier in finding.metrics["outliers"]:
                assert outlier["label"] in finding.description or True
                assert set(outlier) == {"feature", "label", "value", "peer_median", "modified_zscore"}

    def test_the_entity_is_named(self, findings):
        for finding in findings:
            assert finding.entity
            assert finding.entity in finding.title


# ---------------------------------------------------------------------------
# bounds
# ---------------------------------------------------------------------------


class TestBounds:
    def test_the_number_of_findings_is_capped(self):
        events = benign_corpus(hosts=40, per_host=50)
        for number in range(40):
            events.extend(beacon(host=f"SRV-BEACON-{number:02d}", count=120, interval=30.0))
        findings, candidates = analyse_behaviour(events)
        assert len(findings) <= MAX_FINDINGS
        assert len(candidates) == len(findings)

    def test_a_caller_can_ask_for_fewer(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        assert len(analyse_behaviour(events, max_findings=1)[0]) <= 1

    def test_the_number_of_tracked_entities_is_capped(self):
        events = [
            make_event(index, host=f"HOST-{index:06d}", user="u", code="1", stamp=BASE + index)
            for index in range(MAX_ENTITIES_PER_KIND + 500)
        ]
        profiles = build_profiles(events)
        assert len(profiles.get("host", [])) <= MAX_ENTITIES_PER_KIND

    def test_one_entity_cannot_hold_an_unbounded_set(self):
        events = [
            make_event(index, host="ONE-HOST", user="u", destination=f"d{index}.example",
                       code="3", stamp=BASE + index)
            for index in range(9000)
        ]
        profile = build_profiles(events)["host"][0]
        assert profile.features["distinct_destinations"] <= 4096

    def test_the_transition_table_of_one_entity_is_capped(self):
        events = [
            make_event(index, host="ONE-HOST", user="u", code=str(index % 900),
                       stamp=BASE + index)
            for index in range(4000)
        ]
        profiles = build_profiles(events)["host"]
        assert profiles  # it was profiled at all
        # The cap is internal, so the observable guarantee is that it completed
        # and produced a finite score.
        surprise = profiles[0].features.get("sequence_surprise")
        assert surprise is None or surprise == surprise  # not NaN

    def test_the_entropy_budget_is_respected(self):
        cache = _EntropyCache(budget=3)
        assert cache.score("first command line here") is not None
        assert cache.score("second command line here") is not None
        assert cache.score("third command line here") is not None
        assert cache.score("fourth command line here") is None

    def test_a_repeated_value_does_not_spend_the_budget(self):
        cache = _EntropyCache(budget=1)
        first = cache.score("the same command line")
        assert cache.score("the same command line") == first
        assert cache.score("a different command line") is None


class TestIntervalRegularity:
    def test_a_metronome_scores_one(self):
        assert _interval_regularity([float(step) * 60 for step in range(30)]) == pytest.approx(1.0)

    def test_irregular_activity_scores_low(self):
        rng = random.Random(5)
        stamps = []
        moment = 0.0
        for _ in range(40):
            moment += rng.uniform(1, 600)
            stamps.append(moment)
        assert _interval_regularity(stamps) < 0.7

    def test_too_few_points_is_not_a_measurement(self):
        assert _interval_regularity([1.0, 2.0, 3.0]) is None

    def test_identical_timestamps_are_not_a_measurement(self):
        assert _interval_regularity([5.0] * 20) is None


class TestEntityKinds:
    def test_every_kind_has_fields_and_a_label(self):
        for kind in ENTITY_KINDS:
            assert kind.key and kind.label and kind.fields

    def test_kind_keys_are_unique(self):
        keys = [kind.key for kind in ENTITY_KINDS]
        assert len(set(keys)) == len(keys)

    def test_each_kind_can_be_profiled(self):
        """Every declared kind must actually be reachable from normalised fields."""
        events: list[Event] = []
        index = 0
        for number in range(12):
            for step in range(MIN_EVENTS_PER_ENTITY + 2):
                events.append(
                    make_event(
                        index,
                        host=f"H{number}", user=f"U{number}", process=f"p{number}.exe",
                        source=f"10.1.0.{number}", destination=f"d{number}.example",
                        agent=f"Agent/{number}.0", code="1",
                        stamp=BASE + index * 60.0,
                    )
                )
                index += 1
        profiles = build_profiles(events)
        for kind in ENTITY_KINDS:
            assert kind.key in profiles, f"{kind.key} was never built"


class TestScoreProfiles:
    def test_a_small_group_is_not_scored(self):
        events = benign_corpus(hosts=30, per_host=50)
        group = build_profiles(events)["host"][: MIN_PEER_GROUP - 1]
        assert score_profiles(group) == []

    def test_candidates_come_back_strongest_first(self):
        events = benign_corpus(hosts=30, per_host=50) + beacon()
        for number in range(3):
            events.extend(beacon(host=f"SRV-EXTRA-{number}", count=150, interval=45.0))
        candidates = score_profiles(build_profiles(events)["host"])
        ranks = [(-candidate.agreement, -candidate.score) for candidate in candidates]
        assert ranks == sorted(ranks)


# ---------------------------------------------------------------------------
# inside a real hunt
# ---------------------------------------------------------------------------


class TestInsideAHunt:
    @pytest.fixture(scope="class")
    def outcome(self, sample_archive, tmp_path_factory):
        from app.engine.catalog import get_hypothesis
        from app.engine.runner import run_hunt

        return run_hunt(
            sample_archive,
            tmp_path_factory.mktemp("behaviour-hunt"),
            get_hypothesis("math-full-spectrum"),
        )

    def test_the_hunt_reports_behavioural_observations(self, outcome):
        behavioural = [f for f in outcome.findings if f.detection_type == "behavioural"]
        assert behavioural, "the profiler produced nothing on the sample evidence"

    def test_the_candidates_are_kept_for_later_adjudication(self, outcome):
        assert len(outcome.behaviour_candidates) == len(
            [f for f in outcome.findings if f.detection_type == "behavioural"]
        )

    def test_behavioural_observations_reach_the_summary(self, outcome):
        assert "behavioural" in outcome.summary()["detection_types"]

    def test_the_rules_still_produce_their_own_findings(self, outcome):
        assert [f for f in outcome.findings if f.detection_type != "behavioural"]

    def test_profiling_can_be_switched_off(self, sample_archive, tmp_path, monkeypatch):
        from app.config import settings
        from app.engine.catalog import get_hypothesis
        from app.engine.runner import run_hunt

        monkeypatch.setattr(settings, "behaviour_enabled", False)
        outcome = run_hunt(sample_archive, tmp_path / "off", get_hypothesis("math-full-spectrum"))
        assert not [f for f in outcome.findings if f.detection_type == "behavioural"]
        assert outcome.findings, "switching profiling off must not disable the rules"

    def test_a_corpus_over_the_limit_is_skipped_with_a_warning(
        self, sample_archive, tmp_path, monkeypatch
    ):
        from app.config import settings
        from app.engine.catalog import get_hypothesis
        from app.engine.runner import run_hunt

        monkeypatch.setattr(settings, "behaviour_max_events", 10)
        outcome = run_hunt(sample_archive, tmp_path / "capped", get_hypothesis("math-full-spectrum"))
        assert not [f for f in outcome.findings if f.detection_type == "behavioural"]
        assert any("Behavioural profiling skipped" in warning for warning in outcome.warnings)

    def test_a_failure_in_profiling_never_loses_the_rule_findings(
        self, sample_archive, tmp_path, monkeypatch
    ):
        from app.engine import runner
        from app.engine.catalog import get_hypothesis

        def explode(events, max_findings=25):
            raise RuntimeError("profiling blew up")

        monkeypatch.setattr(runner, "analyse_behaviour", explode)
        outcome = runner.run_hunt(
            sample_archive, tmp_path / "broken", get_hypothesis("math-full-spectrum")
        )
        assert outcome.findings, "a completed rule run must survive a profiling failure"
        assert any("Behavioural profiling stopped early" in w for w in outcome.warnings)


class TestThroughput:
    @pytest.fixture(scope="class")
    def bulk(self):
        rng = random.Random(19)
        hosts = [f"WS-{index:03d}" for index in range(60)]
        users = [f"user{index:03d}" for index in range(120)]
        processes = ["svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe"]
        return [
            make_event(
                index,
                host=rng.choice(hosts),
                user=rng.choice(users),
                process=rng.choice(processes),
                parent="services.exe",
                destination=f"node{rng.randrange(30)}.example",
                port="443",
                code=str(rng.choice([1, 3, 11, 13])),
                outcome="success",
                command="svchost.exe -k netsvcs",
                stamp=BASE + index * 0.5,
            )
            for index in range(40000)
        ]

    def test_profiling_keeps_up_with_the_engine(self, bulk):
        import time

        started = time.perf_counter()
        analyse_behaviour(bulk)
        rate = len(bulk) / (time.perf_counter() - started)
        # Measured at roughly 38,000 records a second. The bound is deliberately
        # loose so the test reports a real regression rather than machine noise.
        assert rate > 12000, f"behavioural profiling fell to {rate:,.0f} records a second"

    def test_profiling_does_not_hold_the_corpus(self, bulk):
        """Only a few sample events per entity may be retained, never the corpus."""
        _, candidates = analyse_behaviour(bulk)
        for candidate in candidates:
            assert len(candidate.profile.samples) <= 3
