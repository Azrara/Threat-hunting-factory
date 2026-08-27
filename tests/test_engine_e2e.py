"""End to end engine runs against generated evidence archives."""

from __future__ import annotations

import json
import random
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.engine.catalog import get_hypothesis
from app.engine.runner import evaluate_coverage, parse_evidence, run_hunt, score_hunt


@pytest.fixture(scope="module")
def benign_archive(tmp_path_factory) -> Path:
    """An archive with ordinary activity and nothing malicious in it."""
    rng = random.Random(23)
    base = datetime(2026, 3, 11, 8, 0, 0, tzinfo=timezone.utc)
    hosts = ["WS-A", "WS-B", "WS-C", "SRV-A"]
    users = ["ana", "ben", "chris", "dina"]

    security = []
    for index in range(400):
        moment = (base + timedelta(seconds=index * 60)).isoformat().replace("+00:00", "Z")
        security.append(json.dumps({
            "@timestamp": moment, "Channel": "Security", "EventID": 4624,
            "Computer": rng.choice(hosts), "TargetUserName": rng.choice(users),
            "LogonType": 3, "IpAddress": f"10.0.0.{rng.randint(2, 40)}",
        }))

    access = []
    for index in range(400):
        moment = (base + timedelta(seconds=index * 30)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        access.append(
            f'10.0.0.{rng.randint(2, 40)} - - [{moment}] "GET /app/page{rng.randint(1, 9)} HTTP/1.1" 200 '
            f'{rng.randint(400, 8000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'
        )

    flows = ["timestamp,src_ip,dst_ip,dst_port,protocol,bytes_out,bytes_in"]
    for index in range(400):
        moment = (base + timedelta(seconds=index * 20 + rng.randint(0, 19))).isoformat().replace("+00:00", "Z")
        flows.append(f"{moment},10.0.0.{rng.randint(2, 40)},104.18.{rng.randint(1, 30)}."
                     f"{rng.randint(1, 250)},443,tcp,{rng.randint(500, 40000)},{rng.randint(800, 90000)}")

    target = tmp_path_factory.mktemp("benign") / "benign.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("windows/security.json", "\n".join(security))
        archive.writestr("web/access.log", "\n".join(access))
        archive.writestr("network/flows.csv", "\n".join(flows))
    return target


class TestParsing:
    def test_every_file_is_parsed(self, sample_archive, tmp_path):
        context, outcome = parse_evidence(sample_archive, tmp_path / "work")
        assert outcome.events_parsed > 3000
        assert len(outcome.files) == 9
        formats = {file.log_format for file in outcome.files}
        assert {"json", "windows_evtx_xml", "syslog", "http_access", "zeek_tsv", "csv"} <= formats

    def test_data_sources_are_classified(self, sample_archive, tmp_path):
        _, outcome = parse_evidence(sample_archive, tmp_path / "work")
        for expected in ("windows_security", "sysmon", "linux_auth", "web", "dns",
                         "network_flow", "aws_cloudtrail", "o365_audit"):
            assert outcome.data_sources.get(expected, 0) > 0, expected

    def test_the_timeline_is_recovered(self, sample_archive, tmp_path):
        _, outcome = parse_evidence(sample_archive, tmp_path / "work")
        assert outcome.timespan["start"] and outcome.timespan["end"]
        assert outcome.timespan["duration_seconds"] > 3600


class TestFullSpectrumHunt:
    @pytest.fixture(scope="class")
    def outcome(self, sample_archive, tmp_path_factory):
        return run_hunt(sample_archive, tmp_path_factory.mktemp("run"), get_hypothesis("math-full-spectrum"))

    def test_every_planted_behaviour_is_found(self, outcome):
        found = {finding.rule_id for finding in outcome.findings}
        expected = {
            "win-lsass-credential-dump",      # comsvcs MiniDump of lsass
            "win-shadow-copy-deletion",       # vssadmin delete shadows
            "win-defender-tampering",         # Set-MpPreference
            "win-event-log-cleared",          # event 1102
            "win-office-spawns-shell",        # Word starting PowerShell
            "win-encoded-powershell",         # encoded command
            "win-lolbin-download",            # certutil urlcache
            "win-password-spray",             # many accounts from one address
            "win-discovery-commands",         # whoami, nltest, systeminfo
            "mal-data-staging-archive",       # 7z with a password
            "nix-ssh-brute-force",            # failed passwords
            "nix-account-creation",           # useradd
            "nix-ssh-key-persistence",        # authorized_keys
            "nix-history-tampering",          # history -c
            "web-sql-injection",              # union select
            "web-shell-access",               # uploads/shell.php
            "web-scanner-user-agent",         # sqlmap and gobuster
            "cloud-logging-disabled",         # StopLogging
            "cloud-iam-privilege-escalation", # CreateAccessKey
            "cloud-mailbox-rule-abuse",       # New-InboxRule
            "stat-beaconing-fft",             # sixty second beacon
            "stat-dga-entropy",               # generated domains
        }
        missing = expected - found
        assert not missing, f"detections that did not fire: {sorted(missing)}"

    def test_the_verdict_is_critical(self, outcome):
        assert outcome.risk_score >= 75
        assert outcome.verdict.startswith("Critical")

    def test_every_finding_is_reportable(self, outcome):
        for finding in outcome.findings:
            assert finding.title and finding.description
            assert finding.risk and finding.impact and finding.recommendation
            assert finding.severity in {"critical", "high", "medium", "low", "info"}
            assert finding.score > 0

    def test_findings_carry_the_original_log_line(self, outcome):
        with_evidence = [finding for finding in outcome.findings if finding.evidence]
        assert len(with_evidence) / len(outcome.findings) > 0.9
        for finding in with_evidence:
            first = finding.evidence[0]
            assert first["excerpt"].strip()
            assert first["source_file"]

    def test_beacon_metrics_are_accurate(self, outcome):
        beacons = [finding for finding in outcome.findings if finding.rule_id == "stat-beaconing-fft"]
        assert beacons
        metrics = beacons[0].metrics
        assert 55 <= metrics["median_interval_seconds"] <= 65
        assert metrics["beacon_score"] > 0.8
        assert 50 <= metrics["dominant_period_seconds"] <= 70

    def test_the_summary_is_complete(self, outcome):
        summary = outcome.summary()
        assert summary["severities"]
        assert summary["files"]
        assert summary["top_techniques"]
        assert summary["data_sources"]

    def test_the_run_is_reasonably_fast(self, outcome):
        assert outcome.duration_ms < 60000


class TestTargetedHypotheses:
    @pytest.mark.parametrize("hypothesis_id,expected", [
        ("cti-ransomware-precursor", "win-shadow-copy-deletion"),
        ("cti-cobalt-strike-beacon", "stat-beaconing-fft"),
        ("cti-edge-service-exploitation", "web-shell-access"),
        ("tech-credential-access", "win-lsass-credential-dump"),
        ("tech-cloud-control-plane", "cloud-logging-disabled"),
        ("math-shannon-entropy", "stat-dga-entropy"),
        ("math-fourier-beaconing", "stat-beaconing-fft"),
    ])
    def test_hypothesis_finds_its_signature(self, sample_archive, tmp_path, hypothesis_id, expected):
        outcome = run_hunt(sample_archive, tmp_path / hypothesis_id, get_hypothesis(hypothesis_id))
        assert expected in {finding.rule_id for finding in outcome.findings}

    def test_scoped_hypotheses_run_fewer_rules(self, sample_archive, tmp_path):
        focused = run_hunt(sample_archive, tmp_path / "focused", get_hypothesis("math-fourier-beaconing"))
        full = run_hunt(sample_archive, tmp_path / "full", get_hypothesis("math-full-spectrum"))
        assert focused.rules_evaluated < full.rules_evaluated
        assert len(focused.findings) < len(full.findings)


class TestFalsePositives:
    @pytest.fixture(scope="class")
    def benign_outcome(self, benign_archive, tmp_path_factory):
        return run_hunt(benign_archive, tmp_path_factory.mktemp("benign-run"), get_hypothesis("math-full-spectrum"))

    def test_benign_evidence_raises_no_critical_finding(self, benign_outcome):
        critical = [finding for finding in benign_outcome.findings if finding.severity == "critical"]
        assert critical == [], [finding.rule_id for finding in critical]

    def test_benign_evidence_raises_no_high_finding(self, benign_outcome):
        high = [finding for finding in benign_outcome.findings if finding.severity == "high"]
        assert high == [], [finding.rule_id for finding in high]

    def test_benign_risk_score_stays_low(self, benign_outcome):
        assert benign_outcome.risk_score < 25

    def test_benign_evidence_is_still_parsed(self, benign_outcome):
        assert benign_outcome.events_parsed > 1000


class TestCoverageAndScoring:
    def test_missing_sources_are_reported(self):
        hypothesis = get_hypothesis("cti-ransomware-precursor")
        coverage = evaluate_coverage(hypothesis, {"web": 100})
        assert coverage["missing"] == ["windows_security", "sysmon"]
        assert coverage["coverage_ratio"] == 0.0

    def test_present_sources_are_recognised(self):
        hypothesis = get_hypothesis("cti-ransomware-precursor")
        coverage = evaluate_coverage(hypothesis, {"windows_security": 10, "sysmon": 5})
        assert coverage["missing"] == []
        assert coverage["coverage_ratio"] == 1.0

    def test_empty_result_scores_zero(self):
        assert score_hunt([]) == (0.0, "No significant findings")

    def test_scores_are_bounded(self, sample_archive, tmp_path):
        outcome = run_hunt(sample_archive, tmp_path / "bounds", get_hypothesis("math-full-spectrum"))
        assert 0 <= outcome.risk_score <= 100


class TestRobustness:
    def test_an_empty_archive_is_handled(self, tmp_path):
        archive = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("notes/readme.txt", "")
        outcome = run_hunt(archive, tmp_path / "work", get_hypothesis("math-full-spectrum"))
        assert outcome.findings == []
        assert outcome.warnings

    def test_a_binary_only_archive_is_handled(self, tmp_path):
        archive = tmp_path / "binary.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("payload.exe", b"MZ" + b"\x00" * 500)
        outcome = run_hunt(archive, tmp_path / "work", get_hypothesis("math-full-spectrum"))
        assert outcome.findings == []
        assert outcome.skipped

    def test_unknown_format_still_yields_events(self, tmp_path):
        archive = tmp_path / "weird.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("vendor.log", "\n".join(
                f"~~ RECORD {index} ~~ device=alpha value={index * 7} ~~" for index in range(60)))
        outcome = run_hunt(archive, tmp_path / "work", get_hypothesis("math-full-spectrum"))
        assert outcome.events_parsed == 60
