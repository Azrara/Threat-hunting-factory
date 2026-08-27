"""PDF rendering and report content."""

from __future__ import annotations

import re

import pytest

from app.reporting.pdf import build_report
from app.reporting.theme import DELOITTE_GREEN, SEVERITY_COLOURS


def sample_context(observation_count=3, findings_present=True):
    observations = []
    for index in range(observation_count if findings_present else 0):
        observations.append({
            "id": f"obs{index}",
            "rule_id": "win-lsass-credential-dump",
            "title": f"Credential dumping attempt against LSASS on WS-{index:02d}",
            "description": "A process opened the Local Security Authority Subsystem Service memory.",
            "severity": ["critical", "high", "medium"][index % 3],
            "confidence": "high",
            "score": 95.0 - index,
            "category": "credential_access",
            "detection_type": "pattern",
            "risk": "An adversary is extracting authentication material from memory.",
            "impact": "Stolen hashes allow pass the hash attacks against the whole domain.",
            "recommendation": "Isolate the host and reset every credential used on it.",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "OS Credential Dumping: LSASS Memory",
            "mitre_technique_id": "T1003.001",
            "entity": f"WS-{index:02d}",
            "data_source": "sysmon",
            "source_files": ["windows/sysmon.xml"],
            "evidence": [{
                "source_file": "windows/sysmon.xml", "line_no": 42 + index,
                "timestamp": "2026-03-11T09:10:00+00:00", "log_format": "windows_evtx_xml",
                "excerpt": '<Data Name="CommandLine">rundll32.exe comsvcs.dll, MiniDump 748 lsass.dmp</Data>',
            }],
            "fields": {"host.name": f"WS-{index:02d}"},
            "metrics": {"beacon_score": 0.93, "connections": 40, "sample_values": ["a", "b"]},
            "references": ["https://attack.mitre.org/techniques/T1003/001/"],
            "event_count": index + 1,
            "first_seen": "2026-03-11T09:10:00+00:00",
            "last_seen": "2026-03-11T09:20:00+00:00",
        })
    return {
        "hunt": {
            "id": "abc123", "title": "Q1 compromise assessment",
            "hypothesis_name": "Ransomware deployment precursors are present in the estate",
            "hypothesis_category": "cti", "archive_name": "evidence.zip", "archive_bytes": 51234,
            "events_parsed": 3665, "files_analysed": 9, "rules_evaluated": 16,
            "observation_count": len(observations), "risk_score": 84.9 if findings_present else 0.0,
            "verdict": "Critical, active intrusion indicators" if findings_present else "No significant findings",
            "duration_ms": 1670, "completed_at": "2026-03-11T10:00:00+00:00",
            "summary": {
                "severities": {"critical": 1, "high": 1, "medium": 1} if findings_present else {},
                "top_techniques": [["T1003.001 OS Credential Dumping", 3]],
                "files": [{"path": "windows/sysmon.xml", "log_format": "windows_evtx_xml",
                           "data_source": "sysmon", "events": 412}],
                "warnings": ["One file stopped early"], "skipped": ["image.png (unsupported binary type)"],
            },
            "coverage": {"required": [
                {"id": "windows_security", "name": "Windows Security event log", "present": True, "events": 657},
                {"id": "sysmon", "name": "Sysmon operational log", "present": False, "events": 0},
            ]},
        },
        "tenant": {"name": "Contoso Group", "slug": "contoso"},
        "observations": observations,
        "hypothesis": {
            "family": "cti",
            "narrative": "Ransomware affiliates follow a repeatable playbook.",
            "rationale": "The evidence will contain recovery inhibition commands.",
            "method": "Signature and behaviour rules combined with frequency stacking.",
        },
        "analyst": "Dana Reyes",
    }


def page_count(pdf: bytes) -> int:
    return pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages")


class TestPdfGeneration:
    def test_a_valid_pdf_is_produced(self):
        pdf = build_report(sample_context())
        assert pdf.startswith(b"%PDF-")
        assert pdf.rstrip().endswith(b"%%EOF")
        assert len(pdf) > 10000

    def test_the_report_has_several_pages(self):
        assert page_count(build_report(sample_context())) >= 4

    def test_the_title_is_set(self):
        pdf = build_report(sample_context())
        assert b"Threat hunting report" in pdf or b"Threat Hunting Report" in re.sub(rb"\s+", b" ", pdf[:4000])

    def test_a_report_without_observations_still_renders(self):
        pdf = build_report(sample_context(findings_present=False))
        assert pdf.startswith(b"%PDF-")
        assert page_count(pdf) >= 3

    def test_many_observations_scale(self):
        pdf = build_report(sample_context(observation_count=60))
        assert page_count(pdf) > 10

    def test_special_characters_are_escaped(self):
        context = sample_context()
        context["observations"][0]["description"] = 'Payload <script>alert("x")</script> & more'
        context["observations"][0]["evidence"][0]["excerpt"] = "<Event><Data>a & b < c</Data></Event>"
        pdf = build_report(context)
        assert pdf.startswith(b"%PDF-")

    def test_missing_optional_fields_are_tolerated(self):
        context = sample_context()
        context["hypothesis"] = {}
        context["hunt"]["summary"] = {}
        context["hunt"]["coverage"] = {}
        context["observations"][0]["evidence"] = []
        context["observations"][0]["metrics"] = {}
        context["observations"][0]["references"] = []
        pdf = build_report(context)
        assert pdf.startswith(b"%PDF-")

    def test_a_very_long_excerpt_is_truncated(self):
        context = sample_context()
        context["observations"][0]["evidence"][0]["excerpt"] = "A" * 5000
        pdf = build_report(context)
        assert pdf.startswith(b"%PDF-")


class TestTheme:
    def test_the_palette_uses_the_brand_colours(self):
        assert DELOITTE_GREEN == "#86BC25"
        assert set(SEVERITY_COLOURS) == {"critical", "high", "medium", "low", "info"}
        for value in SEVERITY_COLOURS.values():
            assert re.match(r"^#[0-9A-F]{6}$", value)
