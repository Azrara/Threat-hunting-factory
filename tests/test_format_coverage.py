"""Format conformance.

The platform tells users it reads any log they have. That is only true if it is
measured, so every format in the corpus has to be identified, timestamped and
have its key fields mapped. A format that regresses to the free text fallback
fails here rather than quietly producing a weaker hunt.
"""

from __future__ import annotations

import pytest

from app.engine.parsers import select_parser
from tests.fixtures.log_formats import SAMPLES

IDS = [entry[0] for entry in SAMPLES]


def parse_sample(entry):
    name, _expected_source, _required, lines = entry
    parser, score, scores = select_parser(lines, f"{name}.log")
    events = list(parser.parse(iter(lines), f"{name}.log"))
    return parser, score, events


class TestFormatCoverage:
    @pytest.mark.parametrize("entry", SAMPLES, ids=IDS)
    def test_records_are_produced(self, entry):
        _parser, _score, events = parse_sample(entry)
        assert events, f"{entry[0]} produced no records at all"

    @pytest.mark.parametrize("entry", SAMPLES, ids=IDS)
    def test_the_timestamp_is_recovered(self, entry):
        name, _source, _required, _lines = entry
        _parser, _score, events = parse_sample(entry)
        assert events[-1].timestamp is not None, (
            f"{name} lost its timestamp, so every time based detection is blind to it"
        )

    @pytest.mark.parametrize("entry", SAMPLES, ids=IDS)
    def test_the_key_fields_are_mapped(self, entry):
        name, _source, required, _lines = entry
        _parser, _score, events = parse_sample(entry)
        event = events[-1]
        missing = [field for field in required if not event.get(field)]
        assert not missing, (
            f"{name} did not map {missing}. The rules address fields by their common schema "
            f"name, so an unmapped field means the detections cannot see it."
        )

    @pytest.mark.parametrize("entry", SAMPLES, ids=IDS)
    def test_the_expected_telemetry_type_is_recognised(self, entry):
        name, expected_source, _required, _lines = entry
        if expected_source is None:
            return
        _parser, _score, events = parse_sample(entry)
        assert events[-1].data_source == expected_source, (
            f"{name} was classified as {events[-1].data_source}, expected {expected_source}. "
            f"Hypothesis data source coverage depends on this."
        )


class TestParserSelection:
    """A dedicated parser must win over the fallbacks for the formats it owns."""

    @pytest.mark.parametrize("name,expected_parser", [
        ("suricata_eve", "json"),
        ("zeek_json", "json"),
        ("auditd", "auditd"),
        ("squid", "squid"),
        ("aws_vpc_flow", "vpc_flow"),
        ("palo_alto_csv", "panos_csv"),
        ("windows_firewall", "w3c_extended"),
        ("fortinet_kv", "keyvalue"),
        ("haproxy", "syslog"),
        ("postfix", "syslog"),
        ("o365_message_trace", "csv"),
    ])
    def test_the_right_parser_is_selected(self, name, expected_parser):
        entry = next(item for item in SAMPLES if item[0] == name)
        parser, _score, _events = parse_sample(entry)
        assert parser.name == expected_parser

    def test_a_bracketed_text_line_is_not_taken_for_json(self):
        """An Apache error line starts with a bracket but is not JSON."""
        lines = ["[Wed Mar 11 08:15:22.123456 2026] [php:error] [pid 2345] PHP Warning: x"]
        parser, _score, _scores = select_parser(lines, "error.log")
        assert parser.name == "text"

    def test_the_free_text_fallback_is_the_last_resort(self):
        fallbacks = [entry[0] for entry in SAMPLES if parse_sample(entry)[0].name == "text"]
        # A handful of genuinely unstructured formats belong here. A larger set
        # means a dedicated parser stopped matching.
        assert len(fallbacks) <= 6, f"too many formats fell back to free text: {fallbacks}"


class TestNetworkDeviceExtraction:
    """Appliances state the flow in the message rather than in named fields."""

    @pytest.mark.parametrize("message,source_ip,destination_ip", [
        ("%ASA-4-106023: Deny tcp src outside:198.51.100.7/44321 dst inside:10.20.9.10/3389",
         "198.51.100.7", "10.20.9.10"),
        ("Built outbound TCP connection 1 for outside:203.0.113.9/443 to inside:10.20.4.15/51000",
         "203.0.113.9", "10.20.4.15"),
        ("203.0.113.45:44321 [11/Mar/2026:08:15:22.123] https-in app/app-02 0/0/1/12/13 200 4523",
         "203.0.113.45", None),
    ])
    def test_endpoints_are_recovered(self, message, source_ip, destination_ip):
        from app.engine.event import Event
        from app.engine.parsers import extract_network_endpoints

        event = Event()
        extract_network_endpoints(event, message)
        assert event.get_str("source.ip") == source_ip
        if destination_ip:
            assert event.get_str("destination.ip") == destination_ip

    def test_addresses_without_a_direction_word_are_not_guessed(self):
        """Two addresses in a sentence are not a flow."""
        from app.engine.event import Event
        from app.engine.parsers import extract_network_endpoints

        event = Event()
        extract_network_endpoints(event, "replication between 10.0.0.1 and 10.0.0.2 completed")
        assert event.get("source.ip") is None
        assert event.get("destination.ip") is None
