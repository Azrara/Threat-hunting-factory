"""Format detection, parsing and normalisation across log families."""

from __future__ import annotations

import pytest

from app.engine.event import Event, extract_iocs
from app.engine.fieldmap import canonical_key, flatten
from app.engine.parsers import classify_data_source, enrich, select_parser
from app.engine.timeparse import find_timestamp, parse_timestamp


def parse(lines, filename="evidence.log"):
    parser, score, scores = select_parser(lines, filename)
    events = list(parser.parse(iter(lines), filename))
    return parser, score, events


class TestTimestamps:
    @pytest.mark.parametrize("value,expected", [
        ("2024-03-11T08:15:22Z", "2024-03-11T08:15:22+00:00"),
        ("2024-03-11 08:15:22", "2024-03-11T08:15:22+00:00"),
        ("2024-03-11T08:15:22.500Z", "2024-03-11T08:15:22.500000+00:00"),
        ("2024-03-11T08:15:22+02:00", "2024-03-11T06:15:22+00:00"),
        ("1710144922", "2024-03-11T08:15:22+00:00"),
        ("1710144922000", "2024-03-11T08:15:22+00:00"),
        ("10/Mar/2024:08:15:22 +0000", "2024-03-10T08:15:22+00:00"),
        ("20240311081522", "2024-03-11T08:15:22+00:00"),
    ])
    def test_known_formats(self, value, expected):
        from datetime import datetime, timezone

        epoch = parse_timestamp(value)
        assert epoch is not None, value
        assert datetime.fromtimestamp(epoch, timezone.utc).isoformat() == expected

    @pytest.mark.parametrize("value", ["", None, "not a timestamp", "12345", "0"])
    def test_rejects_non_timestamps(self, value):
        assert parse_timestamp(value) is None

    def test_finds_a_timestamp_inside_a_line(self):
        line = '10.0.0.1 - - [10/Mar/2024:08:15:22 +0000] "GET / HTTP/1.1" 200 12'
        assert find_timestamp(line) is not None


class TestFieldMap:
    @pytest.mark.parametrize("raw,canonical", [
        ("TargetUserName", "user.name"),
        ("src_ip", "source.ip"),
        ("sc-status", "http.response.status_code"),
        ("Image", "process.executable"),
        ("EventID", "event.code"),
        ("winlog.event_data.CommandLine", "process.command_line"),
        ("ClientIP", "source.ip"),
        ("dst_port", "destination.port"),
    ])
    def test_strong_aliases(self, raw, canonical):
        assert canonical_key(raw)[0] == canonical

    def test_unknown_fields_are_not_mapped(self):
        assert canonical_key("vendor_specific_blob")[0] is None

    def test_flatten_nested_documents(self):
        flat = flatten({"a": {"b": 1}, "list": [1, 2], "objects": [{"x": 5}]})
        assert flat == {"a.b": 1, "list": "1, 2", "objects.0.x": 5}


class TestJsonFamily:
    def test_windows_json(self):
        lines = ['{"@timestamp":"2024-03-11T08:15:22Z","Channel":"Security","EventID":4688,'
                 '"Computer":"WS01","TargetUserName":"jdoe","CommandLine":"powershell -enc AAAA"}']
        parser, score, events = parse(lines, "security.json")
        assert parser.name == "json" and score > 0.9
        event = events[0]
        assert event.data_source == "windows_security"
        assert event.get_str("host.name") == "WS01"
        assert event.get_str("user.name") == "jdoe"
        assert event.get_str("event.action") == "process_creation"
        assert event.timestamp is not None

    def test_cloudtrail_records_wrapper(self):
        lines = ['{"Records":[{"eventTime":"2024-03-11T08:15:22Z","eventName":"ConsoleLogin",'
                 '"eventSource":"signin.amazonaws.com","awsRegion":"us-east-1","sourceIPAddress":"5.5.5.5",'
                 '"userIdentity":{"type":"IAMUser","userName":"svc"},"errorCode":"Failure"}]}']
        _, _, events = parse(lines, "trail.json")
        assert len(events) == 1
        event = events[0]
        assert event.data_source == "aws_cloudtrail"
        assert event.get_str("event.action") == "ConsoleLogin"
        assert event.get_str("user.name") == "svc"
        assert event.get_str("event.outcome") == "failure"

    def test_pretty_printed_json_is_detected(self):
        lines = ['{\n', ' "Records": [\n', '  {\n', '   "eventTime": "2024-03-11T08:15:22Z",\n',
                 '   "eventName": "GetObject",\n', '   "eventSource": "s3.amazonaws.com"\n',
                 '  }\n', ' ]\n', '}\n']
        parser, score, events = parse(lines, "trail.json")
        assert parser.name == "json"
        assert len(events) == 1
        assert events[0].get_str("event.action") == "GetObject"

    def test_broken_json_line_does_not_crash(self):
        lines = ['{"a": 1}', '{not json at all', '{"b": 2}']
        _, _, events = parse(lines, "mixed.json")
        assert len(events) >= 2


class TestWindowsXml:
    XML = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
           '<TimeCreated SystemTime="2024-03-11T08:15:22.123Z"/><Computer>WS01</Computer>'
           '<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData>'
           '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
           '<Data Name="CommandLine">cmd.exe /c whoami</Data>'
           '<Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>'
           '<Data Name="User">CORP\\jdoe</Data></EventData></Event>')

    def test_sysmon_event(self):
        parser, score, events = parse([self.XML], "sysmon.xml")
        assert parser.name == "windows_evtx_xml" and score > 0.9
        event = events[0]
        assert event.data_source == "sysmon"
        assert event.get_str("process.name") == "cmd.exe"
        assert event.get_str("process.parent.name") == "WINWORD.EXE"
        assert event.get_str("event.action") == "process_creation"
        assert event.get_str("host.name") == "WS01"

    def test_event_split_over_several_lines(self):
        lines = self.XML.replace("><", ">\n<").splitlines(keepends=True)
        _, _, events = parse(lines, "sysmon.xml")
        assert len(events) == 1
        assert events[0].get_str("process.command_line") == "cmd.exe /c whoami"


class TestSyslogFamily:
    def test_ssh_failure(self):
        lines = ["Mar 11 08:15:22 srv01 sshd[1234]: Failed password for invalid user root "
                 "from 203.0.113.9 port 4444 ssh2"]
        parser, _, events = parse(lines, "auth.log")
        assert parser.name == "syslog"
        event = events[0]
        assert event.data_source == "linux_auth"
        assert event.get_str("event.outcome") == "failure"
        assert event.get_str("source.ip") == "203.0.113.9"
        assert event.get_str("user.name") == "root"

    def test_sudo_command(self):
        lines = ["Mar 11 08:16:00 srv01 sudo:  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"]
        _, _, events = parse(lines, "auth.log")
        event = events[0]
        assert event.get_str("user.name") == "bob"
        assert event.get_str("user.target") == "root"
        assert event.get_str("process.command_line") == "/bin/bash"

    def test_rfc5424(self):
        lines = ['<34>1 2024-03-11T08:15:22.000Z host01 app 4321 ID47 [ex@1 key="value"] Something happened']
        parser, _, events = parse(lines, "syslog.log")
        assert parser.name == "syslog"
        assert events[0].get_str("host.name") == "host01"
        assert events[0].timestamp is not None


class TestWebLogs:
    def test_combined_log_format(self):
        lines = ['10.0.0.5 - - [11/Mar/2024:08:15:22 +0000] "GET /a.php?id=1 HTTP/1.1" 200 4523 "-" "sqlmap/1.5"']
        parser, score, events = parse(lines, "access.log")
        assert parser.name == "http_access" and score > 0.9
        event = events[0]
        assert event.get_str("http.request.method") == "GET"
        assert event.get_str("http.response.status_code") == "200"
        assert event.get_str("user_agent.original") == "sqlmap/1.5"
        assert event.get("http.request.referrer") is None

    def test_iis_w3c(self):
        lines = ["#Software: Microsoft Internet Information Services 10.0",
                 "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query c-ip cs(User-Agent) sc-status sc-bytes",
                 "2024-03-11 08:15:22 10.0.0.1 GET /owa/auth.aspx - 5.5.5.5 Mozilla/5.0 200 1234"]
        parser, _, events = parse(lines, "u_ex.log")
        assert parser.name == "w3c_extended"
        event = events[0]
        assert event.get_str("source.ip") == "5.5.5.5"
        assert event.get_str("url.path") == "/owa/auth.aspx"
        assert event.timestamp is not None


class TestOtherFormats:
    def test_cef(self):
        lines = ["Mar 11 08:15:22 fw01 CEF:0|Palo Alto|PAN-OS|9.1|threat|Malware detected|8|"
                 "src=10.0.0.5 dst=91.240.1.7 spt=51000 dpt=443 suser=jdoe act=blocked"]
        parser, _, events = parse(lines, "fw.cef")
        assert parser.name == "cef"
        event = events[0]
        assert event.get_str("source.ip") == "10.0.0.5"
        assert event.get_str("destination.ip") == "91.240.1.7"
        assert event.get_str("rule.name") == "Malware detected"

    def test_leef(self):
        lines = ["LEEF:2.0|IBM|QRadar|1.0|4625|src=10.0.0.5\tusrName=admin"]
        parser, _, events = parse(lines, "q.leef")
        assert parser.name == "leef"
        assert events[0].get_str("user.name") == "admin"

    def test_zeek_dns(self):
        lines = ["#separator \\x09", "#path\tdns",
                 "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\tqtype_name",
                 "1710144922.123\tCabc\t10.0.0.5\t51000\t8.8.8.8\t53\tevil.xyz\tA"]
        parser, _, events = parse(lines, "dns.log")
        assert parser.name == "zeek_tsv"
        event = events[0]
        assert event.data_source == "dns"
        assert event.get_str("dns.question.name") == "evil.xyz"
        assert event.get_str("source.ip") == "10.0.0.5"
        assert event.get("user.name") is None  # the Zeek uid is not a user

    def test_csv_with_header(self):
        lines = ["timestamp,src_ip,dst_ip,dst_port,bytes,user",
                 "2024-03-11T08:15:22Z,10.0.0.5,91.240.1.7,443,150000,jdoe"]
        parser, _, events = parse(lines, "flows.csv")
        assert parser.name == "csv"
        event = events[0]
        assert event.get_str("destination.ip") == "91.240.1.7"
        assert event.get_int("network.bytes") == 150000
        assert event.data_source == "network_flow"

    def test_semicolon_delimited(self):
        lines = ["time;user;action;status", "2024-03-11 08:15:22;bob;login;200"]
        parser, _, events = parse(lines, "export.csv")
        assert parser.name == "csv"
        assert events[0].get_str("user.name") == "bob"

    def test_key_value(self):
        lines = ['time="2024-03-11T08:15:22Z" level=warn msg="auth failed" user=jdoe src_ip=10.0.0.5 status=401']
        parser, _, events = parse(lines, "app.log")
        assert parser.name == "keyvalue"
        assert events[0].get_str("user.name") == "jdoe"
        assert events[0].get_str("source.ip") == "10.0.0.5"

    def test_free_text_fallback(self):
        lines = ["Something happened on the server at 2024-03-11 08:15:22 with no structure"]
        parser, _, events = parse(lines, "notes.txt")
        assert parser.name == "text"
        assert events[0].timestamp is not None
        assert events[0].get_str("message")

    def test_empty_input_produces_no_events(self):
        _, _, events = parse(["", "   ", "\n"], "empty.log")
        assert events == []


class TestClassification:
    def test_flow_like_records_are_network(self):
        event = enrich(Event(fields={"source.ip": "10.0.0.1", "destination.ip": "8.8.8.8",
                                     "destination.port": "53"}, extra={}))
        assert classify_data_source(event) == "network_flow"

    def test_web_records(self):
        event = Event(fields={"http.request.method": "GET"}, extra={})
        assert classify_data_source(event) == "web"

    def test_unknown_records_are_not_classified(self):
        assert classify_data_source(Event(fields={}, extra={"foo": "bar"})) is None


class TestIocExtraction:
    def test_extracts_indicators(self):
        text = "connect to http://bad.example.com/x from 8.8.8.8 hash d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text)
        assert "8.8.8.8" in iocs["ipv4"]
        assert "http://bad.example.com/x" in iocs["urls"]
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["md5"]
