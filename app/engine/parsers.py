"""Parsers covering the log formats seen in real hunting engagements.

The engine sniffs each file, picks the highest scoring parser and falls back
to a free text parser that still extracts timestamps and indicators. Every
parser emits :class:`~app.engine.event.Event` objects using the common schema
so the rule layer never needs to know where the data came from.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Iterator
from typing import Any

from .event import Event
from .fieldmap import canonical_key, flatten
from .timeparse import find_timestamp, parse_timestamp

# Each retained record costs roughly its raw length in memory, so the cap
# bounds the worst case for files with pathologically long lines. Evidence
# excerpts are truncated to 900 characters when reported anyway.
MAX_RAW_LENGTH = 2000


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def assign(event: Event, key: str, value: Any) -> None:
    """Store a raw key value pair on the event using the alias tables."""
    if value is None:
        return
    if isinstance(value, str):
        value = value.strip()
        if not value or value in ("-", "--", "N/A", "null", "None"):
            return
    canonical, strong = canonical_key(key)
    event.extra[key] = value
    if canonical:
        if strong or not event.fields.get(canonical):
            if canonical == "timestamp":
                epoch = parse_timestamp(value)
                if epoch and not event.timestamp:
                    event.timestamp = epoch
                return
            event.set(canonical, value)


def basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path.strip())[-1]


def enrich(event: Event) -> Event:
    """Derive fields that rules rely on but sources do not always provide."""
    executable = event.get_str("process.executable")
    if executable and not event.get("process.name"):
        event.set("process.name", basename(executable))
    parent = event.get_str("process.parent.executable")
    if parent and not event.get("process.parent.name"):
        event.set("process.parent.name", basename(parent))
    parent_cmd = event.get_str("process.parent.command_line")
    if parent_cmd and not event.get("process.parent.name"):
        first = parent_cmd.strip().strip('"').split('"')[0].split()[0] if parent_cmd.strip() else ""
        if first:
            event.set("process.parent.name", basename(first))
    file_path = event.get_str("file.path")
    if file_path and not event.get("file.name"):
        event.set("file.name", basename(file_path))
    file_name = event.get_str("file.name")
    if file_name and "." in file_name and not event.get("file.extension"):
        event.set("file.extension", file_name.rsplit(".", 1)[-1].lower())
    url = event.get_str("url.original")
    if url:
        match = re.match(r"https?://([^/\s:?#]+)", url, re.IGNORECASE)
        if match:
            event.setdefault_field("url.domain", match.group(1))
            event.setdefault_field("destination.domain", match.group(1))
        path_match = re.match(r"https?://[^/\s]+(/[^\s?#]*)", url, re.IGNORECASE)
        if path_match and not event.get("url.path"):
            event.set("url.path", path_match.group(1))
    command = event.get_str("process.command_line")
    if command and not event.get("process.name"):
        first = command.strip().strip('"').split('"')[0].split()[0] if command.strip() else ""
        if first:
            event.set("process.name", basename(first))
    dns_name = event.get_str("dns.question.name")
    if dns_name and not event.get("destination.domain"):
        event.set("destination.domain", dns_name)
    if event.timestamp is None:
        event.timestamp = find_timestamp(event.raw)
    if event.data_source in ("structured", "generic"):
        classified = classify_data_source(event)
        if classified:
            event.data_source = classified
    return event


def classify_data_source(event: Event) -> str | None:
    """Infer the telemetry type from the fields a record actually carries.

    Generic formats such as CSV and key value carry no vendor marker, so the
    classification has to come from the shape of the data. This is what makes
    hypothesis coverage reporting work for arbitrary exports.
    """
    keys = {key.lower() for key in event.extra}

    # Kubernetes audit records carry an unmistakable envelope.
    if "audit.k8s.io" in event.raw or ("objectref.resource" in keys and "requesturi" in keys):
        return "k8s_audit"
    if "requesturi" in keys and "verb" in keys and "user.username" in keys:
        return "k8s_audit"
    # Identity provider events name the actor and the outcome reason.
    if "eventtype" in keys and ("displaymessage" in keys or "authenticationcontext.authenticationstep" in keys):
        return "idp"
    if "actor.alternateid" in keys or "outcome.reason" in keys:
        return "idp"
    if {"workload", "recordtype"} <= keys or "auditdata" in keys:
        return "o365_audit"
    if {"eventname", "eventsource"} <= keys or "useridentity" in keys or event.get("aws.event_name"):
        return "aws_cloudtrail"
    if event.get("dns.question.name"):
        return "dns"
    if event.get("http.request.method") or (event.get("url.original") and event.get("http.response.status_code")):
        return "web"
    if event.get("tls.ja3"):
        return "tls"
    if event.get("rule.name") and (event.get("source.ip") or event.get("destination.ip")):
        return "ids"
    code = event.get_str("event.code")
    if code.isdigit() and (event.get("host.name") or event.get("process.command_line") or event.get("logon.type")):
        return "windows_event"
    if event.get("source.ip") and event.get("destination.ip") and (
        event.get("destination.port") or event.get("network.protocol")
    ):
        return "network_flow"
    if event.get("process.command_line") or event.get("process.executable"):
        return "endpoint"
    return None


def _clip(line: str) -> str:
    return line if len(line) <= MAX_RAW_LENGTH else line[:MAX_RAW_LENGTH] + " ...[truncated]"


# ---------------------------------------------------------------------------
# base parser
# ---------------------------------------------------------------------------


class BaseParser:
    name = "generic"
    data_source = "generic"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        return 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        raise NotImplementedError

    def _event(self, raw: str, line_no: int, source_file: str) -> Event:
        return Event(
            raw=_clip(raw.rstrip("\n")),
            source_file=source_file,
            line_no=line_no,
            log_format=self.name,
            data_source=self.data_source,
        )


# ---------------------------------------------------------------------------
# JSON family
# ---------------------------------------------------------------------------

_CLOUDTRAIL_HINTS = ("eventsource", "eventname", "useridentity", "awsregion")
_SURICATA_HINTS = ("event_type", "alert", "flow_id")
_ZEEK_JSON_HINTS = ("id.orig_h", "id.resp_h", "uid")
_O365_HINTS = ("workload", "clientip", "userid", "recordtype")


class JsonParser(BaseParser):
    name = "json"
    data_source = "structured"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        hits = 0
        checked = 0
        for line in sample:
            stripped = line.strip()
            if not stripped:
                continue
            checked += 1
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    json.loads(stripped)
                    hits += 1
                except json.JSONDecodeError:
                    if stripped.startswith("{") and stripped.endswith("}"):
                        hits += 0.4
            if checked >= 25:
                break
        if not checked:
            return 0.0
        score = hits / checked
        if score > 0.5:
            return min(0.99, 0.7 + score * 0.3)
        # A pretty printed document is one JSON value spread over many lines, so
        # the sample is a valid prefix rather than a valid document.
        joined = "".join(sample).strip()
        if joined.startswith("{") or joined.startswith("["):
            try:
                json.loads(joined)
                return 0.95
            except json.JSONDecodeError:
                # The sample is only a prefix of a large document. Quoted keys
                # are enough evidence that the file really is JSON.
                if len(re.findall(r'"[^"\n]{1,60}"\s*:', joined)) >= 3:
                    return 0.85
            return max(score * 0.6, 0.35)
        return score * 0.6

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        buffer: list[str] = []
        line_no = 0
        pending: list[str] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = None
            if pending:
                pending.append(line)
                try:
                    payload = json.loads("".join(pending))
                    pending = []
                except json.JSONDecodeError:
                    if len("".join(pending)) > 2_000_000:
                        pending = []
                    continue
            else:
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    pending = [line]
                    buffer.append(line)
                    continue
            if payload is None:
                continue
            yield from self._records(payload, line_no, source_file, stripped)
        if pending:
            text = "".join(pending).strip()
            try:
                payload = json.loads(text)
                yield from self._records(payload, line_no, source_file, text)
            except json.JSONDecodeError:
                for offset, leftover in enumerate(pending):
                    if leftover.strip():
                        event = self._event(leftover, line_no + offset, source_file)
                        event.log_format = "text"
                        yield enrich(event)

    def _records(self, payload: Any, line_no: int, source_file: str, raw: str) -> Iterator[Event]:
        if isinstance(payload, list):
            for item in payload:
                yield from self._records(item, line_no, source_file, json.dumps(item)[:MAX_RAW_LENGTH])
            return
        if not isinstance(payload, dict):
            return
        for wrapper in ("Records", "records", "value", "entries", "events", "data", "hits"):
            inner = payload.get(wrapper)
            if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                for item in inner:
                    yield from self._records(item, line_no, source_file, json.dumps(item)[:MAX_RAW_LENGTH])
                return
        yield self._from_dict(payload, line_no, source_file, raw)

    def _from_dict(self, payload: dict, line_no: int, source_file: str, raw: str) -> Event:
        event = self._event(raw, line_no, source_file)
        flat = flatten(payload)
        lowered = {key.lower() for key in flat}
        for key, value in flat.items():
            assign(event, key, value)
        if "audit.k8s.io" in raw or ({"requesturi", "verb"} <= lowered and "objectref.resource" in lowered):
            event.data_source = "k8s_audit"
            event.log_format = "k8s_audit"
            _map_kubernetes(event, flat)
        elif "eventtype" in lowered and ("displaymessage" in lowered or "actor.alternateid" in lowered):
            event.data_source = "idp"
            event.log_format = "idp"
        elif any(hint in lowered for hint in _CLOUDTRAIL_HINTS):
            event.data_source = "aws_cloudtrail"
            event.log_format = "cloudtrail"
            event.set("cloud.provider", "aws")
            _map_cloudtrail(event, flat)
        elif "workload" in lowered and "recordtype" in lowered:
            event.data_source = "o365_audit"
            event.log_format = "o365"
            event.set("cloud.provider", "microsoft")
        elif any(hint in lowered for hint in _ZEEK_JSON_HINTS):
            event.data_source = "network_flow"
            event.log_format = "zeek_json"
        elif any(hint in lowered for hint in _SURICATA_HINTS):
            event.data_source = "ids"
            event.log_format = "suricata"
        elif "winlog" in " ".join(lowered) or "eventid" in lowered or "event_id" in lowered:
            event.data_source = "windows_event"
            event.log_format = "windows_json"
            _map_windows_semantics(event)
            channel = str(flat.get("Channel") or flat.get("winlog.channel") or "").lower()
            if "sysmon" in channel or str(flat.get("Provider") or "").lower().find("sysmon") >= 0:
                event.data_source = "sysmon"
            elif "powershell" in channel:
                event.data_source = "powershell"
            elif "security" in channel:
                event.data_source = "windows_security"
        elif "dns" in " ".join(lowered) and event.get("dns.question.name"):
            event.data_source = "dns"
        elif event.get("http.request.method") or event.get("url.original"):
            event.data_source = "web"
        return enrich(event)


def _map_kubernetes(event: Event, flat: dict[str, Any]) -> None:
    """Map the Kubernetes audit envelope onto the common schema."""
    user = flat.get("user.username") or flat.get("impersonatedUser.username")
    if user:
        event.set("user.name", user)
    source_ips = flat.get("sourceIPs")
    if source_ips:
        event.set("source.ip", str(source_ips).split(",")[0].strip())
    verb = flat.get("verb")
    resource = flat.get("objectRef.resource")
    subresource = flat.get("objectRef.subresource")
    name = flat.get("objectRef.name")
    if verb and resource:
        action = f"{verb} {resource}" + (f"/{subresource}" if subresource else "")
        event.set("event.action", action)
    if name:
        event.set("container.name", name)
    if flat.get("objectRef.namespace"):
        event.set("kubernetes.namespace", flat["objectRef.namespace"])
    status = flat.get("responseStatus.code")
    if status is not None:
        event.set("event.outcome", "success" if str(status).startswith("2") else "failure")
    event.set("event.provider", "kubernetes")
    # The verb is a Kubernetes action, not an HTTP method.
    event.fields.pop("http.request.method", None)
    event.fields.pop("url.original", None)


def _map_cloudtrail(event: Event, flat: dict[str, Any]) -> None:
    identity_type = flat.get("userIdentity.type")
    arn = flat.get("userIdentity.arn") or flat.get("userIdentity.principalId")
    user = (
        flat.get("userIdentity.userName")
        or flat.get("userIdentity.sessionContext.sessionIssuer.userName")
        or (str(arn).split("/")[-1] if arn else None)
    )
    if user:
        event.set("user.name", user)
    if identity_type:
        event.set("user.type", identity_type)
    if arn:
        event.set("user.arn", arn)
    if flat.get("eventName"):
        event.set("event.action", flat["eventName"])
        event.set("aws.event_name", flat["eventName"])
    if flat.get("eventSource"):
        event.set("event.provider", flat["eventSource"])
    if flat.get("errorCode"):
        event.set("event.outcome", "failure")
        event.set("error.message", str(flat.get("errorCode")) + " " + str(flat.get("errorMessage", "")))
    elif not event.get("event.outcome"):
        event.set("event.outcome", "success")
    mfa = flat.get("userIdentity.sessionContext.attributes.mfaAuthenticated")
    if mfa is not None:
        event.set("auth.mfa", str(mfa))


# ---------------------------------------------------------------------------
# CEF and LEEF
# ---------------------------------------------------------------------------

_CEF_RE = re.compile(r"CEF:\d+\|")
_LEEF_RE = re.compile(r"LEEF:\d(?:\.\d)?\|")


class CefParser(BaseParser):
    name = "cef"
    data_source = "security_appliance"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        hits = sum(1 for line in sample if _CEF_RE.search(line))
        return min(0.98, hits / max(1, len([s for s in sample if s.strip()])) + 0.05) if hits else 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            event = self._event(line, line_no, source_file)
            match = _CEF_RE.search(line)
            if not match:
                yield enrich(event)
                continue
            prefix = line[: match.start()].strip()
            if prefix:
                event.timestamp = find_timestamp(prefix)
            body = line[match.end():]
            parts = re.split(r"(?<!\\)\|", body)
            headers = ["device_vendor", "device_product", "device_version", "signature_id", "name", "severity"]
            for index, header in enumerate(headers):
                if index < len(parts):
                    assign(event, header, parts[index])
            event.set("event.provider", " ".join(parts[:2]).strip())
            if len(parts) > 4:
                event.set("rule.name", parts[4])
                event.set("event.action", parts[4])
            if len(parts) > 3:
                event.set("event.code", parts[3])
            if len(parts) > 5:
                for key, value in _parse_cef_extension(" ".join(parts[5:])).items():
                    assign(event, key, value)
            yield enrich(event)


def _parse_cef_extension(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    tokens = re.findall(r"([A-Za-z0-9_\.\-]+)=((?:[^=]|(?<=\\)=)*?)(?=\s+[A-Za-z0-9_\.\-]+=|$)", text)
    for key, value in tokens:
        result[key.strip()] = value.strip().replace("\\=", "=").replace("\\\\", "\\")
    return result


class LeefParser(BaseParser):
    name = "leef"
    data_source = "security_appliance"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        hits = sum(1 for line in sample if _LEEF_RE.search(line))
        return min(0.98, hits / max(1, len([s for s in sample if s.strip()])) + 0.05) if hits else 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            event = self._event(line, line_no, source_file)
            match = _LEEF_RE.search(line)
            if match:
                parts = line[match.end():].split("|")
                for name, index in (("device_vendor", 0), ("device_product", 1), ("device_version", 2), ("event_id", 3)):
                    if index < len(parts):
                        assign(event, name, parts[index])
                if len(parts) > 3:
                    event.set("event.code", parts[3])
                    event.set("event.action", parts[3])
                if len(parts) > 4:
                    body = "|".join(parts[4:])
                    for chunk in re.split(r"\t|\|", body):
                        if "=" in chunk:
                            key, value = chunk.split("=", 1)
                            assign(event, key, value)
                event.timestamp = event.timestamp or find_timestamp(line)
            yield enrich(event)


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------

_SYSLOG5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>(?:\[[^\]]*\])+|-)\s*(?P<msg>.*)$"
)
_SYSLOG3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\.\-]+)\s+(?P<app>[\w\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[\w\.\-]+)\s+(?P<app>[\w\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)


class SyslogParser(BaseParser):
    name = "syslog"
    data_source = "syslog"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        useful = [line for line in sample if line.strip()]
        if not useful:
            return 0.0
        hits = sum(
            1
            for line in useful
            if _SYSLOG5424_RE.match(line.strip())
            or _SYSLOG3164_RE.match(line.strip())
            or _ISO_SYSLOG_RE.match(line.strip())
        )
        return min(0.95, hits / len(useful))

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = self._event(line, line_no, source_file)
            match = _SYSLOG5424_RE.match(stripped) or _ISO_SYSLOG_RE.match(stripped) or _SYSLOG3164_RE.match(stripped)
            if match:
                groups = match.groupdict()
                event.timestamp = parse_timestamp(groups.get("ts"))
                event.set("host.name", groups.get("host"))
                event.set("process.name", groups.get("app"))
                event.set("event.provider", groups.get("app"))
                if groups.get("pid"):
                    event.set("process.pid", groups.get("pid"))
                message = groups.get("msg") or ""
                event.set("message", message)
                if groups.get("pri"):
                    priority = int(groups["pri"])
                    event.set("log.syslog.facility", priority // 8)
                    event.set("event.severity", priority % 8)
                structured = groups.get("sd")
                if structured and structured != "-":
                    for key, value in re.findall(r'([A-Za-z0-9_\-]+)="([^"]*)"', structured):
                        assign(event, key, value)
                _parse_unix_message(event, message)
            else:
                event.timestamp = find_timestamp(stripped)
                event.set("message", stripped)
                _parse_unix_message(event, stripped)
            for key, value in re.findall(r'\b([A-Za-z0-9_\-]{2,32})=("[^"]*"|\S+)', event.get_str("message")):
                assign(event, key, value.strip('"'))
            yield enrich(event)


_SSH_ACCEPT_RE = re.compile(
    r"(Accepted|Failed)\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", re.IGNORECASE
)
_SSH_INVALID_RE = re.compile(r"Invalid user\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE)
_SUDO_RE = re.compile(r"(\S+)\s*:.*?TTY=(\S*)\s*;\s*PWD=(\S*)\s*;\s*USER=(\S*)\s*;\s*COMMAND=(.+)$")
_USERADD_RE = re.compile(r"new user: name=([^,]+), UID=(\d+), GID=(\d+)", re.IGNORECASE)
_PAM_RE = re.compile(r"authentication failure;.*?ruser=(\S*)\s+rhost=(\S*)\s*(?:user=(\S*))?", re.IGNORECASE)


def _parse_unix_message(event: Event, message: str) -> None:
    """Extract structure from the classic Linux authentication messages."""
    if not message:
        return
    match = _SSH_ACCEPT_RE.search(message)
    if match:
        outcome, method, user, ip, port = match.groups()
        event.set("event.category", "authentication")
        event.set("event.action", "ssh_login")
        event.set("event.outcome", "success" if outcome.lower() == "accepted" else "failure")
        event.set("auth.method", method)
        event.set("user.name", user)
        event.set("source.ip", ip)
        event.set("source.port", port)
        event.data_source = "linux_auth"
        return
    match = _SSH_INVALID_RE.search(message)
    if match:
        event.set("event.category", "authentication")
        event.set("event.action", "ssh_invalid_user")
        event.set("event.outcome", "failure")
        event.set("user.name", match.group(1))
        event.set("source.ip", match.group(2))
        event.data_source = "linux_auth"
        return
    match = _SUDO_RE.search(message)
    if match:
        user, tty, pwd, target, command = match.groups()
        event.set("event.category", "privilege_escalation")
        event.set("event.action", "sudo")
        event.set("user.name", user)
        event.set("user.target", target)
        event.set("process.command_line", command)
        event.set("process.working_directory", pwd)
        event.data_source = "linux_auth"
        return
    match = _USERADD_RE.search(message)
    if match:
        event.set("event.category", "account_management")
        event.set("event.action", "user_created")
        event.set("user.target", match.group(1))
        event.set("user.id", match.group(2))
        event.data_source = "linux_auth"
        return
    match = _PAM_RE.search(message)
    if match:
        event.set("event.category", "authentication")
        event.set("event.action", "pam_auth_failure")
        event.set("event.outcome", "failure")
        if match.group(2):
            event.set("source.ip", match.group(2))
        if match.group(3):
            event.set("user.name", match.group(3))
        event.data_source = "linux_auth"


# ---------------------------------------------------------------------------
# Web server access logs
# ---------------------------------------------------------------------------

_CLF_RE = re.compile(
    r'^(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


class AccessLogParser(BaseParser):
    name = "http_access"
    data_source = "web"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        useful = [line for line in sample if line.strip()]
        if not useful:
            return 0.0
        hits = sum(1 for line in useful if _CLF_RE.match(line.strip()))
        return min(0.97, hits / len(useful))

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = self._event(line, line_no, source_file)
            match = _CLF_RE.match(stripped)
            if match:
                groups = match.groupdict()
                event.timestamp = parse_timestamp(groups["ts"])
                event.set("source.ip", groups["client"])
                if groups["user"] and groups["user"] != "-":
                    event.set("user.name", groups["user"])
                request = groups.get("request") or ""
                request_parts = request.split()
                if request_parts:
                    event.set("http.request.method", request_parts[0])
                if len(request_parts) > 1:
                    event.set("url.original", request_parts[1])
                    event.set("url.path", request_parts[1].split("?")[0])
                    if "?" in request_parts[1]:
                        event.set("url.query", request_parts[1].split("?", 1)[1])
                if len(request_parts) > 2:
                    event.set("http.version", request_parts[2])
                event.set("http.response.status_code", groups["status"])
                if groups["size"] and groups["size"].isdigit():
                    event.set("http.response.bytes", int(groups["size"]))
                if groups.get("referer") and groups["referer"] != "-":
                    event.set("http.request.referrer", groups["referer"])
                if groups.get("agent"):
                    event.set("user_agent.original", groups["agent"])
                event.set("event.category", "web")
            else:
                event.timestamp = find_timestamp(stripped)
                event.set("message", stripped)
            yield enrich(event)


class W3CExtendedParser(BaseParser):
    """Microsoft IIS and other W3C extended log files."""

    name = "w3c_extended"
    data_source = "web"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        for line in sample[:40]:
            if line.lower().startswith("#fields:"):
                return 0.99
            if line.lower().startswith("#software: microsoft internet information services"):
                return 0.95
        return 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        fields: list[str] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                if stripped.lower().startswith("#fields:"):
                    fields = stripped.split(":", 1)[1].split()
                continue
            if not fields:
                continue
            values = stripped.split()
            event = self._event(line, line_no, source_file)
            date_part = time_part = ""
            for index, name in enumerate(fields):
                if index >= len(values):
                    break
                value = values[index]
                lowered = name.lower()
                if lowered == "date":
                    date_part = value
                    continue
                if lowered == "time":
                    time_part = value
                    continue
                assign(event, name, value)
            if date_part or time_part:
                event.timestamp = parse_timestamp(f"{date_part} {time_part}".strip())
            event.set("event.category", "web")
            method = event.get_str("http.request.method")
            stem = event.get_str("url.path")
            query = event.get_str("url.query")
            if stem and not event.get("url.original"):
                event.set("url.original", stem + (("?" + query) if query and query != "-" else ""))
            if method:
                event.set("event.action", method)
            yield enrich(event)


# ---------------------------------------------------------------------------
# Zeek, CSV and key value
# ---------------------------------------------------------------------------


class ZeekParser(BaseParser):
    name = "zeek_tsv"
    data_source = "network_flow"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        head = "".join(sample[:20]).lower()
        if "#separator" in head and "#fields" in head:
            return 0.99
        if "#fields" in head and "\t" in head:
            return 0.9
        return 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        fields: list[str] = []
        separator = "\t"
        path_name = ""
        for line_no, line in enumerate(lines, start=1):
            if line.startswith("#"):
                lowered = line.lower()
                if lowered.startswith("#separator"):
                    raw = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else "\\x09"
                    separator = raw.encode().decode("unicode_escape") if raw.startswith("\\x") else raw
                elif lowered.startswith("#fields"):
                    fields = line.strip().split(separator)[1:]
                elif lowered.startswith("#path"):
                    path_name = line.strip().split(separator)[-1]
                continue
            stripped = line.rstrip("\n")
            if not stripped.strip():
                continue
            values = stripped.split(separator)
            event = self._event(line, line_no, source_file)
            if path_name:
                event.set("event.dataset", path_name)
                if path_name in ("dns",):
                    event.data_source = "dns"
                elif path_name in ("http",):
                    event.data_source = "web"
                elif path_name in ("ssl", "x509"):
                    event.data_source = "tls"
            for index, name in enumerate(fields):
                if index < len(values):
                    assign(event, name, values[index])
            if not event.timestamp:
                event.timestamp = parse_timestamp(values[0] if values else None)
            if path_name == "dns" and event.get("query") is None:
                pass
            query = event.extra.get("query")
            if query:
                event.set("dns.question.name", query)
            yield enrich(event)


class DelimitedParser(BaseParser):
    name = "csv"
    data_source = "structured"

    def __init__(self, delimiter: str = ",") -> None:
        self.delimiter = delimiter

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        useful = [line.rstrip("\n") for line in sample if line.strip() and not line.startswith("#")]
        if len(useful) < 2:
            return 0.0
        best = 0.0
        for delimiter in (",", ";", "\t", "|"):
            counts = [line.count(delimiter) for line in useful[:20]]
            if not counts or counts[0] == 0:
                continue
            consistent = sum(1 for count in counts if count == counts[0]) / len(counts)
            if consistent > 0.8 and counts[0] >= 2:
                header = useful[0].split(delimiter)
                looks_like_header = sum(
                    1 for cell in header if cell.strip() and not cell.strip().replace(".", "").isdigit()
                ) >= max(2, int(len(header) * 0.7))
                score = 0.55 + 0.25 * consistent + (0.15 if looks_like_header else 0.0)
                best = max(best, min(score, 0.9))
        return best

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        iterator = iter(lines)
        buffered: list[str] = []
        for line in iterator:
            if line.strip():
                buffered.append(line)
                break
        if not buffered:
            return
        header_line = buffered[0]
        delimiter = self._detect_delimiter(header_line)
        reader = csv.reader(io.StringIO(header_line), delimiter=delimiter)
        header = next(reader, [])
        header = [cell.strip().lstrip("\ufeff") for cell in header]
        for line_no, line in enumerate(iterator, start=2):
            if not line.strip():
                continue
            try:
                row = next(csv.reader(io.StringIO(line), delimiter=delimiter), [])
            except csv.Error:
                row = line.rstrip("\n").split(delimiter)
            if not row:
                continue
            event = self._event(line, line_no, source_file)
            for index, name in enumerate(header):
                if index < len(row):
                    assign(event, name or f"column_{index}", row[index])
            if not event.timestamp:
                event.timestamp = find_timestamp(line)
            yield enrich(event)

    @staticmethod
    def _detect_delimiter(header_line: str) -> str:
        best, best_count = ",", 0
        for delimiter in (",", ";", "\t", "|"):
            count = header_line.count(delimiter)
            if count > best_count:
                best, best_count = delimiter, count
        return best


_KV_RE = re.compile(r'([A-Za-z0-9_\.\-\[\]]{1,64})=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]+)')


class KeyValueParser(BaseParser):
    name = "keyvalue"
    data_source = "structured"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        useful = [line for line in sample if line.strip()]
        if not useful:
            return 0.0
        scores = []
        for line in useful[:25]:
            pairs = _KV_RE.findall(line)
            tokens = max(1, len(line.split()))
            scores.append(min(1.0, len(pairs) / tokens))
        average = sum(scores) / len(scores)
        return min(0.88, average) if average > 0.35 else average * 0.5

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = self._event(line, line_no, source_file)
            for key, value in _KV_RE.findall(stripped):
                assign(event, key, value.strip('"').strip("'"))
            if not event.timestamp:
                event.timestamp = find_timestamp(stripped)
            if not event.get("message"):
                event.set("message", stripped[:600])
            yield enrich(event)


# ---------------------------------------------------------------------------
# Windows event XML (evtx exported to XML) and Sysmon
# ---------------------------------------------------------------------------

_XML_EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL | re.IGNORECASE)
_XML_DATA_RE = re.compile(r'<Data\s+Name=[\'"]([^\'"]+)[\'"]\s*>(.*?)</Data>', re.DOTALL | re.IGNORECASE)
_XML_TAG_RE = re.compile(r"<(\w+)(\s[^>]*)?>([^<]*)</\1>", re.DOTALL)
_XML_ATTR_RE = re.compile(r'(\w+)=[\'"]([^\'"]*)[\'"]')


class WindowsXmlParser(BaseParser):
    name = "windows_evtx_xml"
    data_source = "windows_event"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        head = "".join(sample[:60])
        if "<Event" in head and ("schemas.microsoft.com/win/2004/08/events" in head or "<EventID" in head):
            return 0.99
        if "<Event" in head and "</Event>" in head:
            return 0.8
        return 0.0

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        buffer: list[str] = []
        start_line = 1
        for line_no, line in enumerate(lines, start=1):
            if not buffer and "<Event" not in line:
                continue
            if not buffer:
                start_line = line_no
            buffer.append(line)
            joined = "".join(buffer)
            if "</Event>" in joined:
                for match in _XML_EVENT_RE.finditer(joined):
                    yield self._from_xml(match.group(0), start_line, source_file)
                buffer = []
        if buffer:
            joined = "".join(buffer)
            for match in _XML_EVENT_RE.finditer(joined):
                yield self._from_xml(match.group(0), start_line, source_file)

    def _from_xml(self, xml: str, line_no: int, source_file: str) -> Event:
        event = self._event(xml, line_no, source_file)
        for key, value in _XML_DATA_RE.findall(xml):
            assign(event, key, _unescape(value))
        for tag, attrs, text in _XML_TAG_RE.findall(xml):
            if tag.lower() in ("data",):
                continue
            if text.strip():
                assign(event, tag, _unescape(text))
            if attrs:
                for attr_key, attr_value in _XML_ATTR_RE.findall(attrs):
                    if attr_key.lower() in ("systemtime", "name", "guid", "processid", "threadid"):
                        assign(event, f"{tag}_{attr_key}", attr_value)
        provider = re.search(r'<Provider[^>]*Name=[\'"]([^\'"]+)[\'"]', xml, re.IGNORECASE)
        if provider:
            event.set("event.provider", provider.group(1))
            if "sysmon" in provider.group(1).lower():
                event.data_source = "sysmon"
        systemtime = re.search(r'<TimeCreated[^>]*SystemTime=[\'"]([^\'"]+)[\'"]', xml, re.IGNORECASE)
        if systemtime:
            event.timestamp = parse_timestamp(systemtime.group(1))
        channel = re.search(r"<Channel>([^<]+)</Channel>", xml, re.IGNORECASE)
        if channel:
            event.set("log.channel", channel.group(1))
            lowered = channel.group(1).lower()
            if "sysmon" in lowered:
                event.data_source = "sysmon"
            elif "powershell" in lowered:
                event.data_source = "powershell"
            elif "security" in lowered:
                event.data_source = "windows_security"
        computer = re.search(r"<Computer>([^<]+)</Computer>", xml, re.IGNORECASE)
        if computer:
            event.set("host.name", computer.group(1))
        event_id = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml, re.IGNORECASE)
        if event_id:
            event.set("event.code", event_id.group(1))
        if not event.timestamp:
            event.timestamp = find_timestamp(xml)
        _map_windows_semantics(event)
        return enrich(event)


def _unescape(value: str) -> str:
    return (
        value.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&#13;", "")
        .replace("&#10;", "\n")
        .replace("&amp;", "&")
        .strip()
    )


WINDOWS_EVENT_ACTIONS = {
    "1": ("process_creation", "process"),
    "3": ("network_connection", "network"),
    "7": ("image_loaded", "process"),
    "8": ("create_remote_thread", "process"),
    "10": ("process_access", "process"),
    "11": ("file_created", "file"),
    "12": ("registry_create_delete", "registry"),
    "13": ("registry_value_set", "registry"),
    "15": ("file_stream_created", "file"),
    "22": ("dns_query", "dns"),
    "23": ("file_delete", "file"),
    "4624": ("logon_success", "authentication"),
    "4625": ("logon_failure", "authentication"),
    "4634": ("logoff", "authentication"),
    "4648": ("explicit_credential_logon", "authentication"),
    "4662": ("directory_object_access", "directory"),
    "4663": ("object_access", "file"),
    "4670": ("permissions_changed", "file"),
    "4672": ("special_privileges_assigned", "authentication"),
    "4688": ("process_creation", "process"),
    "4697": ("service_installed", "service"),
    "4698": ("scheduled_task_created", "persistence"),
    "4699": ("scheduled_task_deleted", "persistence"),
    "4702": ("scheduled_task_updated", "persistence"),
    "4719": ("audit_policy_changed", "defense_evasion"),
    "4720": ("user_account_created", "account_management"),
    "4722": ("user_account_enabled", "account_management"),
    "4724": ("password_reset_attempt", "account_management"),
    "4725": ("user_account_disabled", "account_management"),
    "4726": ("user_account_deleted", "account_management"),
    "4728": ("member_added_to_global_group", "account_management"),
    "4732": ("member_added_to_local_group", "account_management"),
    "4738": ("user_account_changed", "account_management"),
    "4740": ("account_lockout", "authentication"),
    "4768": ("kerberos_tgt_requested", "authentication"),
    "4769": ("kerberos_service_ticket_requested", "authentication"),
    "4771": ("kerberos_preauth_failed", "authentication"),
    "4776": ("ntlm_credential_validation", "authentication"),
    "4778": ("session_reconnected", "authentication"),
    "4781": ("account_renamed", "account_management"),
    "4794": ("dsrm_password_set", "account_management"),
    "5140": ("network_share_access", "lateral_movement"),
    "5145": ("network_share_object_access", "lateral_movement"),
    "1102": ("audit_log_cleared", "defense_evasion"),
    "104": ("event_log_cleared", "defense_evasion"),
    "7045": ("service_installed", "service"),
    "4104": ("powershell_script_block", "script"),
    "4103": ("powershell_module_logging", "script"),
    "400": ("powershell_engine_start", "script"),
    "800": ("powershell_pipeline", "script"),
    "1116": ("defender_malware_detected", "malware"),
    "1117": ("defender_action_taken", "malware"),
    "1006": ("defender_malware_detected", "malware"),
    "5001": ("defender_realtime_disabled", "defense_evasion"),
    "5007": ("defender_configuration_changed", "defense_evasion"),
    "4657": ("registry_value_modified", "registry"),
    "4673": ("privileged_service_called", "privilege"),
    "4674": ("privileged_object_operation", "privilege"),
    "4964": ("special_group_logon", "authentication"),
    "1149": ("rdp_authentication_success", "authentication"),
    "21": ("rdp_session_logon", "authentication"),
    "24": ("rdp_session_disconnect", "authentication"),
    "25": ("rdp_session_reconnect", "authentication"),
}

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def _map_windows_semantics(event: Event) -> None:
    code = event.get_str("event.code")
    if code in WINDOWS_EVENT_ACTIONS:
        action, category = WINDOWS_EVENT_ACTIONS[code]
        event.setdefault_field("event.action", action)
        event.setdefault_field("event.category", category)
        if code == "4625":
            event.set("event.outcome", "failure")
        elif code in ("4624", "4634", "4672", "4688"):
            event.set("event.outcome", "success")
    logon_type = event.get_str("logon.type")
    if logon_type and logon_type in LOGON_TYPES:
        event.set("logon.type_name", LOGON_TYPES[logon_type])
    if event.get("process.command_line") and not event.get("event.category"):
        event.set("event.category", "process")


# ---------------------------------------------------------------------------
# Free text fallback
# ---------------------------------------------------------------------------


class TextParser(BaseParser):
    name = "text"
    data_source = "generic"

    @classmethod
    def sniff(cls, sample: list[str], filename: str) -> float:
        return 0.05

    def parse(self, lines: Iterable[str], source_file: str) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = self._event(line, line_no, source_file)
            event.timestamp = find_timestamp(stripped)
            event.set("message", stripped[:1500])
            for key, value in re.findall(r'\b([A-Za-z][A-Za-z0-9_\-]{2,32})\s*[:=]\s*("[^"]*"|\S+)', stripped):
                assign(event, key, value.strip('"'))
            _parse_unix_message(event, stripped)
            yield enrich(event)


PARSERS: tuple[type[BaseParser], ...] = (
    WindowsXmlParser,
    JsonParser,
    CefParser,
    LeefParser,
    ZeekParser,
    W3CExtendedParser,
    AccessLogParser,
    SyslogParser,
    DelimitedParser,
    KeyValueParser,
    TextParser,
)


def select_parser(sample: list[str], filename: str) -> tuple[BaseParser, float, dict[str, float]]:
    """Score every parser against a sample and return the best candidate."""
    scores: dict[str, float] = {}
    best_cls: type[BaseParser] = TextParser
    best_score = 0.0
    for parser_cls in PARSERS:
        try:
            score = parser_cls.sniff(sample, filename)
        except Exception:  # a broken sample must never stop the hunt
            score = 0.0
        scores[parser_cls.name] = round(score, 3)
        if score > best_score:
            best_cls, best_score = parser_cls, score
    return best_cls(), best_score, scores
