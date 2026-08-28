"""Normalised event model shared by every parser and every detection rule."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# A single field value is capped so that one pathological record cannot make
# every pattern in the library expensive, and so that memory stays bounded.
MAX_FIELD_LENGTH = 4096

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|club|pw|tk|ml|ga|cf|gq|su|cc|to|sh|dev|app|co|uk|de|fr|nl|br|in|jp|us|eu|me|link|live|icu|monster|cyou|zip|mov)\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\]+", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{1,190}\b")


@dataclass(slots=True)
class Event:
    """A single log record after normalisation.

    ``fields`` uses dotted Elastic Common Schema style keys so that rules can
    be written once and applied to any input format. ``extra`` keeps every
    field the source provided, which matters for formats the platform has
    never seen before.
    """

    raw: str = ""
    source_file: str = ""
    line_no: int = 0
    log_format: str = "unknown"
    data_source: str = "generic"
    timestamp: float | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    # -- accessors ---------------------------------------------------------
    def get(self, name: str, default: Any = None) -> Any:
        value = self.fields.get(name)
        if value is None or value == "":
            value = self.extra.get(name)
        if value is None or value == "":
            return default
        return value

    def get_str(self, name: str, default: str = "") -> str:
        value = self.get(name, default)
        if value is None:
            return default
        if isinstance(value, (list, tuple)):
            return " ".join(str(item) for item in value)
        return str(value)

    def get_int(self, name: str, default: int | None = None) -> int | None:
        value = self.get(name)
        if value is None:
            return default
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default

    def get_float(self, name: str, default: float | None = None) -> float | None:
        value = self.get(name)
        if value is None:
            return default
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return default

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    def set(self, name: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return
            if len(value) > MAX_FIELD_LENGTH:
                value = value[:MAX_FIELD_LENGTH]
        self.fields[name] = value

    def setdefault_field(self, name: str, value: Any) -> None:
        if not self.fields.get(name):
            self.set(name, value)

    # -- helpers -----------------------------------------------------------
    @property
    def searchable(self) -> str:
        """Raw text plus every stringified field, lowercased for matching."""
        if self._searchable_cache is None:
            chunks = [self.raw]
            for value in self.fields.values():
                if isinstance(value, (str, int, float)):
                    chunks.append(str(value))
            for value in self.extra.values():
                if isinstance(value, (str, int, float)):
                    chunks.append(str(value))
            self._searchable_cache = " ".join(chunks).lower()
        return self._searchable_cache

    _searchable_cache: str | None = field(default=None, repr=False, compare=False)

    def release_cache(self) -> None:
        """Drop the lowercased search text once matching is finished."""
        self._searchable_cache = None

    @property
    def datetime_utc(self) -> datetime | None:
        if self.timestamp is None:
            return None
        try:
            return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    def excerpt(self, limit: int = 900) -> str:
        text = self.raw.strip()
        if len(text) > limit:
            return text[:limit] + " ... [truncated]"
        return text

    def entity(self) -> str:
        """Best effort subject of the event, used to group observations."""
        for name in ("host.name", "user.name", "source.ip", "host.ip", "cloud.account.id"):
            value = self.get_str(name)
            if value:
                return value
        return self.source_file or "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.datetime_utc.isoformat() if self.datetime_utc else None,
            "source_file": self.source_file,
            "line_no": self.line_no,
            "log_format": self.log_format,
            "data_source": self.data_source,
            "fields": self.fields,
        }


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Pull indicators out of any free form text block."""
    return {
        "ipv4": sorted(set(IPV4_RE.findall(text)))[:25],
        "domains": sorted(set(DOMAIN_RE.findall(text)))[:25],
        "urls": sorted(set(URL_RE.findall(text)))[:25],
        "md5": sorted(set(MD5_RE.findall(text)))[:10],
        "sha1": sorted(set(SHA1_RE.findall(text)))[:10],
        "sha256": sorted(set(SHA256_RE.findall(text)))[:10],
        "emails": sorted(set(EMAIL_RE.findall(text)))[:10],
    }
