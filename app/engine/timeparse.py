"""Timestamp recognition for arbitrary log formats."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_NUMERIC_RE = re.compile(r"^\d{9,19}(?:\.\d+)?$")
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?$"
)
_SYSLOG_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$"
)
_APACHE_RE = re.compile(
    r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$"
)
_COMPACT_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})[T ]?(\d{2})(\d{2})(\d{2})$")

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Day first and month first slash dates are ambiguous. Windows, IIS and most
# security tooling emit month first, so that ordering wins.
_STRPTIME_FORMATS = (
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%d-%m-%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d.%m.%Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    "%d %b %Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
)

# Candidate timestamps embedded anywhere inside a free form line.
_EMBEDDED_PATTERNS = (
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s?[+-]\d{4}"),
    re.compile(r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    re.compile(r"\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}"),
)


def _tz_from_offset(offset: str | None) -> timezone:
    if not offset or offset in ("Z", "z"):
        return timezone.utc
    sign = 1 if offset[0] == "+" else -1
    digits = offset[1:].replace(":", "")
    if len(digits) < 4:
        return timezone.utc
    hours, minutes = int(digits[:2]), int(digits[2:4])
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def parse_timestamp(value, reference_year: int | None = None) -> float | None:
    """Return epoch seconds for a wide range of timestamp representations."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _normalise_epoch(float(value))

    text = str(value).strip().strip('"').strip("[]")
    if not text:
        return None

    match = _COMPACT_RE.match(text)
    if match:
        parts = [int(p) for p in match.groups()]
        try:
            return datetime(*parts, tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None

    if _NUMERIC_RE.match(text):
        try:
            return _normalise_epoch(float(text))
        except ValueError:
            return None

    match = _ISO_RE.match(text)
    if match:
        year, month, day, hour, minute, second, frac, offset = match.groups()
        micro = 0
        if frac:
            micro = int(frac.ljust(6, "0")[:6])
        try:
            return datetime(
                int(year), int(month), int(day), int(hour), int(minute), int(second),
                micro, tzinfo=_tz_from_offset(offset),
            ).timestamp()
        except ValueError:
            return None

    match = _APACHE_RE.match(text)
    if match:
        day, month, year, hour, minute, second, offset = match.groups()
        month_num = _MONTHS.get(month.lower())
        if month_num:
            try:
                return datetime(
                    int(year), month_num, int(day), int(hour), int(minute), int(second),
                    tzinfo=_tz_from_offset(offset),
                ).timestamp()
            except ValueError:
                return None

    match = _SYSLOG_RE.match(text)
    if match:
        month, day, hour, minute, second, _frac = match.groups()
        month_num = _MONTHS.get(month.lower())
        year = reference_year or datetime.now(timezone.utc).year
        if month_num:
            try:
                return datetime(
                    year, month_num, int(day), int(hour), int(minute), int(second),
                    tzinfo=timezone.utc,
                ).timestamp()
            except ValueError:
                return None

    for fmt in _STRPTIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _normalise_epoch(value: float) -> float | None:
    """Accept seconds, milliseconds, microseconds or nanoseconds."""
    if value <= 0:
        return None
    while value > 4_102_444_800:  # year 2100 in seconds
        value /= 1000.0
    if value < 315_532_800:  # before 1980, almost certainly not a timestamp
        return None
    return value


def find_timestamp(line: str, reference_year: int | None = None) -> float | None:
    """Locate the first plausible timestamp inside a free form line."""
    head = line[:120]
    for pattern in _EMBEDDED_PATTERNS:
        match = pattern.search(head)
        if match:
            epoch = parse_timestamp(match.group(0), reference_year)
            if epoch:
                return epoch
    return None
