"""The shipped list of publications the collector reads."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SOURCES_PATH = Path(__file__).resolve().parent / "sources.json"


@lru_cache(maxsize=1)
def load_sources() -> tuple[dict, ...]:
    try:
        payload = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    entries = payload.get("sources", [])
    return tuple(entry for entry in entries if entry.get("slug") and entry.get("url"))
