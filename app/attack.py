"""The MITRE ATT&CK reference the platform validates identifiers against.

A model asked for a technique identifier will produce something that looks like
one whether or not it exists. This table is the answer to "does it exist", and it
is also where the tactic comes from, so the tactic on a generated hypothesis is
read from ATT&CK rather than taken from the model.

The table ships with the repository and is rebuilt with
``tools/build_attack_reference.py``, so validation needs no network access.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REFERENCE_PATH = Path(__file__).resolve().parent / "attack_reference.json"
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    is_subtechnique: bool
    # Set when the identifier asked for was revoked and this is its replacement.
    replaces: str = ""

    @property
    def tactic(self) -> str:
        """The primary tactic, which is the first ATT&CK lists for the technique."""
        return self.tactics[0] if self.tactics else ""

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "tactics": list(self.tactics),
            "platforms": list(self.platforms),
            "sub_technique": self.is_subtechnique,
            "replaces": self.replaces,
            "url": self.url,
        }


@lru_cache(maxsize=1)
def _table() -> dict:
    try:
        return json.loads(REFERENCE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # A missing table must not stop the platform. Every identifier then fails
        # validation, which is the safe direction: nothing unverified gets through.
        return {"version": "", "tactics": [], "techniques": {}, "revoked": {}}


def version() -> str:
    return str(_table().get("version", ""))


def tactics() -> tuple[str, ...]:
    return tuple(_table().get("tactics", []))


def looks_like_technique(value: str) -> bool:
    """Shape only. A well formed identifier is not necessarily a real one."""
    return bool(TECHNIQUE_RE.match(value.strip().upper()))


def resolve(identifier: str) -> Technique | None:
    """Return the technique for an identifier, following revocations.

    ATT&CK retires identifiers and points them at replacements. Rejecting a revoked
    identifier would treat an out of date reference as an invention, so the
    replacement is returned instead, with ``replaces`` recording what was asked for.
    """
    if not identifier:
        return None
    key = identifier.strip().upper()
    if not looks_like_technique(key):
        return None
    table = _table()
    techniques = table.get("techniques", {})
    entry = techniques.get(key)
    replaced = ""
    if entry is None:
        target = table.get("revoked", {}).get(key)
        if not target:
            return None
        entry = techniques.get(target)
        if entry is None:
            return None
        replaced, key = key, target
    return Technique(
        id=key,
        name=entry.get("name", ""),
        tactics=tuple(entry.get("tactics", [])),
        platforms=tuple(entry.get("platforms", [])),
        is_subtechnique=bool(entry.get("sub")),
        replaces=replaced,
    )


def parent_of(identifier: str) -> str:
    """``T1071.001`` belongs to ``T1071``. An identifier without a dot is its own parent."""
    key = identifier.strip().upper()
    return key.split(".", 1)[0] if "." in key else key


def revoked_identifiers() -> dict[str, str]:
    """Every retired identifier and what replaced it."""
    return dict(_table().get("revoked", {}))
