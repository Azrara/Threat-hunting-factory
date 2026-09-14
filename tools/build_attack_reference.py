"""Reduce the MITRE ATT&CK STIX bundle to the compact table the platform ships.

The full enterprise bundle is around 50 MB. Everything the platform needs from it
is the technique identifier, its name, its tactics and its platforms, which is
roughly 200 KB. Shipping the reduced table means technique validation works with
no network access and no dependency on MITRE being reachable.

    python tools/build_attack_reference.py enterprise-attack.json

Source: https://github.com/mitre-attack/attack-stix-data
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "app" / "attack_reference.json"


# "command-and-control" reads as "Command and Control", not "Command And Control".
MINOR_WORDS = {"and", "or", "of", "the", "to"}


def tactic_name(phase: str) -> str:
    parts = phase.split("-")
    return " ".join(
        part if index and part in MINOR_WORDS else part.capitalize()
        for index, part in enumerate(parts)
    )


def identifier_of(obj: dict) -> str:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id", "")
    return ""


def build(bundle_path: Path, output: Path) -> dict:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    techniques: dict[str, dict] = {}
    identifiers: dict[str, str] = {}
    version = ""

    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version", ""))
            continue
        if obj.get("type") != "attack-pattern":
            continue
        identifier = identifier_of(obj)
        if not identifier.startswith("T"):
            continue
        identifiers[obj["id"]] = identifier
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tactics = [
            tactic_name(phase["phase_name"])
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[identifier] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "sub": bool(obj.get("x_mitre_is_subtechnique")),
        }

    # A revoked identifier is not invalid, it moved. Keeping the mapping means an
    # older identifier resolves to the technique that replaced it instead of being
    # rejected as something the model invented.
    revoked: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
            continue
        source = identifiers.get(obj.get("source_ref", ""))
        target = identifiers.get(obj.get("target_ref", ""))
        if source and target and source not in techniques:
            revoked[source] = target

    tactics = sorted({name for entry in techniques.values() for name in entry["tactics"]})
    table = {
        "version": version,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "revoked": dict(sorted(revoked.items())),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(table, indent=0, sort_keys=True), encoding="utf-8")
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="enterprise-attack.json from attack-stix-data")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    table = build(args.bundle, args.output)
    techniques = table["techniques"]
    subs = sum(1 for entry in techniques.values() if entry["sub"])
    print(f"ATT&CK {table['version']}: {len(techniques)} techniques ({subs} sub techniques), "
          f"{len(table['revoked'])} revoked, {len(table['tactics'])} tactics")
    print(f"written to {args.output} ({args.output.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
