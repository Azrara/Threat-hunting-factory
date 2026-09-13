"""The optional AI layer.

Two agents are planned on top of this package: a hypothesis collector that reads
public threat intelligence, and a behavioural analyst that adjudicates anomalies
found by the deterministic engine. See ``docs/ai-agents-design.md``.

Everything here is optional. When no model server is reachable the platform runs
exactly as it does without this package, so nothing in ``app`` may import it at
module scope in a way that makes a hunt depend on it.
"""
