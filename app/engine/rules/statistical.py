"""Mathematical hypotheses: entropy, spectral analysis, rarity and outliers.

These detections do not rely on signatures. They model what the data set as a
whole looks like and report the records that do not fit, which is how unknown
tooling and bespoke command and control channels are found.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from ..event import Event
from ..stats_math import (
    beacon_score,
    benford_chi_square,
    dga_score,
    gini_coefficient,
    looks_hex,
    modified_zscores,
    percentile,
    shannon_entropy,
)
from .base import Finding, StatisticalRule, evidence_from
from .helpers import statistical_rule

MIN_POPULATION = 25


def _finding(rule: StatisticalRule, *, title: str, description: str, entity: str,
             events: list[Event], metrics: dict[str, Any], fields: dict[str, Any] | None = None,
             severity: str | None = None, confidence: str | None = None) -> Finding:
    stamps = [event.timestamp for event in events if event.timestamp]
    finding = rule.base_finding(
        title=title,
        description=description,
        entity=entity,
        data_source=events[0].data_source if events else "",
        source_files=sorted({event.source_file for event in events})[:10],
        evidence=[evidence_from(event) for event in events[:6]],
        fields=fields or {},
        metrics=metrics,
        event_count=len(events),
        first_seen=min(stamps) if stamps else None,
        last_seen=max(stamps) if stamps else None,
    )
    if severity:
        finding.severity = severity
    if confidence:
        finding.confidence = confidence
    return finding


# ---------------------------------------------------------------------------
# 1. Spectral beacon detection
# ---------------------------------------------------------------------------


def analyse_beaconing(context, rule: StatisticalRule) -> list[Finding]:
    channels: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in context.events:
        if event.timestamp is None:
            continue
        source = event.get_str("source.ip") or event.get_str("host.name")
        destination = (
            event.get_str("destination.domain")
            or event.get_str("url.domain")
            or event.get_str("dns.question.name")
            or event.get_str("destination.ip")
        )
        if not source or not destination:
            continue
        channels[(source, destination)].append(event)

    findings: list[Finding] = []
    for (source, destination), events in channels.items():
        if len(events) < 8:
            continue
        stamps = [event.timestamp for event in events if event.timestamp]
        metrics = beacon_score(stamps)
        score = metrics.get("beacon_score", 0.0)
        if score < 0.75 or metrics.get("count", 0) < 8:
            continue
        interval = metrics.get("median_interval") or metrics.get("mean_interval") or 0
        severity = "critical" if score >= 0.9 and len(events) >= 20 else "high"
        findings.append(
            _finding(
                rule,
                title=f"Periodic command and control pattern from {source} to {destination}",
                description=(
                    f"{len(events)} connections between {source} and {destination} arrive at a near constant "
                    f"interval of about {interval} seconds. Fourier analysis of the binned time series shows a "
                    f"dominant frequency with a spectral power ratio of {metrics.get('power_ratio', 0)} against "
                    f"the mean, and the coefficient of variation of the inter arrival times is "
                    f"{metrics.get('coefficient_of_variation', 0)}. Human driven traffic does not display this "
                    "regularity, whereas implant check in traffic does."
                ),
                entity=f"{source} to {destination}",
                events=sorted(events, key=lambda e: e.timestamp or 0)[:6],
                metrics={
                    "beacon_score": score,
                    "connections": len(events),
                    "median_interval_seconds": metrics.get("median_interval"),
                    "mean_interval_seconds": metrics.get("mean_interval"),
                    "coefficient_of_variation": metrics.get("coefficient_of_variation"),
                    "jitter_ratio": metrics.get("jitter_ratio"),
                    "dominant_period_seconds": metrics.get("period_seconds"),
                    "spectral_power_ratio": metrics.get("power_ratio"),
                },
                fields={"source": source, "destination": destination},
                severity=severity,
                confidence="high" if score >= 0.88 else "medium",
            )
        )
    findings.sort(key=lambda item: -float(item.metrics.get("beacon_score", 0)))
    return findings[:20]


# ---------------------------------------------------------------------------
# 2. Domain generation algorithm scoring
# ---------------------------------------------------------------------------


def _parent_domain(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    return ".".join(labels[-2:])


def analyse_dga(context, rule: StatisticalRule) -> list[Finding]:
    """Score DNS labels for algorithmic generation, grouped by parent domain."""
    groups: dict[str, dict[str, Any]] = {}
    for event in context.events:
        name = event.get_str("dns.question.name") or event.get_str("destination.domain") or event.get_str("url.domain")
        if not name or len(name) < 8:
            continue
        domain = name.lower().rstrip(".")
        labels = domain.split(".")
        if len(labels) < 2:
            continue
        label = max(labels[:-1], key=len)
        score = dga_score(label)
        if score < 0.55:
            continue
        parent = _parent_domain(domain)
        bucket = groups.setdefault(parent, {"score": 0.0, "label": label, "domain": domain,
                                            "events": [], "names": set()})
        bucket["names"].add(domain)
        bucket["events"].append(event)
        if score > bucket["score"]:
            bucket["score"] = score
            bucket["label"] = label
            bucket["domain"] = domain

    findings: list[Finding] = []
    for parent, bucket in sorted(groups.items(), key=lambda item: -item[1]["score"])[:20]:
        label = bucket["label"]
        entropy = shannon_entropy(label)
        names = sorted(bucket["names"])
        score = bucket["score"]
        plural = f" across {len(names)} distinct hostnames" if len(names) > 1 else ""
        findings.append(
            _finding(
                rule,
                title=f"Algorithmically generated domain queried under {parent}",
                description=(
                    f"The domain {bucket['domain']} scores {score} on the domain generation algorithm model"
                    f"{plural}. The longest label has {len(label)} characters with a Shannon entropy of "
                    f"{entropy:.2f} bits per character and a consonant heavy structure that does not occur in "
                    "human chosen names. Malware families use generated domains so that takedowns of a single "
                    "command and control server do not break the channel."
                ),
                entity=parent,
                events=bucket["events"][:6],
                metrics={
                    "dga_score": score,
                    "shannon_entropy": round(entropy, 3),
                    "label_length": len(label),
                    "query_count": len(bucket["events"]),
                    "distinct_hostnames": len(names),
                    "sample_hostnames": names[:10],
                },
                fields={"parent_domain": parent, "example": bucket["domain"], "queries": len(bucket["events"])},
                severity="high" if score >= 0.75 else "medium",
                confidence="medium" if score >= 0.7 else "low",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 3. High entropy command lines and encoded payloads
# ---------------------------------------------------------------------------


def analyse_command_entropy(context, rule: StatisticalRule) -> list[Finding]:
    import re

    token_re = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
    findings: list[Finding] = []
    seen: set[str] = set()
    for event in context.events:
        command = event.get_str("process.command_line") or event.get_str("message") or event.raw
        if not command or len(command) < 60:
            continue
        for token in token_re.findall(command)[:3]:
            if len(token) < 48:
                continue
            # Hashes and identifiers are long and hexadecimal but not encoded
            # payloads, so they are excluded before scoring.
            if looks_hex(token):
                continue
            if not (any(c.islower() for c in token) and any(c.isupper() for c in token)):
                continue
            entropy = shannon_entropy(token)
            if entropy < 3.9:
                continue
            key = token[:60]
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    rule,
                    title=f"High entropy encoded payload in a command line on {event.get_str('host.name') or event.source_file}",
                    description=(
                        f"A command line contains a {len(token)} character token with a Shannon entropy of "
                        f"{entropy:.2f} bits per character. Natural language and file paths sit near 3.0 bits, "
                        "so this value indicates compressed, encrypted or base64 encoded content being passed "
                        "to an interpreter, which is the standard way to hide a payload from inspection."
                    ),
                    entity=event.entity(),
                    events=[event],
                    metrics={
                        "shannon_entropy": round(entropy, 3),
                        "token_length": len(token),
                        "token_preview": token[:80],
                    },
                    fields={
                        "host.name": event.get_str("host.name"),
                        "user.name": event.get_str("user.name"),
                        "process.command_line": command[:400],
                    },
                    severity="high" if entropy >= 4.4 else "medium",
                    confidence="medium",
                )
            )
            if len(findings) >= 20:
                return findings
    return findings


# ---------------------------------------------------------------------------
# 4. Long tail stacking of rare values
# ---------------------------------------------------------------------------


def _rarity_findings(context, rule: StatisticalRule, field_name: str, label: str,
                     min_population: int = MIN_POPULATION, max_share: float = 0.05) -> list[Finding]:
    counter: Counter = Counter()
    samples: dict[str, Event] = {}
    for event in context.events:
        value = event.get_str(field_name)
        if not value:
            continue
        value = value.strip().lower()[:200]
        counter[value] += 1
        samples.setdefault(value, event)
    total = sum(counter.values())
    if total < min_population or len(counter) < 5:
        return []
    findings: list[Finding] = []
    rare = [(value, count) for value, count in counter.items() if count / total <= max_share and count <= 3]
    rare.sort(key=lambda item: item[1])
    for value, count in rare[:15]:
        event = samples[value]
        findings.append(
            _finding(
                rule,
                title=f"Rare {label} observed: {value[:80]}",
                description=(
                    f"The value appears {count} time(s) out of {total} records, a frequency of "
                    f"{count / total:.4%}. Long tail stacking works because attacker tooling is unique to the "
                    f"intrusion while normal {label} values repeat constantly across an estate. Rarity alone is "
                    "not proof of malice, so the value should be validated against the environment baseline."
                ),
                entity=value[:120],
                events=[event],
                metrics={
                    "occurrences": count,
                    "population": total,
                    "frequency": round(count / total, 6),
                    "distinct_values": len(counter),
                },
                fields={field_name: value[:200], "host.name": event.get_str("host.name")},
            )
        )
    return findings


def analyse_rare_processes(context, rule: StatisticalRule) -> list[Finding]:
    findings = _rarity_findings(context, rule, "process.executable", "process image")
    if not findings:
        findings = _rarity_findings(context, rule, "process.name", "process name")
    return findings


def analyse_rare_user_agents(context, rule: StatisticalRule) -> list[Finding]:
    return _rarity_findings(context, rule, "user_agent.original", "user agent", max_share=0.05)


def analyse_rare_parent_child(context, rule: StatisticalRule) -> list[Finding]:
    counter: Counter = Counter()
    samples: dict[str, Event] = {}
    for event in context.events:
        parent = event.get_str("process.parent.name")
        child = event.get_str("process.name")
        if not parent or not child:
            continue
        key = f"{parent.lower()} -> {child.lower()}"
        counter[key] += 1
        samples.setdefault(key, event)
    total = sum(counter.values())
    if total < MIN_POPULATION or len(counter) < 5:
        return []
    findings: list[Finding] = []
    for key, count in sorted(counter.items(), key=lambda item: item[1]):
        if count > 2 or count / total > 0.01:
            continue
        event = samples[key]
        findings.append(
            _finding(
                rule,
                title=f"Rare process lineage: {key}",
                description=(
                    f"The parent to child relationship {key} occurs {count} time(s) in {total} process events. "
                    "Software behaves consistently, so an execution chain that appears once in an entire data "
                    "set deserves review even when every binary involved is signed."
                ),
                entity=key,
                events=[event],
                metrics={"occurrences": count, "population": total, "distinct_chains": len(counter)},
                fields={
                    "process.parent.name": event.get_str("process.parent.name"),
                    "process.name": event.get_str("process.name"),
                    "process.command_line": event.get_str("process.command_line")[:300],
                    "host.name": event.get_str("host.name"),
                },
            )
        )
        if len(findings) >= 15:
            break
    return findings


# ---------------------------------------------------------------------------
# 5. Volumetric outliers
# ---------------------------------------------------------------------------


def analyse_volume_outliers(context, rule: StatisticalRule) -> list[Finding]:
    """Compare each entity against its own peer group, never across groups.

    Accounts, source addresses and hosts generate very different volumes, so
    mixing them in one distribution manufactures outliers. Each field is scored
    against its own population.
    """
    findings: list[Finding] = []
    for field_name, label in (
        ("user.name", "account"),
        ("source.ip", "source address"),
        ("host.name", "host"),
    ):
        counter: Counter = Counter()
        samples: dict[str, Event] = {}
        for event in context.events:
            value = event.get_str(field_name)
            if not value:
                continue
            counter[value] += 1
            samples.setdefault(value, event)
        if len(counter) < 8:
            continue
        entities = list(counter.keys())
        values = [float(counter[entity]) for entity in entities]
        scores = modified_zscores(values)
        median = percentile(values, 50)
        for entity, value, score in sorted(zip(entities, values, scores), key=lambda item: -item[2]):
            if score < 6.0 or value < median * 3 or value < 20:
                continue
            event = samples[entity]
            findings.append(
                _finding(
                    rule,
                    title=f"Volumetric outlier: the {label} {entity} generated {int(value)} events",
                    description=(
                        f"{entity} produced {int(value)} records while the median {label} in this data set "
                        f"produced {int(median)}. The median absolute deviation z score is {score:.1f}, far "
                        "beyond the value of 3.5 normally treated as an outlier. Sudden volume changes "
                        "accompany automated tooling, data collection and brute force activity."
                    ),
                    entity=entity,
                    events=[event],
                    metrics={
                        "peer_group": label,
                        "event_count": int(value),
                        "modified_zscore": round(score, 2),
                        "population_median": median,
                        "population_p95": percentile(values, 95),
                        "entities_compared": len(entities),
                    },
                    fields={"entity": entity, "field": field_name},
                    severity="medium" if score < 12 else "high",
                )
            )
            if len(findings) >= 12:
                return findings
    return findings


# ---------------------------------------------------------------------------
# 6. Off hours activity
# ---------------------------------------------------------------------------


def analyse_off_hours(context, rule: StatisticalRule) -> list[Finding]:
    per_user: dict[str, list[Event]] = defaultdict(list)
    for event in context.events:
        if event.timestamp is None:
            continue
        user = event.get_str("user.name")
        if not user or user.endswith("$"):
            continue
        per_user[user].append(event)
    findings: list[Finding] = []
    for user, events in per_user.items():
        if len(events) < 10:
            continue
        off_hours = []
        for event in events:
            moment = datetime.fromtimestamp(event.timestamp or 0, tz=timezone.utc)
            if moment.hour < 6 or moment.hour >= 20 or moment.weekday() >= 5:
                off_hours.append(event)
        ratio = len(off_hours) / len(events)
        if len(off_hours) < 5 or ratio < 0.6:
            continue
        hours = Counter(datetime.fromtimestamp(e.timestamp or 0, tz=timezone.utc).hour for e in off_hours)
        findings.append(
            _finding(
                rule,
                title=f"Activity concentrated outside business hours for {user}",
                description=(
                    f"{len(off_hours)} of {len(events)} records for {user} fall outside 06:00 to 20:00 UTC or "
                    f"land on a weekend, a share of {ratio:.0%}. Attackers frequently operate in the target "
                    "night window to reduce the chance of a user noticing, so a strong shift in the activity "
                    "profile of an account is worth confirming with its owner."
                ),
                entity=user,
                events=sorted(off_hours, key=lambda e: e.timestamp or 0)[:6],
                metrics={
                    "off_hours_events": len(off_hours),
                    "total_events": len(events),
                    "off_hours_ratio": round(ratio, 3),
                    "busiest_hours_utc": [hour for hour, _ in hours.most_common(3)],
                },
                fields={"user.name": user},
            )
        )
        if len(findings) >= 12:
            break
    return findings


# ---------------------------------------------------------------------------
# 7. Benford's law on transferred volumes
# ---------------------------------------------------------------------------


def analyse_benford(context, rule: StatisticalRule) -> list[Finding]:
    values: list[float] = []
    events: list[Event] = []
    for event in context.events:
        for name in ("network.bytes_out", "network.bytes", "http.response.bytes"):
            value = event.get_float(name)
            if value and value >= 10:
                values.append(value)
                events.append(event)
                break
    if len(values) < 200:
        return []
    result = benford_chi_square(values)
    if result["chi_square"] <= 40.0:
        return []
    return [
        _finding(
            rule,
            title="Transfer volume distribution deviates from Benford's law",
            description=(
                f"The leading digits of {int(result['sample_size'])} transfer sizes give a chi square statistic "
                f"of {result['chi_square']} against the Benford distribution, well above the 20.09 critical "
                "value at the one percent level, with a maximum digit deviation of "
                f"{result['deviation']:.3f}. Naturally occurring transfer volumes follow Benford closely, so a "
                "strong deviation suggests fixed size chunking, which is how staged exfiltration and beacon "
                "check in traffic look."
            ),
            entity="network transfer volumes",
            events=events[:6],
            metrics=result,
            fields={"samples": int(result["sample_size"])},
        )
    ]


# ---------------------------------------------------------------------------
# 8. Rare external destinations and concentration
# ---------------------------------------------------------------------------


def analyse_destination_concentration(context, rule: StatisticalRule) -> list[Finding]:
    per_destination: Counter = Counter()
    bytes_per_destination: Counter = Counter()
    samples: dict[str, Event] = {}
    for event in context.events:
        destination = event.get_str("destination.domain") or event.get_str("destination.ip")
        if not destination:
            continue
        volume = event.get_float("network.bytes_out") or event.get_float("network.bytes") or 0.0
        per_destination[destination] += 1
        bytes_per_destination[destination] += volume
        samples.setdefault(destination, event)
    if len(per_destination) < 10:
        return []
    volumes = [float(value) for value in bytes_per_destination.values() if value > 0]
    if len(volumes) < 10:
        return []
    gini = gini_coefficient(volumes)
    if gini < 0.8:
        return []
    top_destination, top_volume = bytes_per_destination.most_common(1)[0]
    total = sum(bytes_per_destination.values()) or 1.0
    share = top_volume / total
    if share < 0.5:
        return []
    event = samples[top_destination]
    return [
        _finding(
            rule,
            title=f"Egress volume concentrated on a single destination: {top_destination}",
            description=(
                f"{top_destination} received {share:.0%} of all outbound bytes in the data set across "
                f"{per_destination[top_destination]} sessions. The Gini coefficient of the destination volume "
                f"distribution is {gini}, which indicates extreme concentration rather than the broad spread "
                "expected from normal browsing and application traffic."
            ),
            entity=top_destination,
            events=[event],
            metrics={
                "gini_coefficient": gini,
                "top_destination_share": round(share, 4),
                "bytes_to_destination": int(top_volume),
                "sessions": per_destination[top_destination],
                "distinct_destinations": len(per_destination),
            },
            fields={"destination": top_destination},
        )
    ]


# ---------------------------------------------------------------------------
# 9. Authentication spread
# ---------------------------------------------------------------------------


def analyse_authentication_spread(context, rule: StatisticalRule) -> list[Finding]:
    per_user: dict[str, set[str]] = defaultdict(set)
    samples: dict[str, Event] = {}
    for event in context.events:
        category = event.get_str("event.category")
        action = event.get_str("event.action")
        if "auth" not in category and "logon" not in action and "login" not in action:
            continue
        user = event.get_str("user.name")
        host = event.get_str("host.name") or event.get_str("destination.ip")
        if not user or not host or user.endswith("$"):
            continue
        per_user[user].add(host)
        samples.setdefault(user, event)
    if len(per_user) < 4:
        return []
    counts = [float(len(hosts)) for hosts in per_user.values()]
    scores = modified_zscores(counts)
    findings: list[Finding] = []
    for (user, hosts), score in sorted(zip(per_user.items(), scores), key=lambda item: -item[1]):
        if len(hosts) < 5 or score < 3.5:
            continue
        findings.append(
            _finding(
                rule,
                title=f"Account {user} authenticated to an unusual number of systems",
                description=(
                    f"{user} authenticated to {len(hosts)} distinct systems while the median account in this "
                    f"data set reached {int(percentile(counts, 50))}. The modified z score of {score:.1f} places "
                    "the account well outside the normal population. Broad authentication spread is the "
                    "clearest behavioural signal of credential misuse during lateral movement."
                ),
                entity=user,
                events=[samples[user]],
                metrics={
                    "distinct_systems": len(hosts),
                    "modified_zscore": round(score, 2),
                    "population_median": percentile(counts, 50),
                    "systems": sorted(hosts)[:20],
                },
                fields={"user.name": user},
                severity="high",
            )
        )
        if len(findings) >= 10:
            break
    return findings


# ---------------------------------------------------------------------------
# 10. Burst detection on the event time series
# ---------------------------------------------------------------------------


def analyse_activity_bursts(context, rule: StatisticalRule) -> list[Finding]:
    stamps = sorted(event.timestamp for event in context.events if event.timestamp)
    if len(stamps) < 120:
        return []
    span = stamps[-1] - stamps[0]
    if span < 3600:
        return []
    bin_seconds = max(60.0, span / 240.0)
    buckets: Counter = Counter()
    for stamp in stamps:
        buckets[int((stamp - stamps[0]) // bin_seconds)] += 1
    series = [float(buckets.get(index, 0)) for index in range(int(span // bin_seconds) + 1)]
    if len(series) < 20:
        return []
    scores = modified_zscores(series)
    peaks = [(index, series[index], scores[index]) for index in range(len(series)) if scores[index] >= 8.0 and series[index] >= 20]
    if not peaks:
        return []
    peaks.sort(key=lambda item: -item[2])
    findings: list[Finding] = []
    for index, count, score in peaks[:6]:
        window_start = stamps[0] + index * bin_seconds
        window_end = window_start + bin_seconds
        window_events = [event for event in context.events
                         if event.timestamp and window_start <= event.timestamp < window_end][:6]
        moment = datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat()
        findings.append(
            _finding(
                rule,
                title=f"Activity burst at {moment}",
                description=(
                    f"{int(count)} records fall inside a {int(bin_seconds)} second window starting at {moment}, "
                    f"a modified z score of {score:.1f} against the rest of the timeline. Sharp bursts mark "
                    "automated activity such as scanning, mass file access or scripted account operations."
                ),
                entity=moment,
                events=window_events,
                metrics={
                    "events_in_window": int(count),
                    "window_seconds": int(bin_seconds),
                    "modified_zscore": round(score, 2),
                    "timeline_bins": len(series),
                },
                fields={"window_start_utc": moment},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 11. High entropy file and URL paths
# ---------------------------------------------------------------------------


def analyse_random_names(context, rule: StatisticalRule) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for event in context.events:
        for field_name in ("file.name", "url.path", "process.name"):
            value = event.get_str(field_name)
            if not value:
                continue
            stem = value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            stem = stem.split(".")[0]
            if len(stem) < 10 or stem.lower() in seen:
                continue
            entropy = shannon_entropy(stem)
            score = dga_score(stem)
            if entropy < 3.6 or score < 0.6:
                continue
            seen.add(stem.lower())
            findings.append(
                _finding(
                    rule,
                    title=f"Randomly generated name observed: {stem[:60]}",
                    description=(
                        f"The name {stem[:60]} has a Shannon entropy of {entropy:.2f} bits per character and a "
                        f"randomness score of {score}. Droppers and ransomware generate names at runtime so that "
                        "static indicators cannot be shared between victims, which produces exactly this profile."
                    ),
                    entity=stem[:80],
                    events=[event],
                    metrics={"shannon_entropy": round(entropy, 3), "randomness_score": score, "length": len(stem)},
                    fields={field_name: value[:200], "host.name": event.get_str("host.name")},
                )
            )
            if len(findings) >= 15:
                return findings
    return findings


# ---------------------------------------------------------------------------
# rule declarations
# ---------------------------------------------------------------------------

RULES = [
    statistical_rule(
        "stat-beaconing-fft",
        "Periodic beaconing detected by spectral analysis",
        "Fourier analysis of connection timestamps that identifies constant interval command and control channels.",
        analyse=analyse_beaconing,
        severity="high",
        confidence="high",
        category="command_and_control",
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol",
        mitre_technique_id="T1071",
        risk="A machine driven check in interval indicates that software on the host is under external control "
             "and is waiting for instructions.",
        impact="Command and control access allows the operator to deploy further tooling, harvest credentials "
               "and stage data theft at a time of their choosing.",
        recommendation="Identify the process that owns the connection on the source host, block the destination and "
                       "isolate the endpoint for analysis. Baseline outbound destinations per host and alert on new "
                       "regular interval channels.",
        references=("https://attack.mitre.org/techniques/T1071/",),
    ),
    statistical_rule(
        "stat-dga-entropy",
        "Domain generation algorithm candidate",
        "Shannon entropy and linguistic scoring of DNS labels to identify algorithmically generated domains.",
        analyse=analyse_dga,
        severity="high",
        confidence="medium",
        category="command_and_control",
        mitre_tactic="Command and Control",
        mitre_technique="Dynamic Resolution: Domain Generation Algorithms",
        mitre_technique_id="T1568.002",
        risk="Generated domains give malware a resilient rendezvous mechanism that survives the takedown of "
             "individual servers.",
        impact="The infected host retains a route back to the operator even after known infrastructure is "
               "blocked, extending the intrusion.",
        recommendation="Resolve and reputation check the domains, block the algorithm seed domains at the resolver and "
                       "investigate the querying host for malware. Deploy protective DNS with algorithmic scoring.",
        references=("https://attack.mitre.org/techniques/T1568/002/",),
    ),
    statistical_rule(
        "stat-command-entropy",
        "High entropy encoded content in command execution",
        "Shannon entropy measurement of command line tokens to reveal encoded or encrypted payloads.",
        analyse=analyse_command_entropy,
        severity="high",
        confidence="medium",
        category="execution",
        mitre_tactic="Defense Evasion",
        mitre_technique="Obfuscated Files or Information",
        mitre_technique_id="T1027",
        risk="Encoded command content is used specifically to prevent inspection by humans and by signature "
             "based tooling.",
        impact="The obfuscated payload usually loads a second stage in memory, giving the attacker execution "
               "without writing a detectable file to disk.",
        recommendation="Decode the token to establish what was executed, then hunt for the same payload across the "
                       "estate. Enable script block logging so decoded content is recorded, and restrict interpreter "
                       "use for standard users.",
        references=("https://attack.mitre.org/techniques/T1027/",),
    ),
    statistical_rule(
        "stat-rare-process",
        "Rare process image in the data set",
        "Long tail frequency stacking of process images to surface tooling unique to the intrusion.",
        analyse=analyse_rare_processes,
        severity="medium",
        confidence="low",
        category="discovery",
        mitre_tactic="Execution",
        mitre_technique="Frequency analysis",
        mitre_technique_id="T1059",
        risk="Attacker tooling is by definition uncommon in an estate where standard software runs everywhere, "
             "so rarity is a reliable first filter.",
        impact="A single unrecognised binary can be the loader for the whole intrusion, so unexplained rare "
               "executions deserve confirmation.",
        recommendation="Validate each rare image against the software inventory, check its signature and hash, and "
                       "remove anything unapproved. Maintain an application inventory so rarity can be judged against "
                       "a real baseline.",
        references=("https://attack.mitre.org/",),
    ),
    statistical_rule(
        "stat-rare-user-agent",
        "Rare HTTP user agent",
        "Frequency analysis of user agent strings to identify custom clients and tooling.",
        analyse=analyse_rare_user_agents,
        severity="medium",
        confidence="low",
        category="command_and_control",
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol: Web Protocols",
        mitre_technique_id="T1071.001",
        risk="Custom implants often present a user agent that appears only once in a data set full of "
             "standard browser strings.",
        impact="An unrecognised client communicating outbound may be an implant channel that bypasses proxy "
               "category controls.",
        recommendation="Correlate the user agent with the destination and the requesting host, then block confirmed "
                       "malicious clients at the proxy. Alert on user agents that appear on a single host only.",
        references=("https://attack.mitre.org/techniques/T1071/001/",),
    ),
    statistical_rule(
        "stat-rare-lineage",
        "Rare parent and child process relationship",
        "Stacking of process lineage pairs to reveal execution chains that occur only once.",
        analyse=analyse_rare_parent_child,
        severity="medium",
        confidence="low",
        category="execution",
        mitre_tactic="Execution",
        mitre_technique="Frequency analysis",
        mitre_technique_id="T1059",
        risk="Software behaves consistently, so a lineage that appears once in a large data set is either a "
             "rare administrative action or attacker activity.",
        impact="Unusual lineage frequently reveals macro execution, exploitation of a service or injection into "
               "a trusted process.",
        recommendation="Review the full command line for each rare chain and confirm it against expected "
                       "administration. Build a lineage baseline per system role to make this signal precise.",
        references=("https://attack.mitre.org/",),
    ),
    statistical_rule(
        "stat-volume-outlier",
        "Volumetric outlier entity",
        "Median absolute deviation z scores over per entity event counts.",
        analyse=analyse_volume_outliers,
        severity="medium",
        confidence="medium",
        category="anomaly",
        mitre_tactic="Discovery",
        mitre_technique="Statistical outlier",
        mitre_technique_id="T1078",
        risk="A user or address generating far more activity than its peers is usually running automation, "
             "which may be attacker tooling.",
        impact="Automated activity at scale accompanies brute force, enumeration and mass data collection.",
        recommendation="Establish whether the entity is a service account or scanner, and if not investigate the "
                       "session in detail. Baseline expected volumes per account type and alert on deviation.",
        references=("https://attack.mitre.org/",),
    ),
    statistical_rule(
        "stat-off-hours",
        "Account activity concentrated outside business hours",
        "Temporal profiling of per account activity against a standard working window.",
        analyse=analyse_off_hours,
        severity="medium",
        confidence="low",
        category="anomaly",
        mitre_tactic="Defense Evasion",
        mitre_technique="Valid Accounts",
        mitre_technique_id="T1078",
        risk="Operators work in the victim night window to reduce the chance of a user noticing session "
             "activity on their account.",
        impact="Credential misuse can continue for days when it happens outside the hours that anyone is "
               "watching.",
        recommendation="Confirm the activity with the account owner and their manager, and review what the session "
                       "accessed. Apply conditional access policies with time and location awareness for sensitive "
                       "roles.",
        references=("https://attack.mitre.org/techniques/T1078/",),
    ),
    statistical_rule(
        "stat-benford",
        "Transfer size distribution deviates from Benford's law",
        "Chi square test of leading digit frequencies against the Benford distribution.",
        analyse=analyse_benford,
        severity="medium",
        confidence="low",
        category="exfiltration",
        mitre_tactic="Exfiltration",
        mitre_technique="Data Transfer Size Limits",
        mitre_technique_id="T1030",
        risk="Fixed size chunking of transfers, which breaks the natural Benford distribution, is used to keep "
             "exfiltration below volume based alert thresholds.",
        impact="Data can leave the environment steadily without triggering any single large transfer alert.",
        recommendation="Examine the destinations receiving the uniform transfer sizes and correlate with the "
                       "originating process. Alert on repeated identical transfer sizes to external destinations.",
        references=("https://attack.mitre.org/techniques/T1030/",),
    ),
    statistical_rule(
        "stat-egress-concentration",
        "Outbound volume concentrated on one destination",
        "Gini coefficient analysis of outbound byte distribution across destinations.",
        analyse=analyse_destination_concentration,
        severity="medium",
        confidence="medium",
        category="exfiltration",
        mitre_tactic="Exfiltration",
        mitre_technique="Exfiltration Over C2 Channel",
        mitre_technique_id="T1041",
        risk="When most egress bytes go to one external destination, that destination is either a sanctioned "
             "service or an exfiltration endpoint.",
        impact="Bulk transfer to an unapproved destination means the data is already outside organisational "
               "control.",
        recommendation="Identify the destination owner and the internal sources, and block it if it is not a "
                       "sanctioned service. Baseline egress by destination and alert on new high volume "
                       "relationships.",
        references=("https://attack.mitre.org/techniques/T1041/",),
    ),
    statistical_rule(
        "stat-auth-spread",
        "Account authenticated to an unusual number of systems",
        "Modified z score analysis of the number of distinct systems reached per account.",
        analyse=analyse_authentication_spread,
        severity="high",
        confidence="medium",
        category="lateral_movement",
        mitre_tactic="Lateral Movement",
        mitre_technique="Valid Accounts",
        mitre_technique_id="T1078",
        risk="Credential theft shows itself as an account suddenly touching far more systems than it ever has "
             "before.",
        impact="Broad authentication spread precedes domain wide deployment of ransomware or mass data "
               "collection.",
        recommendation="Reset the account, revoke its sessions and review every system it reached. Enforce tiered "
                       "administration so no single account can authenticate across all zones.",
        references=("https://attack.mitre.org/techniques/T1078/",),
    ),
    statistical_rule(
        "stat-activity-burst",
        "Sharp burst in event volume",
        "Time series binning with robust z scores to locate abnormal spikes in activity.",
        analyse=analyse_activity_bursts,
        severity="medium",
        confidence="medium",
        category="anomaly",
        mitre_tactic="Discovery",
        mitre_technique="Statistical outlier",
        mitre_technique_id="T1046",
        risk="Bursts mark the moments when automation ran, which are the highest value windows to examine in "
             "a large data set.",
        impact="Scanning, mass file access and scripted account changes all produce this signature and all "
               "precede material impact.",
        recommendation="Review the records inside each burst window in detail and identify the responsible process or "
                       "account. Use the burst timestamps as pivots for the wider investigation timeline.",
        references=("https://attack.mitre.org/",),
    ),
    statistical_rule(
        "stat-random-names",
        "Randomly generated file or path name",
        "Entropy and linguistic scoring of file, process and URL names.",
        analyse=analyse_random_names,
        severity="medium",
        confidence="low",
        category="defense_evasion",
        mitre_tactic="Defense Evasion",
        mitre_technique="Masquerading",
        mitre_technique_id="T1036",
        risk="Runtime generated names prevent defenders from sharing simple file name indicators between "
             "victims and across an estate.",
        impact="Malicious files blend into temporary directories where random names are common, delaying "
               "discovery.",
        recommendation="Retrieve and analyse the named artefacts, and check whether the same pattern appears on other "
                       "systems. Alert on execution of randomly named binaries from user writable directories.",
        references=("https://attack.mitre.org/techniques/T1036/",),
    ),
]
