"""Network, DNS, command and control and exfiltration detections."""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

NET_SOURCES = ("network_flow", "dns", "security_appliance", "ids", "tls", "generic", "structured", "syslog", "web")

SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".club", ".online", ".site", ".icu", ".cyou", ".monster", ".pw",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".su", ".ru", ".cc", ".zip", ".mov", ".rest", ".buzz",
)

RULES = [
    pattern_rule(
        "net-dns-tunnelling-indicator",
        "Possible DNS tunnelling to {dns.question.name}",
        "A DNS query used an unusually long label or a TXT and NULL record type against a rarely seen "
        "domain, which is how data is smuggled inside DNS.",
        all_of=[C("dns.question.name", "exists", None)],
        any_of=[
            C("dns.question.name", "any_regex", [r"[a-z0-9+/=_-]{45,}\.", r"(?:[a-f0-9]{20,}\.){2,}"]),
            C("dns.question.type", "in", ["TXT", "NULL", "CNAME", "16", "10"]),
        ],
        keywords=(),
        group_by=("destination.domain",),
        severity="high",
        confidence="low",
        category="exfiltration",
        data_sources=("dns", "network_flow", "structured", "generic"),
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol: DNS",
        mitre_technique_id="T1071.004",
        risk="DNS is almost never blocked or inspected, so it is an ideal covert channel for command and "
             "control traffic and data theft.",
        impact="Sensitive data can leave the network slowly and invisibly, and the same channel gives the "
               "attacker durable remote control of internal hosts.",
        recommendation="Inspect the full query stream for the domain, block the parent domain at the resolver and "
                       "force all clients through logging resolvers. Alert on high query volumes, long labels and "
                       "unusual record types per host.",
        references=("https://attack.mitre.org/techniques/T1071/004/",),
        detail_fields=("source.ip", "dns.question.name", "dns.question.type", "host.name"),
    ),
    threshold_rule(
        "net-dns-query-volume",
        "Excessive DNS query volume from {source.ip}",
        "{count} DNS queries were issued by one host in the window, far above normal client behaviour and "
        "consistent with tunnelling or a domain generation algorithm.",
        all_of=[C("dns.question.name", "exists", None)],
        group_by=("source.ip",),
        distinct_field="dns.question.name",
        min_count=150,
        window_seconds=600,
        keywords=(),
        severity="medium",
        confidence="medium",
        category="command_and_control",
        data_sources=("dns", "network_flow", "structured"),
        mitre_tactic="Command and Control",
        mitre_technique="Dynamic Resolution: Domain Generation Algorithms",
        mitre_technique_id="T1568.002",
        risk="A host generating hundreds of distinct domains is either running malware with a domain "
             "generation algorithm or is being used as a tunnelling endpoint.",
        impact="The affected host is very likely infected and under external control, which places every "
               "credential and file it can reach at risk.",
        recommendation="Isolate the host and inspect it for malware, then block the queried domains at the resolver. "
                       "Deploy protective DNS with algorithmic domain detection and alert on per host query volume.",
        references=("https://attack.mitre.org/techniques/T1568/002/",),
    ),
    pattern_rule(
        "net-suspicious-tld",
        "Connection to a high risk top level domain",
        "Traffic was observed to a domain in a top level domain that is disproportionately used for "
        "malicious infrastructure because registration is cheap and anonymous.",
        any_of=[
            C("destination.domain", "any_regex", [r"\.(?:xyz|top|club|online|site|icu|cyou|monster|pw|tk|ml|ga|cf|gq|su|zip|mov|rest|buzz)$"]),
            C("dns.question.name", "any_regex", [r"\.(?:xyz|top|club|online|site|icu|cyou|monster|pw|tk|ml|ga|cf|gq|su|zip|mov|rest|buzz)$"]),
        ],
        keywords=SUSPICIOUS_TLDS,
        group_by=("destination.domain",),
        severity="low",
        confidence="low",
        category="command_and_control",
        data_sources=NET_SOURCES,
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol",
        mitre_technique_id="T1071",
        risk="Low cost top level domains host a large share of phishing and malware command and control "
             "infrastructure.",
        impact="On its own the traffic may be benign, but combined with beaconing or download activity it points "
               "to an active infection.",
        recommendation="Review the reputation of each domain, correlate with the process that made the request and "
                       "block confirmed malicious destinations. Consider blocking unused high risk top level domains "
                       "at the resolver.",
        references=("https://attack.mitre.org/techniques/T1071/",),
        detail_fields=("source.ip", "destination.domain", "dns.question.name", "url.original"),
        max_findings=15,
    ),
    pattern_rule(
        "net-non-standard-port-web",
        "Web protocol on a non standard port to {destination.ip}",
        "An outbound session used a port commonly chosen by command and control frameworks rather than "
        "the standard web ports.",
        all_of=[
            C("destination.port", "in", ["4444", "4443", "8443", "8080", "8888", "9001", "1337", "31337",
                                          "5555", "6666", "7777", "9999", "50050", "2222", "10443"]),
        ],
        any_of=[C("destination.ip", "public_ip", None)],
        keywords=(),
        group_by=("destination.ip", "destination.port"),
        severity="medium",
        confidence="low",
        category="command_and_control",
        data_sources=("network_flow", "security_appliance", "structured", "ids"),
        mitre_tactic="Command and Control",
        mitre_technique="Non-Standard Port",
        mitre_technique_id="T1571",
        risk="Command and control frameworks default to these ports, and legitimate business traffic rarely "
             "uses them outbound to the internet.",
        impact="An established channel on an unusual port allows continuous remote control and staged data theft "
               "with little chance of inspection.",
        recommendation="Identify the internal process owning the connection, block the destination and restrict "
                       "outbound traffic to an approved port and proxy list. Investigate the source host for an "
                       "implant.",
        references=("https://attack.mitre.org/techniques/T1571/",),
        detail_fields=("source.ip", "destination.ip", "destination.port", "network.protocol"),
        max_findings=15,
    ),
    pattern_rule(
        "net-cobalt-strike-indicator",
        "Command and control framework artefact observed",
        "Traffic or process data contained an artefact associated with a known offensive framework such "
        "as Cobalt Strike, Sliver, Metasploit or Havoc.",
        any_of=[
            C("_text", "any_contains", [
                "/submit.php?id=", "jquery-3.3.1.min.js?", "/pixel.gif?", "/updates.rss",
                "beacon.dll", "artifact.exe", "malleable", "cobaltstrike", "teamserver",
                "meterpreter", "metasploit", "sliver-client", "havoc", "brc4", "bruteratel",
                "/msadc/", "stager", "rundll32.exe amsi.dll",
            ]),
            C("tls.ja3", "in", [
                "72a589da586844d7f0818ce684948eea", "a0e9f5d64349fb13191bc781f81f42e1",
                "6734f37431670b3ab4292b8f60f29984",
            ]),
        ],
        keywords=("cobaltstrike", "teamserver", "meterpreter", "metasploit", "sliver", "havoc",
                  "bruteratel", "beacon.dll", "/submit.php?id=", "malleable", "/pixel.gif?", "/updates.rss"),
        group_by=("destination.ip", "host.name"),
        severity="critical",
        confidence="medium",
        category="command_and_control",
        data_sources=NET_SOURCES + ("windows_event", "sysmon"),
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol: Web Protocols",
        mitre_technique_id="T1071.001",
        risk="Presence of a commercial or open source command and control framework indicates a capable, "
             "hands on adversary rather than commodity malware.",
        impact="These frameworks provide credential theft, lateral movement and file transfer in one package, so "
               "the intrusion is likely to progress quickly to domain compromise.",
        recommendation="Contain the affected hosts, block the command and control infrastructure and hunt for the same "
                       "indicators across the estate. Assume credential compromise on every host that the beacon "
                       "touched and rebuild rather than clean.",
        references=("https://attack.mitre.org/techniques/T1071/001/",),
        detail_fields=("host.name", "source.ip", "destination.ip", "url.original", "process.command_line"),
    ),
    pattern_rule(
        "net-tor-or-anonymiser",
        "Traffic to an anonymising service",
        "A connection was made to Tor, a public VPN or an anonymising proxy, which attackers use to hide "
        "the true source or destination of their traffic.",
        any_of=[
            C("_text", "any_regex", [
                r"\.onion\b", r"torproject\.org", r"\btor2web\b", r"\bnordvpn\b", r"\bexpressvpn\b",
                r"\bprotonvpn\b", r"\bmullvad\b", r"\bhide\.?me\b", r"\bpsiphon\b", r"\bultrasurf\b",
                r"\bngrok\.io\b", r"\btrycloudflare\.com\b", r"\blocaltunnel\b", r"\bserveo\.net\b",
                r"\bpagekite\b", r"\btailscale\b",
            ]),
            C("destination.port", "in", ["9001", "9030", "9050", "9150"]),
        ],
        keywords=(".onion", "torproject", "nordvpn", "expressvpn", "protonvpn", "mullvad", "ngrok.io",
                  "trycloudflare.com", "serveo.net", "psiphon", "tailscale", "localtunnel"),
        group_by=("source.ip", "destination.domain"),
        severity="high",
        confidence="medium",
        category="command_and_control",
        data_sources=NET_SOURCES,
        mitre_tactic="Command and Control",
        mitre_technique="Proxy: Multi-hop Proxy",
        mitre_technique_id="T1090.003",
        risk="Anonymising tunnels defeat network monitoring and are frequently used to expose internal services "
             "to the internet or to reach ransomware negotiation infrastructure.",
        impact="An unmanaged inbound tunnel bypasses every perimeter control, and outbound anonymised traffic "
               "prevents attribution and blocking of the real destination.",
        recommendation="Identify the process and user responsible, block the service at the proxy and firewall, and "
                       "confirm no inbound tunnel is exposing internal systems. Treat unauthorised tunnelling software "
                       "as a policy violation and remove it.",
        references=("https://attack.mitre.org/techniques/T1090/003/",),
        detail_fields=("source.ip", "destination.domain", "destination.ip", "destination.port"),
    ),
    pattern_rule(
        "net-cloud-storage-exfiltration",
        "Upload to a public file sharing service",
        "Traffic was observed to a consumer file sharing or paste service, a common route for data theft "
        "because the destination is widely trusted.",
        any_of=[
            C("_text", "any_regex", [
                r"\b(?:mega\.nz|mega\.io|anonfiles|gofile\.io|file\.io|transfer\.sh|wetransfer|sendspace)\b",
                r"\b(?:pastebin\.com|paste\.ee|hastebin|ghostbin|dpaste|privatebin|controlc\.com)\b",
                r"\b(?:temp\.sh|0x0\.st|bashupload|filebin|uguu\.se|catbox\.moe|litterbox)\b",
                r"\bdiscord(?:app)?\.com/api/webhooks\b", r"\bapi\.telegram\.org/bot\b",
            ]),
        ],
        keywords=("mega.nz", "anonfiles", "gofile.io", "file.io", "transfer.sh", "wetransfer", "pastebin.com",
                  "privatebin", "0x0.st", "catbox.moe", "discord.com/api/webhooks", "api.telegram.org", "filebin"),
        group_by=("source.ip", "destination.domain"),
        severity="high",
        confidence="medium",
        category="exfiltration",
        data_sources=NET_SOURCES,
        mitre_tactic="Exfiltration",
        mitre_technique="Exfiltration to Cloud Storage",
        mitre_technique_id="T1567.002",
        risk="Public sharing services provide a fast, encrypted and generally allowed channel for moving stolen "
             "data out of the network.",
        impact="Loss of intellectual property or regulated personal data, with legal notification duties and "
               "extortion leverage for the attacker.",
        recommendation="Determine the volume transferred and the user or process involved, then block the service and "
                       "preserve proxy logs for the investigation. Apply data loss prevention rules and restrict "
                       "uploads to sanctioned services only.",
        references=("https://attack.mitre.org/techniques/T1567/002/",),
        detail_fields=("source.ip", "user.name", "destination.domain", "url.original", "network.bytes_out"),
    ),
    pattern_rule(
        "net-large-outbound-transfer",
        "Large outbound data transfer to {destination.ip}",
        "A single session moved a large volume of data to an external address, which may represent bulk "
        "data theft.",
        any_of=[
            C("network.bytes_out", "gt", 500_000_000),
            C("network.bytes", "gt", 1_000_000_000),
        ],
        keywords=(),
        group_by=("source.ip", "destination.ip"),
        severity="medium",
        confidence="low",
        category="exfiltration",
        data_sources=("network_flow", "security_appliance", "structured"),
        mitre_tactic="Exfiltration",
        mitre_technique="Exfiltration Over C2 Channel",
        mitre_technique_id="T1041",
        risk="High volume outbound transfers to unfamiliar destinations are the clearest network signal of "
             "data theft in progress.",
        impact="Once data has left the network it cannot be recalled, and the organisation carries the "
               "regulatory and contractual consequences.",
        recommendation="Identify the destination owner and the internal source, block the flow if it is not a known "
                       "business transfer and preserve the full session records. Baseline normal egress volume per host "
                       "and alert on deviations.",
        references=("https://attack.mitre.org/techniques/T1041/",),
        detail_fields=("source.ip", "destination.ip", "destination.port", "network.bytes_out", "network.bytes"),
    ),
    threshold_rule(
        "net-port-scan",
        "Port scanning activity from {source.ip}",
        "One source contacted {count} distinct destination ports in the window, which is characteristic "
        "of network reconnaissance.",
        all_of=[C("destination.port", "exists", None)],
        group_by=("source.ip",),
        distinct_field="destination.port",
        min_count=30,
        window_seconds=300,
        keywords=(),
        severity="medium",
        confidence="medium",
        category="discovery",
        data_sources=("network_flow", "security_appliance", "structured", "ids"),
        mitre_tactic="Discovery",
        mitre_technique="Network Service Discovery",
        mitre_technique_id="T1046",
        risk="Scanning identifies live services to attack and, when it originates internally, usually means a "
             "host is already compromised and mapping the network.",
        impact="Reconnaissance shortens the attacker path to a vulnerable service and precedes lateral movement "
               "or exploitation.",
        recommendation="Determine whether the source is an authorised scanner, and if not isolate it and investigate "
                       "for compromise. Segment the network so that workstations cannot reach server management ports "
                       "directly.",
        references=("https://attack.mitre.org/techniques/T1046/",),
    ),
    threshold_rule(
        "net-internal-host-sweep",
        "Internal host sweep from {source.ip}",
        "One internal source contacted {count} distinct internal destinations in the window, which "
        "indicates lateral movement reconnaissance.",
        all_of=[
            C("source.ip", "private_ip", None),
            C("destination.ip", "private_ip", None),
        ],
        group_by=("source.ip",),
        distinct_field="destination.ip",
        min_count=40,
        window_seconds=600,
        keywords=(),
        severity="high",
        confidence="medium",
        category="discovery",
        data_sources=("network_flow", "security_appliance", "structured", "ids"),
        mitre_tactic="Discovery",
        mitre_technique="Remote System Discovery",
        mitre_technique_id="T1018",
        risk="A workstation talking to dozens of internal systems in minutes is behaving like an attacker "
             "mapping the estate, not like a user.",
        impact="Successful mapping is the precursor to targeted lateral movement toward domain controllers, "
               "backup servers and data repositories.",
        recommendation="Isolate the source host and examine it for tooling, then review which destinations accepted "
                       "connections. Enforce east west segmentation and restrict administrative protocols to a "
                       "management tier.",
        references=("https://attack.mitre.org/techniques/T1018/",),
    ),
    pattern_rule(
        "net-smb-external",
        "SMB or RDP traffic crossing the network boundary",
        "File sharing or remote desktop protocols were seen to or from a public address. These protocols "
        "should never traverse the internet directly.",
        all_of=[C("destination.port", "in", ["445", "139", "3389", "5985", "5986"])],
        any_of=[C("destination.ip", "public_ip", None), C("source.ip", "public_ip", None)],
        keywords=(),
        group_by=("source.ip", "destination.ip", "destination.port"),
        severity="high",
        confidence="medium",
        category="lateral_movement",
        data_sources=("network_flow", "security_appliance", "structured", "ids"),
        mitre_tactic="Lateral Movement",
        mitre_technique="Remote Services",
        mitre_technique_id="T1021",
        risk="Exposing SMB or remote desktop to the internet invites credential attacks and exploitation of "
             "protocol vulnerabilities such as EternalBlue and BlueKeep.",
        impact="Direct exposure has repeatedly resulted in domain wide ransomware within hours of a successful "
               "authentication or exploit.",
        recommendation="Block these ports at the perimeter immediately and place remote access behind a VPN or gateway "
                       "with multi factor authentication. Verify the exposed hosts are fully patched and review their "
                       "authentication logs.",
        references=("https://attack.mitre.org/techniques/T1021/",),
        detail_fields=("source.ip", "destination.ip", "destination.port", "network.protocol"),
    ),
    pattern_rule(
        "net-ids-alert",
        "Intrusion detection signature triggered: {rule.name}",
        "A network intrusion detection or prevention system raised a signature for this traffic.",
        any_of=[
            C("rule.name", "exists", None),
            C("event.category", "any_contains", ["intrusion", "exploit", "malware", "trojan", "attack"]),
        ],
        all_of=[C("_data_source", "in", ["ids", "security_appliance"])],
        keywords=(),
        group_by=("rule.name", "source.ip"),
        severity="high",
        confidence="medium",
        category="intrusion_detection",
        data_sources=("ids", "security_appliance"),
        mitre_tactic="Multiple",
        mitre_technique="Network intrusion signature",
        mitre_technique_id="T1071",
        risk="A dedicated detection product identified traffic matching known attack behaviour, which deserves "
             "confirmation rather than dismissal.",
        impact="If the signature reflects a successful exploit, the affected host is compromised and can be used "
               "to reach the rest of the network.",
        recommendation="Validate the alert against the endpoint telemetry for both parties, confirm whether the exploit "
                       "succeeded and patch the targeted service. Tune noisy signatures and ensure alerts of this class "
                       "reach the response team.",
        references=("https://attack.mitre.org/",),
        detail_fields=("rule.name", "source.ip", "destination.ip", "destination.port", "event.severity"),
        max_findings=20,
    ),
]
