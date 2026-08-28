"""Hypothesis catalogue and the data sources each hypothesis consumes.

Three families are offered:

``cti``           scenarios reported by threat intelligence for a named actor or campaign
``technique``     standard hunts built around adversary techniques
``mathematical``  hunts driven by statistics and signal processing rather than signatures
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .rules import RULES_BY_ID, rules_for


@dataclass(frozen=True)
class DataSource:
    id: str
    name: str
    description: str
    formats: tuple[str, ...]
    examples: tuple[str, ...]
    collection_hint: str


DATA_SOURCES: dict[str, DataSource] = {
    source.id: source
    for source in (
        DataSource(
            "windows_security",
            "Windows Security event log",
            "Authentication, account management, privilege use and process creation events from Windows "
            "endpoints and domain controllers.",
            ("EVTX", "EVTX exported to XML", "JSON", "CSV"),
            ("Security.evtx", "security-export.xml", "winlogbeat.json"),
            "Export with wevtutil epl Security C:\\evidence\\Security.evtx or collect the forwarded copy from "
            "the SIEM. Both the binary event log and an XML or JSON export are accepted.",
        ),
        DataSource(
            "sysmon",
            "Sysmon operational log",
            "Process creation with command lines and hashes, network connections, image loads, registry "
            "changes and DNS queries.",
            ("EVTX", "XML", "JSON"),
            ("Microsoft-Windows-Sysmon-Operational.evtx", "sysmon.xml"),
            "Collect Microsoft-Windows-Sysmon/Operational. Sysmon gives the process lineage and command line "
            "detail that the Security log alone does not provide.",
        ),
        DataSource(
            "powershell",
            "PowerShell script block and module logs",
            "Script block logging (event 4104), module logging (4103) and engine lifecycle events.",
            ("EVTX", "XML", "JSON", "TXT"),
            ("Microsoft-Windows-PowerShell-Operational.evtx", "powershell-transcripts.txt"),
            "Enable script block logging by policy, then export the PowerShell operational channel. "
            "Transcripts are also accepted as plain text.",
        ),
        DataSource(
            "linux_auth",
            "Linux authentication and system logs",
            "SSH authentication, sudo use, account creation and service messages from auth.log, secure and "
            "messages.",
            ("Syslog text", "JSON", "journald export"),
            ("auth.log", "secure", "messages", "journal.json"),
            "Collect /var/log/auth.log or /var/log/secure together with /var/log/syslog. journalctl -o json "
            "output is also supported.",
        ),
        DataSource(
            "linux_audit",
            "Linux audit daemon and shell history",
            "Execve records from auditd, command history and cron configuration.",
            ("Audit text", "Key value", "JSON"),
            ("audit.log", "bash_history", "crontab.txt"),
            "Collect /var/log/audit/audit.log and the crontab listings for each account of interest.",
        ),
        DataSource(
            "web_server",
            "Web server access logs",
            "Request lines, status codes, response sizes and user agents from Apache, Nginx or IIS.",
            ("Combined log format", "W3C extended", "JSON", "CSV"),
            ("access.log", "u_ex240311.log", "nginx-access.json"),
            "Collect the access logs for every internet facing virtual host, covering the full period of "
            "interest and including the user agent field.",
        ),
        DataSource(
            "proxy",
            "Web proxy or secure web gateway logs",
            "Outbound web requests with the internal client, destination, bytes transferred and category.",
            ("CSV", "W3C extended", "Key value", "JSON"),
            ("proxy.log", "swg-export.csv"),
            "Export outbound web traffic including bytes sent and received per session so that beaconing and "
            "exfiltration analysis can run.",
        ),
        DataSource(
            "dns",
            "DNS resolver query logs",
            "Client queries with the queried name, record type and answers.",
            ("Zeek TSV", "JSON", "CSV", "Syslog text"),
            ("dns.log", "dnsquery.json", "resolver.csv"),
            "Collect resolver query logs with the client address preserved. Zeek dns.log and Windows DNS "
            "analytical logs both work.",
        ),
        DataSource(
            "network_flow",
            "Firewall, flow or connection records",
            "Session records with source, destination, ports, protocol, byte counts and timestamps.",
            ("Zeek TSV", "CSV", "CEF", "LEEF", "JSON", "NetFlow export"),
            ("conn.log", "firewall.csv", "paloalto-traffic.cef"),
            "Export session records covering both directions with byte counters. Byte counts enable "
            "exfiltration and Benford analysis.",
        ),
        DataSource(
            "ids",
            "Intrusion detection and prevention alerts",
            "Signature alerts with the rule name, severity and the traffic that triggered them.",
            ("EVE JSON", "CEF", "Syslog text", "CSV"),
            ("eve.json", "ids-alerts.cef"),
            "Export alerts for the period of interest with the source and destination preserved.",
        ),
        DataSource(
            "aws_cloudtrail",
            "AWS CloudTrail management events",
            "API calls with the calling identity, source address, region, request parameters and errors.",
            ("JSON", "gzip JSON"),
            ("CloudTrail_us-east-1_20240311.json.gz",),
            "Export the CloudTrail management event history for the account and period of interest. Both the "
            "Records wrapper and one event per line are supported.",
        ),
        DataSource(
            "entra_signin",
            "Entra ID or Azure AD sign in logs",
            "Interactive and non interactive sign ins with risk state, address, device and application.",
            ("JSON", "CSV"),
            ("SignInLogs.json", "signins.csv"),
            "Export sign in logs from the identity portal or the Graph API covering the investigation window.",
        ),
        DataSource(
            "m365_audit",
            "Microsoft 365 unified audit log",
            "Mailbox, SharePoint, Teams and administrative operations across the tenant.",
            ("JSON", "CSV"),
            ("UnifiedAuditLog.csv", "audit.json"),
            "Export the unified audit log with the AuditData column intact so that the operation detail is "
            "preserved.",
        ),
        DataSource(
            "email_gateway",
            "Email security gateway logs",
            "Message metadata, attachment names, verdicts and authentication results.",
            ("CSV", "Key value", "JSON", "CEF"),
            ("message-trace.csv", "gateway.log"),
            "Export the message trace including sender, recipient, subject, attachment name and the "
            "authentication results.",
        ),
        DataSource(
            "edr",
            "Endpoint detection and response telemetry",
            "Process, file, registry and network telemetry exported from the endpoint agent.",
            ("JSON", "CSV", "CEF"),
            ("edr-events.json", "telemetry.csv"),
            "Export raw telemetry rather than only the alerts, so that the engine can apply its own logic to "
            "the underlying events.",
        ),
        DataSource(
            "vpn",
            "VPN and remote access logs",
            "Remote access authentications with the account, source address and session duration.",
            ("Syslog text", "CSV", "CEF", "JSON"),
            ("vpn.log", "remote-access.csv"),
            "Collect authentication and session records for every remote access gateway.",
        ),
        DataSource(
            "k8s_audit",
            "Kubernetes API server audit log",
            "Every request to the cluster API with the calling identity, the verb, the resource and the "
            "response, which is the only complete record of what happened in a cluster.",
            ("JSON", "NDJSON"),
            ("kube-apiserver-audit.log", "audit.json"),
            "Enable the audit policy at Metadata level or above for secrets, pods/exec and RBAC "
            "resources, then export the API server audit log for the period of interest.",
        ),
        DataSource(
            "idp",
            "Identity provider system log",
            "Authentication, multi factor challenges, administrative role grants and API token creation "
            "from the single sign on provider.",
            ("JSON", "CSV"),
            ("okta-system-log.json", "idp-events.csv"),
            "Export the provider system log with the actor, the client address and the outcome reason "
            "preserved, covering the full investigation window.",
        ),
        DataSource(
            "scm",
            "Source control and delivery pipeline audit",
            "Repository, organisation and pipeline events including access grants, exports, visibility "
            "changes and workflow modifications.",
            ("JSON", "CSV"),
            ("github-audit.json", "gitlab-audit.csv"),
            "Export the organisation audit log and the pipeline run history. Include the actor and the "
            "repository for each entry.",
        ),
        DataSource(
            "database",
            "Database engine audit and error log",
            "Authentication results, privilege changes and statements that reach the operating system or "
            "export data in bulk.",
            ("Text", "CSV", "JSON", "XEL export"),
            ("errorlog", "postgresql.log", "mysql-audit.log"),
            "Collect the engine error log together with the audit log if one is configured. Failed "
            "logons and privilege grants matter most.",
        ),
        DataSource(
            "macos_endpoint",
            "macOS endpoint telemetry",
            "Process execution, persistence item creation and security control changes from the unified "
            "log or an endpoint agent.",
            ("JSON", "Text", "CSV"),
            ("unified-log.json", "macos-edr.csv"),
            "Export a predicate filtered unified log covering process execution and file writes, or the "
            "raw telemetry from the endpoint agent.",
        ),
        DataSource(
            "network_device",
            "Network and remote access device logs",
            "Configuration changes, administrative sessions and remote access authentications from "
            "routers, firewalls and VPN concentrators.",
            ("Syslog text", "CEF", "CSV"),
            ("firewall.log", "vpn-gateway.log"),
            "Forward device syslog at informational level or above, including configuration commit and "
            "authentication messages.",
        ),
        DataSource(
            "file_share",
            "File share and object access audit",
            "Access to network shares, file operations and object audit records.",
            ("EVTX", "CSV", "JSON"),
            ("file-audit.csv", "Security-fileaudit.evtx"),
            "Enable object access auditing on the shares that hold sensitive data and export the resulting "
            "records.",
        ),
    )
}


@dataclass(frozen=True)
class Hypothesis:
    id: str
    name: str
    family: str  # cti, technique, mathematical
    summary: str
    narrative: str
    rationale: str
    priority: str  # critical, high, medium
    threat_actors: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()
    required_data_sources: tuple[str, ...] = ()
    optional_data_sources: tuple[str, ...] = ()
    rule_selectors: tuple[str, ...] = ()
    expected_findings: tuple[str, ...] = ()
    method: str = ""

    def rules(self):
        return rules_for(self.rule_selectors)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["required_data_sources"] = [
            {**asdict(DATA_SOURCES[source]), "required": True}
            for source in self.required_data_sources
            if source in DATA_SOURCES
        ]
        payload["optional_data_sources"] = [
            {**asdict(DATA_SOURCES[source]), "required": False}
            for source in self.optional_data_sources
            if source in DATA_SOURCES
        ]
        rules = self.rules()
        payload["rule_count"] = len(rules)
        payload["techniques"] = sorted({rule.mitre_technique_id for rule in rules if rule.mitre_technique_id})
        payload["detection_types"] = sorted({rule.detection_type for rule in rules})
        return payload


HYPOTHESES: tuple[Hypothesis, ...] = (
    # ---------------------------------------------------------------- CTI ---
    Hypothesis(
        id="cti-ransomware-precursor",
        name="Ransomware deployment precursors are present in the estate",
        family="cti",
        summary="Hunt for the preparation steps that reliably precede enterprise ransomware encryption.",
        narrative=(
            "Ransomware affiliates follow a repeatable playbook. After obtaining access they disable endpoint "
            "protection, delete volume shadow copies, harvest credentials, spread through administrative shares "
            "and only then run the encryptor. Each of those steps is far easier to detect than the encryption "
            "itself, and detecting any one of them gives the response team hours rather than minutes."
        ),
        rationale=(
            "If an affiliate is preparing to deploy ransomware in this environment, the evidence will contain "
            "recovery inhibition commands, security tooling tampering, credential access against LSASS and "
            "remote execution across administrative shares."
        ),
        priority="critical",
        threat_actors=("LockBit affiliates", "ALPHV/BlackCat", "Akira", "Play", "Royal/BlackSuit"),
        mitre_tactics=("Impact", "Defense Evasion", "Credential Access", "Lateral Movement"),
        required_data_sources=("windows_security", "sysmon"),
        optional_data_sources=("edr", "powershell", "network_flow", "file_share"),
        rule_selectors=(
            "win-shadow-copy-deletion", "win-defender-tampering", "win-lsass-credential-dump",
            "win-psexec-lateral", "win-service-installed", "win-event-log-cleared",
            "mal-ransomware-note", "mal-mass-file-modification", "mal-vulnerable-driver-load",
            "mal-data-staging-archive", "mal-process-injection", "win-encoded-powershell",
            "win-intrusion-chain", "stat-rare-process", "stat-activity-burst", "stat-auth-spread",
        ),
        expected_findings=(
            "Volume shadow copy deletion or recovery configuration changes",
            "Endpoint protection disabled or exclusions added",
            "Credential dumping against LSASS",
            "Remote service creation consistent with PsExec style movement",
        ),
        method=(
            "Signature and behaviour rules for the ransomware preparation playbook, combined with frequency "
            "stacking to surface unfamiliar tooling and a sequence rule that correlates logon, discovery and "
            "credential access on the same host."
        ),
    ),
    Hypothesis(
        id="cti-cobalt-strike-beacon",
        name="A commercial command and control framework is beaconing from the estate",
        family="cti",
        summary="Detect Cobalt Strike, Sliver, Brute Ratel and similar implants through their traffic profile.",
        narrative=(
            "Offensive frameworks check in to their team server at a configured interval with a jitter "
            "percentage. Even with malleable profiles that imitate legitimate web traffic, the timing "
            "signature survives, because the implant sleeps between calls rather than responding to a human. "
            "Combining spectral analysis of connection timing with framework specific artefacts finds these "
            "channels without needing a signature for the payload itself."
        ),
        rationale=(
            "If an implant is running, connection records will show a small number of internal hosts contacting "
            "one external destination at a near constant interval, often on a non standard port or with a rare "
            "user agent."
        ),
        priority="critical",
        threat_actors=("Ransomware affiliates", "FIN7", "Wizard Spider", "Commodity access brokers"),
        mitre_tactics=("Command and Control", "Defense Evasion"),
        required_data_sources=("network_flow",),
        optional_data_sources=("proxy", "dns", "sysmon", "ids", "edr"),
        rule_selectors=(
            "stat-beaconing-fft", "net-cobalt-strike-indicator", "net-non-standard-port-web",
            "stat-rare-user-agent", "stat-benford", "stat-egress-concentration",
            "net-tor-or-anonymiser", "mal-process-injection", "net-suspicious-tld",
        ),
        expected_findings=(
            "Constant interval sessions between one internal host and one external destination",
            "Framework specific URI or JA3 artefacts",
            "Traffic on ports associated with default framework listeners",
        ),
        method=(
            "Fast Fourier transform of binned connection timestamps plus interval regularity statistics, "
            "supported by framework artefact matching and rarity analysis of client fingerprints."
        ),
    ),
    Hypothesis(
        id="cti-cloud-identity-intrusion",
        name="A state aligned actor is abusing cloud identities for persistent access",
        family="cti",
        summary="Hunt for identity plane persistence in Microsoft 365, Entra ID and AWS.",
        narrative=(
            "Sophisticated actors targeting cloud tenants avoid malware entirely. They obtain a valid "
            "credential, weaken multi factor authentication, add credentials to a service principal or "
            "application, create mailbox rules and then read mail quietly for months. Detection therefore "
            "depends on control plane audit records rather than endpoint telemetry."
        ),
        rationale=(
            "If a cloud identity has been compromised, the audit log will contain authentication method "
            "changes, application consent or service principal credential additions, new inbox rules and sign "
            "ins from anonymising infrastructure."
        ),
        priority="critical",
        threat_actors=("APT29 / Midnight Blizzard", "Storm-0558 style token abuse", "APT41"),
        mitre_tactics=("Initial Access", "Persistence", "Collection", "Defense Evasion"),
        required_data_sources=("m365_audit",),
        optional_data_sources=("entra_signin", "aws_cloudtrail", "proxy"),
        rule_selectors=(
            "cloud-oauth-consent-abuse", "cloud-mfa-weakened", "cloud-mailbox-rule-abuse",
            "cloud-impossible-source", "cloud-iam-privilege-escalation", "cloud-logging-disabled",
            "cloud-root-account-usage", "cloud-api-enumeration", "cloud-failed-console-logins",
            "stat-off-hours", "stat-volume-outlier",
        ),
        expected_findings=(
            "Service principal credentials or application consent granted",
            "Multi factor authentication methods changed for a user",
            "Inbox rules that forward or hide mail",
            "Sign ins from anonymised or unusual infrastructure",
        ),
        method=(
            "Control plane rule matching across identity and collaboration audit logs, combined with temporal "
            "profiling to surface activity outside the account's normal pattern."
        ),
    ),
    Hypothesis(
        id="cti-help-desk-social-engineering",
        name="Help desk social engineering was used to take over privileged accounts",
        family="cti",
        summary="Hunt for the account takeover pattern used by voice phishing and multi factor fatigue actors.",
        narrative=(
            "Groups that specialise in social engineering call the service desk, impersonate an employee and "
            "have the password and multi factor method reset. The technical evidence is a burst of "
            "authentication failures or push approvals, followed by an authentication method change and then a "
            "successful sign in from a new address, often within minutes."
        ),
        rationale=(
            "If this technique was used, the identity logs will show authentication method registration, a "
            "password reset outside the normal help desk pattern and a successful sign in from an unfamiliar "
            "network shortly afterwards."
        ),
        priority="high",
        threat_actors=("Scattered Spider / Octo Tempest", "LAPSUS$ style actors"),
        mitre_tactics=("Initial Access", "Persistence", "Credential Access"),
        required_data_sources=("entra_signin",),
        optional_data_sources=("m365_audit", "vpn", "windows_security"),
        rule_selectors=(
            "cloud-mfa-weakened", "cloud-impossible-source", "cloud-failed-console-logins",
            "win-remote-admin-account-created", "win-rdp-external-source", "cloud-iam-privilege-escalation",
            "stat-off-hours", "stat-auth-spread", "nix-successful-login-after-failures",
        ),
        expected_findings=(
            "Authentication method reset followed by a sign in from a new address",
            "Repeated failed authentications immediately before the reset",
            "Privileged group membership changes shortly after the takeover",
        ),
        method=(
            "Identity control plane rules with temporal correlation between authentication failures, method "
            "changes and successful sign ins."
        ),
    ),
    Hypothesis(
        id="cti-living-off-the-land",
        name="A state actor is operating with built in tooling only",
        family="cti",
        summary="Hunt for hands on keyboard intrusions that never drop a malicious binary.",
        narrative=(
            "Actors focused on long term access in critical infrastructure avoid malware. They use built in "
            "Windows utilities for discovery, credential access through registry hive copies, and remote "
            "desktop or WMI for movement. Detection depends on recognising unusual combinations of otherwise "
            "legitimate commands rather than on file reputation."
        ),
        rationale=(
            "If a living off the land intrusion is present, the process telemetry will contain clusters of "
            "discovery commands, archive staging, hive extraction and remote execution attributed to accounts "
            "that do not normally perform administration."
        ),
        priority="critical",
        threat_actors=("Volt Typhoon", "APT41", "Sandworm"),
        mitre_tactics=("Discovery", "Credential Access", "Lateral Movement", "Defense Evasion"),
        required_data_sources=("sysmon",),
        optional_data_sources=("windows_security", "powershell", "edr", "network_flow"),
        rule_selectors=(
            "win-discovery-commands", "win-lolbin-download", "win-wmi-remote-execution",
            "win-ntds-extraction", "mal-browser-credential-theft", "mal-data-staging-archive",
            "win-event-log-cleared", "win-suspicious-parent-child", "win-intrusion-chain",
            "stat-rare-lineage", "stat-off-hours", "stat-auth-spread", "stat-rare-process",
        ),
        expected_findings=(
            "Clusters of discovery commands from a single session",
            "Registry hive or credential store access",
            "Remote execution through WMI without any dropped binary",
        ),
        method=(
            "Behavioural rules for built in tooling combined with process lineage rarity analysis, which is the "
            "only reliable way to separate administrative use from adversary use."
        ),
    ),
    Hypothesis(
        id="cti-edge-service-exploitation",
        name="An internet facing service was exploited for initial access",
        family="cti",
        summary="Hunt for exploitation of exposed mail, file transfer and application servers.",
        narrative=(
            "Mass exploitation campaigns against edge products follow a consistent shape. A crafted request "
            "reaches an exposed endpoint, the server process spawns a shell, a script file appears in the web "
            "root and the attacker returns through it. The web logs and the process telemetry from the same "
            "server together prove or disprove the hypothesis."
        ),
        rationale=(
            "If an edge service was exploited, the access logs will contain requests to known exploitation "
            "paths and the host telemetry will show the web service process creating unexpected children or "
            "writing script files."
        ),
        priority="critical",
        threat_actors=("Cl0p", "Ransomware affiliates", "State aligned exploitation crews"),
        mitre_tactics=("Initial Access", "Persistence", "Execution"),
        required_data_sources=("web_server",),
        optional_data_sources=("sysmon", "windows_security", "ids", "network_flow"),
        rule_selectors=(
            "web-exchange-proxyshell", "web-log4shell", "web-shell-access", "web-command-injection",
            "web-suspicious-upload", "web-path-traversal", "web-sql-injection", "web-ssrf-attempt",
            "win-suspicious-parent-child", "mal-exploit-attempt-generic", "web-scanner-user-agent",
            "stat-rare-user-agent",
        ),
        expected_findings=(
            "Requests to known vulnerable endpoints returning success codes",
            "Web service process spawning a command interpreter",
            "Script files requested from upload or temporary directories",
        ),
        method=(
            "Request pattern matching against known exploitation chains, correlated with server process "
            "behaviour and rarity analysis of clients."
        ),
    ),
    Hypothesis(
        id="cti-business-email-compromise",
        name="A mailbox is being used for payment fraud",
        family="cti",
        summary="Hunt for the mailbox manipulation that underpins business email compromise.",
        narrative=(
            "Payment fraud through a compromised mailbox depends on the attacker seeing the conversation and "
            "the legitimate owner not seeing the replies. That requires an inbox rule that moves or deletes "
            "mail, or an external forwarding address, both of which are recorded in the audit log."
        ),
        rationale=(
            "If a mailbox is being used for fraud, the audit log will contain new inbox or transport rules, "
            "delegation changes and sign ins that do not match the owner's normal pattern."
        ),
        priority="high",
        threat_actors=("Business email compromise crews", "Storm-1167 style actors"),
        mitre_tactics=("Collection", "Persistence", "Initial Access"),
        required_data_sources=("m365_audit",),
        optional_data_sources=("entra_signin", "email_gateway"),
        rule_selectors=(
            "cloud-mailbox-rule-abuse", "cloud-impossible-source", "cloud-mfa-weakened",
            "cloud-failed-console-logins", "mal-phishing-indicator", "stat-off-hours",
        ),
        expected_findings=(
            "Inbox rules that delete or forward mail to an external address",
            "Mailbox permission or delegation changes",
            "Sign ins from an address that does not match the user's history",
        ),
        method="Audit log rule matching with temporal profiling of the mailbox owner's normal activity window.",
    ),
    # ---------------------------------------------------------- techniques ---
    Hypothesis(
        id="tech-credential-access",
        name="Credentials are being harvested from endpoints and the directory",
        family="technique",
        summary="Hunt for every practical route an attacker uses to obtain authentication material.",
        narrative=(
            "Credential access is the pivot point of almost every intrusion. It covers memory dumping from "
            "LSASS, extraction of the domain database, Kerberos ticket harvesting, browser credential theft "
            "and brute force. Each has a distinct signature, and covering them together answers whether the "
            "identity plane is at risk."
        ),
        rationale=(
            "If credential theft has occurred, the evidence will contain LSASS access artefacts, ticket "
            "requests with weak encryption, credential store access or a burst of authentication failures."
        ),
        priority="critical",
        mitre_tactics=("Credential Access",),
        required_data_sources=("windows_security",),
        optional_data_sources=("sysmon", "linux_auth", "powershell", "edr"),
        rule_selectors=(
            "win-lsass-credential-dump", "win-ntds-extraction", "win-dcsync", "win-kerberoasting-ticket",
            "win-asrep-roasting", "win-kerberoast-volume", "win-failed-logon-burst", "win-password-spray",
            "win-account-lockout-storm", "mal-browser-credential-theft", "nix-ssh-brute-force",
            "mal-clipboard-keylogger", "win-pass-the-hash-indicator", "stat-auth-spread",
        ),
        expected_findings=(
            "LSASS memory access or credential dumping tool artefacts",
            "Kerberos ticket requests consistent with roasting",
            "Password spraying or brute force against accounts",
        ),
        method="Signature, threshold and behavioural rules across the full credential access technique family.",
    ),
    Hypothesis(
        id="tech-persistence",
        name="An adversary has established persistence on hosts in scope",
        family="technique",
        summary="Sweep for every common persistence mechanism on Windows and Linux.",
        narrative=(
            "Persistence is what turns an incident into a campaign. Scheduled tasks, services, autorun keys, "
            "cron entries, SSH keys and web shells all give an attacker a way back after remediation. A "
            "persistence sweep is the highest value hunt after any confirmed compromise."
        ),
        rationale=(
            "If persistence exists, the evidence will contain newly created tasks or services, autorun "
            "registry writes, cron or systemd changes, added SSH keys or script files in web directories."
        ),
        priority="high",
        mitre_tactics=("Persistence",),
        required_data_sources=("windows_security",),
        optional_data_sources=("sysmon", "linux_auth", "linux_audit", "web_server"),
        rule_selectors=(
            "win-scheduled-task-persistence", "win-run-key-persistence", "win-service-installed",
            "nix-persistence-cron", "nix-ssh-key-persistence", "nix-account-creation",
            "web-shell-access", "web-suspicious-upload", "win-remote-admin-account-created",
            "cloud-oauth-consent-abuse", "mal-dll-sideloading", "stat-rare-process",
        ),
        expected_findings=(
            "Scheduled tasks or services running interpreters or user writable binaries",
            "Autorun registry values pointing at unusual paths",
            "Cron entries, systemd units or SSH keys added outside change control",
        ),
        method="Broad persistence rule sweep across operating systems, cloud identities and web servers.",
    ),
    Hypothesis(
        id="tech-lateral-movement",
        name="An adversary is moving laterally with valid credentials",
        family="technique",
        summary="Hunt for the movement patterns that follow a successful credential theft.",
        narrative=(
            "Once credentials are obtained the attacker moves toward the systems that matter. Remote service "
            "creation, WMI process calls, administrative share access and remote desktop sessions all leave "
            "traces, and behavioural analysis of how widely an account authenticates makes the pattern obvious "
            "even when each individual logon looks legitimate."
        ),
        rationale=(
            "If lateral movement is occurring, one or more accounts will authenticate to an unusual number of "
            "systems and remote execution artefacts will appear on the destination hosts."
        ),
        priority="high",
        mitre_tactics=("Lateral Movement", "Execution"),
        required_data_sources=("windows_security",),
        optional_data_sources=("sysmon", "network_flow", "file_share", "vpn"),
        rule_selectors=(
            "win-psexec-lateral", "win-wmi-remote-execution", "win-rdp-external-source",
            "win-pass-the-hash-indicator", "net-smb-external", "net-internal-host-sweep",
            "stat-auth-spread", "stat-volume-outlier", "win-service-installed", "win-intrusion-chain",
        ),
        expected_findings=(
            "Remote service creation or WMI process calls on multiple hosts",
            "One account authenticating to far more systems than its peers",
            "Internal host sweeping from a workstation",
        ),
        method="Remote execution rules combined with statistical analysis of authentication spread per account.",
    ),
    Hypothesis(
        id="tech-privilege-escalation",
        name="Privilege escalation has been attempted on hosts in scope",
        family="technique",
        summary="Hunt for local and domain privilege escalation attempts.",
        narrative=(
            "Attackers rarely land with the privileges they need. User Account Control bypasses, vulnerable "
            "driver loading, sudo abuse, container escapes and privileged group changes are the routes they "
            "take, and each is visible in host telemetry."
        ),
        rationale=(
            "If escalation was attempted, the evidence will contain registry hijacks used for elevation, "
            "vulnerable driver loads, setuid discovery, container breakout commands or privileged group "
            "membership changes."
        ),
        priority="high",
        mitre_tactics=("Privilege Escalation",),
        required_data_sources=("sysmon",),
        optional_data_sources=("windows_security", "linux_auth", "linux_audit", "edr"),
        rule_selectors=(
            "win-uac-bypass", "mal-vulnerable-driver-load", "nix-privilege-escalation",
            "nix-container-escape", "win-remote-admin-account-created", "cloud-iam-privilege-escalation",
            "cloud-root-account-usage", "mal-exploit-attempt-generic", "stat-rare-lineage",
        ),
        expected_findings=(
            "Elevation registry hijacks such as fodhelper or ms-settings",
            "Loading of a known vulnerable driver",
            "Container escape or docker socket abuse",
        ),
        method="Technique specific rules across Windows, Linux, container and cloud escalation paths.",
    ),
    Hypothesis(
        id="tech-defense-evasion",
        name="Security controls and audit trails have been tampered with",
        family="technique",
        summary="Hunt for the anti forensic and control tampering that precedes major impact.",
        narrative=(
            "Before doing damage, an attacker removes what would record it. Cleared event logs, disabled "
            "antivirus, script logging bypasses, deleted cloud trails and wiped shell history are all "
            "deliberate acts with no legitimate explanation in most environments."
        ),
        rationale=(
            "If controls have been tampered with, the evidence will contain log clearing events, endpoint "
            "protection changes, scanning interface bypasses or cloud logging changes."
        ),
        priority="critical",
        mitre_tactics=("Defense Evasion",),
        required_data_sources=("windows_security",),
        optional_data_sources=("sysmon", "powershell", "linux_auth", "aws_cloudtrail", "m365_audit"),
        rule_selectors=(
            "win-event-log-cleared", "win-defender-tampering", "mal-amsi-etw-bypass",
            "nix-history-tampering", "cloud-logging-disabled", "mal-process-injection",
            "mal-suspicious-execution-path", "win-lolbin-download", "stat-random-names",
        ),
        expected_findings=(
            "Event logs cleared or audit policy changed",
            "Endpoint protection disabled or exclusions added",
            "Script scanning or event tracing disabled",
        ),
        method="Control tampering rules across endpoint, script host and cloud control planes.",
    ),
    Hypothesis(
        id="tech-discovery",
        name="Internal reconnaissance is being performed",
        family="technique",
        summary="Hunt for the enumeration that precedes lateral movement.",
        narrative=(
            "Every operator enumerates before moving. Host, user, group, trust and network discovery happen "
            "within minutes of a foothold. Individually the commands are unremarkable, so the signal comes "
            "from their clustering in a single session and from network sweeping behaviour."
        ),
        rationale=(
            "If reconnaissance is happening, the evidence will contain clusters of enumeration commands, "
            "internal host sweeps, port scans or bulk cloud list operations."
        ),
        priority="medium",
        mitre_tactics=("Discovery", "Reconnaissance"),
        required_data_sources=("sysmon",),
        optional_data_sources=("windows_security", "network_flow", "aws_cloudtrail", "web_server"),
        rule_selectors=(
            "win-discovery-commands", "net-port-scan", "net-internal-host-sweep",
            "cloud-api-enumeration", "web-directory-bruteforce", "web-scanner-user-agent",
            "stat-activity-burst", "stat-volume-outlier",
        ),
        expected_findings=(
            "Clusters of enumeration commands from one account",
            "Port scanning or host sweeping from an internal address",
            "Bulk list and describe operations in the cloud control plane",
        ),
        method="Command pattern rules plus distinct value threshold analysis for scanning and enumeration.",
    ),
    Hypothesis(
        id="tech-exfiltration",
        name="Data is being staged and moved out of the environment",
        family="technique",
        summary="Hunt for collection, staging and egress of business data.",
        narrative=(
            "Data theft has three visible phases: collection from shares and mailboxes, staging into archives, "
            "and transfer to an external destination. Detecting the staging phase is the last opportunity to "
            "prevent the loss, and volume analytics detect the transfer even when the destination is unknown."
        ),
        rationale=(
            "If data is being exfiltrated, the evidence will contain archive creation on servers, large "
            "outbound transfers, uploads to file sharing services or unusual DNS volumes."
        ),
        priority="critical",
        mitre_tactics=("Collection", "Exfiltration"),
        required_data_sources=("network_flow",),
        optional_data_sources=("proxy", "sysmon", "dns", "web_server", "m365_audit"),
        rule_selectors=(
            "mal-data-staging-archive", "net-cloud-storage-exfiltration", "net-large-outbound-transfer",
            "net-dns-tunnelling-indicator", "net-dns-query-volume", "web-large-response-exfiltration",
            "cloud-storage-exposed", "stat-egress-concentration", "stat-benford",
            "stat-beaconing-fft", "net-tor-or-anonymiser",
        ),
        expected_findings=(
            "Password protected archives created on file servers",
            "Large or concentrated outbound transfers",
            "Uploads to consumer file sharing services",
        ),
        method="Staging and egress rules combined with Gini concentration and Benford analysis of transfer volumes.",
    ),
    Hypothesis(
        id="tech-phishing-execution",
        name="A user opened a malicious document or link",
        family="technique",
        summary="Hunt for the execution chain that follows a successful phishing message.",
        narrative=(
            "The chain from phishing to compromise is short and distinctive: a mail client or Office "
            "application starts a script interpreter, the interpreter downloads a payload with a trusted "
            "utility, and the payload establishes persistence and contacts its controller."
        ),
        rationale=(
            "If a phishing message was successful, the evidence will contain an Office or mail process "
            "spawning an interpreter, followed by download activity and outbound connections."
        ),
        priority="high",
        mitre_tactics=("Initial Access", "Execution"),
        required_data_sources=("sysmon",),
        optional_data_sources=("email_gateway", "proxy", "powershell", "windows_security"),
        rule_selectors=(
            "win-office-spawns-shell", "win-encoded-powershell", "win-lolbin-download",
            "mal-phishing-indicator", "mal-suspicious-execution-path", "mal-antivirus-detection",
            "stat-command-entropy", "stat-rare-lineage", "net-suspicious-tld", "stat-beaconing-fft",
        ),
        expected_findings=(
            "Office application spawning a command interpreter",
            "Encoded PowerShell or trusted utility downloads",
            "Outbound connections to newly registered infrastructure",
        ),
        method="Process lineage rules with entropy analysis of command lines and rarity scoring of the chain.",
    ),
    Hypothesis(
        id="tech-brute-force",
        name="Authentication surfaces are under credential attack",
        family="technique",
        summary="Hunt for brute force, password spraying and credential stuffing across every login surface.",
        narrative=(
            "Credential attacks are constant against anything reachable from the internet. What matters is "
            "distinguishing background noise from an attack that eventually succeeded, which requires "
            "correlating failures with the successes that follow them."
        ),
        rationale=(
            "If a credential attack is in progress, the evidence will show clusters of failures per source or "
            "per account, and possibly a success from the same source afterwards."
        ),
        priority="high",
        mitre_tactics=("Credential Access",),
        required_data_sources=("windows_security",),
        optional_data_sources=("linux_auth", "vpn", "web_server", "entra_signin", "m365_audit"),
        rule_selectors=(
            "win-failed-logon-burst", "win-password-spray", "win-account-lockout-storm",
            "nix-ssh-brute-force", "nix-successful-login-after-failures", "web-credential-stuffing",
            "cloud-failed-console-logins", "win-rdp-external-source", "net-smb-external",
            "stat-volume-outlier", "stat-activity-burst",
        ),
        expected_findings=(
            "High volumes of failed authentication from single sources",
            "Failures spread across many accounts from one address",
            "A successful authentication following the failure burst",
        ),
        method="Sliding window threshold analysis per source and per account, with distinct value counting for spraying.",
    ),
    Hypothesis(
        id="tech-cloud-control-plane",
        name="The cloud control plane is being abused",
        family="technique",
        summary="Hunt for identity, logging, storage and destruction abuse in cloud accounts.",
        narrative=(
            "Cloud compromise is quiet. There is no malware and no endpoint, only API calls. The pattern is "
            "consistent: enumerate, add a credential, weaken logging, then act on objectives against storage "
            "or compute."
        ),
        rationale=(
            "If a cloud account is compromised, the trail will contain enumeration bursts, identity changes, "
            "logging changes and storage or key operations that were never requested."
        ),
        priority="critical",
        mitre_tactics=("Persistence", "Privilege Escalation", "Defense Evasion", "Impact"),
        required_data_sources=("aws_cloudtrail",),
        optional_data_sources=("entra_signin", "m365_audit"),
        rule_selectors=(
            "cloud-iam-privilege-escalation", "cloud-logging-disabled", "cloud-storage-exposed",
            "cloud-resource-destruction", "cloud-root-account-usage", "cloud-api-enumeration",
            "cloud-failed-console-logins", "cloud-impossible-source", "cloud-oauth-consent-abuse",
            "stat-volume-outlier", "stat-off-hours",
        ),
        expected_findings=(
            "Access keys or login profiles created outside change control",
            "Audit trails stopped or deleted",
            "Storage made public or backups and keys deleted",
        ),
        method="Control plane rule matching with volumetric and temporal outlier analysis per identity.",
    ),
    Hypothesis(
        id="tech-container-workload",
        name="Container workloads are being abused or escaped",
        family="technique",
        summary="Hunt for container escape, privileged workloads and workload level malware.",
        narrative=(
            "Containers share a kernel with the node. A workload that mounts the host filesystem, runs "
            "privileged or reaches the container runtime socket can take control of the node and every other "
            "workload on it."
        ),
        rationale=(
            "If container isolation has been broken, the evidence will contain privileged runs, host path "
            "mounts, runtime socket access or namespace entry commands."
        ),
        priority="high",
        mitre_tactics=("Privilege Escalation", "Execution", "Impact"),
        required_data_sources=("linux_audit",),
        optional_data_sources=("linux_auth", "edr", "network_flow"),
        rule_selectors=(
            "nix-container-escape", "nix-privilege-escalation", "nix-reverse-shell",
            "mal-cryptominer", "nix-suspicious-download-execute", "stat-rare-process",
            "nix-persistence-cron",
        ),
        expected_findings=(
            "Privileged containers or host path mounts",
            "Container runtime socket access from inside a workload",
            "Cryptomining or reverse shell activity in a workload",
        ),
        method="Container specific behavioural rules with rarity analysis of executed images.",
    ),
    Hypothesis(
        id="tech-insider-data-access",
        name="An insider is collecting data beyond their normal pattern",
        family="technique",
        summary="Hunt for abnormal data access and egress by authorised accounts.",
        narrative=(
            "Insider risk does not produce malware alerts. It shows as an account that suddenly reads far more "
            "than usual, works outside its normal hours and moves data to personal destinations. Detection is "
            "therefore behavioural, comparing each account against its peers."
        ),
        rationale=(
            "If an insider is collecting data, the evidence will show volumetric outliers per account, off "
            "hours concentration and transfers to consumer services."
        ),
        priority="medium",
        mitre_tactics=("Collection", "Exfiltration"),
        required_data_sources=("file_share",),
        optional_data_sources=("proxy", "m365_audit", "web_server", "network_flow"),
        rule_selectors=(
            "stat-volume-outlier", "stat-off-hours", "stat-egress-concentration",
            "net-cloud-storage-exfiltration", "mal-data-staging-archive",
            "web-large-response-exfiltration", "mal-removable-media", "stat-activity-burst",
        ),
        expected_findings=(
            "One account far outside the peer distribution for access volume",
            "Activity concentrated outside working hours",
            "Uploads to personal cloud storage or removable media use",
        ),
        method="Peer group statistical comparison with rules for staging, removable media and egress destinations.",
    ),
    Hypothesis(
        id="cti-directory-escalation",
        name="An adversary is escalating to domain control through Active Directory",
        family="cti",
        summary="Hunt for the certificate, delegation and policy paths that lead from a user to domain admin.",
        narrative=(
            "Modern intrusions rarely need an exploit to reach domain control. The paths that work are "
            "misconfigurations already present in the directory: a certificate template that lets the "
            "requester choose the subject, delegation rights on a machine account, write access to a "
            "group policy object, or a permission written directly onto a protected object. Each of "
            "these turns an ordinary account into a domain administrator in minutes, and each leaves "
            "traces that look like administration unless you know what to look for."
        ),
        rationale=(
            "If an adversary is walking one of these paths, the directory telemetry will contain "
            "certificate requests with foreign subjects, delegation or key credential attribute writes, "
            "policy changes outside the change window, or permission grants on tier zero objects."
        ),
        priority="critical",
        threat_actors=("Ransomware affiliates", "Access brokers", "State aligned intrusion sets"),
        mitre_tactics=("Privilege Escalation", "Persistence", "Credential Access"),
        required_data_sources=("windows_security",),
        optional_data_sources=("sysmon", "powershell", "edr"),
        rule_selectors=(
            "ad-certificate-template-abuse", "ad-shadow-credentials", "ad-delegation-abuse",
            "ad-group-policy-modified", "ad-trust-modified", "ad-dpapi-backup-key",
            "ad-machine-account-created", "ad-adminsdholder-or-acl-change",
            "ad-zerologon-or-netlogon-abuse", "ad-printnightmare-or-spooler", "ad-ldap-enumeration",
            "win-dcsync", "win-ntds-extraction", "win-remote-admin-account-created",
            "win-kerberoast-volume", "stat-auth-spread",
        ),
        expected_findings=(
            "Certificate requests with a subject that does not match the requester",
            "Delegation or key credential attributes written on an account",
            "Group policy or directory permission changes outside the change window",
            "Directory replication or database extraction from a non controller identity",
        ),
        method=(
            "Directory specific rules for each known escalation path, combined with threshold analysis "
            "of enumeration volume and statistical analysis of how widely each account authenticates."
        ),
    ),
    Hypothesis(
        id="cti-saas-account-takeover",
        name="A federated identity has been taken over",
        family="cti",
        summary="Hunt for account takeover in the identity provider and the applications behind it.",
        narrative=(
            "When the perimeter is single sign on, the intrusion starts at the identity provider. The "
            "pattern is consistent: the password is phished or stuffed, the attacker sends multi factor "
            "prompts until one is approved or replays a stolen session cookie, then establishes "
            "persistence by registering an authentication method, creating an API token or granting "
            "themselves an administrative role. None of this touches the corporate network."
        ),
        rationale=(
            "If an identity has been taken over, the provider log will show a burst of multi factor "
            "challenges or a session used from an unexpected context, followed by an authentication "
            "method change, a token creation or a role grant."
        ),
        priority="critical",
        threat_actors=("Scattered Spider / Octo Tempest", "Adversary in the middle phishing crews"),
        mitre_tactics=("Initial Access", "Credential Access", "Persistence"),
        required_data_sources=("idp",),
        optional_data_sources=("m365_audit", "entra_signin", "scm", "proxy"),
        rule_selectors=(
            "idp-mfa-push-fatigue", "idp-session-hijack-indicator", "idp-admin-role-granted",
            "idp-api-token-created", "cloud-mfa-weakened", "cloud-impossible-source",
            "cloud-mailbox-rule-abuse", "cloud-oauth-consent-abuse", "saas-bulk-download",
            "stat-off-hours", "stat-volume-outlier",
        ),
        expected_findings=(
            "Repeated multi factor challenges for a single account",
            "Session or token replay from an unexpected context",
            "Authentication method changes, tokens or admin roles created after the sign in",
        ),
        method=(
            "Identity provider rules with sliding window analysis of challenge volume, combined with "
            "temporal profiling of each account against its own pattern."
        ),
    ),
    Hypothesis(
        id="tech-kubernetes-compromise",
        name="A Kubernetes cluster is being abused",
        family="technique",
        summary="Hunt for exec sessions, privileged workloads, RBAC escalation and secret collection.",
        narrative=(
            "Cluster compromise follows a short path. The attacker reaches the API server with a token "
            "taken from a workload or a pipeline, enumerates what the token can do, reads the secrets it "
            "can reach, then grants itself broader rights or schedules a privileged workload to break "
            "out onto the node. The audit log records every step, which makes this one of the most "
            "tractable hunts in a cloud native estate."
        ),
        rationale=(
            "If a cluster is being abused, the audit log will contain exec or attach subresource "
            "requests, privileged or host mounting workloads, bulk secret reads or new cluster scoped "
            "role bindings."
        ),
        priority="critical",
        mitre_tactics=("Execution", "Privilege Escalation", "Credential Access"),
        required_data_sources=("k8s_audit",),
        optional_data_sources=("linux_audit", "network_flow", "aws_cloudtrail"),
        rule_selectors=(
            "k8s-exec-into-pod", "k8s-privileged-workload", "k8s-rbac-escalation",
            "k8s-secret-enumeration", "k8s-anonymous-or-unauthenticated-access",
            "k8s-workload-image-anomaly", "nix-container-escape", "nix-reverse-shell",
            "mal-cryptominer", "stat-volume-outlier", "stat-rare-process",
        ),
        expected_findings=(
            "Interactive sessions opened inside running workloads",
            "Privileged or host mounting workloads admitted",
            "Bulk secret reads or new cluster administrator bindings",
        ),
        method=(
            "Audit log rules for the control plane paths, combined with volumetric analysis per subject "
            "to separate application behaviour from collection."
        ),
    ),
    Hypothesis(
        id="tech-supply-chain-pipeline",
        name="The build pipeline or source control has been tampered with",
        family="technique",
        summary="Hunt for pipeline modification, token abuse and repository exfiltration.",
        narrative=(
            "The delivery pipeline holds the credentials that reach production and the code that "
            "customers receive. An attacker who edits a workflow file, registers a runner or creates a "
            "personal access token gains both, and the change looks like ordinary engineering work. "
            "This hunt reads the source control and pipeline audit trail for those specific actions."
        ),
        rationale=(
            "If the pipeline has been tampered with, the audit trail will contain workflow or runner "
            "changes, new long lived tokens or deploy keys, and repository exports or visibility changes."
        ),
        priority="high",
        mitre_tactics=("Initial Access", "Persistence", "Collection"),
        required_data_sources=("scm",),
        optional_data_sources=("idp", "aws_cloudtrail", "linux_audit"),
        rule_selectors=(
            "cicd-pipeline-tampering", "scm-repository-exfiltration", "idp-api-token-created",
            "saas-secret-in-log", "idp-admin-role-granted", "cloud-iam-privilege-escalation",
            "stat-off-hours", "stat-volume-outlier",
        ),
        expected_findings=(
            "Workflow definitions or self hosted runners changed",
            "Long lived tokens or deploy keys created",
            "Repositories exported or made public",
        ),
        method="Audit trail rules for the pipeline surface, with temporal and volumetric profiling per actor.",
    ),
    Hypothesis(
        id="tech-database-compromise",
        name="The database tier is being attacked",
        family="technique",
        summary="Hunt for command execution, bulk export and privilege changes on database servers.",
        narrative=(
            "Databases are the objective of most intrusions, and they are also a route to the host. The "
            "engine features that reach the operating system run with high privilege, bulk export moves "
            "the whole dataset in one statement, and a new privileged login is persistence that most "
            "remediation never looks at."
        ),
        rationale=(
            "If the data tier is under attack, the engine logs will contain command execution features "
            "being enabled or used, bulk export statements, new privileged logins or a burst of failed "
            "authentications."
        ),
        priority="critical",
        mitre_tactics=("Execution", "Collection", "Credential Access", "Persistence"),
        required_data_sources=("database",),
        optional_data_sources=("windows_security", "sysmon", "web_server", "network_flow"),
        rule_selectors=(
            "db-command-execution", "db-mass-export", "db-authentication-failures",
            "db-privilege-change", "web-sql-injection", "win-suspicious-parent-child",
            "net-large-outbound-transfer", "stat-volume-outlier", "stat-egress-concentration",
        ),
        expected_findings=(
            "Operating system command execution from the engine",
            "Bulk export statements outside the backup window",
            "New privileged logins or failed authentication bursts",
        ),
        method="Statement and authentication rules for the data tier, with egress analysis for what left afterwards.",
    ),
    Hypothesis(
        id="tech-macos-endpoint",
        name="A macOS endpoint has been compromised",
        family="technique",
        summary="Hunt for launch item persistence, scripting abuse and security control tampering on macOS.",
        narrative=(
            "macOS intrusions follow their own playbook. Execution arrives through AppleScript or a "
            "signed interpreter, persistence is a launch agent, the platform protections are disabled "
            "with a handful of well known commands, and the objective is usually the keychain. The "
            "commands involved are short, specific and rare in normal use."
        ),
        rationale=(
            "If a macOS endpoint is compromised, the telemetry will contain launch item writes, "
            "osascript with inline code, Gatekeeper or quarantine tampering, or keychain access from "
            "the command line."
        ),
        priority="high",
        mitre_tactics=("Execution", "Persistence", "Defense Evasion", "Credential Access"),
        required_data_sources=("macos_endpoint",),
        optional_data_sources=("linux_auth", "proxy", "dns", "network_flow"),
        rule_selectors=(
            "mac-launch-persistence", "mac-osascript-abuse", "mac-security-control-tampering",
            "mac-credential-access", "nix-reverse-shell", "nix-suspicious-download-execute",
            "stat-beaconing-fft", "stat-rare-process", "net-suspicious-tld",
        ),
        expected_findings=(
            "Launch agents or daemons written outside device management",
            "AppleScript executing inline code or prompting for a password",
            "Gatekeeper, quarantine or consent database tampering",
        ),
        method="macOS specific behavioural rules with rarity analysis of executed binaries and beacon detection.",
    ),
    Hypothesis(
        id="tech-secret-exposure",
        name="Credentials are exposed in the evidence itself",
        family="technique",
        summary="Sweep every uploaded log for live credential material and unsecured secrets.",
        narrative=(
            "Secrets leak into logs constantly: a connection string in an error message, an access key in "
            "a debug line, a token in a request URL. Anyone who can read the logs then holds the "
            "credential, and log archives are shared far more widely than the systems they describe. "
            "This hunt reads the evidence itself as the finding."
        ),
        rationale=(
            "If secrets are present, pattern matching for cloud access keys, private key blocks, "
            "provider tokens and assignment style credentials will find them in the supplied files."
        ),
        priority="high",
        mitre_tactics=("Credential Access",),
        required_data_sources=(),
        optional_data_sources=("windows_security", "web_server", "linux_auth", "scm", "aws_cloudtrail",
                               "k8s_audit", "database"),
        rule_selectors=(
            "saas-secret-in-log", "mal-browser-credential-theft", "k8s-secret-enumeration",
            "idp-api-token-created", "stat-command-entropy",
        ),
        expected_findings=(
            "Cloud access keys, private key blocks or provider tokens in log content",
            "Assignment style credentials in command lines or configuration",
            "High entropy tokens passed to interpreters",
        ),
        method=(
            "Provider specific credential patterns and generic assignment matching, supported by entropy "
            "scoring of long tokens."
        ),
    ),
    # ------------------------------------------------------- mathematical ---
    Hypothesis(
        id="math-fourier-beaconing",
        name="Fourier analysis reveals periodic command and control channels",
        family="mathematical",
        summary="Apply a discrete Fourier transform to connection timing to find machine driven traffic.",
        narrative=(
            "Human generated network traffic is bursty and irregular. Software that checks in on a timer "
            "produces a periodic signal. Binning connection timestamps into a time series and taking the "
            "Fourier transform makes that periodicity measurable: a dominant frequency whose spectral power "
            "sits far above the mean indicates a fixed interval, and the coefficient of variation of the "
            "inter arrival times confirms it. The method needs no signature, so it finds channels that no "
            "threat intelligence has ever described."
        ),
        rationale=(
            "If any host is running an implant, its connection timestamps to the controller will contain a "
            "dominant spectral component that legitimate browsing traffic does not have."
        ),
        priority="critical",
        mitre_tactics=("Command and Control",),
        required_data_sources=("network_flow",),
        optional_data_sources=("proxy", "dns", "web_server"),
        rule_selectors=("stat-beaconing-fft", "stat-egress-concentration", "stat-benford",
                        "net-non-standard-port-web", "stat-rare-user-agent"),
        expected_findings=(
            "Source and destination pairs with a dominant spectral peak",
            "Interval coefficient of variation close to zero",
            "Sustained low volume sessions over a long period",
        ),
        method=(
            "Timestamps are grouped per source and destination pair, binned at a quarter of the median "
            "interval, mean centred and transformed with an iterative radix 2 fast Fourier transform. The "
            "dominant peak power is compared against the mean spectrum, and the result is combined with "
            "interval regularity and jitter into a single beacon score."
        ),
    ),
    Hypothesis(
        id="math-shannon-entropy",
        name="Shannon entropy exposes generated domains and encoded payloads",
        family="mathematical",
        summary="Measure information density to find randomness that humans do not produce.",
        narrative=(
            "Language is redundant. English text sits near 2.5 to 3.0 bits of entropy per character and file "
            "paths are similar. Encrypted, compressed and base64 encoded content approaches the theoretical "
            "maximum for its alphabet, and algorithmically generated domain names sit far above natural words. "
            "Measuring entropy therefore separates attacker generated strings from everything else without any "
            "prior knowledge of the payload."
        ),
        rationale=(
            "If malware is present, its domains, file names or command line arguments will show entropy and "
            "letter distributions that do not occur in human chosen names."
        ),
        priority="high",
        mitre_tactics=("Command and Control", "Defense Evasion"),
        required_data_sources=("dns",),
        optional_data_sources=("sysmon", "proxy", "powershell", "web_server"),
        rule_selectors=("stat-dga-entropy", "stat-command-entropy", "stat-random-names",
                        "net-dns-tunnelling-indicator", "net-dns-query-volume", "win-encoded-powershell"),
        expected_findings=(
            "Domain labels with high entropy and consonant heavy structure",
            "Long high entropy tokens inside command lines",
            "Randomly generated file and process names",
        ),
        method=(
            "Shannon entropy is computed per string, then combined with consonant ratio, digit ratio, longest "
            "consonant run and length into a composite randomness score. Thresholds are set so that ordinary "
            "vocabulary and content delivery network hostnames stay below the reporting line."
        ),
    ),
    Hypothesis(
        id="math-longtail-stacking",
        name="Frequency stacking surfaces the rarest activity in the estate",
        family="mathematical",
        summary="Count everything, then investigate what appears only once.",
        narrative=(
            "In a healthy estate, activity repeats. The same processes, the same lineages and the same clients "
            "appear thousands of times. Attacker tooling is unique to the intrusion, so it sits in the long "
            "tail of every frequency distribution. Stacking counts values and reports the tail, which is the "
            "oldest and still one of the most effective hunting methods."
        ),
        rationale=(
            "If unfamiliar tooling ran in this environment, it will appear once or twice in a data set where "
            "legitimate software appears constantly."
        ),
        priority="medium",
        mitre_tactics=("Execution", "Defense Evasion"),
        required_data_sources=("sysmon",),
        optional_data_sources=("web_server", "proxy", "edr", "windows_security"),
        rule_selectors=("stat-rare-process", "stat-rare-lineage", "stat-rare-user-agent",
                        "mal-suspicious-execution-path", "stat-random-names"),
        expected_findings=(
            "Process images seen only once across the data set",
            "Parent and child relationships that occur a single time",
            "User agents unique to one host",
        ),
        method=(
            "Values are counted per field, the population size is checked for statistical meaning, and values "
            "below a frequency floor are reported with their share of the population so the analyst can judge "
            "significance."
        ),
    ),
    Hypothesis(
        id="math-outlier-detection",
        name="Robust outlier detection identifies entities behaving abnormally",
        family="mathematical",
        summary="Use median absolute deviation z scores to compare every entity against its peers.",
        narrative=(
            "Averages and standard deviations are distorted by the very outliers they are meant to find. The "
            "median absolute deviation is robust: a single extreme value cannot hide itself by moving the "
            "centre. Applying it to per entity event counts and per account system counts finds the accounts "
            "and hosts that no longer behave like their peers."
        ),
        rationale=(
            "If an account or host has been taken over, its activity volume or its authentication spread will "
            "sit far outside the population distribution."
        ),
        priority="high",
        mitre_tactics=("Lateral Movement", "Discovery"),
        required_data_sources=("windows_security",),
        optional_data_sources=("linux_auth", "network_flow", "aws_cloudtrail", "m365_audit"),
        rule_selectors=("stat-volume-outlier", "stat-auth-spread", "stat-activity-burst",
                        "stat-off-hours", "stat-egress-concentration"),
        expected_findings=(
            "Accounts reaching far more systems than their peers",
            "Entities generating extreme event volumes",
            "Sharp bursts in the activity timeline",
        ),
        method=(
            "Modified z scores based on the median absolute deviation are computed across entities, with a "
            "reporting threshold well above the conventional 3.5 so that only decisive outliers are raised. "
            "The timeline is binned and scored the same way to locate bursts."
        ),
    ),
    Hypothesis(
        id="math-benford-transfers",
        name="Benford's law testing detects manipulated transfer volumes",
        family="mathematical",
        summary="Test the leading digit distribution of transfer sizes for artificial regularity.",
        narrative=(
            "Naturally occurring quantities that span several orders of magnitude follow Benford's law, where "
            "the digit one leads about thirty percent of values. Network transfer sizes follow it closely. "
            "When an attacker chunks data into fixed sizes to stay below alerting thresholds, the distribution "
            "flattens and the chi square statistic against Benford rises sharply."
        ),
        rationale=(
            "If data is leaving in fixed size chunks, the leading digit distribution of transfer volumes will "
            "deviate significantly from the Benford expectation."
        ),
        priority="medium",
        mitre_tactics=("Exfiltration",),
        required_data_sources=("network_flow",),
        optional_data_sources=("proxy", "web_server"),
        rule_selectors=("stat-benford", "stat-egress-concentration", "net-large-outbound-transfer",
                        "net-cloud-storage-exfiltration"),
        expected_findings=(
            "Chi square statistic above the one percent critical value",
            "Egress concentrated on a single destination",
            "Repeated identical transfer sizes",
        ),
        method=(
            "Leading digits are extracted from every transfer size above ten bytes, compared against the "
            "Benford expectation with a chi square test on eight degrees of freedom, and reported when the "
            "statistic exceeds twice the one percent critical value with a sufficient sample."
        ),
    ),
    Hypothesis(
        id="math-temporal-profiling",
        name="Temporal profiling reveals activity outside human working patterns",
        family="mathematical",
        summary="Profile when each account acts and report those working against the clock.",
        narrative=(
            "People work in patterns. An account whose activity suddenly concentrates at night or at weekends "
            "is either automation that should be documented or an operator in a different time zone. Combining "
            "hour of day profiling with burst detection over the whole timeline produces a short list of "
            "windows worth reading line by line."
        ),
        rationale=(
            "If a stolen credential is being used, its activity profile will differ from the profile of the "
            "legitimate owner and of the wider population."
        ),
        priority="medium",
        mitre_tactics=("Defense Evasion", "Discovery"),
        required_data_sources=("windows_security",),
        optional_data_sources=("linux_auth", "m365_audit", "aws_cloudtrail", "file_share"),
        rule_selectors=("stat-off-hours", "stat-activity-burst", "stat-volume-outlier", "stat-auth-spread"),
        expected_findings=(
            "Accounts with most activity outside working hours",
            "Sharp bursts in the event timeline",
            "Volumetric outliers coinciding with the bursts",
        ),
        method=(
            "Timestamps are converted to coordinated universal time, profiled per account against a standard "
            "working window, and the whole timeline is binned and scored with robust z scores to locate "
            "bursts."
        ),
    ),
    Hypothesis(
        id="math-full-spectrum",
        name="Full spectrum analysis with every detection available",
        family="mathematical",
        summary="Run the complete rule library and every statistical model against the evidence.",
        narrative=(
            "When the objective is coverage rather than a specific question, the whole library is applied. "
            "This is the right choice for a first pass on unfamiliar evidence, for compromise assessments and "
            "for periodic assurance work, because it makes no assumption about what the data contains."
        ),
        rationale=(
            "If anything in the rule library or the statistical models matches this evidence, it will be "
            "reported, ranked by severity and confidence."
        ),
        priority="high",
        mitre_tactics=("Multiple",),
        required_data_sources=(),
        optional_data_sources=(
            "windows_security", "sysmon", "powershell", "linux_auth", "web_server", "dns",
            "network_flow", "aws_cloudtrail", "m365_audit", "proxy", "ids", "edr",
        ),
        rule_selectors=("*",),
        expected_findings=(
            "Any behaviour covered by the detection library",
            "Statistical anomalies across timing, volume, entropy and rarity",
        ),
        method="The complete rule set, covering pattern, threshold, sequence and statistical detections.",
    ),
)

HYPOTHESES_BY_ID: dict[str, Hypothesis] = {item.id: item for item in HYPOTHESES}

FAMILY_LABELS = {
    "cti": "Threat intelligence scenario",
    "technique": "Technique based hunt",
    "mathematical": "Mathematical and statistical hunt",
}


def catalogue() -> list[dict]:
    return [item.to_dict() for item in HYPOTHESES]


def get_hypothesis(hypothesis_id: str) -> Hypothesis | None:
    return HYPOTHESES_BY_ID.get(hypothesis_id)


def validate_catalogue() -> list[str]:
    """Return a list of problems, used by the test suite and at start up."""
    problems: list[str] = []
    for item in HYPOTHESES:
        if not item.rule_selectors:
            problems.append(f"{item.id}: no rules selected")
        resolved = item.rules()
        if not resolved:
            problems.append(f"{item.id}: rule selectors resolved to nothing")
        for selector in item.rule_selectors:
            if selector in ("*",) or selector.endswith("*"):
                continue
            if selector not in RULES_BY_ID and not any(rule.category == selector for rule in resolved):
                problems.append(f"{item.id}: unknown rule selector {selector}")
        for source in item.required_data_sources + item.optional_data_sources:
            if source not in DATA_SOURCES:
                problems.append(f"{item.id}: unknown data source {source}")
    return problems
