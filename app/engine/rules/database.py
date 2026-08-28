"""Database and network appliance detections."""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

DB_SOURCES = ("structured", "generic", "syslog", "windows_event", "sysmon", "security_appliance", "endpoint")

RULES = [
    pattern_rule(
        "db-command-execution",
        "Operating system command execution from the database engine",
        "A database feature that reaches the operating system was invoked, such as xp_cmdshell, an "
        "external script, a CLR assembly or a COPY to a program. Databases run with high privilege, so "
        "this converts data access into host compromise.",
        any_of=[
            C("_text", "any_regex", [
                r"xp_cmdshell", r"sp_configure[^\n]{0,60}xp_cmdshell", r"sp_oacreate", r"sp_execute_external_script",
                r"create\s+assembly", r"clr\s+enabled", r"copy\s+[^\n]{0,60}\s+from\s+program",
                r"copy\s+[^\n]{0,60}\s+to\s+program", r"lo_import\s*\(", r"select[^\n]{0,40}into\s+outfile",
                r"sys_exec\s*\(", r"utl_file", r"dbms_scheduler[^\n]{0,40}create_job",
            ]),
        ],
        keywords=("xp_cmdshell", "sp_oacreate", "sp_execute_external_script", "create assembly",
                  "clr enabled", "from program", "to program", "lo_import", "outfile", "sys_exec",
                  "utl_file", "dbms_scheduler"),
        group_by=("host.name", "user.name"),
        severity="critical",
        confidence="high",
        category="execution",
        data_sources=DB_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Command and Scripting Interpreter",
        mitre_technique_id="T1059",
        risk="These features give the database service account, which is usually highly privileged, "
             "arbitrary command execution on the host.",
        impact="Compromise of the database server and of every record it holds, plus a pivot into the "
               "internal network from a system that is normally trusted.",
        recommendation="Disable the feature unless a documented application requires it, review what was "
                       "executed and run the database under a least privilege service account. Investigate how "
                       "the statement was issued, which is often through a web application injection flaw.",
        references=("https://attack.mitre.org/techniques/T1059/",),
        detail_fields=("host.name", "user.name", "process.command_line", "message"),
    ),
    pattern_rule(
        "db-mass-export",
        "Bulk data export from the database",
        "A statement was executed that exports a whole table or database, such as a dump utility, a bulk "
        "copy or a select into an outfile.",
        any_of=[
            C("_text", "any_regex", [
                r"\bmysqldump\b", r"\bpg_dump(?:all)?\b", r"\bbcp\b[^\n]{0,60}\bout\b",
                r"\bexpdp\b", r"\bsqlcmd\b[^\n]{0,60}-o\s", r"backup\s+database[^\n]{0,60}to\s+disk",
                r"select\s+\*\s+from\s+[\w.\"\[\]]+\s*(?:into\s+outfile|;?\s*$)",
                r"\\copy\s+[\w.\"]+\s+to\s", r"generate_series[^\n]{0,40}information_schema",
            ]),
        ],
        keywords=("mysqldump", "pg_dump", "pg_dumpall", "bcp", "expdp", "backup database", "outfile",
                  "sqlcmd"),
        group_by=("host.name", "user.name"),
        severity="high",
        confidence="medium",
        category="collection",
        data_sources=DB_SOURCES,
        mitre_tactic="Collection",
        mitre_technique="Data from Information Repositories",
        mitre_technique_id="T1213",
        risk="A full export moves the entire dataset in one action, which is the step immediately before "
             "exfiltration in most data breaches.",
        impact="Loss of the complete record set, including regulated personal data, with breach "
               "notification duties and contractual exposure.",
        recommendation="Establish whether the export matches a scheduled backup, and if not locate the output "
                       "file and any outbound transfer that followed. Restrict export privileges, log them "
                       "centrally and alert when they run outside the backup window.",
        references=("https://attack.mitre.org/techniques/T1213/",),
        detail_fields=("host.name", "user.name", "process.command_line", "message"),
    ),
    threshold_rule(
        "db-authentication-failures",
        "Repeated database authentication failures against {host.name}",
        "{count} failed database logins were recorded in the window, which indicates credential guessing "
        "against the data tier.",
        any_of=[
            C("_text", "any_contains", [
                "login failed for user", "password authentication failed", "access denied for user",
                "ora-01017", "authentication failure", "invalid password", "18456",
            ]),
        ],
        group_by=("host.name", "source.ip"),
        min_count=12,
        window_seconds=600,
        keywords=("login failed for user", "password authentication failed", "access denied for user",
                  "ora-01017", "18456", "invalid password"),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=DB_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        risk="Database services are frequently reachable from more of the network than intended and often "
             "still carry default or shared application credentials.",
        impact="A successful guess gives direct access to the records without passing through any "
               "application authorisation logic.",
        recommendation="Block the source, confirm no session eventually succeeded and rotate the targeted "
                       "accounts. Restrict database listeners to application subnets and enforce individual "
                       "accounts with strong secrets rather than shared logins.",
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    pattern_rule(
        "db-privilege-change",
        "Database privilege or account change",
        "A database account was created or granted elevated privileges, which provides durable access to "
        "the data tier independent of the application.",
        any_of=[
            C("_text", "any_regex", [
                r"create\s+(?:login|user)\s+", r"alter\s+(?:login|user|role)\s+",
                r"grant\s+(?:all|dba|sysadmin|superuser|control\s+server)",
                r"sp_addsrvrolemember[^\n]{0,40}sysadmin", r"alter\s+server\s+role[^\n]{0,40}sysadmin",
                r"grant\s+[^\n]{0,40}\s+with\s+grant\s+option", r"create\s+role\s+[^\n]{0,40}superuser",
            ]),
        ],
        keywords=("create login", "create user", "alter login", "grant all", "sysadmin", "superuser",
                  "sp_addsrvrolemember", "with grant option", "control server"),
        group_by=("host.name", "user.name"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=DB_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Create Account",
        mitre_technique_id="T1136",
        risk="A privileged database account is persistence that most remediation misses, because it lives "
             "in the database rather than in the directory or on the filesystem.",
        impact="Continued access to the records after the original entry point is closed, and the ability "
               "to re enable command execution features.",
        recommendation="Validate the change against a change record, remove unauthorised accounts and grants, "
                       "and review the database audit log for what they did. Manage database accounts through "
                       "the directory where possible and alert on privilege grants.",
        references=("https://attack.mitre.org/techniques/T1136/",),
        detail_fields=("host.name", "user.name", "message", "process.command_line"),
    ),
    pattern_rule(
        "net-device-config-change",
        "Network device configuration changed",
        "A router, switch, firewall or VPN concentrator configuration was modified or exported. Device "
        "configurations define the network boundary and contain credential material.",
        any_of=[
            C("_text", "any_regex", [
                r"configured from console", r"%sys-5-config_i", r"running-config",
                r"copy\s+running-config\s+tftp", r"write\s+memory\b", r"configure\s+terminal",
                r"commit\s+(?:force|confirmed)?\s*$", r"set\s+security\s+policies",
                r"config\s+system\s+admin", r"execute\s+backup\s+config",
                r"tacacs|radius[^\n]{0,40}key\s+\d",
            ]),
        ],
        keywords=("running-config", "config_i", "configure terminal", "write memory", "configured from console",
                  "set security policies", "config system admin", "execute backup config"),
        group_by=("host.name", "user.name"),
        severity="high",
        confidence="low",
        category="defense_evasion",
        data_sources=DB_SOURCES + ("network_flow",),
        mitre_tactic="Defense Evasion",
        mitre_technique="Modify System Image",
        mitre_technique_id="T1601",
        risk="Changing the device configuration can open a path through the perimeter, disable logging or "
             "add an administrative account, and exporting it discloses hashed credentials.",
        impact="Loss of the network boundary and of the visibility used to detect what happens next, with "
               "persistence that survives rebuilding every server behind it.",
        recommendation="Compare the configuration against the last approved version and revert unauthorised "
                       "changes, then rotate the device credentials and shared secrets. Restrict management "
                       "access to a dedicated network and alert on every configuration commit.",
        references=("https://attack.mitre.org/techniques/T1601/",),
        detail_fields=("host.name", "user.name", "source.ip", "message"),
    ),
    pattern_rule(
        "vpn-anomalous-access",
        "Remote access session from an unexpected context",
        "A remote access gateway accepted a session from a public address associated with hosting or "
        "anonymising infrastructure, or an account connected from a new country.",
        any_of=[
            C("_text", "any_regex", [
                r"vpn[^\n]{0,40}(?:connected|established|session start)",
                r"tunnel[^\n]{0,20}(?:up|established)",
                r"anyconnect|globalprotect|pulse secure|ivanti connect|fortigate ssl-vpn|openvpn",
            ]),
        ],
        all_of=[C("source.ip", "public_ip", None)],
        keywords=("vpn", "anyconnect", "globalprotect", "pulse secure", "ivanti", "ssl-vpn", "openvpn",
                  "tunnel"),
        group_by=("user.name", "source.ip"),
        severity="medium",
        confidence="low",
        category="initial_access",
        data_sources=DB_SOURCES + ("network_flow",),
        mitre_tactic="Initial Access",
        mitre_technique="External Remote Services",
        mitre_technique_id="T1133",
        risk="Remote access gateways are the most consistently targeted external service, and a valid "
             "credential on one places the attacker inside the network perimeter.",
        impact="Direct network level access to internal systems with no exploit required, which is the "
               "starting point of most ransomware intrusions.",
        recommendation="Confirm the session with the account owner, review what it reached and reset the "
                       "credential if it was not expected. Enforce multi factor authentication and device "
                       "compliance on remote access, and keep the gateway fully patched.",
        references=("https://attack.mitre.org/techniques/T1133/",),
        detail_fields=("user.name", "source.ip", "host.name", "message"),
        max_findings=15,
    ),
]
