"""Windows endpoint and domain detections (Security log, Sysmon, PowerShell)."""

from __future__ import annotations

from .helpers import C, pattern_rule, sequence_rule, stage, threshold_rule

WINDOWS_SOURCES = ("windows_event", "windows_security", "sysmon", "powershell", "generic", "structured", "syslog")

RULES = [
    pattern_rule(
        "win-lsass-credential-dump",
        "Credential dumping attempt against LSASS on {host.name}",
        "A process opened the Local Security Authority Subsystem Service memory or a known credential "
        "dumping utility was executed. This is the standard way attackers harvest plaintext passwords, "
        "NTLM hashes and Kerberos tickets from a compromised host.",
        any_of=[
            C("_text", "any_contains", [
                "mimikatz", "sekurlsa::", "lsadump::", "privilege::debug", "procdump -ma lsass",
                "procdump.exe -ma lsass", "comsvcs.dll, minidump", "comsvcs.dll,minidump",
                "rundll32.exe c:\\windows\\system32\\comsvcs.dll", "invoke-mimikatz", "dumpert",
                "nanodump", "lsass.dmp", "out-minidump",
            ]),
            C("registry.path", "icontains", "wdigest\\useLogonCredential"),
        ],
        keywords=("mimikatz", "sekurlsa", "lsadump", "lsass.dmp", "comsvcs.dll", "procdump", "nanodump", "dumpert", "uselogoncredential"),
        severity="critical",
        confidence="high",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="OS Credential Dumping: LSASS Memory",
        mitre_technique_id="T1003.001",
        risk="An adversary is extracting authentication material from memory, which converts a single "
             "compromised endpoint into domain wide credential access.",
        impact="Stolen hashes and tickets allow pass the hash, pass the ticket and Golden Ticket attacks, "
               "leading to full Active Directory compromise and access to every business system that trusts it.",
        recommendation="Isolate the host immediately, capture memory before shutdown, and force a password reset for "
                       "every account that authenticated to it, including the krbtgt account if domain controllers are "
                       "affected. Enable LSA Protection (RunAsPPL), Credential Guard and attack surface reduction rules "
                       "that block credential theft from LSASS.",
        references=("https://attack.mitre.org/techniques/T1003/001/",),
        detail_fields=("host.name", "user.name", "process.command_line", "process.parent.name"),
    ),
    pattern_rule(
        "win-encoded-powershell",
        "Obfuscated or encoded PowerShell executed on {host.name}",
        "PowerShell was launched with an encoded command, a hidden window or an execution policy bypass. "
        "These switches are rare in day to day administration and are a hallmark of loader and post "
        "exploitation activity.",
        all_of=[C("_text", "any_contains", ["powershell", "pwsh"])],
        any_of=[
            C("_text", "any_regex", [
                r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}",
                r"-e\s+[A-Za-z0-9+/=]{60,}",
                r"-(?:ex|exec|executionpolicy)\s+bypass",
                r"-w(?:indowstyle)?\s+hidden",
                r"-nop(?:rofile)?\b.*-c",
                r"frombase64string",
                r"iex\s*\(",
                r"invoke-expression",
                r"downloadstring",
                r"downloadfile",
                r"-noni",
            ]),
        ],
        keywords=("powershell", "pwsh"),
        severity="high",
        confidence="medium",
        category="execution",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Command and Scripting Interpreter: PowerShell",
        mitre_technique_id="T1059.001",
        risk="Encoded and hidden PowerShell is used to deliver in memory payloads that never touch disk and "
             "therefore evade signature based antivirus.",
        impact="Successful execution gives the attacker arbitrary code execution in the user context, commonly the "
               "first stage of a ransomware or espionage intrusion.",
        recommendation="Decode the command line to establish intent, then hunt for follow on network connections from "
                       "the same process. Enable PowerShell script block logging and module logging, deploy Constrained "
                       "Language Mode where possible and restrict PowerShell to signed scripts for standard users.",
        references=("https://attack.mitre.org/techniques/T1059/001/",),
        detail_fields=("host.name", "user.name", "process.command_line", "process.parent.name"),
    ),
    pattern_rule(
        "win-office-spawns-shell",
        "Office application spawned a command interpreter on {host.name}",
        "A Microsoft Office process created a scripting or command shell child process. Documents do not "
        "normally start shells, so this pattern indicates macro or exploit driven code execution.",
        all_of=[
            C("process.parent.name", "any_regex", [r"^(winword|excel|powerpnt|outlook|msaccess|onenote|visio)\.exe$"]),
            C("process.name", "any_regex", [
                r"^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl|wmic|schtasks)\.exe$"
            ]),
        ],
        keywords=("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"),
        severity="critical",
        confidence="high",
        category="execution",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Phishing: Spearphishing Attachment",
        mitre_technique_id="T1566.001",
        risk="A weaponised document executed code on the endpoint, which is the most common initial access "
             "vector for ransomware and commodity loaders.",
        impact="The attacker gains a foothold with the privileges of the user who opened the document and can "
               "immediately begin discovery, credential theft and lateral movement.",
        recommendation="Retrieve the originating document and mail item, block the sender and the delivery infrastructure, "
                       "and reimage the endpoint if a second stage was downloaded. Deploy the attack surface reduction rule "
                       "that blocks Office applications from creating child processes and disable macros from the internet.",
        references=("https://attack.mitre.org/techniques/T1566/001/",),
        detail_fields=("host.name", "user.name", "process.parent.name", "process.name", "process.command_line"),
    ),
    pattern_rule(
        "win-lolbin-download",
        "Living off the land binary used to download content on {host.name}",
        "A trusted Microsoft signed binary was used to retrieve remote content. Attackers prefer these "
        "utilities because they are allow listed and rarely inspected.",
        any_of=[
            C("_text", "any_regex", [
                r"certutil(?:\.exe)?[^\n]{0,120}(?:-urlcache|-decode|-encode|-verifyctl)",
                r"bitsadmin(?:\.exe)?[^\n]{0,120}(?:/transfer|/addfile)",
                r"mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
                r"regsvr32(?:\.exe)?[^\n]{0,120}(?:/i:https?://|scrobj\.dll)",
                r"rundll32(?:\.exe)?[^\n]{0,120}javascript:",
                r"msiexec(?:\.exe)?[^\n]{0,120}/(?:i|package)\s+https?://",
                r"curl(?:\.exe)?[^\n]{0,120}-o\s",
                r"(?:^|\s)wget(?:\.exe)?\s+https?://",
                r"installutil(?:\.exe)?[^\n]{0,120}/logfile=",
                r"odbcconf(?:\.exe)?[^\n]{0,60}/a\s",
            ]),
        ],
        keywords=("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "msiexec", "installutil", "odbcconf", "curl.exe", "wget.exe"),
        severity="high",
        confidence="medium",
        category="defense_evasion",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="System Binary Proxy Execution",
        mitre_technique_id="T1218",
        risk="Payload delivery through signed system binaries defeats application control policies that trust "
             "the Windows directory.",
        impact="Second stage malware can be staged on the endpoint without triggering conventional download "
               "controls, enabling persistent access.",
        recommendation="Confirm the destination URL and file written to disk, then block the infrastructure at the proxy. "
                       "Apply WDAC or AppLocker rules that constrain these binaries and alert on their use with network "
                       "arguments.",
        references=("https://attack.mitre.org/techniques/T1218/", "https://lolbas-project.github.io/"),
        detail_fields=("host.name", "user.name", "process.command_line", "process.parent.name"),
    ),
    pattern_rule(
        "win-shadow-copy-deletion",
        "Volume shadow copies deleted or recovery disabled on {host.name}",
        "Commands were executed to remove Windows shadow copies, disable the recovery environment or "
        "clear the backup catalogue. This is the final preparation step before ransomware encryption.",
        any_of=[
            C("_text", "any_regex", [
                r"vssadmin(?:\.exe)?[^\n]{0,80}delete\s+shadows",
                r"wmic[^\n]{0,60}shadowcopy[^\n]{0,40}delete",
                r"wbadmin[^\n]{0,60}delete\s+(?:catalog|systemstatebackup|backup)",
                r"bcdedit[^\n]{0,80}(?:recoveryenabled\s+no|ignoreallfailures)",
                r"delete\s+shadows\s+/all",
                r"resize\s+shadowstorage",
                r"powershell[^\n]{0,80}get-wmiobject\s+win32_shadowcopy[^\n]{0,40}delete",
            ]),
        ],
        keywords=("vssadmin", "shadowcopy", "wbadmin", "bcdedit", "shadowstorage", "win32_shadowcopy"),
        severity="critical",
        confidence="high",
        category="impact",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Impact",
        mitre_technique="Inhibit System Recovery",
        mitre_technique_id="T1490",
        risk="Destroying local recovery points removes the cheapest route back from an encryption event and "
             "signals that ransomware deployment is imminent or already underway.",
        impact="Business systems may become unrecoverable without offline backups, extending outage duration from "
               "hours to weeks and increasing extortion leverage.",
        recommendation="Treat this as an active ransomware incident. Isolate the host and its network segment, verify "
                       "the integrity of offline and immutable backups, and start the ransomware playbook. Restrict "
                       "vssadmin and wbadmin to administrators and alert on any use.",
        references=("https://attack.mitre.org/techniques/T1490/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "win-event-log-cleared",
        "Windows event log cleared on {host.name}",
        "An audit log was cleared, either through the Security log clear event or a command line utility. "
        "Legitimate administration almost never requires clearing logs.",
        any_of=[
            C("event.code", "in", ["1102", "104"]),
            C("_text", "any_regex", [
                r"wevtutil(?:\.exe)?\s+cl\s", r"clear-eventlog", r"remove-eventlog",
                r"wevtutil[^\n]{0,40}clear-log",
            ]),
        ],
        keywords=("wevtutil", "clear-eventlog", "remove-eventlog", "audit log was cleared", "the system log file was cleared"),
        event_codes=("1102", "104"),
        severity="critical",
        confidence="high",
        category="defense_evasion",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Indicator Removal: Clear Windows Event Logs",
        mitre_technique_id="T1070.001",
        risk="Anti forensic activity destroys the evidence needed to scope an intrusion and usually follows "
             "hands on keyboard access.",
        impact="Investigators lose the timeline for the affected host, so the true dwell time and the full set of "
               "compromised accounts cannot be established from that endpoint alone.",
        recommendation="Pivot to forwarded copies of the logs in the SIEM, collect the host for forensic imaging and "
                       "review all activity for the account that cleared the log. Enforce Windows Event Forwarding so "
                       "that a local clear does not destroy the only copy.",
        references=("https://attack.mitre.org/techniques/T1070/001/",),
        detail_fields=("host.name", "user.name", "event.code", "process.command_line"),
    ),
    pattern_rule(
        "win-defender-tampering",
        "Endpoint protection disabled or tampered with on {host.name}",
        "Microsoft Defender or another endpoint agent was disabled, exclusions were added or real time "
        "protection was switched off.",
        any_of=[
            C("_text", "any_regex", [
                r"set-mppreference[^\n]{0,120}(?:-disablerealtimemonitoring|-disableioavprotection|-disablebehaviormonitoring)\s*\$?true",
                r"add-mppreference[^\n]{0,80}-exclusionpath",
                r"sc(?:\.exe)?\s+(?:stop|config|delete)\s+(?:windefend|sense|sysmon|mssecflt)",
                r"net\s+stop\s+(?:windefend|sense|sepmasterservice|mcafee)",
                r"disableantispyware",
                r"disablerealtimemonitoring",
                r"uninstall-windowsfeature[^\n]{0,40}windows-defender",
                r"mpcmdrun(?:\.exe)?[^\n]{0,60}-removedefinitions",
            ]),
            C("event.code", "in", ["5001", "5007", "1006"]),
        ],
        keywords=("set-mppreference", "add-mppreference", "disableantispyware", "disablerealtimemonitoring",
                  "windefend", "mpcmdrun", "exclusionpath", "sepmasterservice"),
        severity="high",
        confidence="high",
        category="defense_evasion",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Impair Defenses: Disable or Modify Tools",
        mitre_technique_id="T1562.001",
        risk="Security controls are being removed so that the next stage of the intrusion executes without "
             "detection or prevention.",
        impact="The endpoint stops generating telemetry and stops blocking known malware, which materially "
               "increases the probability of a successful ransomware deployment.",
        recommendation="Restore protection settings through policy, confirm exclusions were not used to hide payload "
                       "directories, and investigate all activity around the change. Enable tamper protection and "
                       "deliver Defender configuration exclusively through managed policy.",
        references=("https://attack.mitre.org/techniques/T1562/001/",),
        detail_fields=("host.name", "user.name", "process.command_line", "event.code"),
    ),
    pattern_rule(
        "win-scheduled-task-persistence",
        "Suspicious scheduled task created on {host.name}",
        "A scheduled task was registered that runs a scripting engine, a binary from a user writable "
        "directory or a command with encoded arguments.",
        any_of=[
            C("_text", "any_regex", [
                r"schtasks(?:\.exe)?[^\n]{0,200}/create",
                r"register-scheduledtask",
                r"new-scheduledtaskaction",
            ]),
            C("event.code", "in", ["4698", "4702"]),
        ],
        keywords=("schtasks", "register-scheduledtask", "new-scheduledtask", "scheduled task"),
        event_codes=("4698", "4702"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Scheduled Task/Job: Scheduled Task",
        mitre_technique_id="T1053.005",
        risk="Scheduled tasks survive reboots and often run as SYSTEM, so they give an attacker durable and "
             "privileged access to the endpoint.",
        impact="Persistence allows the adversary to return after remediation, defeating cleanup that only removes "
               "the running payload.",
        recommendation="Export the task definition, confirm whether the action is legitimate, and remove unauthorised "
                       "tasks across the estate. Baseline scheduled tasks per system role and alert on new tasks that "
                       "invoke interpreters or run from user writable paths.",
        references=("https://attack.mitre.org/techniques/T1053/005/",),
        detail_fields=("host.name", "user.name", "process.command_line", "event.code"),
    ),
    pattern_rule(
        "win-run-key-persistence",
        "Autorun registry key modified on {host.name}",
        "A registry value was written under a Run, RunOnce, Winlogon or Image File Execution Options key. "
        "These locations start code automatically at logon or when a program is launched.",
        any_of=[
            C("registry.path", "any_regex", [
                r"currentversion\\\\?run", r"currentversion\\\\?runonce", r"winlogon\\\\?(?:shell|userinit)",
                r"image file execution options", r"currentversion\\\\?policies\\\\?explorer\\\\?run",
            ]),
            C("_text", "any_regex", [
                r"reg(?:\.exe)?\s+add[^\n]{0,160}currentversion\\+run",
                r"new-itemproperty[^\n]{0,160}currentversion\\+run",
                r"set-itemproperty[^\n]{0,160}\\+run\b",
                r"image file execution options\\+[^\n]{0,60}debugger",
            ]),
        ],
        keywords=("currentversion\\run", "currentversion\\runonce", "image file execution options", "userinit", "winlogon\\shell"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Boot or Logon Autostart Execution: Registry Run Keys",
        mitre_technique_id="T1547.001",
        risk="Autorun persistence re establishes attacker access every time the user logs on, and Image File "
             "Execution Options entries can also hijack legitimate binaries.",
        impact="The intrusion survives password resets and malware removal, extending dwell time and the window "
               "for data theft.",
        recommendation="Capture the value data, verify the referenced binary, and remove unauthorised entries. Monitor "
                       "autorun locations centrally and restrict write access to them with endpoint policy.",
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        detail_fields=("host.name", "user.name", "registry.path", "registry.value", "process.command_line"),
    ),
    pattern_rule(
        "win-service-installed",
        "New Windows service installed on {host.name}",
        "A service was installed on the host. Remote execution frameworks such as PsExec and many "
        "implants create a service to obtain SYSTEM privileges.",
        any_of=[
            C("event.code", "in", ["7045", "4697"]),
            C("_text", "any_regex", [r"sc(?:\.exe)?\s+create\s", r"new-service\s"]),
        ],
        keywords=("service was installed", "sc create", "new-service", "psexesvc", "service name"),
        event_codes=("7045", "4697"),
        severity="medium",
        confidence="medium",
        category="persistence",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Create or Modify System Process: Windows Service",
        mitre_technique_id="T1543.003",
        risk="Services run as SYSTEM and start automatically, so an unauthorised service is both privileged "
             "persistence and a common lateral movement artefact.",
        impact="An attacker retains SYSTEM level access to the host and can use it as a staging point for the rest "
               "of the estate.",
        recommendation="Compare the service binary path against a known good baseline, remove unauthorised services and "
                       "check neighbouring hosts for the same service name. Alert on service creation from non "
                       "management accounts.",
        references=("https://attack.mitre.org/techniques/T1543/003/",),
        detail_fields=("host.name", "user.name", "service.name", "process.command_line", "event.code"),
    ),
    pattern_rule(
        "win-psexec-lateral",
        "Remote execution utility observed on {host.name}",
        "Artefacts of a remote execution tool such as PsExec, PAExec, wmiexec or smbexec were found. "
        "These tools move an attacker between systems using stolen credentials.",
        any_of=[
            C("_text", "any_contains", [
                "psexesvc", "psexec.exe", "paexec", "remcomsvc", "csexec", "wmiexec", "smbexec",
                "atexec", "dcomexec", "\\\\admin$", "\\\\ipc$", "-accepteula",
            ]),
            C("service.name", "any_contains", ["psexesvc", "paexec", "remcom"]),
        ],
        keywords=("psexesvc", "psexec", "paexec", "remcomsvc", "wmiexec", "smbexec", "atexec", "dcomexec", "admin$"),
        severity="high",
        confidence="medium",
        category="lateral_movement",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Lateral Movement",
        mitre_technique="Remote Services: SMB/Windows Admin Shares",
        mitre_technique_id="T1021.002",
        risk="Interactive remote execution indicates hands on keyboard movement with valid credentials rather "
             "than automated malware.",
        impact="The adversary can reach file servers, domain controllers and backup infrastructure, which is the "
               "precondition for estate wide encryption or mass data theft.",
        recommendation="Identify the source host and the account used, reset that account and review its full session "
                       "history. Restrict administrative share access with host firewalls, deploy the Local "
                       "Administrator Password Solution and enforce tiered administration.",
        references=("https://attack.mitre.org/techniques/T1021/002/",),
        detail_fields=("host.name", "user.name", "source.ip", "service.name", "process.command_line"),
    ),
    pattern_rule(
        "win-wmi-remote-execution",
        "Remote process creation through WMI on {host.name}",
        "WMI was used to create a process, either locally with wmic or remotely against another host. "
        "WMI execution leaves few artefacts and is favoured for stealthy lateral movement.",
        any_of=[
            C("_text", "any_regex", [
                r"wmic(?:\.exe)?[^\n]{0,120}/node:", r"wmic(?:\.exe)?[^\n]{0,80}process\s+call\s+create",
                r"invoke-wmimethod[^\n]{0,80}(?:-class\s+win32_process|create)",
                r"invoke-cimmethod[^\n]{0,80}win32_process",
                r"win32_process[^\n]{0,40}create",
            ]),
            C("process.parent.name", "eq", "wmiprvse.exe"),
        ],
        keywords=("wmic", "win32_process", "invoke-wmimethod", "invoke-cimmethod", "wmiprvse.exe"),
        severity="high",
        confidence="medium",
        category="lateral_movement",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Windows Management Instrumentation",
        mitre_technique_id="T1047",
        risk="WMI process creation is a fileless execution channel that bypasses controls focused on binaries "
             "written to disk.",
        impact="An attacker can execute code on many hosts in seconds, accelerating the spread of an intrusion "
               "across the domain.",
        recommendation="Review the parent and child processes for the WMI activity and correlate with logons from the "
                       "same account. Enable WMI activity tracing, restrict remote WMI to a management tier and alert on "
                       "wmiprvse.exe spawning interpreters.",
        references=("https://attack.mitre.org/techniques/T1047/",),
        detail_fields=("host.name", "user.name", "process.command_line", "process.parent.name"),
    ),
    pattern_rule(
        "win-ntds-extraction",
        "Active Directory database extraction attempt on {host.name}",
        "Commands consistent with copying the NTDS.dit domain database or creating a shadow copy of the "
        "system drive to extract it were observed.",
        any_of=[
            C("_text", "any_regex", [
                r"ntdsutil[^\n]{0,120}(?:ifm|create\s+full)", r"ntds\.dit",
                r"vssadmin[^\n]{0,60}create\s+shadow[^\n]{0,60}/for=c:",
                r"esentutl[^\n]{0,80}/y[^\n]{0,60}ntds",
                r"secretsdump", r"diskshadow[^\n]{0,60}/s",
            ]),
        ],
        keywords=("ntdsutil", "ntds.dit", "secretsdump", "diskshadow", "esentutl", "create full"),
        severity="critical",
        confidence="high",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="OS Credential Dumping: NTDS",
        mitre_technique_id="T1003.003",
        risk="Extraction of NTDS.dit hands the attacker every password hash in the domain, including service "
             "and administrative accounts.",
        impact="Complete and persistent compromise of the identity plane. Recovery requires a domain wide credential "
               "reset and a double reset of the krbtgt account.",
        recommendation="Declare a major incident, isolate the domain controller, and plan an Active Directory recovery "
                       "with two krbtgt resets. Restrict Domain Controller logon rights, monitor for volume shadow copy "
                       "creation on controllers and alert on any ntdsutil use.",
        references=("https://attack.mitre.org/techniques/T1003/003/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "win-dcsync",
        "Directory replication rights used from a non controller account",
        "Directory service access consistent with DCSync was observed, where an account requested "
        "replication of secrets from a domain controller.",
        any_of=[
            C("_text", "any_contains", [
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                "89e95b76-444d-4c62-991a-0facbeda640c", "lsadump::dcsync", "drsuapi", "getnc",
            ]),
        ],
        keywords=("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                  "dcsync", "drsuapi", "89e95b76-444d-4c62-991a-0facbeda640c"),
        severity="critical",
        confidence="high",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="OS Credential Dumping: DCSync",
        mitre_technique_id="T1003.006",
        risk="An account is impersonating a domain controller to replicate password hashes, which is a direct "
             "path to Golden Ticket forgery.",
        impact="Full domain compromise with the ability to authenticate as any user, including after passwords "
               "are changed, until the krbtgt key is reset twice.",
        recommendation="Identify and disable the calling account, reset krbtgt twice with the recommended interval and "
                       "audit all accounts holding replication rights. Alert permanently on directory replication from "
                       "any principal that is not a domain controller computer account.",
        references=("https://attack.mitre.org/techniques/T1003/006/",),
        detail_fields=("host.name", "user.name", "source.ip", "event.code"),
    ),
    pattern_rule(
        "win-kerberoasting-ticket",
        "Kerberos service ticket requested with weak encryption",
        "A Kerberos service ticket was issued with RC4 encryption for a service account, the pattern "
        "produced by Kerberoasting tools that harvest tickets for offline cracking.",
        all_of=[
            C("event.code", "eq", "4769"),
            C("_text", "any_contains", ["0x17", "0x18", "rc4"]),
        ],
        none_of=[C("_text", "icontains", "krbtgt")],
        keywords=("4769", "ticketencryptiontype"),
        event_codes=("4769",),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Steal or Forge Kerberos Tickets: Kerberoasting",
        mitre_technique_id="T1558.003",
        risk="RC4 service tickets can be cracked offline to recover the plaintext password of the service "
             "account, frequently a privileged account with a static password.",
        impact="Compromise of service accounts often provides administrative access to databases, application "
               "servers and sometimes the domain itself.",
        recommendation="Identify the requested service principal names, rotate those account passwords to at least 25 "
                       "random characters and migrate them to group Managed Service Accounts. Disable RC4 for Kerberos "
                       "and alert on high volumes of 4769 events from a single account.",
        references=("https://attack.mitre.org/techniques/T1558/003/",),
        detail_fields=("host.name", "user.name", "source.ip", "service.name"),
    ),
    pattern_rule(
        "win-asrep-roasting",
        "Kerberos pre authentication disabled account requested",
        "A ticket granting ticket was requested for an account that does not require Kerberos pre "
        "authentication, which allows offline cracking of the account password.",
        all_of=[C("event.code", "eq", "4768")],
        any_of=[C("_text", "any_contains", ["0x0", "preauthtype: 0", "pre-authentication type: 0"])],
        keywords=("4768", "preauthtype"),
        event_codes=("4768",),
        severity="medium",
        confidence="low",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Steal or Forge Kerberos Tickets: AS-REP Roasting",
        mitre_technique_id="T1558.004",
        risk="Accounts without Kerberos pre authentication expose an encrypted blob that can be cracked "
             "offline without any failed logon being recorded.",
        impact="Password recovery for these accounts gives the attacker valid credentials and a quiet route into "
               "the domain.",
        recommendation="Enumerate accounts with pre authentication disabled, re enable it wherever possible and rotate "
                       "the affected passwords. Where the setting must remain, enforce long random passwords and "
                       "monitor ticket requests closely.",
        references=("https://attack.mitre.org/techniques/T1558/004/",),
        detail_fields=("host.name", "user.name", "source.ip"),
    ),
    pattern_rule(
        "win-uac-bypass",
        "User Account Control bypass technique on {host.name}",
        "Registry or process artefacts associated with known User Account Control bypasses were observed, "
        "such as fodhelper, eventvwr, sdclt or computerdefaults hijacks.",
        any_of=[
            C("_text", "any_regex", [
                r"software\\+classes\\+ms-settings\\+shell\\+open\\+command",
                r"software\\+classes\\+mscfile\\+shell\\+open\\+command",
                r"software\\+classes\\+exefile\\+shell\\+runas\\+command\\+isolatedcommand",
                r"fodhelper(?:\.exe)?", r"computerdefaults(?:\.exe)?", r"sdclt(?:\.exe)?\s+/kickoffelev",
                r"eventvwr(?:\.exe)?[^\n]{0,40}mmc", r"cmstp(?:\.exe)?[^\n]{0,40}/s",
                r"delegateexecute",
            ]),
        ],
        keywords=("fodhelper", "computerdefaults", "ms-settings\\shell", "mscfile\\shell", "delegateexecute",
                  "eventvwr", "cmstp", "sdclt"),
        severity="high",
        confidence="medium",
        category="privilege_escalation",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Abuse Elevation Control Mechanism: Bypass User Account Control",
        mitre_technique_id="T1548.002",
        risk="The attacker is elevating from a standard user token to full administrator without prompting "
             "the user.",
        impact="Administrative rights on the endpoint enable credential theft, security tool tampering and "
               "installation of persistent implants.",
        recommendation="Remove the hijacked registry values, verify the elevated process and review what ran afterwards. "
                       "Set User Account Control to always prompt on the secure desktop and remove local administrator "
                       "rights from standard users.",
        references=("https://attack.mitre.org/techniques/T1548/002/",),
        detail_fields=("host.name", "user.name", "registry.path", "process.command_line"),
    ),
    pattern_rule(
        "win-suspicious-parent-child",
        "Anomalous process lineage on {host.name}",
        "A system process created a child that it never spawns during normal operation, for example "
        "services.exe launching a script interpreter or a browser spawning a shell.",
        any_of=[
            C("_text", "any_regex", [
                r"(?:w3wp|httpd|nginx|tomcat|java)\.exe[^\n]{0,200}(?:cmd|powershell|pwsh|bash)\.exe",
                r"(?:sqlservr)\.exe[^\n]{0,200}(?:cmd|powershell)\.exe",
                r"(?:chrome|firefox|msedge|iexplore)\.exe[^\n]{0,200}(?:cmd|powershell|wscript|cscript|mshta)\.exe",
                r"(?:spoolsv|lsass|svchost)\.exe[^\n]{0,200}(?:cmd|powershell|net|whoami)\.exe",
            ]),
        ],
        keywords=("w3wp.exe", "sqlservr.exe", "spoolsv.exe", "tomcat", "httpd.exe", "nginx.exe"),
        severity="high",
        confidence="medium",
        category="execution",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Command and Scripting Interpreter",
        mitre_technique_id="T1059",
        risk="A server or browser process executing a shell is the classic signature of web shell activity or "
             "successful exploitation of a service.",
        impact="Remote code execution on an internet facing service gives the attacker an entry point that "
               "bypasses perimeter controls entirely.",
        recommendation="Inspect the web root and application directories for recently written script files, review "
                       "requests to the service around the timestamp and patch the exposed application. Run web "
                       "services under least privilege service accounts.",
        references=("https://attack.mitre.org/techniques/T1059/",),
        detail_fields=("host.name", "process.parent.name", "process.name", "process.command_line"),
    ),
    pattern_rule(
        "win-discovery-commands",
        "Host and domain discovery commands executed on {host.name}",
        "Reconnaissance commands typical of the first minutes of hands on keyboard access were executed, "
        "for example whoami, net group domain admins, nltest and systeminfo.",
        any_of=[
            C("_text", "any_regex", [
                r"\bwhoami(?:\.exe)?\s+/(?:all|groups|priv)",
                r"net(?:1)?\s+group\s+\"?domain admins",
                r"net(?:1)?\s+localgroup\s+administrators",
                r"nltest[^\n]{0,60}/(?:domain_trusts|dclist|trusted_domains)",
                r"\bsysteminfo(?:\.exe)?\b",
                r"\bnet(?:1)?\s+view\s+/domain",
                r"adfind(?:\.exe)?", r"\bdsquery\b", r"\bbloodhound\b", r"sharphound",
                r"get-adcomputer", r"get-aduser[^\n]{0,40}-filter", r"get-domain(?:controller|user|computer)",
                r"\bquser\b", r"\btasklist\s+/v\b", r"\barp\s+-a\b", r"\bipconfig\s+/all\b",
            ]),
        ],
        keywords=("whoami", "net group", "nltest", "systeminfo", "adfind", "dsquery", "bloodhound",
                  "sharphound", "get-adcomputer", "get-aduser", "quser", "net view", "localgroup administrators"),
        severity="medium",
        confidence="medium",
        category="discovery",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Discovery",
        mitre_technique="System Owner/User Discovery",
        mitre_technique_id="T1033",
        risk="Rapid enumeration of users, groups and trusts indicates an operator mapping the environment "
             "before choosing a lateral movement path.",
        impact="Discovery output tells the attacker which accounts to target for privilege escalation, shortening "
               "the time from foothold to domain compromise.",
        recommendation="Establish whether the account normally performs administration, then review the full command "
                       "history for that session. Restrict discovery tooling on workstations and alert on clusters of "
                       "enumeration commands from a single user in a short window.",
        references=("https://attack.mitre.org/techniques/T1033/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
        max_findings=15,
    ),
    pattern_rule(
        "win-remote-admin-account-created",
        "Privileged group membership change",
        "An account was added to a privileged group such as Domain Admins, Enterprise Admins or the local "
        "Administrators group.",
        any_of=[
            C("event.code", "in", ["4728", "4732", "4756"]),
            C("_text", "any_regex", [
                r"net(?:1)?\s+localgroup\s+administrators[^\n]{0,60}/add",
                r"net(?:1)?\s+group\s+\"?domain admins\"?[^\n]{0,60}/add",
                r"add-adgroupmember[^\n]{0,80}(?:domain admins|enterprise admins)",
            ]),
        ],
        keywords=("4728", "4732", "4756", "domain admins", "enterprise admins", "localgroup administrators",
                  "add-adgroupmember", "a member was added to a security-enabled"),
        event_codes=("4728", "4732", "4756"),
        severity="high",
        confidence="medium",
        category="privilege_escalation",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation",
        mitre_technique_id="T1098",
        risk="Adding an account to a privileged group is both a privilege escalation and a persistence "
             "mechanism that survives the loss of the original foothold.",
        impact="The attacker keeps administrative control of the domain or the endpoint even after the initial "
               "malware is removed.",
        recommendation="Validate the change against the change management record, remove unauthorised membership and "
                       "reset the affected accounts. Enforce approval workflows and time bound elevation for privileged "
                       "group membership.",
        references=("https://attack.mitre.org/techniques/T1098/",),
        detail_fields=("host.name", "user.name", "user.target", "event.code"),
    ),
    pattern_rule(
        "win-rdp-external-source",
        "Remote desktop logon from a public address",
        "A remote interactive logon originated from an address outside the private ranges, meaning the "
        "remote desktop service is reachable from the internet or through a compromised tunnel.",
        all_of=[
            C("logon.type", "eq", "10"),
            C("source.ip", "public_ip", None),
        ],
        keywords=("4624", "logontype", "remoteinteractive"),
        severity="high",
        confidence="medium",
        category="initial_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="External Remote Services",
        mitre_technique_id="T1133",
        risk="Directly exposed remote desktop is one of the most common ransomware entry points and is "
             "constantly targeted by credential stuffing.",
        impact="A single valid credential gives an attacker a full interactive desktop session inside the network "
               "with no exploit required.",
        recommendation="Verify whether the session was authorised, then remove direct exposure by placing remote desktop "
                       "behind a VPN or gateway with multi factor authentication. Enforce network level authentication "
                       "and account lockout policies.",
        references=("https://attack.mitre.org/techniques/T1133/",),
        detail_fields=("host.name", "user.name", "source.ip", "logon.type_name"),
    ),
    pattern_rule(
        "win-pass-the-hash-indicator",
        "Network logon with NTLM from a workstation account pattern",
        "A network logon used NTLM with a logon process associated with credential replay tooling rather "
        "than an interactive user session.",
        all_of=[C("event.code", "in", ["4624", "4776"])],
        any_of=[
            C("_text", "any_contains", ["seclogo", "ntlmssp", "logon process: ntlmssp"]),
            C("logon.type", "eq", "9"),
        ],
        keywords=("ntlmssp", "seclogo", "4776", "newcredentials"),
        event_codes=("4624", "4776"),
        severity="medium",
        confidence="low",
        category="lateral_movement",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Lateral Movement",
        mitre_technique="Use Alternate Authentication Material: Pass the Hash",
        mitre_technique_id="T1550.002",
        risk="Authentication using a hash rather than a password lets an attacker move laterally without ever "
             "knowing the plaintext credential.",
        impact="Lateral movement continues even after users change passwords if the underlying hash has not been "
               "invalidated, prolonging attacker access.",
        recommendation="Correlate with the source host, confirm whether the account should authenticate there and reset "
                       "the credential. Restrict NTLM where possible, enable Credential Guard and enforce tiered "
                       "administration so privileged hashes never reach workstations.",
        references=("https://attack.mitre.org/techniques/T1550/002/",),
        detail_fields=("host.name", "user.name", "source.ip", "logon.type"),
        max_findings=10,
    ),
    threshold_rule(
        "win-failed-logon-burst",
        "Password attack against {host.name}",
        "{count} failed logon attempts were recorded for the same target within the correlation window, "
        "which is consistent with password guessing or brute force.",
        all_of=[C("event.code", "eq", "4625")],
        group_by=("host.name", "source.ip"),
        min_count=15,
        window_seconds=600,
        keywords=("4625",),
        event_codes=("4625",),
        severity="high",
        confidence="high",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        risk="Sustained authentication failures indicate an active attempt to guess credentials against the "
             "environment.",
        impact="A single weak or reused password results in a valid foothold, and the attempt volume also risks "
               "locking out legitimate users and causing an availability incident.",
        recommendation="Block the source address, confirm no account eventually succeeded and check the targeted "
                       "accounts for weak passwords. Enforce account lockout, multi factor authentication and modern "
                       "password policy with a banned password list.",
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    threshold_rule(
        "win-password-spray",
        "Password spraying against multiple accounts from {source.ip}",
        "A single source generated failed logons against {count} distinct accounts, the signature of a "
        "password spray that stays under per account lockout thresholds.",
        all_of=[C("event.code", "in", ["4625", "4771"])],
        group_by=("source.ip",),
        distinct_field="user.name",
        min_count=8,
        window_seconds=1800,
        keywords=("4625", "4771"),
        event_codes=("4625", "4771"),
        severity="high",
        confidence="high",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force: Password Spraying",
        mitre_technique_id="T1110.003",
        risk="Spraying a common password across many accounts reliably finds at least one weak credential "
             "while avoiding lockout based detection.",
        impact="A successful spray produces valid credentials for an account that is unlikely to be monitored, "
               "giving quiet initial access to the network.",
        recommendation="Block the source, review whether any of the sprayed accounts later authenticated successfully "
                       "and force password resets for those accounts. Deploy multi factor authentication on all remote "
                       "authentication paths and alert on failures spread across many accounts from one source.",
        references=("https://attack.mitre.org/techniques/T1110/003/",),
    ),
    threshold_rule(
        "win-kerberoast-volume",
        "High volume of Kerberos service ticket requests by {user.name}",
        "A single account requested {count} distinct service tickets in a short period, which matches "
        "automated Kerberoasting rather than normal application access.",
        all_of=[C("event.code", "eq", "4769")],
        group_by=("user.name",),
        distinct_field="service.name",
        min_count=10,
        window_seconds=600,
        keywords=("4769",),
        event_codes=("4769",),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Steal or Forge Kerberos Tickets: Kerberoasting",
        mitre_technique_id="T1558.003",
        risk="Bulk ticket collection provides offline crackable material for every service account in the "
             "domain.",
        impact="Service account compromise frequently yields administrative access to critical applications and "
               "sometimes to the domain itself.",
        recommendation="Reset the passwords of the targeted service accounts with long random values, prefer group "
                       "Managed Service Accounts and disable RC4. Investigate the requesting account as compromised.",
        references=("https://attack.mitre.org/techniques/T1558/003/",),
    ),
    threshold_rule(
        "win-account-lockout-storm",
        "Account lockout storm affecting the estate",
        "{count} account lockouts were recorded in the window, which indicates either an aggressive "
        "credential attack or credential replay from a compromised system.",
        all_of=[C("event.code", "eq", "4740")],
        group_by=("host.name",),
        min_count=5,
        window_seconds=900,
        keywords=("4740",),
        event_codes=("4740",),
        severity="medium",
        confidence="medium",
        category="credential_access",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        risk="Mass lockouts are both a symptom of an ongoing credential attack and a denial of service against "
             "the affected users.",
        impact="Business operations are disrupted while the security team investigates, and the noise can mask a "
               "successful authentication hidden in the volume.",
        recommendation="Identify the calling computer for the lockouts, isolate it if it is replaying stale credentials "
                       "and confirm no successful logon followed. Tune lockout thresholds and monitor the source of "
                       "lockout events centrally.",
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    sequence_rule(
        "win-intrusion-chain",
        "Intrusion chain observed on {host.name}",
        "A successful logon was followed by discovery activity and then by credential access or "
        "persistence on the same host, which is the classic progression of a hands on keyboard intrusion.",
        stages=[
            stage("Authentication", any_of=[
                C("event.code", "in", ["4624", "4648"]),
                C("event.action", "in", ["ssh_login", "logon_success"]),
            ]),
            stage("Discovery", any_of=[
                C("_text", "any_regex", [r"\bwhoami\b", r"net(?:1)?\s+group", r"\bnltest\b", r"\bsysteminfo\b", r"net(?:1)?\s+view"]),
            ]),
            stage("Credential access or persistence", any_of=[
                C("_text", "any_contains", ["mimikatz", "lsass", "vssadmin", "schtasks /create", "sc create",
                                            "reg add", "currentversion\\run", "ntdsutil"]),
            ]),
        ],
        group_by=("host.name",),
        window_seconds=7200,
        keywords=("whoami", "net group", "nltest", "systeminfo", "mimikatz", "lsass", "vssadmin",
                  "schtasks", "sc create", "reg add", "ntdsutil", "4624", "4648", "net view"),
        event_codes=("4624", "4648"),
        severity="critical",
        confidence="high",
        category="attack_chain",
        data_sources=WINDOWS_SOURCES,
        mitre_tactic="Multiple",
        mitre_technique="Attack chain correlation",
        mitre_technique_id="T1078",
        risk="Several stages of the attack lifecycle were observed for the same host inside one window, which "
             "raises confidence far above any single indicator.",
        impact="The environment is likely to be facing an active intrusion rather than isolated noise, with a "
               "credible path to domain compromise or ransomware.",
        recommendation="Treat this host as compromised. Isolate it, preserve volatile evidence, reset the credentials "
                       "used in the session and start a scoped incident response covering every host the account "
                       "touched.",
        references=("https://attack.mitre.org/",),
    ),
]
