"""Linux and Unix host detections."""

from __future__ import annotations

from .helpers import C, pattern_rule, sequence_rule, stage, threshold_rule

LINUX_SOURCES = ("linux_auth", "syslog", "generic", "structured", "security_appliance")

RULES = [
    threshold_rule(
        "nix-ssh-brute-force",
        "SSH brute force against {host.name} from {source.ip}",
        "{count} failed SSH authentication attempts arrived from the same address inside the window.",
        any_of=[
            C("event.action", "in", ["ssh_login", "ssh_invalid_user", "pam_auth_failure"]),
            C("_text", "any_contains", ["failed password", "invalid user", "authentication failure"]),
        ],
        all_of=[C("event.outcome", "eq", "failure")],
        group_by=("host.name", "source.ip"),
        min_count=12,
        window_seconds=600,
        keywords=("failed password", "invalid user", "authentication failure", "ssh"),
        severity="high",
        confidence="high",
        category="credential_access",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        risk="An external or internal source is systematically guessing SSH credentials against the host.",
        impact="A weak or reused password results in shell access to the server, from which an attacker can "
               "escalate privileges and pivot into the internal network.",
        recommendation="Block the source address, disable password authentication in favour of keys and enforce "
                       "multi factor authentication for administrative access. Deploy fail2ban or an equivalent "
                       "rate limiter and confirm no session was eventually accepted.",
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    pattern_rule(
        "nix-successful-login-after-failures",
        "SSH login accepted for {user.name} from {source.ip}",
        "An SSH session was accepted. When it follows a burst of failures from the same source it "
        "indicates a successful brute force.",
        all_of=[
            C("event.action", "eq", "ssh_login"),
            C("event.outcome", "eq", "success"),
        ],
        any_of=[C("source.ip", "public_ip", None)],
        group_by=("host.name", "user.name", "source.ip"),
        keywords=("accepted password", "accepted publickey"),
        severity="medium",
        confidence="medium",
        category="initial_access",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="External Remote Services",
        mitre_technique_id="T1133",
        risk="Interactive shell access from a public address bypasses the network perimeter and is a frequent "
             "starting point for server compromise.",
        impact="An attacker with shell access can install persistence, harvest credentials and use the server as a "
               "pivot into internal segments.",
        recommendation="Verify the session against approved administration, restrict SSH exposure to a bastion or VPN "
                       "and enforce key based authentication with multi factor. Review the shell history for the "
                       "session.",
        references=("https://attack.mitre.org/techniques/T1133/",),
    ),
    pattern_rule(
        "nix-reverse-shell",
        "Reverse shell command executed on {host.name}",
        "A command line matching a known reverse shell one liner was executed, giving an attacker "
        "interactive control of the host over an outbound connection.",
        any_of=[
            C("_text", "any_regex", [
                r"bash\s+-i\s*>&\s*/dev/tcp/", r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
                r"nc(?:\.traditional)?\s+(?:-[a-z]*e[a-z]*\s+)?\S+\s+\d+\s*(?:-e\s*/bin/(?:ba)?sh)?",
                r"ncat\s+[^\n]{0,60}--exec", r"socat\s+[^\n]{0,60}exec:",
                r"python[0-9.]*\s+-c\s+['\"]?import\s+socket",
                r"perl\s+-e\s+['\"]?use\s+socket", r"php\s+-r\s+['\"]?\$sock\s*=\s*fsockopen",
                r"ruby\s+-rsocket", r"mkfifo\s+/tmp/\w+;\s*(?:cat|nc)",
                r"sh\s+-i\s*>&\s*/dev/tcp",
            ]),
        ],
        keywords=("/dev/tcp/", "mkfifo", "fsockopen", "-rsocket", "socat", "ncat", "bash -i", "nc -e"),
        severity="critical",
        confidence="high",
        category="command_and_control",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol",
        mitre_technique_id="T1071",
        risk="A reverse shell provides direct interactive control of the server from attacker infrastructure, "
             "traversing outbound firewall rules that are usually permissive.",
        impact="Complete compromise of the host and any data or credentials it holds, plus a stable pivot into "
               "adjacent network segments.",
        recommendation="Isolate the host, capture the process tree and network connections, and identify the "
                       "originating vulnerability or credential. Enforce egress filtering so servers cannot open "
                       "arbitrary outbound connections.",
        references=("https://attack.mitre.org/techniques/T1071/",),
        detail_fields=("host.name", "user.name", "process.command_line", "destination.ip"),
    ),
    pattern_rule(
        "nix-persistence-cron",
        "Scheduled job or startup persistence created on {host.name}",
        "A cron entry, systemd unit or shell profile was modified in a way that runs code automatically.",
        any_of=[
            C("_text", "any_regex", [
                r"crontab\s+-[el]?\s*[^\n]{0,40}(?:/tmp|/dev/shm|curl|wget|base64)",
                r"echo[^\n]{0,120}>>\s*/etc/cron", r"/etc/cron\.(?:d|daily|hourly)/[\w.-]+",
                r"systemctl\s+(?:enable|start)\s+[\w.-]+\.service",
                r">>\s*(?:~|/root|/home/[\w.-]+)/\.(?:bashrc|bash_profile|profile|zshrc)",
                r"/etc/rc\.local", r"/etc/init\.d/", r"systemd/system/[\w.-]+\.service",
                r"@reboot\s",
            ]),
        ],
        keywords=("crontab", "/etc/cron", "rc.local", "systemd/system", "@reboot", ".bashrc", "init.d"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Scheduled Task/Job: Cron",
        mitre_technique_id="T1053.003",
        risk="Automatic execution at boot or on a schedule means the attacker keeps access after the host is "
             "restarted or the running payload is killed.",
        impact="Remediation that only removes the active process leaves the intrusion intact, so the attacker "
               "returns within minutes.",
        recommendation="Review and remove unauthorised cron entries, systemd units and shell profile modifications, then "
                       "confirm what the referenced script does. Monitor these paths with file integrity monitoring.",
        references=("https://attack.mitre.org/techniques/T1053/003/",),
        detail_fields=("host.name", "user.name", "process.command_line", "file.path"),
    ),
    pattern_rule(
        "nix-privilege-escalation",
        "Privilege escalation attempt on {host.name}",
        "Commands associated with local privilege escalation were executed, such as setuid searches, "
        "sudo abuse or known escalation helpers.",
        any_of=[
            C("_text", "any_regex", [
                r"find\s+/[^\n]{0,60}-perm\s+[-+/]?[24]000",
                r"chmod\s+[u+]?s\s", r"chmod\s+4755", r"sudo\s+-l\b",
                r"pkexec[^\n]{0,40}", r"dirtypipe", r"dirtycow", r"linpeas", r"linenum",
                r"echo[^\n]{0,60}>>\s*/etc/sudoers", r"usermod\s+-aG\s+(?:sudo|wheel|root)",
                r"nsenter\s+[^\n]{0,40}--target\s+1",
                r"docker\s+run[^\n]{0,80}(?:--privileged|-v\s+/:/)",
            ]),
        ],
        keywords=("-perm -4000", "sudoers", "pkexec", "dirtypipe", "dirtycow", "linpeas", "usermod -ag",
                  "nsenter", "--privileged", "chmod 4755", "sudo -l"),
        severity="high",
        confidence="medium",
        category="privilege_escalation",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Abuse Elevation Control Mechanism",
        mitre_technique_id="T1548",
        risk="The attacker is attempting to move from a limited service account to root, which removes every "
             "remaining containment boundary on the host.",
        impact="Root access allows tampering with logs, installation of kernel level persistence and theft of all "
               "secrets stored on the system.",
        recommendation="Patch the kernel and affected packages, review sudoers for unsafe entries and audit setuid "
                       "binaries. Run services under dedicated unprivileged accounts and enable auditd rules for "
                       "escalation attempts.",
        references=("https://attack.mitre.org/techniques/T1548/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "nix-history-tampering",
        "Shell history or log tampering on {host.name}",
        "Commands were executed that disable or destroy shell history and system logs, an anti forensic "
        "step taken by interactive intruders.",
        any_of=[
            C("_text", "any_regex", [
                r"history\s+-c", r"unset\s+HISTFILE", r"export\s+HISTSIZE=0", r"HISTFILE=/dev/null",
                r"rm\s+-rf?\s+[^\n]{0,40}\.bash_history", r">\s*/var/log/(?:auth\.log|secure|messages|wtmp|btmp)",
                r"shred\s+[^\n]{0,40}/var/log", r"truncate\s+-s\s*0\s+/var/log",
                r"journalctl\s+--vacuum-time=1s", r"rm\s+-rf?\s+/var/log/",
            ]),
        ],
        keywords=("history -c", "histfile", "bash_history", "/var/log/auth.log", "shred", "vacuum-time", "histsize"),
        severity="high",
        confidence="high",
        category="defense_evasion",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Indicator Removal",
        mitre_technique_id="T1070",
        risk="Deliberate destruction of audit trails indicates a human operator covering their tracks after "
             "hands on activity.",
        impact="The investigation loses the ability to reconstruct what the attacker did on the host, which "
               "prevents accurate scoping and increases the chance of missed persistence.",
        recommendation="Preserve the host for forensic imaging, pivot to centrally forwarded copies of the logs and "
                       "treat the system as fully compromised. Ship logs off host in real time and make history files "
                       "append only.",
        references=("https://attack.mitre.org/techniques/T1070/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "nix-account-creation",
        "New privileged local account created on {host.name}",
        "A local account was created or added to an administrative group, which provides durable access "
        "independent of the original compromise vector.",
        any_of=[
            C("event.action", "eq", "user_created"),
            C("_text", "any_regex", [
                r"useradd\s", r"adduser\s", r"new user:\s*name=",
                r"usermod\s+-aG\s+(?:sudo|wheel|admin|root)",
                r"passwd\s+(?:root|admin)\b",
            ]),
        ],
        keywords=("useradd", "adduser", "new user:", "usermod -ag", "group added to"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Create Account: Local Account",
        mitre_technique_id="T1136.001",
        risk="A rogue local account is a quiet persistence mechanism that survives patching and password "
             "resets on other accounts.",
        impact="The attacker retains legitimate looking access to the server long after the initial vulnerability "
               "is closed.",
        recommendation="Verify the account against change records, disable it if unauthorised and review its command "
                       "history and SSH keys. Centralise identity so local accounts are the exception and alert on "
                       "their creation.",
        references=("https://attack.mitre.org/techniques/T1136/001/",),
        detail_fields=("host.name", "user.name", "user.target", "process.command_line"),
    ),
    pattern_rule(
        "nix-suspicious-download-execute",
        "Remote payload downloaded and executed on {host.name}",
        "A command retrieved a remote file and piped it straight into a shell or interpreter, the "
        "standard installer pattern for Linux malware and cryptominers.",
        any_of=[
            C("_text", "any_regex", [
                r"(?:curl|wget)[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba)?sh",
                r"(?:curl|wget)[^\n|]{0,160}\|\s*python[0-9.]*",
                r"(?:curl|wget)[^\n]{0,120}(?:-O|-o)\s+/tmp/[\w.-]+[^\n]{0,40};\s*chmod\s+\+x",
                r"chmod\s+\+x\s+/(?:tmp|dev/shm|var/tmp)/[\w.-]+",
                r"base64\s+-d[^\n]{0,60}\|\s*(?:ba)?sh",
            ]),
        ],
        keywords=("curl", "wget", "/tmp/", "/dev/shm", "chmod +x", "base64 -d"),
        severity="high",
        confidence="medium",
        category="execution",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Command and Scripting Interpreter: Unix Shell",
        mitre_technique_id="T1059.004",
        risk="Downloading and executing remote code in a single step means the payload is never inspected and "
             "often never written to a monitored location.",
        impact="Arbitrary attacker code runs with the privileges of the calling service, commonly leading to "
               "cryptomining, botnet enrolment or a persistent backdoor.",
        recommendation="Recover the downloaded artefact for analysis, block the hosting infrastructure and rebuild the "
                       "host if execution succeeded. Apply egress filtering and mount temporary directories with the "
                       "noexec option.",
        references=("https://attack.mitre.org/techniques/T1059/004/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "nix-container-escape",
        "Container escape or docker socket abuse on {host.name}",
        "Activity consistent with breaking out of a container was observed, such as mounting the host "
        "filesystem, using the docker socket or running a privileged container.",
        any_of=[
            C("_text", "any_regex", [
                r"/var/run/docker\.sock", r"docker\s+run[^\n]{0,120}--privileged",
                r"docker\s+run[^\n]{0,120}-v\s+/:/(?:host|mnt)?",
                r"kubectl\s+exec[^\n]{0,80}--\s*(?:/bin/)?(?:ba)?sh",
                r"nsenter[^\n]{0,60}--mount=/proc/1/ns/mnt",
                r"mount\s+/dev/[sv]d[a-z]\d?\s+/mnt",
                r"capsh\s+--print", r"/proc/1/root",
            ]),
        ],
        keywords=("docker.sock", "--privileged", "nsenter", "kubectl exec", "/proc/1/root", "capsh"),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=LINUX_SOURCES + ("structured",),
        mitre_tactic="Privilege Escalation",
        mitre_technique="Escape to Host",
        mitre_technique_id="T1611",
        risk="Escaping a container removes the isolation that the workload design depends on and gives the "
             "attacker control of the node.",
        impact="Every workload on the node, and any credentials mounted into them, must be considered compromised, "
               "including cluster service account tokens.",
        recommendation="Cordon and rebuild the node, rotate all secrets that were mounted into workloads on it and "
                       "review admission policies. Forbid privileged containers and host path mounts through policy, "
                       "and never expose the container runtime socket inside a workload.",
        references=("https://attack.mitre.org/techniques/T1611/",),
        detail_fields=("host.name", "user.name", "process.command_line", "container.name"),
    ),
    pattern_rule(
        "nix-ssh-key-persistence",
        "SSH authorized_keys modified on {host.name}",
        "An SSH public key was appended to an authorized_keys file, granting passwordless access to the "
        "account that owns it.",
        any_of=[
            C("_text", "any_regex", [
                r"\.ssh/authorized_keys", r"echo[^\n]{0,200}ssh-(?:rsa|ed25519|dss)",
                r"ssh-keygen[^\n]{0,60}-f\s+/(?:tmp|dev/shm)",
            ]),
        ],
        keywords=("authorized_keys", "ssh-rsa", "ssh-ed25519", "ssh-keygen"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation: SSH Authorized Keys",
        mitre_technique_id="T1098.004",
        risk="An attacker controlled key provides silent, password independent access that survives credential "
             "rotation.",
        impact="Access persists through patching and password resets, so the intrusion continues even after the "
               "team believes it is contained.",
        recommendation="Audit every authorized_keys file on the estate, remove unknown keys and rotate the account. "
                       "Manage keys centrally, disable key based root logon and monitor the files for change.",
        references=("https://attack.mitre.org/techniques/T1098/004/",),
        detail_fields=("host.name", "user.name", "file.path", "process.command_line"),
    ),
    sequence_rule(
        "nix-brute-then-shell",
        "Successful login followed by suspicious execution on {host.name}",
        "A remote session was established and shortly afterwards commands consistent with tooling "
        "download, privilege escalation or persistence were executed on the same host.",
        stages=[
            stage("Remote logon", all_of=[C("event.action", "eq", "ssh_login"), C("event.outcome", "eq", "success")]),
            stage("Post exploitation", any_of=[
                C("_text", "any_contains", ["/dev/tcp/", "chmod +x", "wget ", "curl ", "crontab", "useradd",
                                            "authorized_keys", "history -c", "sudo -l"]),
            ]),
        ],
        group_by=("host.name",),
        window_seconds=3600,
        keywords=("accepted password", "accepted publickey", "/dev/tcp/", "chmod +x", "wget", "curl",
                  "crontab", "useradd", "authorized_keys", "history -c", "sudo -l"),
        severity="critical",
        confidence="high",
        category="attack_chain",
        data_sources=LINUX_SOURCES,
        mitre_tactic="Multiple",
        mitre_technique="Attack chain correlation",
        mitre_technique_id="T1078",
        risk="Authentication immediately followed by tooling activity indicates an operator working "
             "interactively rather than routine administration.",
        impact="The server should be considered fully compromised, along with any credentials or data accessible "
               "from it.",
        recommendation="Isolate and image the host, reset the account and any keys it holds, and scope which other "
                       "systems that identity reached. Rebuild from a known good image rather than cleaning in place.",
        references=("https://attack.mitre.org/",),
    ),
]
