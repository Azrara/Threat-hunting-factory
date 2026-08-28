"""macOS endpoint detections."""

from __future__ import annotations

from .helpers import C, pattern_rule

MAC_SOURCES = ("linux_auth", "syslog", "generic", "structured", "endpoint")

RULES = [
    pattern_rule(
        "mac-launch-persistence",
        "macOS launch agent or daemon installed on {host.name}",
        "A property list was written into a launch agent or launch daemon directory, or loaded with "
        "launchctl. These run automatically at login or at boot and are the primary persistence "
        "mechanism on macOS.",
        any_of=[
            C("_text", "any_regex", [
                r"/library/launchagents/", r"/library/launchdaemons/",
                r"~/library/launchagents/", r"launchctl\s+(?:load|bootstrap|enable|submit)",
                r"/system/library/launchdaemons/[a-z0-9._-]+\.plist",
            ]),
        ],
        keywords=("launchagents", "launchdaemons", "launchctl", "plist"),
        group_by=("host.name", "file.path"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=MAC_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Create or Modify System Process: Launch Agent",
        mitre_technique_id="T1543.001",
        risk="Launch items restart the payload at every login or boot, so removing the running process "
             "does not remove the intrusion.",
        impact="Durable access to the endpoint and to the user data and credentials it holds, surviving "
               "reboots and user password changes.",
        recommendation="Inspect the property list and the binary it references, remove unauthorised items from "
                       "every launch directory and check other endpoints for the same file name. Manage launch "
                       "items through device management and alert on new ones.",
        references=("https://attack.mitre.org/techniques/T1543/001/",),
        detail_fields=("host.name", "user.name", "file.path", "process.command_line"),
    ),
    pattern_rule(
        "mac-osascript-abuse",
        "AppleScript or shell scripting abuse on {host.name}",
        "osascript was invoked with inline code, a credential prompt or a remote payload. It is the "
        "usual execution vehicle for macOS malware because it is signed and present by default.",
        any_of=[
            C("_text", "any_regex", [
                r"osascript\s+-e", r"do shell script", r"display dialog[^\n]{0,60}password",
                r"with administrator privileges", r"osascript[^\n]{0,60}https?://",
                r"curl[^\n]{0,80}\|\s*osascript",
            ]),
        ],
        keywords=("osascript", "do shell script", "administrator privileges", "display dialog"),
        group_by=("host.name", "user.name"),
        severity="high",
        confidence="medium",
        category="execution",
        data_sources=MAC_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Command and Scripting Interpreter: AppleScript",
        mitre_technique_id="T1059.002",
        risk="AppleScript can drive other applications and can prompt the user for their password in a "
             "dialog indistinguishable from a legitimate one.",
        impact="Credential theft through a convincing prompt and privileged execution once the user "
               "approves, with no exploit required.",
        recommendation="Review the script content and what it contacted, reset the user credentials if a "
                       "password prompt was shown, and check for launch item persistence. Restrict scripting "
                       "with application control policy where the platform allows it.",
        references=("https://attack.mitre.org/techniques/T1059/002/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "mac-security-control-tampering",
        "macOS security control disabled on {host.name}",
        "Gatekeeper, System Integrity Protection, the quarantine attribute or the transparency and "
        "consent database was modified, which removes the platform protections against untrusted code.",
        any_of=[
            C("_text", "any_regex", [
                r"spctl\s+--master-disable", r"csrutil\s+disable",
                r"xattr\s+-d[r]?\s+com\.apple\.quarantine", r"xattr\s+-c\s",
                r"tccutil\s+reset", r"/library/application support/com\.apple\.tcc/tcc\.db",
                r"defaults\s+write[^\n]{0,60}(?:gkautorearm|lsquarantine)",
            ]),
        ],
        keywords=("spctl", "csrutil", "com.apple.quarantine", "tccutil", "tcc.db", "gkautorearm",
                  "lsquarantine", "xattr"),
        group_by=("host.name",),
        severity="critical",
        confidence="high",
        category="defense_evasion",
        data_sources=MAC_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Subvert Trust Controls: Gatekeeper Bypass",
        mitre_technique_id="T1553.001",
        risk="Disabling these controls is a deliberate act with no routine administrative reason, and it "
             "is done specifically so that unsigned code can run and access protected data.",
        impact="Unsigned payloads execute freely and can read the camera, microphone, screen and full disk "
               "once the consent database is manipulated.",
        recommendation="Re enable the controls, rebuild the endpoint if unsigned code ran and review the consent "
                       "database for entries the user did not approve. Enforce these settings through device "
                       "management so they cannot be changed locally.",
        references=("https://attack.mitre.org/techniques/T1553/001/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "mac-credential-access",
        "macOS keychain or credential store access on {host.name}",
        "The keychain was queried from the command line or a credential dumping utility for macOS was "
        "executed.",
        any_of=[
            C("_text", "any_regex", [
                r"security\s+(?:dump-keychain|find-generic-password|find-internet-password|unlock-keychain)",
                r"login\.keychain", r"chainbreaker", r"keychaindump",
                r"/private/var/db/dslocal/nodes/default/users/",
                r"dscl\s+\.\s+-read[^\n]{0,40}shadowhash",
            ]),
        ],
        keywords=("dump-keychain", "find-generic-password", "find-internet-password", "login.keychain",
                  "chainbreaker", "keychaindump", "shadowhash", "dslocal"),
        group_by=("host.name", "user.name"),
        severity="critical",
        confidence="high",
        category="credential_access",
        data_sources=MAC_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Credentials from Password Stores: Keychain",
        mitre_technique_id="T1555.001",
        risk="The keychain holds saved application, website and certificate credentials for the user, so "
             "one extraction yields access to many systems.",
        impact="Compromise of the user's accounts across corporate and third party services, often "
               "including session tokens that bypass multi factor authentication.",
        recommendation="Reset every credential stored in the keychain, revoke the associated sessions and "
                       "rebuild the endpoint. Discourage credential storage in the local keychain for privileged "
                       "accounts and enforce phishing resistant authentication.",
        references=("https://attack.mitre.org/techniques/T1555/001/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
]
