"""Active Directory specific detections.

The directory is the control plane of most enterprises, and the paths that
lead from a normal account to domain control are well known: certificate
template abuse, delegation, group policy, trust manipulation and the DPAPI
backup key. These detections cover those paths.
"""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

AD_SOURCES = ("windows_event", "windows_security", "sysmon", "powershell", "generic",
              "structured", "syslog")

RULES = [
    pattern_rule(
        "ad-certificate-template-abuse",
        "Active Directory certificate template abuse on {host.name}",
        "A certificate was requested with a subject alternative name that does not belong to the "
        "requesting account, or a template was modified to allow the requester to supply the subject. "
        "This is the ESC1 family of escalation paths and it yields a certificate that authenticates "
        "as any user, including a domain administrator.",
        any_of=[
            C("event.code", "in", ["4886", "4887", "4899", "4900"]),
            C("_text", "any_regex", [
                r"certipy", r"certify(?:\.exe)?\s+(?:request|find|req)",
                r"enrollee_supplies_subject", r"ct_flag_enrollee_supplies_subject",
                r"certreq[^\n]{0,80}-attrib[^\n]{0,60}san",
                r"get-certificatetemplate", r"add-certificatetemplate",
                r"esc[1-8]\b",
            ]),
        ],
        keywords=("certipy", "certify.exe", "enrollee_supplies_subject", "certreq", "4886", "4887",
                  "4899", "4900", "certificatetemplate"),
        event_codes=("4886", "4887", "4899", "4900"),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=AD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Steal or Forge Authentication Certificates",
        mitre_technique_id="T1649",
        risk="A certificate issued with an attacker chosen subject authenticates as that identity for "
             "the lifetime of the certificate, and password resets do not revoke it.",
        impact="Immediate and durable domain compromise. The attacker can return as a domain "
               "administrator months later even after every password in the estate has been rotated.",
        recommendation="Identify the issued certificate and revoke it, then audit every template for the "
                       "enrollee supplies subject flag and for over broad enrolment rights. Enable strong "
                       "certificate mapping on domain controllers and monitor certificate authority issuance "
                       "events continuously.",
        references=("https://attack.mitre.org/techniques/T1649/",),
        detail_fields=("host.name", "user.name", "event.code", "process.command_line"),
    ),
    pattern_rule(
        "ad-shadow-credentials",
        "Shadow credentials added to an account",
        "The key credential link attribute of an account was modified, which lets an attacker "
        "authenticate as that account using a certificate they control rather than its password.",
        any_of=[
            C("_text", "any_contains", [
                "msds-keycredentiallink", "msds-keycredential", "whisker", "pywhisker",
                "set-adcomputer -keycredentiallink", "add-adcomputerkeycredential",
            ]),
        ],
        keywords=("keycredentiallink", "keycredential", "whisker", "pywhisker"),
        severity="critical",
        confidence="high",
        category="persistence",
        data_sources=AD_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation",
        mitre_technique_id="T1098",
        risk="Shadow credentials give silent, password independent access to the target account and "
             "survive credential rotation.",
        impact="If the target is a privileged account or a domain controller computer object, the "
               "attacker retains domain level access indefinitely.",
        recommendation="Clear the key credential link attribute on the affected objects, reset the accounts and "
                       "audit who holds write access to that attribute. Alert on directory changes to the key "
                       "credential attribute for every privileged object.",
        references=("https://attack.mitre.org/techniques/T1098/",),
        detail_fields=("host.name", "user.name", "user.target", "process.command_line"),
    ),
    pattern_rule(
        "ad-delegation-abuse",
        "Kerberos delegation configured on an account",
        "An account was given constrained or resource based constrained delegation rights. Delegation "
        "lets the account impersonate other users to the delegated service, which is a direct "
        "escalation path when the attacker controls the account.",
        any_of=[
            C("_text", "any_contains", [
                "msds-allowedtoactonbehalfofotheridentity", "msds-allowedtodelegateto",
                "trusted_to_auth_for_delegation", "trusted_for_delegation",
                "set-adcomputer -principalsallowedtodelegatetoaccount", "rubeus s4u",
                "getst.py", "s4u2proxy", "s4u2self",
            ]),
            C("event.code", "in", ["4738", "5136"]),
        ],
        keywords=("allowedtoactonbehalfofotheridentity", "allowedtodelegateto", "trusted_for_delegation",
                  "principalsallowedtodelegatetoaccount", "s4u2proxy", "s4u2self", "rubeus", "5136"),
        event_codes=("5136",),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=AD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Use Alternate Authentication Material",
        mitre_technique_id="T1550",
        risk="Delegation rights let a controlled account request service tickets on behalf of any user, "
             "including domain administrators.",
        impact="Full compromise of the delegated service and, in the resource based case, of the target "
               "computer, which is frequently a domain controller.",
        recommendation="Remove the delegation configuration, reset the accounts involved and mark sensitive "
                       "accounts as not delegatable. Review who can write the delegation attributes and restrict "
                       "machine account quota to zero.",
        references=("https://attack.mitre.org/techniques/T1550/",),
        detail_fields=("host.name", "user.name", "user.target", "event.code", "process.command_line"),
    ),
    pattern_rule(
        "ad-group-policy-modified",
        "Group policy object created or modified",
        "A group policy object was changed. Policy applies to every machine in its scope, so an "
        "attacker who can edit one gains code execution across the estate in a single step.",
        any_of=[
            C("event.code", "in", ["5136", "5137", "5141"]),
            C("_text", "any_regex", [
                r"\\\\sysvol\\\\[^\n]{0,80}\\\\policies\\\\\{",
                r"new-gpo\b", r"set-gpprefregistryvalue", r"new-gplink", r"set-gppermission",
                r"scheduledtasks\.xml", r"groups\.xml", r"gpttmpl\.inf",
                r"sharpgpoabuse", r"pygpoabuse",
            ]),
        ],
        keywords=("sysvol", "new-gpo", "gpprefregistryvalue", "new-gplink", "scheduledtasks.xml",
                  "gpttmpl.inf", "sharpgpoabuse", "5137", "5141"),
        event_codes=("5137", "5141"),
        severity="high",
        confidence="medium",
        category="lateral_movement",
        data_sources=AD_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Domain Policy Modification: Group Policy Modification",
        mitre_technique_id="T1484.001",
        risk="Group policy is a trusted deployment channel, so a malicious policy runs on every machine "
             "in scope with system privileges and without any exploit.",
        impact="This is the fastest route to estate wide ransomware deployment and it looks like normal "
               "administration in most monitoring.",
        recommendation="Compare the policy against its last approved version, revert unauthorised changes and "
                       "review the sysvol share for scheduled task and startup script additions. Restrict policy "
                       "editing to a small tier zero group and alert on every change.",
        references=("https://attack.mitre.org/techniques/T1484/001/",),
        detail_fields=("host.name", "user.name", "event.code", "file.path", "process.command_line"),
    ),
    pattern_rule(
        "ad-trust-modified",
        "Domain or forest trust changed",
        "A trust relationship was created, modified or removed. Trusts define which other domains are "
        "believed, so a new trust can import attacker controlled identities into the environment.",
        any_of=[
            C("event.code", "in", ["4706", "4707", "4716", "4717", "4718", "4865", "4866", "4867"]),
            C("_text", "any_contains", ["new-adtrust", "netdom trust", "set-adtrust", "trust was created",
                                        "trust was removed", "sid history", "sidhistory", "mimikatz sid::"]),
        ],
        keywords=("netdom", "adtrust", "sidhistory", "sid history", "4706", "4707", "4716", "4865", "4866"),
        event_codes=("4706", "4707", "4716", "4717", "4718", "4865", "4866", "4867"),
        severity="critical",
        confidence="medium",
        category="persistence",
        data_sources=AD_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Domain Policy Modification: Domain Trust Modification",
        mitre_technique_id="T1484.002",
        risk="A trust or SID history change makes identities from another domain authoritative here, "
             "which bypasses every control that assumes the local directory is the boundary.",
        impact="Persistent domain compromise that survives credential resets, because the attacker "
               "authenticates from a domain the environment has been told to believe.",
        recommendation="Validate the change against approved architecture, remove unauthorised trusts and audit "
                       "SID history on every account. Enable SID filtering on external trusts and alert on all "
                       "trust modifications.",
        references=("https://attack.mitre.org/techniques/T1484/002/",),
        detail_fields=("host.name", "user.name", "event.code", "process.command_line"),
    ),
    pattern_rule(
        "ad-dpapi-backup-key",
        "Domain DPAPI backup key accessed",
        "The domain wide data protection backup key was retrieved from a domain controller. That key "
        "decrypts every DPAPI protected secret in the domain, including saved browser and application "
        "credentials on every workstation.",
        any_of=[
            C("_text", "any_contains", [
                "bkrp", "backupkey", "g$bckupkey", "lsadump::backupkeys", "mimikatz lsadump::backupkeys",
                "dpapi::masterkey", "dpapi::backupkey",
            ]),
        ],
        keywords=("bckupkey", "backupkeys", "backupkey", "dpapi", "bkrp"),
        severity="critical",
        confidence="high",
        category="credential_access",
        data_sources=AD_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Credentials from Password Stores",
        mitre_technique_id="T1555",
        risk="The backup key is a master key for the whole domain. With it an attacker decrypts stored "
             "secrets on any machine, offline, without touching those machines again.",
        impact="Wholesale credential compromise across the estate, including credentials for third party "
               "services that never appear in the directory.",
        recommendation="Treat this as a full domain compromise. Plan a domain rebuild or a coordinated rotation "
                       "of every stored secret, and restrict access to the backup key to tier zero only. Alert "
                       "permanently on any retrieval of it.",
        references=("https://attack.mitre.org/techniques/T1555/",),
        detail_fields=("host.name", "user.name", "process.command_line"),
    ),
    pattern_rule(
        "ad-machine-account-created",
        "Computer account created by a standard user",
        "A machine account was added to the domain. The default machine account quota lets any user "
        "create ten, and attacker controlled machine accounts enable resource based delegation attacks.",
        all_of=[C("event.code", "eq", "4741")],
        none_of=[C("user.actor", "any_regex", [r"\$$"])],
        keywords=("4741",),
        event_codes=("4741",),
        severity="medium",
        confidence="low",
        category="privilege_escalation",
        data_sources=AD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Create Account: Domain Account",
        mitre_technique_id="T1136.002",
        risk="A machine account the attacker controls is the prerequisite for resource based constrained "
             "delegation escalation, which turns a normal user into a local administrator on a target.",
        impact="Escalation to system on the targeted computer, and to domain administrator when the "
               "target is a domain controller.",
        recommendation="Confirm the account was created by an approved provisioning process, delete it if not, "
                       "and set the machine account quota to zero so only delegated administrators can join "
                       "machines to the domain.",
        references=("https://attack.mitre.org/techniques/T1136/002/",),
        detail_fields=("host.name", "user.name", "user.target", "event.code"),
    ),
    pattern_rule(
        "ad-adminsdholder-or-acl-change",
        "Directory permissions changed on a protected object",
        "An access control entry was written on a privileged directory object such as the domain root, "
        "the AdminSDHolder container or a tier zero group. This grants durable rights that are easy to "
        "overlook during remediation.",
        any_of=[
            C("_text", "any_contains", [
                "adminsdholder", "cn=adminsdholder", "add-domainobjectacl", "set-acl -path ad:",
                "dsacls", "grant-adpermission", "genericall", "writedacl", "writeowner", "allextendedrights",
            ]),
            C("event.code", "in", ["5136", "4670"]),
        ],
        keywords=("adminsdholder", "domainobjectacl", "dsacls", "genericall", "writedacl", "writeowner",
                  "allextendedrights", "4670"),
        event_codes=("4670",),
        severity="critical",
        confidence="medium",
        category="persistence",
        data_sources=AD_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Domain Policy Modification",
        mitre_technique_id="T1484",
        risk="Rights written into the directory itself are the quietest form of persistence: they leave "
             "no process, no file and no service, and they are re applied automatically to protected groups.",
        impact="The attacker can re grant themselves domain administrator at any time, so remediation that "
               "only resets passwords fails.",
        recommendation="Audit the access control lists on the domain root, AdminSDHolder and every tier zero "
                       "group against a known good baseline, remove unauthorised entries and reset the accounts "
                       "that held them. Monitor directory object permission changes continuously.",
        references=("https://attack.mitre.org/techniques/T1484/",),
        detail_fields=("host.name", "user.name", "event.code", "process.command_line"),
    ),
    pattern_rule(
        "ad-zerologon-or-netlogon-abuse",
        "Netlogon or domain controller authentication anomaly",
        "Authentication patterns consistent with the Netlogon elevation of privilege family were "
        "observed, such as a domain controller computer account authenticating with an empty or reset "
        "secure channel password.",
        any_of=[
            C("event.code", "in", ["5805", "5723", "4742"]),
            C("_text", "any_contains", ["zerologon", "netlogon secure channel", "cve-2020-1472",
                                        "netrserverauthenticate", "netrserverpasswordset"]),
        ],
        keywords=("zerologon", "netlogon", "cve-2020-1472", "netrserverauthenticate",
                  "netrserverpasswordset", "5805", "5723"),
        event_codes=("5805", "5723"),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=AD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Exploitation for Privilege Escalation",
        mitre_technique_id="T1068",
        risk="This vulnerability class takes an unauthenticated attacker with network access to a domain "
             "controller straight to domain administrator in seconds.",
        impact="Complete domain compromise, and resetting the controller machine account password "
               "incorrectly during recovery can break replication across the estate.",
        recommendation="Confirm the domain controllers are fully patched and enforcing secure channel signing, "
                       "then investigate the source host. If exploitation succeeded, follow the vendor recovery "
                       "procedure for the computer account password and reset krbtgt twice.",
        references=("https://attack.mitre.org/techniques/T1068/",),
        detail_fields=("host.name", "user.name", "source.ip", "event.code"),
    ),
    threshold_rule(
        "ad-ldap-enumeration",
        "Bulk directory enumeration by {user.name}",
        "One account performed {count} directory object reads in the window, which matches automated "
        "collection tooling rather than an administrator using a console.",
        any_of=[
            C("event.code", "in", ["4662"]),
            C("_text", "any_contains", ["ldapsearch", "adexplorer", "sharphound", "bloodhound",
                                        "get-domainobject", "adfind"]),
        ],
        group_by=("user.name",),
        min_count=40,
        window_seconds=600,
        keywords=("4662", "ldapsearch", "adexplorer", "sharphound", "bloodhound", "get-domainobject", "adfind"),
        event_codes=("4662",),
        severity="high",
        confidence="medium",
        category="discovery",
        data_sources=AD_SOURCES,
        mitre_tactic="Discovery",
        mitre_technique="Domain Trust Discovery",
        mitre_technique_id="T1482",
        risk="Directory collection produces the full attack graph of the environment, which tells the "
             "operator the shortest path from their foothold to domain administrator.",
        impact="Once the graph is collected, escalation usually follows within hours because the "
               "attacker no longer needs to guess where the privileges are.",
        recommendation="Identify the collecting host and account, isolate it and review what the session did "
                       "next. Reduce the attack paths the collection would have revealed, starting with excessive "
                       "rights on tier zero objects.",
        references=("https://attack.mitre.org/techniques/T1482/",),
    ),
    pattern_rule(
        "ad-printnightmare-or-spooler",
        "Print spooler exploitation attempt",
        "Activity consistent with the print spooler vulnerability family was observed, such as a driver "
        "being installed remotely or spooler exploitation tooling.",
        any_of=[
            C("_text", "any_contains", [
                "printnightmare", "cve-2021-34527", "cve-2021-1675", "addprinterdriverex",
                "rprn", "spoolsample", "printerbug", "\\pipe\\spoolss",
            ]),
            C("event.code", "in", ["808", "316"]),
        ],
        keywords=("printnightmare", "cve-2021-34527", "addprinterdriverex", "spoolsample", "printerbug",
                  "spoolss"),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=AD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Exploitation for Privilege Escalation",
        mitre_technique_id="T1068",
        risk="Spooler exploitation gives system level code execution remotely, and the coercion variant "
             "forces a domain controller to authenticate to an attacker controlled host.",
        impact="System level access on domain controllers, which is equivalent to full domain compromise.",
        recommendation="Patch the affected systems, disable the print spooler on domain controllers and servers "
                       "that do not need it, and restrict driver installation to administrators. Review the host "
                       "for the payload the driver installed.",
        references=("https://attack.mitre.org/techniques/T1068/",),
        detail_fields=("host.name", "user.name", "source.ip", "process.command_line"),
    ),
]
