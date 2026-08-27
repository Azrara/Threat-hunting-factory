"""Cloud control plane and identity provider detections (AWS, Azure, Microsoft 365)."""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

CLOUD_SOURCES = ("aws_cloudtrail", "o365_audit", "structured", "generic")

RULES = [
    pattern_rule(
        "cloud-root-account-usage",
        "Cloud root or global administrator account used",
        "An action was taken by the account root identity or a global administrator, which should be "
        "reserved for break glass scenarios only.",
        any_of=[
            C("user.type", "eq", "Root"),
            C("user.arn", "any_regex", [r":root$"]),
            C("_text", "any_contains", ["\"type\":\"root\"", "global administrator", "company administrator"]),
        ],
        keywords=(":root", "\"root\"", "global administrator", "company administrator"),
        group_by=("cloud.account.id", "user.name"),
        severity="high",
        confidence="medium",
        category="privilege_escalation",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Valid Accounts: Cloud Accounts",
        mitre_technique_id="T1078.004",
        risk="The root identity has unrestricted control of the tenant and cannot be constrained by policy, "
             "so any misuse is unbounded.",
        impact="An attacker with root can disable logging, delete backups and create persistent access paths "
               "across every workload in the account.",
        recommendation="Confirm the activity against a change record, rotate the root credentials and enforce hardware "
                       "multi factor authentication on the root identity. Operate day to day through role based access "
                       "and alert on every root action.",
        references=("https://attack.mitre.org/techniques/T1078/004/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip", "cloud.region"),
    ),
    pattern_rule(
        "cloud-logging-disabled",
        "Cloud audit logging disabled or deleted",
        "An action stopped, deleted or reconfigured the audit trail, which is an anti forensic step that "
        "precedes further attacker activity.",
        any_of=[
            C("event.action", "in", [
                "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                "DeleteFlowLogs", "DeleteLogGroup", "DeleteConfigRule", "StopConfigurationRecorder",
                "DeleteDetector", "DisableSecurityHub", "DeleteConfigurationRecorder",
                "Set-AdminAuditLogConfig", "Remove-UnifiedAuditLog", "Set-MailboxAuditBypassAssociation",
            ]),
            C("_text", "any_contains", ["stoplogging", "deletetrail", "deleteflowlogs", "disablesecurityhub",
                                         "set-adminauditlogconfig", "unifiedauditlogingestionenabled false"]),
        ],
        keywords=("stoplogging", "deletetrail", "updatetrail", "puteventselectors", "deleteflowlogs",
                  "deleteloggroup", "stopconfigurationrecorder", "disablesecurityhub", "deletedetector",
                  "set-adminauditlogconfig", "mailboxauditbypass"),
        group_by=("cloud.account.id", "user.name"),
        severity="critical",
        confidence="high",
        category="defense_evasion",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Impair Defenses: Disable Cloud Logs",
        mitre_technique_id="T1562.008",
        risk="Disabling the audit trail blinds the organisation to everything the attacker does next in the "
             "cloud environment.",
        impact="Investigations cannot establish what was accessed or changed, and regulatory evidence "
               "requirements may not be met.",
        recommendation="Re enable logging immediately, deliver logs to a separate hardened account with object lock, "
                       "and review every action by the calling identity. Apply service control policies that prevent "
                       "logging from being disabled outside a break glass process.",
        references=("https://attack.mitre.org/techniques/T1562/008/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip", "cloud.region"),
    ),
    pattern_rule(
        "cloud-iam-privilege-escalation",
        "Cloud identity permissions expanded",
        "An identity or policy change granted broader permissions, created a new access key or attached "
        "an administrative policy.",
        any_of=[
            C("event.action", "in", [
                "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile",
                "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy",
                "PutRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
                "UpdateAssumeRolePolicy", "AddUserToGroup", "CreateServiceLinkedRole",
                "Add member to role", "Add service principal credentials",
                "Add app role assignment to service principal", "Consent to application",
            ]),
            C("_text", "any_contains", ["createaccesskey", "attachuserpolicy", "administratoraccess",
                                         "createloginprofile", "updateassumerolepolicy",
                                         "add service principal credentials", "consent to application"]),
        ],
        keywords=("createaccesskey", "createuser", "createloginprofile", "attachuserpolicy", "attachrolepolicy",
                  "putuserpolicy", "putrolepolicy", "createpolicyversion", "updateassumerolepolicy",
                  "addusertogroup", "administratoraccess", "service principal credentials", "consent to application"),
        group_by=("cloud.account.id", "user.name", "event.action"),
        severity="high",
        confidence="medium",
        category="privilege_escalation",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation: Additional Cloud Credentials",
        mitre_technique_id="T1098.001",
        risk="New credentials and broadened policies give the attacker independent, long lived access that "
             "survives the loss of the original session.",
        impact="Persistent administrative access to cloud workloads and data, including the ability to create "
               "further hidden identities.",
        recommendation="Validate each change against approved requests, delete unauthorised keys and identities and "
                       "review what those identities accessed. Require infrastructure as code with peer review for "
                       "identity changes and alert on direct console modifications.",
        references=("https://attack.mitre.org/techniques/T1098/001/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "cloud-storage-exposed",
        "Cloud storage made publicly accessible",
        "A bucket or container policy was changed in a way that can expose stored objects to anonymous "
        "access.",
        any_of=[
            C("event.action", "in", [
                "PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPolicy",
                "DeletePublicAccessBlock", "PutObjectAcl", "SetBlobContainerPublicAccess",
            ]),
            C("_text", "any_contains", ["allusers", "authenticatedusers", "\"public\":true", "publicaccess",
                                         "acl=public-read", "blobpublicaccess"]),
        ],
        keywords=("putbucketacl", "putbucketpolicy", "deletebucketpolicy", "publicaccessblock", "allusers",
                  "authenticatedusers", "public-read", "blobpublicaccess"),
        group_by=("cloud.account.id", "user.name"),
        severity="high",
        confidence="medium",
        category="exfiltration",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Exfiltration",
        mitre_technique="Data from Cloud Storage",
        mitre_technique_id="T1530",
        risk="Publicly readable storage is discovered by automated scanners within minutes and is a leading "
             "cause of large data breaches.",
        impact="Uncontrolled disclosure of whatever the bucket holds, frequently backups, customer records or "
               "credentials, with immediate regulatory exposure.",
        recommendation="Revert the policy, enable account level public access blocking and review access logs for "
                       "anonymous reads. Enforce preventive guardrails so storage cannot be made public without an "
                       "exception process.",
        references=("https://attack.mitre.org/techniques/T1530/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "cloud-mfa-weakened",
        "Multi factor authentication removed or bypassed",
        "A change disabled multi factor authentication, deleted a device registration or added an "
        "authentication method for another identity.",
        any_of=[
            C("event.action", "in", [
                "DeactivateMFADevice", "DeleteVirtualMFADevice", "Disable Strong Authentication",
                "Update StrongAuthenticationMethod", "User registered security info",
                "Disable account", "Set-MsolUser", "Update user", "Remove security info",
            ]),
            C("_text", "any_contains", ["deactivatemfadevice", "deletevirtualmfadevice",
                                         "strongauthenticationmethod", "disable strong authentication",
                                         "mfa disabled", "conditional access policy updated"]),
        ],
        keywords=("deactivatemfadevice", "deletevirtualmfadevice", "strongauthentication", "mfa disabled",
                  "security info", "conditional access"),
        group_by=("cloud.account.id", "user.name"),
        severity="critical",
        confidence="medium",
        category="persistence",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Modify Authentication Process: Multi-Factor Authentication",
        mitre_technique_id="T1556.006",
        risk="Weakening multi factor authentication removes the single most effective control against account "
             "takeover and enables quiet re entry.",
        impact="The attacker keeps access with a password alone, and other users can be targeted with the same "
               "technique, undermining the identity perimeter.",
        recommendation="Restore the original configuration, re register the affected user with a trusted device and "
                       "review all sign ins for that identity. Protect authentication method changes with privileged "
                       "identity management and alert on every modification.",
        references=("https://attack.mitre.org/techniques/T1556/006/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "cloud-mailbox-rule-abuse",
        "Suspicious mailbox rule or forwarding created",
        "An inbox rule or forwarding configuration was created that hides or redirects mail, a standard "
        "step in business email compromise.",
        any_of=[
            C("event.action", "in", [
                "New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules",
                "Set-TransportRule", "New-TransportRule", "Add-MailboxPermission",
            ]),
            C("_text", "any_contains", ["new-inboxrule", "set-inboxrule", "forwardingsmtpaddress",
                                         "deliverToMailboxAndForward", "movetofolder", "markasread",
                                         "deletemessage", "add-mailboxpermission"]),
        ],
        keywords=("new-inboxrule", "set-inboxrule", "forwardingsmtpaddress", "updateinboxrules",
                  "add-mailboxpermission", "transportrule", "deliverytomailboxandforward"),
        group_by=("user.name",),
        severity="high",
        confidence="medium",
        category="collection",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Collection",
        mitre_technique="Email Collection: Email Forwarding Rule",
        mitre_technique_id="T1114.003",
        risk="Hidden rules let an attacker read and suppress mail from the compromised mailbox, which enables "
             "invoice fraud and further phishing from a trusted identity.",
        impact="Financial loss through payment redirection, disclosure of confidential correspondence and use of "
               "the mailbox to attack partners and customers.",
        recommendation="Remove the rule, reset the account credentials and revoke active sessions, then review sent "
                       "items and any payment changes. Block automatic external forwarding by policy and alert on new "
                       "inbox rules that delete or forward mail.",
        references=("https://attack.mitre.org/techniques/T1114/003/",),
        detail_fields=("user.name", "event.action", "source.ip", "cloud.account.id"),
    ),
    pattern_rule(
        "cloud-impossible-source",
        "Cloud sign in from an anonymising or unusual network",
        "An authentication to the cloud tenant came from an address associated with hosting providers, "
        "anonymisers or a country outside normal operations.",
        all_of=[C("source.ip", "public_ip", None)],
        any_of=[
            C("_text", "any_contains", ["tor exit", "anonymous proxy", "unfamiliar sign-in", "risky sign-in",
                                         "atypical travel", "impossibletravel", "unfamiliarfeatures",
                                         "malwarelinkedipaddress", "anonymizedipaddress"]),
        ],
        keywords=("impossibletravel", "atypical travel", "anonymizedipaddress", "unfamiliarfeatures",
                  "risky sign-in", "malwarelinkedipaddress", "tor exit"),
        group_by=("user.name", "source.ip"),
        severity="high",
        confidence="medium",
        category="initial_access",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Valid Accounts: Cloud Accounts",
        mitre_technique_id="T1078.004",
        risk="Sign ins from anonymised infrastructure indicate that the credential is being used by someone "
             "other than the legitimate owner.",
        impact="Full access to the user mailbox, files and connected applications, and a launch point for "
               "internal phishing.",
        recommendation="Revoke the sessions, reset the credential and require re registration of multi factor methods. "
                       "Enforce conditional access with device compliance and block legacy authentication protocols.",
        references=("https://attack.mitre.org/techniques/T1078/004/",),
        detail_fields=("user.name", "source.ip", "event.action", "cloud.account.id"),
    ),
    threshold_rule(
        "cloud-failed-console-logins",
        "Repeated failed cloud sign ins for {user.name}",
        "{count} failed cloud authentications were recorded in the window, which indicates credential "
        "guessing against the tenant.",
        all_of=[C("event.outcome", "eq", "failure")],
        any_of=[
            C("event.action", "any_contains", ["consolelogin", "signin", "userloginfailed", "login"]),
        ],
        group_by=("user.name",),
        min_count=10,
        window_seconds=900,
        keywords=("consolelogin", "userloginfailed", "signin", "login"),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        risk="Cloud identities are internet reachable by design, so credential guessing can run continuously "
             "from anywhere.",
        impact="A successful guess gives immediate access to mail, files and cloud infrastructure without "
               "touching the corporate network.",
        recommendation="Confirm whether any attempt succeeded, reset the targeted accounts and enforce multi factor "
                       "authentication with conditional access. Enable identity protection risk policies and block "
                       "legacy authentication.",
        references=("https://attack.mitre.org/techniques/T1110/",),
    ),
    threshold_rule(
        "cloud-api-enumeration",
        "Cloud reconnaissance by {user.name}",
        "One identity issued {count} distinct read and list operations in the window, which matches "
        "automated enumeration of the environment rather than normal use.",
        any_of=[
            C("event.action", "any_regex", [r"^(?:List|Describe|Get)[A-Z]", r"^(?:Get|List)-"]),
        ],
        group_by=("user.name",),
        distinct_field="event.action",
        min_count=25,
        window_seconds=600,
        keywords=(),
        severity="medium",
        confidence="medium",
        category="discovery",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Discovery",
        mitre_technique="Cloud Service Discovery",
        mitre_technique_id="T1526",
        risk="Broad enumeration is how an attacker with stolen cloud credentials establishes what the identity "
             "can reach before acting.",
        impact="Enumeration output guides the attacker straight to the data stores and escalation paths that "
               "matter, reducing the time available to detect them.",
        recommendation="Determine whether the identity belongs to an automation pipeline, and if not revoke its "
                       "credentials and review subsequent activity. Apply least privilege to roles and alert on "
                       "enumeration bursts from human identities.",
        references=("https://attack.mitre.org/techniques/T1526/",),
    ),
    pattern_rule(
        "cloud-resource-destruction",
        "Destructive cloud operation performed",
        "An action deleted infrastructure, snapshots or encryption keys, which can be either sabotage or "
        "preparation for extortion.",
        any_of=[
            C("event.action", "in", [
                "DeleteBucket", "DeleteDBInstance", "DeleteDBCluster", "TerminateInstances",
                "DeleteSnapshot", "DeleteDBSnapshot", "ScheduleKeyDeletion", "DisableKey",
                "DeleteVolume", "DeleteFileSystem", "DeleteBackupVault", "DeleteRecoveryPoint",
                "DeleteCluster", "DeleteStack",
            ]),
        ],
        keywords=("deletebucket", "terminateinstances", "deletesnapshot", "schedulekeydeletion",
                  "deletebackupvault", "deleterecoverypoint", "deletedbinstance", "deletefilesystem"),
        group_by=("cloud.account.id", "user.name", "event.action"),
        severity="critical",
        confidence="medium",
        category="impact",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Impact",
        mitre_technique="Data Destruction",
        mitre_technique_id="T1485",
        risk="Deleting backups, snapshots and keys removes the ability to recover, and scheduling key deletion "
             "renders encrypted data permanently unreadable.",
        impact="Irreversible loss of production data and extended outage, with maximum leverage for an extortion "
               "demand.",
        recommendation="Cancel any pending key deletions immediately, restore from immutable backups in a separate "
                       "account and revoke the calling identity. Enforce multi party approval and object lock on "
                       "backup and key deletion operations.",
        references=("https://attack.mitre.org/techniques/T1485/",),
        detail_fields=("cloud.account.id", "user.name", "event.action", "source.ip", "cloud.region"),
    ),
    pattern_rule(
        "cloud-oauth-consent-abuse",
        "Application consent or service principal credential added",
        "An application was granted access to tenant data or a credential was added to a service "
        "principal, a persistence technique that survives password resets.",
        any_of=[
            C("_text", "any_contains", [
                "consent to application", "add service principal", "add delegated permission grant",
                "add app role assignment", "add owner to service principal",
                "update application - certificates and secrets management",
                "add service principal credentials",
            ]),
        ],
        keywords=("consent to application", "service principal", "delegated permission grant",
                  "app role assignment", "certificates and secrets management"),
        group_by=("user.name",),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=CLOUD_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation: Additional Cloud Roles",
        mitre_technique_id="T1098.003",
        risk="An application identity with tenant permissions keeps access independently of any user and is "
             "rarely reviewed.",
        impact="Silent, long lived access to mail and files across the whole tenant, which is the persistence "
               "mechanism seen in several large supply chain intrusions.",
        recommendation="Review the application, its publisher and the permissions granted, then revoke unnecessary "
                       "grants and added credentials. Require administrator consent for all applications and audit "
                       "service principal credentials regularly.",
        references=("https://attack.mitre.org/techniques/T1098/003/",),
        detail_fields=("user.name", "event.action", "source.ip"),
    ),
]
