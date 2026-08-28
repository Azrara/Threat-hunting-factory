"""Identity provider, source control and delivery pipeline detections.

Modern intrusions increasingly bypass the corporate network entirely: the
attacker signs in to the identity provider, adds themselves to a pipeline, and
takes what they need from source control. These detections cover that surface.
"""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

SAAS_SOURCES = ("idp", "o365_audit", "aws_cloudtrail", "entra_signin", "structured",
                "generic", "web", "syslog", "endpoint")

RULES = [
    threshold_rule(
        "idp-mfa-push-fatigue",
        "Repeated multi factor prompts for {user.name}",
        "{count} multi factor challenges were issued for one account inside the window. Attackers who "
        "already hold the password send prompts repeatedly until the user approves one out of fatigue.",
        any_of=[
            C("_text", "any_contains", [
                "mfa", "multifactor", "multi-factor", "push", "verify", "second factor",
                "authentication.challenge", "user.mfa.okta_verify", "strong authentication",
            ]),
        ],
        all_of=[C("user.name", "exists", None)],
        group_by=("user.name",),
        min_count=8,
        window_seconds=600,
        keywords=("mfa", "multifactor", "authentication challenge", "okta_verify", "push notification",
                  "strong authentication", "second factor"),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Multi-Factor Authentication Request Generation",
        mitre_technique_id="T1621",
        risk="Prompt bombing works because one approval is enough, and the password is already known to "
             "the attacker before the first prompt is sent.",
        impact="A single accidental approval gives full access to the account and everything federated "
               "to it, usually mail, files and cloud infrastructure.",
        recommendation="Contact the user to confirm whether they approved a prompt, reset the credential and "
                       "revoke the sessions. Move to number matching or phishing resistant authentication and "
                       "rate limit push challenges per account.",
        references=("https://attack.mitre.org/techniques/T1621/",),
    ),
    pattern_rule(
        "idp-admin-role-granted",
        "Privileged identity provider role granted",
        "An account was granted an administrative role in the identity provider. Identity administrators "
        "can reset any password and register any authentication method, so the role is equivalent to "
        "control of every federated application.",
        any_of=[
            C("_text", "any_contains", [
                "user.account.privilege.grant", "group.privilege.grant", "assign super admin",
                "super administrator", "org admin", "grant admin role", "add member to role",
                "user_admin", "app_admin", "role assignment created", "privileged role assignment",
            ]),
        ],
        keywords=("privilege.grant", "super admin", "super administrator", "org admin", "admin role",
                  "role assignment", "privileged role", "user_admin"),
        group_by=("user.name",),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Account Manipulation: Additional Cloud Roles",
        mitre_technique_id="T1098.003",
        risk="Identity administration is the highest privilege in a federated estate, and the role can be "
             "used to mint further access silently.",
        impact="Complete control of every application behind single sign on, including the ability to lock "
               "the legitimate administrators out.",
        recommendation="Validate the grant against an approved request, remove it if unauthorised and review "
                       "everything the account did. Put privileged roles behind just in time elevation with "
                       "approval and alert on every assignment.",
        references=("https://attack.mitre.org/techniques/T1098/003/",),
        detail_fields=("user.name", "user.target", "event.action", "source.ip"),
    ),
    pattern_rule(
        "idp-api-token-created",
        "Long lived API token or service credential created",
        "An API token, personal access token or service account key was created. These credentials skip "
        "interactive authentication entirely, so they are not protected by multi factor policy.",
        any_of=[
            C("_text", "any_contains", [
                "system.api_token.create", "personal access token", "create access token",
                "createserviceaccountkey", "create_service_account_key", "createapikey",
                "oauth token issued", "client secret created", "deploy key added", "ssh key added",
                "createaccesskey", "generate token",
            ]),
        ],
        keywords=("api_token", "personal access token", "access token", "serviceaccountkey", "apikey",
                  "client secret", "deploy key", "generate token"),
        group_by=("user.name",),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Account Manipulation: Additional Cloud Credentials",
        mitre_technique_id="T1098.001",
        risk="Tokens are bearer credentials with long lifetimes that bypass multi factor authentication "
             "and are rarely inventoried.",
        impact="Access that survives password resets and session revocation, often with broader scope than "
               "the user who created it realised.",
        recommendation="Confirm the token was created deliberately and scope it down or revoke it. Maintain an "
                       "inventory of tokens with owners and expiry, and alert on creation outside the normal "
                       "provisioning path.",
        references=("https://attack.mitre.org/techniques/T1098/001/",),
        detail_fields=("user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "idp-session-hijack-indicator",
        "Session token replay indicator",
        "A session was used from a context that does not match where it was issued, or an authentication "
        "completed without any interactive factor, which is the signature of stolen session cookies.",
        any_of=[
            C("_text", "any_contains", [
                "token replay", "anomalous token", "session anomaly", "unfamiliar sign-in properties",
                "token issuer anomaly", "device code", "devicecode", "primary refresh token",
                "cookie theft", "evilginx", "adversary in the middle", "aitm",
            ]),
        ],
        keywords=("token replay", "anomalous token", "session anomaly", "device code", "devicecode",
                  "primary refresh token", "evilginx", "aitm", "adversary in the middle"),
        group_by=("user.name", "source.ip"),
        severity="critical",
        confidence="medium",
        category="initial_access",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Defense Evasion",
        mitre_technique="Use Alternate Authentication Material: Web Session Cookie",
        mitre_technique_id="T1550.004",
        risk="A stolen session token authenticates without the password and without any multi factor "
             "challenge, so the strongest sign in controls do not apply.",
        impact="Full account access that persists until the token expires or is explicitly revoked, which "
               "password resets alone do not achieve.",
        recommendation="Revoke all refresh tokens and sessions for the account, not just the password, and "
                       "require re registration of authentication methods. Enforce token protection or device "
                       "bound sessions and continuous access evaluation.",
        references=("https://attack.mitre.org/techniques/T1550/004/",),
        detail_fields=("user.name", "source.ip", "event.action", "user_agent.original"),
    ),
    pattern_rule(
        "scm-repository-exfiltration",
        "Bulk source code access or repository export",
        "A repository was cloned, exported or transferred in a way that moves the whole codebase, or "
        "visibility was changed to public.",
        any_of=[
            C("_text", "any_contains", [
                "repo.export", "repository.export", "repo.transfer", "repo.visibility_change",
                "repo.destroy", "made public", "public_repo", "git.clone", "repo.download_zip",
                "project.export", "archive downloaded",
            ]),
        ],
        keywords=("repo.export", "repository.export", "repo.transfer", "visibility_change", "made public",
                  "git.clone", "download_zip", "project.export"),
        group_by=("user.name",),
        severity="high",
        confidence="medium",
        category="exfiltration",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Collection",
        mitre_technique="Data from Information Repositories",
        mitre_technique_id="T1213",
        risk="Source code carries intellectual property and frequently embedded credentials, so its loss "
             "compounds into further compromise.",
        impact="Disclosure of proprietary code and of any secret committed into its history, which then "
               "grants access to the systems those secrets protect.",
        recommendation="Confirm the action was authorised, restore private visibility and scan the repository "
                       "history for secrets, rotating anything found. Restrict export and visibility changes to "
                       "administrators and alert on them.",
        references=("https://attack.mitre.org/techniques/T1213/",),
        detail_fields=("user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "cicd-pipeline-tampering",
        "Delivery pipeline definition or runner modified",
        "A build pipeline, workflow definition or self hosted runner was changed. Pipelines execute with "
        "deployment credentials, so controlling one means controlling production.",
        any_of=[
            C("_text", "any_regex", [
                r"\.github/workflows/", r"\.gitlab-ci\.yml", r"jenkinsfile", r"azure-pipelines\.yml",
                r"buildspec\.yml", r"\.circleci/config\.yml",
                r"self-hosted runner", r"runner registered", r"workflow_run", r"pull_request_target",
                r"actions/checkout[^\n]{0,40}persist-credentials",
            ]),
        ],
        keywords=("workflows/", "gitlab-ci", "jenkinsfile", "azure-pipelines", "buildspec",
                  "circleci", "self-hosted runner", "runner registered", "pull_request_target"),
        group_by=("user.name",),
        severity="high",
        confidence="low",
        category="execution",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Supply Chain Compromise",
        mitre_technique_id="T1195.002",
        risk="A modified pipeline runs attacker code with the deployment identity, which usually has "
             "write access to production and to the artefacts customers receive.",
        impact="Compromise of released software and of production infrastructure, with a blast radius that "
               "extends to every downstream consumer.",
        recommendation="Review the change against its approval record, require reviewed pull requests for "
                       "pipeline files and pin third party actions to a digest. Isolate self hosted runners and "
                       "scope deployment credentials to the minimum.",
        references=("https://attack.mitre.org/techniques/T1195/002/",),
        detail_fields=("user.name", "file.path", "event.action", "source.ip"),
    ),
    pattern_rule(
        "saas-secret-in-log",
        "Credential material present in the evidence",
        "A record contains what looks like a live secret: a cloud access key, a private key block or a "
        "provider token. Secrets in logs are readable by anyone who can read the logs.",
        any_of=[
            C("_text", "any_regex", [
                r"\bAKIA[0-9A-Z]{16}\b", r"\bASIA[0-9A-Z]{16}\b",
                r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
                r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
                r"\bsk-[A-Za-z0-9]{32,}\b", r"\bAIza[0-9A-Za-z_-]{35}\b",
                r"\bglpat-[A-Za-z0-9_-]{20,}\b",
                r"(?:password|passwd|pwd|secret|api_?key|token)\s*[=:]\s*[\"']?[^\s\"',;]{12,}",
            ]),
        ],
        keywords=("akia", "asia", "private key", "ghp_", "gho_", "xoxb", "glpat", "aiza",
                  "password=", "apikey=", "api_key=", "secret="),
        group_by=("source_file",),
        severity="high",
        confidence="low",
        category="credential_access",
        data_sources=SAAS_SOURCES + ("windows_event", "linux_auth", "network_flow"),
        mitre_tactic="Credential Access",
        mitre_technique="Unsecured Credentials",
        mitre_technique_id="T1552.001",
        risk="A secret written to a log is available to every person and system that can read that log, "
             "including anyone who obtains the log archive.",
        impact="Direct access to whatever the credential protects, with no exploitation required and no "
               "trace in the authentication logs of a compromise.",
        recommendation="Rotate the exposed credential immediately and then remove it from the logs and from any "
                       "backup of them. Add secret scanning to the logging pipeline and redact known credential "
                       "patterns at ingestion.",
        references=("https://attack.mitre.org/techniques/T1552/001/",),
        detail_fields=("source_file", "host.name", "user.name"),
        max_findings=15,
    ),
    threshold_rule(
        "saas-bulk-download",
        "Bulk file access by {user.name}",
        "{count} file access or download operations were recorded for one account in the window, which "
        "is well beyond interactive use and matches a collection script.",
        any_of=[
            C("event.action", "any_contains", ["filedownloaded", "filepreviewed", "fileaccessed",
                                                "filesyncdownloaded", "download", "getobject",
                                                "filecopied", "filemoved"]),
        ],
        group_by=("user.name",),
        min_count=200,
        window_seconds=900,
        keywords=("filedownloaded", "fileaccessed", "filesyncdownloaded", "download", "getobject",
                  "filecopied", "filepreviewed"),
        severity="high",
        confidence="medium",
        category="collection",
        data_sources=SAAS_SOURCES,
        mitre_tactic="Collection",
        mitre_technique="Data from Cloud Storage",
        mitre_technique_id="T1530",
        risk="Mass download from a collaboration platform is how data leaves an organisation without ever "
             "touching the corporate network or a monitored endpoint.",
        impact="Loss of whatever the account could reach, which in a flat permission model is often the "
               "entire document estate.",
        recommendation="Confirm the activity with the account owner, revoke the sessions and review what was "
                       "taken. Apply sensitivity labelling and download limits, and alert on volume anomalies "
                       "per account rather than per file.",
        references=("https://attack.mitre.org/techniques/T1530/",),
    ),
]
