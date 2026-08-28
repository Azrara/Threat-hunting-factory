"""Kubernetes control plane detections built on the audit log."""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

K8S_SOURCES = ("k8s_audit", "structured", "generic", "endpoint", "linux_auth", "syslog")

RULES = [
    pattern_rule(
        "k8s-exec-into-pod",
        "Interactive shell opened inside a workload",
        "A request created an exec or attach subresource on a pod, which opens an interactive session "
        "inside a running container. Production workloads should be immutable, so this is either "
        "unmanaged debugging or hands on keyboard access.",
        any_of=[
            C("_text", "any_regex", [
                r"pods/exec", r"pods/attach", r"pods/portforward",
                r"kubectl\s+exec[^\n]{0,80}--\s*(?:/bin/)?(?:ba|z)?sh",
                r"\"subresource\"\s*:\s*\"exec\"",
            ]),
        ],
        keywords=("pods/exec", "pods/attach", "pods/portforward", "kubectl exec", "subresource"),
        group_by=("user.name", "container.name"),
        severity="high",
        confidence="medium",
        category="execution",
        data_sources=K8S_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Container Administration Command",
        mitre_technique_id="T1609",
        risk="An interactive session inside a workload gives access to its service account token, its "
             "mounted secrets and the network position of the pod.",
        impact="The service account token can be replayed against the API server, so a single pod session "
               "often becomes cluster wide access.",
        recommendation="Confirm the session was an approved break glass action, then rotate the service account "
                       "token and any secret the pod mounted. Disable exec in production namespaces and require "
                       "ephemeral debug containers with an audit trail instead.",
        references=("https://attack.mitre.org/techniques/T1609/",),
        detail_fields=("user.name", "container.name", "source.ip", "event.action"),
    ),
    pattern_rule(
        "k8s-privileged-workload",
        "Privileged or host mounting workload admitted",
        "A workload was created with privileged mode, host namespaces or a host path mount. Any of these "
        "removes the isolation boundary between the container and the node.",
        any_of=[
            C("_text", "any_regex", [
                r"\"privileged\"\s*:\s*true", r"\"hostpid\"\s*:\s*true", r"\"hostnetwork\"\s*:\s*true",
                r"\"hostipc\"\s*:\s*true", r"\"hostpath\"\s*:", r"\"allowprivilegeescalation\"\s*:\s*true",
                r"\"runasuser\"\s*:\s*0", r"securitycontext[^\n]{0,80}privileged",
                r"capabilities[^\n]{0,60}sys_admin",
            ]),
        ],
        keywords=("privileged", "hostpid", "hostnetwork", "hostipc", "hostpath", "allowprivilegeescalation",
                  "securitycontext", "sys_admin"),
        group_by=("container.name", "user.name"),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=K8S_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Escape to Host",
        mitre_technique_id="T1611",
        risk="A privileged container is equivalent to root on the node, so admitting one is equivalent to "
             "granting node level access to whoever controls the image.",
        impact="Compromise of the node and of every other workload scheduled on it, including their secrets "
               "and service account tokens.",
        recommendation="Delete the workload, rebuild the node if it ran, and rotate the secrets that were "
                       "mounted on it. Enforce a restricted pod security admission policy so privileged and host "
                       "mounting workloads are rejected rather than audited.",
        references=("https://attack.mitre.org/techniques/T1611/",),
        detail_fields=("container.name", "user.name", "event.action", "source.ip"),
    ),
    pattern_rule(
        "k8s-rbac-escalation",
        "Cluster role or binding granting broad rights",
        "A role or binding was created that grants wildcard verbs, wildcard resources or cluster "
        "administrator. This is the standard persistence step once an attacker reaches the API server.",
        any_of=[
            C("_text", "any_regex", [
                r"clusterrolebinding", r"cluster-admin", r"\"verbs\"\s*:\s*\[\s*\"\*\"",
                r"\"resources\"\s*:\s*\[\s*\"\*\"", r"\"apigroups\"\s*:\s*\[\s*\"\*\"",
                r"system:masters", r"escalate", r"bind\b[^\n]{0,40}clusterrole",
            ]),
        ],
        keywords=("clusterrolebinding", "cluster-admin", "system:masters", "apigroups", "clusterrole"),
        group_by=("user.name",),
        severity="critical",
        confidence="medium",
        category="privilege_escalation",
        data_sources=K8S_SOURCES,
        mitre_tactic="Privilege Escalation",
        mitre_technique="Valid Accounts: Cloud Accounts",
        mitre_technique_id="T1078.004",
        risk="Cluster administrator rights allow reading every secret, scheduling workloads on every node "
             "and disabling the admission controls that would stop the next step.",
        impact="Full control of the cluster and of the applications and data it runs, with persistence that "
               "survives the loss of the original workload.",
        recommendation="Remove the binding, review what the subject accessed and rotate the secrets it could "
                       "read. Apply least privilege roles, forbid wildcard verbs by policy and require review for "
                       "cluster scoped bindings.",
        references=("https://attack.mitre.org/techniques/T1078/004/",),
        detail_fields=("user.name", "event.action", "source.ip"),
    ),
    threshold_rule(
        "k8s-secret-enumeration",
        "Bulk secret access by {user.name}",
        "{count} secret read operations were recorded for one subject in the window, which matches "
        "automated collection rather than an application reading its own configuration.",
        all_of=[C("_text", "any_contains", ["secrets", "secret"])],
        any_of=[C("_text", "any_contains", ["list", "get", "watch", "\"verb\""])],
        group_by=("user.name",),
        min_count=15,
        window_seconds=300,
        keywords=("secrets", "serviceaccounts/token", "\"verb\""),
        severity="critical",
        confidence="low",
        category="credential_access",
        data_sources=K8S_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Unsecured Credentials: Container API",
        mitre_technique_id="T1552.007",
        risk="Cluster secrets hold database passwords, cloud credentials and signing keys, so reading them "
             "in bulk converts cluster access into access to everything the cluster talks to.",
        impact="Compromise of the systems behind the cluster, including production databases and cloud "
               "accounts, from a single foothold.",
        recommendation="Rotate every secret the subject could read and review what it authenticated to "
                       "afterwards. Move secrets to an external manager with per workload access and short "
                       "leases, and alert on list operations against the secrets resource.",
        references=("https://attack.mitre.org/techniques/T1552/007/",),
    ),
    pattern_rule(
        "k8s-anonymous-or-unauthenticated-access",
        "Unauthenticated access to the cluster API",
        "A request reached the API server as system:anonymous or system:unauthenticated. The API server "
        "should never accept anonymous requests beyond health endpoints.",
        any_of=[
            C("_text", "any_contains", ["system:anonymous", "system:unauthenticated",
                                        "\"username\":\"system:anonymous\""]),
        ],
        keywords=("system:anonymous", "system:unauthenticated"),
        group_by=("source.ip",),
        severity="critical",
        confidence="high",
        category="initial_access",
        data_sources=K8S_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_technique_id="T1190",
        risk="An anonymously reachable API server is a direct path from the internet to workload "
             "execution, and it is found routinely by internet wide scanning.",
        impact="Unauthenticated cluster access allows scheduling arbitrary workloads, which is complete "
               "compromise of the cluster and its data.",
        recommendation="Disable anonymous authentication, remove any binding that grants rights to the "
                       "unauthenticated group and place the API server behind a private endpoint or an "
                       "authenticating proxy. Review what the anonymous requests reached.",
        references=("https://attack.mitre.org/techniques/T1190/",),
        detail_fields=("source.ip", "event.action", "user.name"),
    ),
    pattern_rule(
        "k8s-workload-image-anomaly",
        "Workload image pulled from an untrusted registry",
        "A container image was pulled from a public or unrecognised registry, or with a mutable tag. "
        "Image provenance is the supply chain boundary for a cluster.",
        any_of=[
            C("_text", "any_regex", [
                r"image[\"']?\s*[:=]\s*[\"']?(?:docker\.io/)?[a-z0-9._-]+/[a-z0-9._-]+:latest",
                r"\"image\"\s*:\s*\"(?!.*(?:@sha256:))[^\"]{3,120}\"",
                r"imagepullbackoff", r"errimagepull",
                r"registry-1\.docker\.io", r"quay\.io/[a-z0-9._-]+/", r"ghcr\.io/[a-z0-9._-]+/",
            ]),
        ],
        keywords=("imagepullbackoff", "errimagepull", "registry-1.docker.io", "quay.io", "ghcr.io",
                  "docker.io", ":latest"),
        group_by=("container.name",),
        severity="medium",
        confidence="low",
        category="execution",
        data_sources=K8S_SOURCES,
        mitre_tactic="Execution",
        mitre_technique="Deploy Container",
        mitre_technique_id="T1610",
        risk="An image from an uncontrolled registry, or a mutable tag, means the code running in the "
             "cluster can change without any change to the manifest that was reviewed.",
        impact="Attacker controlled code executes inside the trust boundary of the cluster with whatever "
               "service account and secrets the workload is given.",
        recommendation="Mirror approved images into an internal registry, pin them by digest and enforce that "
                       "with an admission policy. Scan images on ingestion and require signature verification for "
                       "production namespaces.",
        references=("https://attack.mitre.org/techniques/T1610/",),
        detail_fields=("container.name", "user.name", "event.action"),
        max_findings=10,
    ),
]
