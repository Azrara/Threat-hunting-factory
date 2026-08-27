"""Web server, application and proxy detections."""

from __future__ import annotations

from .helpers import C, pattern_rule, threshold_rule

WEB_SOURCES = ("web", "generic", "structured", "security_appliance", "syslog")

RULES = [
    pattern_rule(
        "web-sql-injection",
        "SQL injection attempt against {url.path}",
        "Request parameters contained SQL syntax typical of injection testing or exploitation, for "
        "example union select, boolean tautologies or time based payloads.",
        any_of=[
            C("_text", "any_regex", [
                r"union[\s/*+%]+(?:all[\s/*+%]+)?select", r"or\s+1\s*=\s*1", r"'\s*or\s*'1'\s*=\s*'1",
                r"%27\s*or\s*%271%27", r"sleep\s*\(\s*\d+\s*\)", r"waitfor\s+delay",
                r"benchmark\s*\(\s*\d+", r"information_schema\.(?:tables|columns)",
                r"(?:xp_cmdshell|sp_executesql)", r"load_file\s*\(", r"into\s+outfile",
                r"extractvalue\s*\(", r"updatexml\s*\(", r"'\s*and\s*'\d'\s*=\s*'\d",
                r"select\s+.{0,40}\s+from\s+.{0,40}\s+where",
            ]),
        ],
        keywords=("union", "select", "1=1", "information_schema", "xp_cmdshell", "sleep(", "waitfor",
                  "benchmark(", "outfile", "extractvalue", "updatexml", "%27"),
        group_by=("source.ip", "url.path"),
        severity="high",
        confidence="medium",
        category="initial_access",
        data_sources=WEB_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_technique_id="T1190",
        risk="Injection of database syntax into an application parameter can expose or modify any data the "
             "application account can reach, and in some configurations allows command execution.",
        impact="Mass extraction of customer or employee records, authentication bypass and potential full "
               "compromise of the database server, with direct regulatory consequences.",
        recommendation="Confirm whether the requests returned successful responses or unusual response sizes, then "
                       "review database logs for the same window. Fix the application with parameterised queries, "
                       "deploy a web application firewall in blocking mode and rotate any exposed credentials.",
        references=("https://attack.mitre.org/techniques/T1190/", "https://owasp.org/Top10/A03_2021-Injection/"),
        detail_fields=("source.ip", "url.original", "http.request.method", "http.response.status_code", "user_agent.original"),
    ),
    pattern_rule(
        "web-command-injection",
        "Operating system command injection attempt against {url.path}",
        "Request data contained shell metacharacters combined with operating system commands, which "
        "indicates an attempt to execute code on the web server.",
        any_of=[
            C("_text", "any_regex", [
                r"[;|&`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\s",
                r"\$\(\s*(?:id|whoami|cat)\b", r"%3b\s*(?:cat|ls|id|whoami)",
                r"\|\s*(?:nc|ncat|bash|sh)\s", r"%7c%7c", r"&&\s*(?:cat|whoami|id)\b",
                r"/etc/passwd", r"c:\\+windows\\+win\.ini",
            ]),
        ],
        keywords=("/etc/passwd", "whoami", "%3b", "$(", "win.ini", "|nc", "&&cat", ";cat"),
        group_by=("source.ip", "url.path"),
        severity="critical",
        confidence="medium",
        category="initial_access",
        data_sources=WEB_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_technique_id="T1190",
        risk="Command injection gives an attacker code execution on the server with the privileges of the web "
             "service, without needing any credential.",
        impact="Full compromise of the web tier, theft of application secrets and a pivot point into internal "
               "networks, commonly followed by web shell installation.",
        recommendation="Check the server for newly written files and unexpected child processes, then patch or "
                       "refactor the affected endpoint to remove shell invocation. Run the web service with minimal "
                       "privileges and enforce strict input validation.",
        references=("https://attack.mitre.org/techniques/T1190/",),
        detail_fields=("source.ip", "url.original", "http.response.status_code", "user_agent.original"),
    ),
    pattern_rule(
        "web-path-traversal",
        "Directory traversal attempt against {url.path}",
        "The request path or query contained traversal sequences aiming to read files outside the web "
        "root.",
        any_of=[
            C("_text", "any_regex", [
                r"\.\./\.\./", r"\.\.\\\\\.\.", r"%2e%2e[/%]", r"%252e%252e",
                r"\.\.%2f", r"%c0%ae%c0%ae", r"/etc/(?:passwd|shadow|hosts)",
                r"\\\\windows\\\\system32\\\\config",
            ]),
        ],
        keywords=("../", "%2e%2e", "..\\", "/etc/passwd", "system32\\config", "%252e"),
        group_by=("source.ip", "url.path"),
        severity="high",
        confidence="medium",
        category="discovery",
        data_sources=WEB_SOURCES,
        mitre_tactic="Discovery",
        mitre_technique="File and Directory Discovery",
        mitre_technique_id="T1083",
        risk="Traversal allows an attacker to read configuration files, credentials and private keys stored on "
             "the server filesystem.",
        impact="Disclosure of database passwords and API keys typically converts a read only flaw into full "
               "application and infrastructure compromise.",
        recommendation="Determine which responses returned content, rotate any secrets that could have been read and "
                       "patch the file handling code to canonicalise and validate paths. Run the service in a chroot or "
                       "container with minimal filesystem access.",
        references=("https://attack.mitre.org/techniques/T1083/",),
        detail_fields=("source.ip", "url.original", "http.response.status_code"),
    ),
    pattern_rule(
        "web-shell-access",
        "Possible web shell interaction on {url.path}",
        "A request targeted a file name or parameter pattern associated with web shells, or a script was "
        "requested from an upload directory.",
        any_of=[
            C("url.original", "any_regex", [
                r"/(?:c99|r57|b374k|wso|shell|cmd|backdoor|hacked|up|adminer)\.(?:php|asp|aspx|jsp)",
                r"\.(?:php|asp|aspx|jsp|jspx|cfm)\?(?:cmd|exec|command|shell|run|c)=",
                r"/(?:uploads?|images?|tmp|temp|files?|assets)/[\w.-]*\.(?:php|asp|aspx|jsp|jspx)",
                r"/wp-content/uploads/[^\s]*\.php",
                r"\.(?:php|aspx?|jsp)\?(?:pass|password|key|token)=",
            ]),
            C("_text", "any_contains", ["eval(base64_decode", "assert($_", "system($_", "shell_exec($_",
                                        "passthru($_", "<%eval request", "chr(101)&chr(118)"]),
        ],
        keywords=("shell.php", "cmd.asp", "c99", "r57", "b374k", "wso", "eval(base64_decode", "shell_exec",
                  "passthru", "uploads/", "adminer.php"),
        group_by=("source.ip", "url.path"),
        severity="critical",
        confidence="medium",
        category="persistence",
        data_sources=WEB_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Server Software Component: Web Shell",
        mitre_technique_id="T1505.003",
        risk="A web shell gives persistent remote command execution through ordinary looking web traffic that "
             "passes through firewalls and proxies.",
        impact="The attacker retains control of the server indefinitely, can pivot inward and can stage data theft, "
               "even after the original vulnerability is patched.",
        recommendation="Take a forensic copy of the web root, remove the shell, and hunt for the same file across all "
                       "web servers. Patch the upload or injection flaw that allowed the write and add file integrity "
                       "monitoring on web directories.",
        references=("https://attack.mitre.org/techniques/T1505/003/",),
        detail_fields=("source.ip", "url.original", "http.request.method", "http.response.status_code"),
    ),
    pattern_rule(
        "web-log4shell",
        "Log4Shell style JNDI injection attempt",
        "A request contained a JNDI lookup expression, the payload used to exploit the Log4j remote code "
        "execution vulnerability and similar deserialisation flaws.",
        any_of=[
            C("_text", "any_regex", [
                r"\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nis|nds)://",
                r"\$\{\s*(?:lower|upper|env|sys|date|::-j)[^\}]{0,40}\}",
                r"jndi%3a(?:ldap|rmi|dns)%3a",
                r"\$\{base64:",
            ]),
        ],
        keywords=("${jndi:", "jndi%3a", "${lower:", "${upper:", "${base64:", "ldap://", "rmi://"),
        group_by=("source.ip",),
        severity="critical",
        confidence="high",
        category="initial_access",
        data_sources=WEB_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_technique_id="T1190",
        risk="A successful JNDI lookup causes the server to fetch and execute attacker controlled code with no "
             "authentication required.",
        impact="Immediate remote code execution on the application server, historically exploited at scale for "
               "ransomware staging and cryptomining within hours of exposure.",
        recommendation="Confirm the Log4j version in use and patch or apply the formatMsgNoLookups mitigation, then "
                       "check for outbound LDAP or RMI connections from the server around the request time. Block "
                       "outbound connections from application servers by default.",
        references=("https://attack.mitre.org/techniques/T1190/", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
        detail_fields=("source.ip", "url.original", "user_agent.original", "http.response.status_code"),
    ),
    pattern_rule(
        "web-exchange-proxyshell",
        "Exchange or SharePoint exploitation attempt",
        "The request targeted a path associated with widely exploited Microsoft server vulnerabilities "
        "such as ProxyShell, ProxyLogon or the SharePoint ToolPane chain.",
        any_of=[
            C("url.original", "any_regex", [
                r"/autodiscover/autodiscover\.json", r"/owa/auth/[\w.-]*\.(?:aspx|js)",
                r"/ecp/[\w-]{0,20}(?:default|proxylogon|y)\.(?:flt|aspx)",
                r"/mapi/nspi", r"/powershell/", r"x-anonresource-backend",
                r"/_layouts/15/toolpane\.aspx", r"/autodiscover/autodiscover\.xml\?.*email=",
            ]),
        ],
        keywords=("autodiscover.json", "/owa/auth/", "/ecp/", "toolpane.aspx", "x-anonresource", "/mapi/nspi", "/powershell/"),
        group_by=("source.ip", "url.path"),
        severity="critical",
        confidence="medium",
        category="initial_access",
        data_sources=WEB_SOURCES,
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_technique_id="T1190",
        risk="These vulnerability chains give unauthenticated attackers SYSTEM level code execution on servers "
             "that hold mail and document repositories.",
        impact="Mailbox export, web shell installation and domain credential theft, historically the entry point "
               "for major ransomware campaigns.",
        recommendation="Verify the patch level of the server, inspect the web root and mailbox export directories for "
                       "new files, and review Exchange management logs. Remove direct internet exposure of management "
                       "endpoints and place them behind an authenticating proxy.",
        references=("https://attack.mitre.org/techniques/T1190/",),
        detail_fields=("source.ip", "url.original", "http.response.status_code", "user_agent.original"),
    ),
    pattern_rule(
        "web-scanner-user-agent",
        "Security scanner or exploitation tool user agent from {source.ip}",
        "The client identified itself with a user agent belonging to a vulnerability scanner or "
        "exploitation framework.",
        any_of=[
            C("user_agent.original", "any_regex", [
                r"sqlmap", r"nikto", r"nmap", r"masscan", r"acunetix", r"nessus", r"burp",
                r"wpscan", r"dirbuster", r"gobuster", r"feroxbuster", r"ffuf", r"hydra",
                r"metasploit", r"zgrab", r"nuclei", r"httpx", r"python-requests", r"curl/",
                r"go-http-client", r"libwww-perl",
            ]),
        ],
        keywords=("sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus", "burp", "wpscan",
                  "gobuster", "ffuf", "nuclei", "zgrab", "python-requests", "go-http-client", "libwww-perl"),
        group_by=("source.ip", "user_agent.original"),
        severity="medium",
        confidence="high",
        category="reconnaissance",
        data_sources=WEB_SOURCES,
        mitre_tactic="Reconnaissance",
        mitre_technique="Active Scanning",
        mitre_technique_id="T1595",
        risk="Automated scanning maps the attack surface and identifies exploitable components before a "
             "targeted attempt.",
        impact="Scanning itself rarely causes damage, but it reliably precedes exploitation and shows that the "
               "asset is on an attacker target list.",
        recommendation="Correlate the source with any successful requests, rate limit or block the address and confirm "
                       "the exposed services are patched. Reduce the external attack surface and monitor for follow up "
                       "activity from the same network range.",
        references=("https://attack.mitre.org/techniques/T1595/",),
        detail_fields=("source.ip", "user_agent.original", "url.original", "http.response.status_code"),
    ),
    threshold_rule(
        "web-directory-bruteforce",
        "Content discovery scan from {source.ip}",
        "{count} requests from one address returned not found responses in the window, which indicates "
        "directory or file brute forcing.",
        all_of=[C("http.response.status_code", "in", ["404", "403"])],
        group_by=("source.ip",),
        distinct_field="url.path",
        min_count=40,
        window_seconds=300,
        keywords=("404", "403"),
        severity="medium",
        confidence="medium",
        category="reconnaissance",
        data_sources=WEB_SOURCES,
        mitre_tactic="Reconnaissance",
        mitre_technique="Active Scanning: Wordlist Scanning",
        mitre_technique_id="T1595.003",
        risk="Brute forcing paths discovers forgotten administrative interfaces, backup files and development "
             "endpoints that were never meant to be public.",
        impact="Exposure of an unprotected management console or a database backup file can hand over the "
               "application without any exploitation.",
        recommendation="Block or rate limit the source, then review which paths returned success codes and remove any "
                       "unnecessary exposed content. Serve a uniform response for unknown paths and monitor for "
                       "sustained scanning.",
        references=("https://attack.mitre.org/techniques/T1595/003/",),
    ),
    threshold_rule(
        "web-credential-stuffing",
        "Authentication abuse against the web application from {source.ip}",
        "{count} authentication attempts were sent from one address in the window, which matches "
        "credential stuffing against the login endpoint.",
        all_of=[
            C("url.path", "any_regex", [r"(?:login|signin|auth|token|session|account/verify|oauth)"]),
        ],
        any_of=[
            C("http.request.method", "eq", "POST"),
            C("http.response.status_code", "in", ["401", "403", "302"]),
        ],
        group_by=("source.ip",),
        min_count=25,
        window_seconds=600,
        keywords=("login", "signin", "auth", "oauth", "session"),
        severity="high",
        confidence="medium",
        category="credential_access",
        data_sources=WEB_SOURCES,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force: Credential Stuffing",
        mitre_technique_id="T1110.004",
        risk="Reused credentials from third party breaches are replayed against the application until one "
             "combination works.",
        impact="Account takeover leads to fraud, data theft and reputational damage, and compromised customer "
               "accounts often go unnoticed for months.",
        recommendation="Block the source, enforce multi factor authentication and add adaptive rate limiting with "
                       "device fingerprinting on the login endpoint. Check for successful authentications from the same "
                       "address and force resets on those accounts.",
        references=("https://attack.mitre.org/techniques/T1110/004/",),
    ),
    pattern_rule(
        "web-large-response-exfiltration",
        "Unusually large response returned to {source.ip}",
        "A single web response transferred a very large volume of data, which can indicate bulk export "
        "of records through the application.",
        all_of=[C("http.response.bytes", "gt", 50_000_000)],
        group_by=("source.ip", "url.path"),
        keywords=(),
        severity="medium",
        confidence="low",
        category="exfiltration",
        data_sources=("web",),
        mitre_tactic="Exfiltration",
        mitre_technique="Exfiltration Over Web Service",
        mitre_technique_id="T1567",
        risk="Large application responses are a common route for stealing structured data because they use "
             "an approved protocol and an authenticated session.",
        impact="Loss of regulated data through a legitimate channel, which triggers breach notification duties "
               "and contractual penalties.",
        recommendation="Identify the endpoint and the authenticated identity, confirm whether the volume matches a "
                       "legitimate export and apply pagination or export limits. Add data loss prevention monitoring on "
                       "application responses.",
        references=("https://attack.mitre.org/techniques/T1567/",),
        detail_fields=("source.ip", "url.original", "http.response.bytes", "user.name"),
    ),
    pattern_rule(
        "web-suspicious-upload",
        "Executable or script uploaded through the web application",
        "A POST or PUT request carried a file name with an executable or server side script extension, "
        "which is how web shells are planted.",
        all_of=[C("http.request.method", "in", ["POST", "PUT"])],
        any_of=[
            C("_text", "any_regex", [
                r"filename=\"[^\"]+\.(?:php\d?|phtml|asp|aspx|jsp|jspx|exe|dll|sh|py|pl|war|jar)\"",
                r"\.(?:php\d?|phtml|aspx?|jspx?)(?:%00|\x00|;|\.)",
                r"content-type:\s*application/x-(?:php|httpd-php)",
            ]),
        ],
        keywords=("filename=", "multipart/form-data", ".php", ".aspx", ".jsp", "x-httpd-php"),
        group_by=("source.ip", "url.path"),
        severity="high",
        confidence="medium",
        category="persistence",
        data_sources=WEB_SOURCES,
        mitre_tactic="Persistence",
        mitre_technique="Server Software Component: Web Shell",
        mitre_technique_id="T1505.003",
        risk="Uploading server side script files to a web accessible directory converts a file upload feature "
             "into remote code execution.",
        impact="Persistent attacker control of the web server and any data or internal systems it can reach.",
        recommendation="Locate the uploaded file, remove it and analyse it, then fix the upload handler to validate "
                       "content type and store files outside the web root with execution disabled. Review all uploads "
                       "from the same source.",
        references=("https://attack.mitre.org/techniques/T1505/003/",),
        detail_fields=("source.ip", "url.original", "http.request.method", "http.response.status_code"),
    ),
    pattern_rule(
        "web-ssrf-attempt",
        "Server side request forgery attempt against {url.path}",
        "Request parameters referenced internal addresses or cloud metadata endpoints, which is the "
        "signature of server side request forgery.",
        any_of=[
            C("_text", "any_regex", [
                r"169\.254\.169\.254", r"metadata\.google\.internal", r"metadata\.azure\.com",
                r"(?:url|uri|path|dest|redirect|next|target|src|feed|host)=(?:https?%3a%2f%2f|https?://)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)",
                r"file%3a%2f%2f", r"gopher%3a%2f%2f", r"dict%3a%2f%2f",
            ]),
        ],
        keywords=("169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "gopher%3a", "file%3a"),
        group_by=("source.ip", "url.path"),
        severity="high",
        confidence="medium",
        category="discovery",
        data_sources=WEB_SOURCES,
        mitre_tactic="Discovery",
        mitre_technique="Cloud Infrastructure Discovery",
        mitre_technique_id="T1580",
        risk="Server side request forgery lets an attacker reach internal services and cloud metadata endpoints "
             "from a trusted position inside the network.",
        impact="Theft of cloud instance credentials from the metadata service escalates a web flaw into full "
               "control of the cloud account.",
        recommendation="Confirm whether the metadata service responded, rotate the instance role credentials and enforce "
                       "IMDSv2 or its equivalent. Validate and allow list outbound destinations in the application.",
        references=("https://attack.mitre.org/techniques/T1580/",),
        detail_fields=("source.ip", "url.original", "http.response.status_code"),
    ),
]
