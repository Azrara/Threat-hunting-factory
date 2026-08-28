"""Mapping from arbitrary vendor field names to the common schema.

Two tables are used. Strong aliases are unambiguous and always overwrite,
weak aliases are context dependent (``status``, ``name``, ``path`` and so on)
and only fill a canonical field that is still empty.
"""

from __future__ import annotations

import re
from typing import Any

STRONG_ALIASES: dict[str, str] = {}
WEAK_ALIASES: dict[str, str] = {}


def _register(target: dict[str, str], canonical: str, names: str) -> None:
    for name in names.split():
        target[name] = canonical


_register(STRONG_ALIASES, "timestamp", """
    timestamp @timestamp time eventtime event_time _time datetime date_time
    timegenerated timecreated systemtime eventreceivedtime creationtime
    logtime ts rt start receipttime createdat created_at date_created
    utctime eventdate occurredat activitydatetime timestamp_utc
    requestreceivedtimestamp stagetimestamp published publishedat eventtimestamp
    firstseen lastseen detectiontime insertid receivedat ingesttime
""")
_register(STRONG_ALIASES, "host.name", """
    hostname host_name computer computername machinename machine_name
    dvchost devicehostname nodename node_name log_host source_host
    agent_name workstation workstationname resourcename servername
    server_name systemname sysname devname
""")
_register(STRONG_ALIASES, "host.ip", """
    host_ip hostip dvc deviceaddress agent_ip local_ip localip
""")
_register(STRONG_ALIASES, "user.name", """
    username user_name accountname account_name
    targetusername suser duser samaccountname userprincipalname upn
    caller_username callerusername actor_name principalname identityname usrname
    logon_user login user_id_name onbehalfofuser
    useridentity_username requestor
""")
_register(STRONG_ALIASES, "user.actor", """
    subjectusername subject_user_name subjectaccountname callerusername
    initiatedby_user actorusername
""")
_register(WEAK_ALIASES, "user.name", "subjectusername subject_user_name")
_register(STRONG_ALIASES, "user.target", """
    targetaccountname target_account_name objectusername memberaccountname
""")
_register(STRONG_ALIASES, "user.domain", """
    userdomain subjectdomainname targetdomainname user_domain
    domainname dnsdomainname accountdomain
""")
_register(STRONG_ALIASES, "source.ip", """
    src_ip srcip source_ip sourceip clientip client_ip remote_addr
    remoteip remote_ip callerip caller_ip sourceaddress ip_src srcaddr
    sourcenetworkaddress c_ip cip id_orig_h x_forwarded_for origin_ip
    ipaddress ip_address clientaddress callipaddress attacker_ip
""")
_register(STRONG_ALIASES, "source.port", """
    src_port srcport sport source_port spt id_orig_p sourceport
    clientport c_port
""")
_register(STRONG_ALIASES, "destination.ip", """
    dst_ip dstip destination_ip destip dest_ip serverip server_ip
    id_resp_h dstaddr destinationaddress d_ip target_ip remotehost_ip
""")
_register(STRONG_ALIASES, "destination.port", """
    dst_port dstport dport destination_port dpt id_resp_p destinationport
    server_port targetport s_port
""")
_register(STRONG_ALIASES, "destination.domain", """
    dest_host desthost targethost destination_host destinationhostname
    remote_host server_name_indication sni vhost host_header
""")
_register(STRONG_ALIASES, "network.protocol", """
    proto protocol ip_proto transport transport_protocol l4_proto
    networkprotocol
""")
_register(STRONG_ALIASES, "network.bytes", """
    bytes total_bytes byte_count bytes_total flow_bytes
""")
_register(STRONG_ALIASES, "network.bytes_out", """
    bytes_out out_bytes sent_bytes orig_bytes bytes_sent out
    bytesout upload_bytes tx_bytes
""")
_register(STRONG_ALIASES, "network.bytes_in", """
    bytes_in in_bytes received_bytes resp_bytes bytes_received
    bytesin download_bytes rx_bytes
""")
_register(STRONG_ALIASES, "process.name", """
    processname process_name proc_name image_name executable_name
    newprocessname_base sproc comm
""")
_register(STRONG_ALIASES, "process.executable", """
    image processpath process_path newprocessname executable
    process_executable exe_path imagepath binarypath
""")
_register(STRONG_ALIASES, "process.command_line", """
    commandline command_line cmdline process_command_line
    processcommandline cmd_line command args arguments
""")
_register(STRONG_ALIASES, "process.pid", """
    pid processid process_id new_process_id newprocessid
""")
_register(STRONG_ALIASES, "process.parent.name", """
    parentprocessname parent_process_name parent_name parentimage_base
""")
_register(STRONG_ALIASES, "process.parent.executable", """
    parentimage parentprocesspath parent_process_path
    parentprocessname_full creatorprocessname
""")
_register(STRONG_ALIASES, "process.parent.command_line", """
    parentcommandline parent_command_line parentcmdline
    parentprocesscommandline
""")
_register(STRONG_ALIASES, "process.parent.pid", """
    ppid parentprocessid parent_process_id creatorprocessid
""")
_register(STRONG_ALIASES, "process.hash.md5", "md5 process_md5 md5_hash filehash_md5")
_register(STRONG_ALIASES, "process.hash.sha1", "sha1 process_sha1 sha1_hash")
_register(STRONG_ALIASES, "process.hash.sha256", "sha256 process_sha256 sha256_hash")
_register(STRONG_ALIASES, "file.path", """
    filepath file_path targetfilename target_filename fullpath
    objectpath filefullpath sourcefilename destinationfilename
""")
_register(STRONG_ALIASES, "file.name", "filename file_name basename fname")
_register(STRONG_ALIASES, "dns.question.name", """
    dns_query query_name qname dnsname dns_name question_name
    domain_name queried_domain dns_question requested_domain
""")
_register(STRONG_ALIASES, "dns.question.type", "qtype query_type dns_type record_type")
_register(STRONG_ALIASES, "dns.answers", "answers dns_answer rdata resolved_ip")
_register(STRONG_ALIASES, "url.original", """
    url request_url requesturl full_url uri_full weburl original_url
""")
_register(STRONG_ALIASES, "url.path", "uri uri_path cs_uri_stem url_path request_path uri_stem")
_register(STRONG_ALIASES, "url.query", "query_string cs_uri_query uri_query url_query")
_register(STRONG_ALIASES, "http.request.method", """
    http_method request_method cs_method verb method_name
""")
_register(STRONG_ALIASES, "http.response.status_code", """
    status_code sc_status http_status response_code statuscode
    responsestatus http_response_code
""")
_register(STRONG_ALIASES, "http.response.bytes", "sc_bytes response_size resp_size body_bytes_sent")
_register(STRONG_ALIASES, "http.request.referrer", "referer referrer cs_referer http_referer")
_register(STRONG_ALIASES, "user_agent.original", """
    user_agent useragent http_user_agent cs_user_agent ua
    useragentstring client_user_agent
""")
_register(STRONG_ALIASES, "event.code", """
    eventid event_id eventcode event_code signature_id sigid signatureid
    winlog_event_id sid_id
""")
_register(STRONG_ALIASES, "event.action", """
    eventname event_name eventtype event_type activity operation
    operationname action_name activityname task taskname requestparameters_action
""")
_register(STRONG_ALIASES, "event.outcome", """
    outcome event_outcome resultstatus result_status logon_result
    responseelements_status errorcode_status
""")
_register(STRONG_ALIASES, "event.provider", """
    provider providername sourcename channel log_source logsource
    product vendor event_source eventsource sourcetype
""")
_register(STRONG_ALIASES, "event.severity", "severity level loglevel log_level priority sev")
_register(STRONG_ALIASES, "registry.path", """
    targetobject registrykey registry_key registrypath reg_key
""")
_register(STRONG_ALIASES, "registry.value", "registryvalue registry_value valuename value_name")
_register(STRONG_ALIASES, "service.name", "servicename service_name svc_name")
_register(STRONG_ALIASES, "cloud.account.id", """
    accountid account_id recipientaccountid subscriptionid subscription_id
    tenantid tenant_id project_id awsaccountid
""")
_register(STRONG_ALIASES, "cloud.region", "awsregion aws_region region_name availability_zone")
_register(STRONG_ALIASES, "cloud.provider", "cloud_provider csp")
_register(STRONG_ALIASES, "rule.name", "signature rule_name rulename alert_signature detection_name")
_register(STRONG_ALIASES, "tls.ja3", "ja3 ja3_hash ja3s tls_fingerprint")
_register(STRONG_ALIASES, "logon.type", "logontype logon_type authentication_type auth_type")
_register(STRONG_ALIASES, "email.sender", "sender from_address mail_from sender_address")
_register(STRONG_ALIASES, "email.recipient", "recipient to_address rcpt_to recipient_address")
_register(STRONG_ALIASES, "email.subject", "subject mail_subject")
_register(STRONG_ALIASES, "container.name", "container_name pod_name podname")
_register(STRONG_ALIASES, "error.message", "error errormessage error_message failurereason failure_reason")

_register(WEAK_ALIASES, "user.name", "user account principal identity actor subject caller owner alternateid")
_register(WEAK_ALIASES, "host.name", "host computer machine device node server agent source_name")
_register(WEAK_ALIASES, "source.ip", "src ip clientaddr addr address peer")
_register(WEAK_ALIASES, "destination.ip", "dst dest destination target remote")
_register(WEAK_ALIASES, "user.domain", "domain realm")
_register(WEAK_ALIASES, "http.response.status_code", "status response")
_register(WEAK_ALIASES, "message", "message msg description details text detail summary body raw rawmessage note reason")
_register(WEAK_ALIASES, "file.path", "path file object objectname target_file")
_register(WEAK_ALIASES, "event.action", "type command event category_name")
_register(WEAK_ALIASES, "event.category", "category class classification group")
_register(WEAK_ALIASES, "network.protocol", "service app application app_protocol")
_register(WEAK_ALIASES, "process.name", "process program exe binary")
_register(WEAK_ALIASES, "event.code", "code id signature_number")
_register(WEAK_ALIASES, "dns.question.name", "domain fqdn hostname_queried question")
_register(WEAK_ALIASES, "network.bytes", "size length len")
_register(WEAK_ALIASES, "event.outcome", "result success state disposition verdict")

_CLEAN_RE = re.compile(r"[^a-z0-9]+")


def canonical_key(key: str) -> tuple[str | None, bool]:
    """Return the canonical field for a raw key and whether it is a strong match.

    The second element is ``True`` for strong aliases, ``False`` for weak ones
    and the function returns ``(None, False)`` when nothing matches.
    """
    if not key:
        return None, False
    flat = _CLEAN_RE.sub("_", key.strip().lower()).strip("_")
    if not flat:
        return None, False
    if flat in STRONG_ALIASES:
        return STRONG_ALIASES[flat], True
    if flat in WEAK_ALIASES:
        return WEAK_ALIASES[flat], False
    # Nested keys such as ``winlog.event_data.TargetUserName`` or
    # ``userIdentity.arn`` are matched on their last segment.
    tail = flat.rsplit("_", 1)[-1]
    parts = key.replace("/", ".").split(".")
    if len(parts) > 1:
        tail_key = _CLEAN_RE.sub("_", parts[-1].lower()).strip("_")
        if tail_key in STRONG_ALIASES:
            return STRONG_ALIASES[tail_key], True
        if tail_key in WEAK_ALIASES:
            return WEAK_ALIASES[tail_key], False
    if tail in STRONG_ALIASES:
        return STRONG_ALIASES[tail], False
    return None, False


def flatten(payload: Any, prefix: str = "", out: dict[str, Any] | None = None, depth: int = 0) -> dict[str, Any]:
    """Flatten nested JSON into dotted keys, keeping lists as joined strings."""
    if out is None:
        out = {}
    if depth > 8:
        return out
    if isinstance(payload, dict):
        for key, value in payload.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            flatten(value, child, out, depth + 1)
    elif isinstance(payload, list):
        if payload and all(not isinstance(item, (dict, list)) for item in payload):
            out[prefix] = ", ".join(str(item) for item in payload[:50])
        else:
            for index, item in enumerate(payload[:50]):
                flatten(item, f"{prefix}.{index}", out, depth + 1)
    else:
        if prefix:
            out[prefix] = payload
    return out
