"""Sysmon operational log sample for the privilege escalation hypothesis.

Covers the record types the data source calls for: process creation with
command lines and hashes (event 1), network connections (3), driver and image
loads (6, 7), registry changes (12, 13) and DNS queries (22). A single
escalation chain is planted inside ordinary workstation activity.
"""
import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone

RNG = random.Random(20260311)
BASE = datetime(2026, 3, 11, 8, 0, 0, tzinfo=timezone.utc)
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROVIDER = "Microsoft-Windows-Sysmon"
GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"

HOSTS = ["WS-FIN-014", "WS-HR-022", "WS-ENG-101", "WS-MKT-047", "SRV-APP-02"]
USERS = ["CORP\\j.dupont", "CORP\\m.laurent", "CORP\\a.schmidt", "CORP\\p.novak"]
DOMAINS = ["www.microsoft.com", "login.microsoftonline.com", "outlook.office365.com",
           "teams.microsoft.com", "update.googleapis.com", "cdn.jsdelivr.net"]

records = []
_pid = [4000]


def pid():
    _pid[0] += RNG.randint(4, 40)
    return _pid[0]


def utc(offset):
    return (BASE + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def iso(offset):
    return (BASE + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")


def hashes(name):
    seed = hashlib.sha256(name.encode()).hexdigest()
    return (f"SHA1={seed[:40].upper()},MD5={seed[40:72].upper()},"
            f"SHA256={seed.upper()},IMPHASH={seed[:32].upper()}")


def base(offset, event_id, task, host, user):
    return {
        "@timestamp": iso(offset),
        "EventID": event_id,
        "Channel": CHANNEL,
        "Provider": PROVIDER,
        "ProviderGuid": GUID,
        "Computer": host,
        "Task": task,
        "UtcTime": utc(offset),
        "ProcessGuid": "{%08x-0000-0000-0000-%012x}" % (RNG.getrandbits(32), RNG.getrandbits(48)),
        "User": user,
    }


def process_create(offset, host, user, image, command, parent_image, parent_command,
                   integrity="Medium", process_id=None, parent_pid=None):
    record = base(offset, 1, "Process Create", host, user)
    record.update({
        "Image": image,
        "CommandLine": command,
        "CurrentDirectory": "C:\\Users\\" + user.split("\\")[-1] + "\\",
        "ProcessId": process_id or pid(),
        "IntegrityLevel": integrity,
        "Hashes": hashes(image),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command,
        "ParentProcessId": parent_pid or pid(),
        "OriginalFileName": image.rsplit("\\", 1)[-1],
        "LogonId": "0x%x" % RNG.getrandbits(24),
    })
    return record


def network_connect(offset, host, user, image, dest_ip, dest_port, dest_host="", initiated=True):
    record = base(offset, 3, "Network connection detected", host, user)
    record.update({
        "Image": image,
        "Protocol": "tcp",
        "Initiated": initiated,
        "SourceIp": "10.20.4.%d" % RNG.randint(10, 80),
        "SourcePort": RNG.randint(49152, 65535),
        "DestinationIp": dest_ip,
        "DestinationPort": dest_port,
        "DestinationHostname": dest_host,
        "ProcessId": pid(),
    })
    return record


def image_load(offset, host, user, image, loaded, signed=True, signature="Microsoft Windows"):
    record = base(offset, 7, "Image loaded", host, user)
    record.update({
        "Image": image,
        "ImageLoaded": loaded,
        "Hashes": hashes(loaded),
        "Signed": str(signed).lower(),
        "Signature": signature,
        "SignatureStatus": "Valid" if signed else "Unavailable",
        "ProcessId": pid(),
    })
    return record


def driver_load(offset, host, loaded, signed, signature):
    record = base(offset, 6, "Driver loaded", host, "NT AUTHORITY\\SYSTEM")
    record.update({
        "ImageLoaded": loaded,
        "Hashes": hashes(loaded),
        "Signed": str(signed).lower(),
        "Signature": signature,
        "SignatureStatus": "Valid" if signed else "Unavailable",
    })
    return record


def registry_set(offset, host, user, image, target, details, event_id=13):
    record = base(offset, event_id, "Registry value set", host, user)
    record.update({
        "EventType": "SetValue" if event_id == 13 else "CreateKey",
        "Image": image,
        "TargetObject": target,
        "Details": details,
        "ProcessId": pid(),
    })
    return record


def dns_query(offset, host, user, image, query, results):
    record = base(offset, 22, "Dns query", host, user)
    record.update({
        "Image": image,
        "QueryName": query,
        "QueryStatus": "0",
        "QueryResults": results,
        "ProcessId": pid(),
    })
    return record


# --------------------------------------------------------------- background
BENIGN = [
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE /recycle", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe {222A245B}", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Microsoft Teams\\Teams.exe", "Teams.exe --system-initiated", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\SearchIndexer.exe", "SearchIndexer.exe /Embedding", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\System32\\RuntimeBroker.exe", "RuntimeBroker.exe -Embedding", "C:\\Windows\\System32\\svchost.exe"),
]
BENIGN_DLLS = [
    "C:\\Windows\\System32\\kernel32.dll", "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\advapi32.dll", "C:\\Windows\\System32\\ole32.dll",
]

for index in range(240):
    offset = index * 11 + RNG.uniform(0, 5)
    host, user = RNG.choice(HOSTS), RNG.choice(USERS)
    image, command, parent = RNG.choice(BENIGN)
    records.append(process_create(offset, host, user, image, command, parent, parent.rsplit("\\", 1)[-1]))
    if index % 3 == 0:
        records.append(image_load(offset + 1, host, user, image, RNG.choice(BENIGN_DLLS)))
    if index % 4 == 0:
        domain = RNG.choice(DOMAINS)
        records.append(dns_query(offset + 2, host, user, image, domain, "type: 5 " + domain))
        records.append(network_connect(offset + 3, host, user, image,
                                       "104.18.%d.%d" % (RNG.randint(1, 40), RNG.randint(1, 250)),
                                       443, domain))
    if index % 6 == 0:
        records.append(registry_set(
            offset + 4, host, user, image,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden", "DWORD (0x00000001)"))

# ------------------------------------------------------- escalation chain
H, U = "WS-FIN-014", "CORP\\j.dupont"
EXPLORER = "C:\\Windows\\explorer.exe"

# 1. Foothold: an interactive shell at medium integrity.
records.append(process_create(
    1800, H, U, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c \"whoami /priv\"",
    EXPLORER, "C:\\Windows\\Explorer.EXE", integrity="Medium"))

# 2. UAC bypass staged in the registry, then triggered by the auto elevating binary.
records.append(registry_set(
    1830, H, U, "C:\\Windows\\System32\\reg.exe",
    "HKU\\S-1-5-21-1004336348-1177238915-682003330-1004\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\(Default)",
    "C:\\Users\\Public\\updater.exe", event_id=13))
records.append(registry_set(
    1832, H, U, "C:\\Windows\\System32\\reg.exe",
    "HKU\\S-1-5-21-1004336348-1177238915-682003330-1004\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute",
    "", event_id=13))
records.append(process_create(
    1860, H, U, "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe",
    EXPLORER, "C:\\Windows\\Explorer.EXE", integrity="High"))
records.append(process_create(
    1862, H, U, "C:\\Users\\Public\\updater.exe", "\"C:\\Users\\Public\\updater.exe\" -elevated",
    "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe", integrity="High"))

# 3. A second bypass path, tried when the first is patched.
records.append(process_create(
    1920, H, U, "C:\\Windows\\System32\\computerdefaults.exe", "computerdefaults.exe",
    EXPLORER, "C:\\Windows\\Explorer.EXE", integrity="High"))

# 4. Bring your own vulnerable driver, from service creation to the kernel load.
records.append(process_create(
    1980, H, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\sc.exe",
    "sc.exe create RTCore64 binPath= C:\\Users\\Public\\RTCore64.sys type= kernel start= demand",
    "C:\\Users\\Public\\updater.exe", "\"C:\\Users\\Public\\updater.exe\" -elevated", integrity="High"))
records.append(driver_load(
    2010, H, "C:\\Users\\Public\\RTCore64.sys", False, "MICRO-STAR INTERNATIONAL CO., LTD."))
records.append(image_load(
    2012, H, "NT AUTHORITY\\SYSTEM", "C:\\Users\\Public\\updater.exe",
    "C:\\Users\\Public\\RTCore64.sys", signed=False, signature="MICRO-STAR INTERNATIONAL CO., LTD."))

# 5. Exploitation of a named vulnerability against the print spooler.
records.append(process_create(
    2070, H, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\spoolsv.exe",
    "spoolsv.exe -k print CVE-2021-34527 printnightmare AddPrinterDriverEx",
    "C:\\Windows\\System32\\services.exe", "services.exe", integrity="System"))
records.append(image_load(
    2072, H, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\spoolsv.exe",
    "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\evil.dll", signed=False, signature=""))

# 6. Persisting the gained privilege in a local group.
records.append(process_create(
    2130, H, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\net.exe",
    "net.exe localgroup administrators svc_helpdesk /add",
    "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net localgroup administrators svc_helpdesk /add",
    integrity="System"))
records.append(process_create(
    2132, H, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\net1.exe",
    "C:\\Windows\\system32\\net1 localgroup administrators svc_helpdesk /add",
    "C:\\Windows\\System32\\net.exe", "net.exe localgroup administrators svc_helpdesk /add",
    integrity="System"))

# 7. The elevated payload reaches its controller.
records.append(dns_query(
    2190, H, "NT AUTHORITY\\SYSTEM", "C:\\Users\\Public\\updater.exe",
    "cdn-update-svc.duckdns.org", "type: 1 185.220.101.44"))
records.append(network_connect(
    2192, H, "NT AUTHORITY\\SYSTEM", "C:\\Users\\Public\\updater.exe",
    "185.220.101.44", 8443, "cdn-update-svc.duckdns.org"))

records.sort(key=lambda item: item["@timestamp"])

if __name__ == "__main__":
    from collections import Counter
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?",
                        default="samples/sysmon-privilege-escalation.json")
    arguments = parser.parse_args()
    target = Path(arguments.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    print(f"Wrote {target} with {len(records)} records")
    print("event ids:", dict(sorted(Counter(item["EventID"] for item in records).items())))
