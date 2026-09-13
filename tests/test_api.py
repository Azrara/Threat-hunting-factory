"""API contract, authentication, tenant isolation and the hunt lifecycle."""

from __future__ import annotations

import time

import pytest


def wait_for_completion(client, headers, hunt_id, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/api/hunts/{hunt_id}", headers=headers)
        assert response.status_code == 200
        hunt = response.json()
        if hunt["status"] in ("completed", "failed"):
            return hunt
        time.sleep(0.3)
    raise AssertionError("The hunt did not complete in time")


class TestHealth:
    def test_health_is_public(self, client):
        payload = client.get("/api/health").json()
        assert payload["status"] == "ok"
        assert payload["engine"]["total"] >= 100

    def test_the_hypothesis_count_is_served_rather_than_hard_coded(self, client):
        """The sign in page shows this number, so a stale constant is a visible lie."""
        from app.engine.catalog import HYPOTHESES

        payload = client.get("/api/health").json()
        assert payload["hypotheses"] == len(HYPOTHESES)

    def test_the_interface_is_served(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "Threat Hunting Factory" in response.text


class TestRegistration:
    def test_registration_creates_an_administrator(self, workspace):
        payload = workspace["payload"]
        assert payload["user"]["role"] == "admin"
        assert payload["tenant"]["slug"] == workspace["slug"]
        assert payload["access_token"]

    def test_duplicate_workspace_is_rejected(self, client, workspace):
        response = client.post("/api/auth/register", json={
            "tenant_name": "Copy", "tenant_slug": workspace["slug"], "full_name": "Someone",
            "email": "other@example.com", "password": "AnotherPass123",
        })
        assert response.status_code == 409

    @pytest.mark.parametrize("slug", ["ab", "Has Spaces", "under_score", "-leading", "a" * 80])
    def test_invalid_workspace_identifiers_are_rejected(self, client, slug):
        response = client.post("/api/auth/register", json={
            "tenant_name": "Test", "tenant_slug": slug, "full_name": "Test User",
            "email": "user@example.com", "password": "ValidPassword1",
        })
        assert response.status_code == 422
        assert isinstance(response.json()["detail"], str)

    def test_workspace_identifiers_are_normalised(self, client):
        response = client.post("/api/auth/register", json={
            "tenant_name": "Test", "tenant_slug": "  MixedCase-Slug  ", "full_name": "Test User",
            "email": "user@mixedcase.test", "password": "ValidPassword1",
        })
        assert response.status_code == 201
        assert response.json()["tenant"]["slug"] == "mixedcase-slug"

    def test_short_password_is_rejected(self, client):
        response = client.post("/api/auth/register", json={
            "tenant_name": "Test", "tenant_slug": "shortpw", "full_name": "Test User",
            "email": "user@example.com", "password": "short",
        })
        assert response.status_code == 422


class TestAuthentication:
    def test_login_succeeds(self, workspace):
        response = workspace["client"].post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": workspace["email"], "password": workspace["password"],
        })
        assert response.status_code == 200
        assert response.json()["user"]["email"] == workspace["email"]

    def test_email_is_case_insensitive(self, workspace):
        response = workspace["client"].post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": workspace["email"].upper(),
            "password": workspace["password"],
        })
        assert response.status_code == 200

    def test_wrong_password_is_rejected(self, workspace):
        response = workspace["client"].post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": workspace["email"], "password": "WrongPassword1",
        })
        assert response.status_code == 401
        # The interface shows this text, and it must not leak which part was wrong.
        detail = response.json()["detail"]
        assert detail == "Invalid workspace, email address or password"

    def test_the_rejection_is_identical_for_every_wrong_input(self, workspace):
        """A different message for each case would enumerate accounts."""
        client, slug = workspace["client"], workspace["slug"]
        cases = [
            {"tenant_slug": slug, "email": workspace["email"], "password": "WrongPassword1"},
            {"tenant_slug": slug, "email": "nobody@nowhere.test", "password": "WrongPassword1"},
            {"tenant_slug": "no-such-workspace", "email": workspace["email"], "password": "WrongPassword1"},
        ]
        details = {client.post("/api/auth/login", json=case).json()["detail"] for case in cases}
        assert len(details) == 1

    def test_unknown_workspace_is_rejected(self, workspace):
        response = workspace["client"].post("/api/auth/login", json={
            "tenant_slug": "no-such-workspace", "email": workspace["email"], "password": workspace["password"],
        })
        assert response.status_code == 401

    @pytest.mark.parametrize("path", [
        "/api/hypotheses", "/api/hunts", "/api/stats/overview", "/api/rules",
        "/api/data-sources", "/api/admin/users",
    ])
    def test_endpoints_require_a_token(self, client, path):
        assert client.get(path).status_code == 401

    def test_a_forged_token_is_rejected(self, client):
        response = client.get("/api/hunts", headers={"Authorization": "Bearer not.a.real.token"})
        assert response.status_code == 401

    def test_me_returns_the_session(self, workspace):
        payload = workspace["client"].get("/api/auth/me", headers=workspace["headers"]).json()
        assert payload["user"]["email"] == workspace["email"]
        assert payload["tenant"]["slug"] == workspace["slug"]


class TestCatalogueEndpoints:
    def test_hypotheses_are_listed(self, workspace):
        payload = workspace["client"].get("/api/hypotheses", headers=workspace["headers"]).json()
        assert payload["total"] >= 20
        assert set(payload["families"]) == {"cti", "technique", "mathematical"}

    def test_family_filter(self, workspace):
        payload = workspace["client"].get(
            "/api/hypotheses?family=mathematical", headers=workspace["headers"]).json()
        assert payload["total"] > 0
        assert all(item["family"] == "mathematical" for item in payload["items"])

    def test_search_filter(self, workspace):
        payload = workspace["client"].get(
            "/api/hypotheses?search=ransomware", headers=workspace["headers"]).json()
        assert payload["total"] >= 1

    def test_hypothesis_detail_carries_its_rules(self, workspace):
        payload = workspace["client"].get(
            "/api/hypotheses/cti-ransomware-precursor", headers=workspace["headers"]).json()
        assert payload["rule_count"] == len(payload["rules"])
        assert payload["required_data_sources"][0]["collection_hint"]

    def test_unknown_hypothesis_is_a_404(self, workspace):
        assert workspace["client"].get(
            "/api/hypotheses/does-not-exist", headers=workspace["headers"]).status_code == 404

    def test_data_sources_are_documented(self, workspace):
        payload = workspace["client"].get("/api/data-sources", headers=workspace["headers"]).json()
        assert len(payload["items"]) >= 15
        for source in payload["items"]:
            assert source["formats"] and source["collection_hint"]

    def test_rule_library_is_exposed(self, workspace):
        payload = workspace["client"].get("/api/rules", headers=workspace["headers"]).json()
        assert len(payload["items"]) == payload["statistics"]["total"]


class TestHuntLifecycle:
    @pytest.fixture(scope="class")
    def completed(self, request):
        """One hunt executed once and reused by the assertions below."""
        import uuid

        from fastapi.testclient import TestClient

        from app.main import app
        from tools.generate_sample_evidence import build

        archive = build(request.config.rootpath / "data" / "test-evidence.zip", seed=31)
        client = TestClient(app)
        client.__enter__()
        slug = f"hunt{uuid.uuid4().hex[:8]}"
        payload = client.post("/api/auth/register", json={
            "tenant_name": "Hunt Workspace", "tenant_slug": slug, "full_name": "Hunter",
            "email": f"hunter@{slug}.test", "password": "HuntPassword123",
        }).json()
        headers = {"Authorization": f"Bearer {payload['access_token']}"}
        with open(archive, "rb") as handle:
            response = client.post("/api/hunts", headers=headers,
                                   data={"hypothesis_id": "math-full-spectrum", "title": "Contract test"},
                                   files={"file": ("evidence.zip", handle, "application/zip")})
        assert response.status_code == 201
        hunt = wait_for_completion(client, headers, response.json()["id"])
        yield {"client": client, "headers": headers, "hunt": hunt}
        client.__exit__(None, None, None)
        archive.unlink(missing_ok=True)

    def test_the_hunt_completes(self, completed):
        hunt = completed["hunt"]
        assert hunt["status"] == "completed"
        assert hunt["progress"] == 100
        assert hunt["observation_count"] > 10
        assert hunt["events_parsed"] > 1000
        assert hunt["risk_score"] > 0
        assert hunt["error"] == ""

    def test_the_detail_carries_the_hypothesis(self, completed):
        detail = completed["client"].get(
            f"/api/hunts/{completed['hunt']['id']}", headers=completed["headers"]).json()
        assert detail["hypothesis"]["id"] == "math-full-spectrum"
        assert detail["summary"]["files"]
        assert detail["coverage"]

    def test_observations_are_complete(self, completed):
        payload = completed["client"].get(
            f"/api/hunts/{completed['hunt']['id']}/observations", headers=completed["headers"]).json()
        assert payload["total"] == completed["hunt"]["observation_count"]
        for observation in payload["items"]:
            assert observation["title"] and observation["description"]
            assert observation["risk"] and observation["impact"] and observation["recommendation"]
            assert observation["severity"] in {"critical", "high", "medium", "low", "info"}
        assert any(observation["evidence"] for observation in payload["items"])

    def test_observations_are_sorted_by_score(self, completed):
        items = completed["client"].get(
            f"/api/hunts/{completed['hunt']['id']}/observations", headers=completed["headers"]).json()["items"]
        scores = [item["score"] for item in items]
        assert scores == sorted(scores, reverse=True)

    def test_observation_filters(self, completed):
        base = f"/api/hunts/{completed['hunt']['id']}/observations"
        critical = completed["client"].get(f"{base}?severity=critical", headers=completed["headers"]).json()
        assert all(item["severity"] == "critical" for item in critical["items"])
        search = completed["client"].get(f"{base}?search=lsass", headers=completed["headers"]).json()
        assert search["total"] >= 1

    def test_pdf_export(self, completed):
        response = completed["client"].get(
            f"/api/hunts/{completed['hunt']['id']}/report.pdf", headers=completed["headers"])
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-")
        assert len(response.content) > 40000
        assert "attachment" in response.headers["content-disposition"]

    def test_json_export(self, completed):
        response = completed["client"].get(
            f"/api/hunts/{completed['hunt']['id']}/report.json", headers=completed["headers"])
        assert response.status_code == 200
        payload = response.json()
        assert payload["hunt"]["id"] == completed["hunt"]["id"]
        assert payload["hypothesis"]["id"] == "math-full-spectrum"
        assert len(payload["observations"]) == completed["hunt"]["observation_count"]

    def test_statistics_reflect_the_hunt(self, completed):
        stats = completed["client"].get("/api/stats/overview", headers=completed["headers"]).json()
        assert stats["totals"]["hunts"] == 1
        assert stats["totals"]["observations"] == completed["hunt"]["observation_count"]
        assert stats["totals"]["events_analysed"] == completed["hunt"]["events_parsed"]
        assert stats["techniques"] and stats["tactics"]
        assert stats["timeline"]
        assert stats["recent_hunts"][0]["id"] == completed["hunt"]["id"]


class TestUploadValidation:
    def test_unknown_hypothesis_is_rejected(self, workspace):
        response = workspace["client"].post("/api/hunts", headers=workspace["headers"],
                                            data={"hypothesis_id": "nope"},
                                            files={"file": ("a.zip", b"PK\x03\x04", "application/zip")})
        assert response.status_code == 400

    def test_unsupported_extension_is_rejected(self, workspace):
        response = workspace["client"].post("/api/hunts", headers=workspace["headers"],
                                            data={"hypothesis_id": "math-full-spectrum"},
                                            files={"file": ("payload.exe", b"MZ", "application/octet-stream")})
        assert response.status_code == 400

    def test_empty_upload_is_rejected(self, workspace):
        response = workspace["client"].post("/api/hunts", headers=workspace["headers"],
                                            data={"hypothesis_id": "math-full-spectrum"},
                                            files={"file": ("empty.log", b"", "text/plain")})
        assert response.status_code == 400

    def test_a_single_log_file_is_accepted(self, workspace):
        content = b"\n".join(
            b'Mar 11 08:15:2%d srv sshd[1]: Failed password for root from 91.240.118.172 port 22 ssh2' % (index % 10)
            for index in range(40))
        response = workspace["client"].post("/api/hunts", headers=workspace["headers"],
                                            data={"hypothesis_id": "tech-brute-force"},
                                            files={"file": ("auth.log", content, "text/plain")})
        assert response.status_code == 201
        hunt = wait_for_completion(workspace["client"], workspace["headers"], response.json()["id"])
        assert hunt["status"] == "completed"
        assert hunt["events_parsed"] == 40

    def test_unknown_hunt_is_a_404(self, workspace):
        assert workspace["client"].get(
            "/api/hunts/0123456789abcdef", headers=workspace["headers"]).status_code == 404

    def test_report_before_completion_is_rejected(self, workspace):
        response = workspace["client"].get(
            "/api/hunts/0123456789abcdef/report.pdf", headers=workspace["headers"])
        assert response.status_code == 404


class TestTenantIsolation:
    @pytest.fixture()
    def two_workspaces(self, client):
        import uuid

        created = []
        for _ in range(2):
            slug = f"iso{uuid.uuid4().hex[:8]}"
            payload = client.post("/api/auth/register", json={
                "tenant_name": "Isolated", "tenant_slug": slug, "full_name": "User",
                "email": f"user@{slug}.test", "password": "IsolationPass1",
            }).json()
            created.append({"slug": slug, "headers": {"Authorization": f"Bearer {payload['access_token']}"}})
        return client, created[0], created[1]

    def test_hunts_are_not_visible_across_workspaces(self, two_workspaces):
        client, first, second = two_workspaces
        response = client.post("/api/hunts", headers=first["headers"],
                               data={"hypothesis_id": "tech-brute-force"},
                               files={"file": ("auth.log", b"Mar 11 08:15:22 srv sshd[1]: Failed password\n",
                                               "text/plain")})
        hunt_id = response.json()["id"]
        assert client.get(f"/api/hunts/{hunt_id}", headers=second["headers"]).status_code == 404
        assert client.get(f"/api/hunts/{hunt_id}/observations", headers=second["headers"]).status_code == 404
        assert client.get(f"/api/hunts/{hunt_id}/report.pdf", headers=second["headers"]).status_code == 404
        assert client.get("/api/hunts", headers=second["headers"]).json()["total"] == 0

    def test_statistics_are_scoped(self, two_workspaces):
        client, first, second = two_workspaces
        client.post("/api/hunts", headers=first["headers"],
                    data={"hypothesis_id": "tech-brute-force"},
                    files={"file": ("auth.log", b"Mar 11 08:15:22 srv sshd[1]: Failed password\n", "text/plain")})
        assert client.get("/api/stats/overview", headers=second["headers"]).json()["totals"]["hunts"] == 0

    def test_members_are_scoped(self, two_workspaces):
        client, first, second = two_workspaces
        first_users = client.get("/api/admin/users", headers=first["headers"]).json()
        second_users = client.get("/api/admin/users", headers=second["headers"]).json()
        assert first_users["total"] == second_users["total"] == 1
        assert first_users["items"][0]["email"] != second_users["items"][0]["email"]


class TestAdministration:
    def test_members_can_be_added_and_updated(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/admin/users", headers=headers, json={
            "email": "analyst2@example.com", "full_name": "Second Analyst",
            "password": "SecondPass123", "role": "analyst",
        })
        assert created.status_code == 201
        user_id = created.json()["id"]

        updated = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"role": "viewer"})
        assert updated.json()["role"] == "viewer"

        disabled = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"is_active": False})
        assert disabled.json()["is_active"] is False

        assert client.delete(f"/api/admin/users/{user_id}", headers=headers).status_code == 204

    def test_duplicate_member_is_rejected(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        client.post("/api/admin/users", headers=headers, json={
            "email": "dup@example.com", "full_name": "Dup", "password": "DupPassword1", "role": "analyst"})
        second = client.post("/api/admin/users", headers=headers, json={
            "email": "dup@example.com", "full_name": "Dup", "password": "DupPassword1", "role": "analyst"})
        assert second.status_code == 409

    def test_an_administrator_cannot_demote_themselves(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        me = client.get("/api/auth/me", headers=headers).json()["user"]
        response = client.patch(f"/api/admin/users/{me['id']}", headers=headers, json={"role": "viewer"})
        assert response.status_code == 400

    def test_viewers_cannot_run_hunts(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        client.post("/api/admin/users", headers=headers, json={
            "email": "viewer@example.com", "full_name": "Viewer",
            "password": "ViewerPass123", "role": "viewer"})
        token = client.post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": "viewer@example.com",
            "password": "ViewerPass123"}).json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/api/hunts", headers=viewer_headers,
                               data={"hypothesis_id": "math-full-spectrum"},
                               files={"file": ("a.log", b"line\n", "text/plain")})
        assert response.status_code == 403
        assert client.get("/api/hunts", headers=viewer_headers).status_code == 200

    def test_non_administrators_cannot_manage_members(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        client.post("/api/admin/users", headers=headers, json={
            "email": "analyst3@example.com", "full_name": "Analyst",
            "password": "AnalystPass1", "role": "analyst"})
        token = client.post("/api/auth/login", json={
            "tenant_slug": workspace["slug"], "email": "analyst3@example.com",
            "password": "AnalystPass1"}).json()["access_token"]
        analyst_headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/api/admin/users", headers=analyst_headers, json={
            "email": "another@example.com", "full_name": "Another",
            "password": "AnotherPass1", "role": "analyst"})
        assert response.status_code == 403
        assert client.get("/api/admin/audit", headers=analyst_headers).status_code == 403

    def test_the_audit_trail_records_actions(self, workspace):
        payload = workspace["client"].get("/api/admin/audit", headers=workspace["headers"]).json()
        actions = {entry["action"] for entry in payload["items"]}
        assert "tenant.created" in actions


class TestStaticHosting:
    def test_unknown_api_paths_return_404(self, client):
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/json")

    def test_unknown_interface_routes_serve_the_application(self, client):
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_static_assets_are_served(self, client):
        assert client.get("/css/theme.css").status_code == 200
        assert client.get("/js/app.js").status_code == 200

    def test_path_traversal_is_not_served(self, client):
        response = client.get("/../app/config.py")
        assert response.status_code in (200, 404)
        assert "THF_JWT_SECRET" not in response.text


class TestUntrustedContent:
    """Log content is attacker influenced and reaches the browser and the PDF."""

    @pytest.fixture(scope="class")
    def hostile(self, tmp_path_factory):
        import json
        import zipfile

        payloads = [
            '<script>window.pwned=1</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            '<onDraw name="x"/><font color="red">inject</font>',
            "'; DROP TABLE hunts; --",
        ]
        records = []
        for index, payload in enumerate(payloads):
            records.append(json.dumps({
                "@timestamp": f"2026-03-11T09:0{index}:00Z", "Channel": "Security", "EventID": 4688,
                "Computer": f"WS-{payload}", "TargetUserName": payload,
                "CommandLine": f"vssadmin.exe delete shadows /all {payload}",
            }))
        target = tmp_path_factory.mktemp("hostile") / "hostile.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("windows/security.json", "\n".join(records))
        return target

    def test_the_pipeline_carries_payloads_without_executing_them(self, workspace, hostile):
        client, headers = workspace["client"], workspace["headers"]
        with open(hostile, "rb") as handle:
            response = client.post("/api/hunts", headers=headers,
                                   data={"hypothesis_id": "math-full-spectrum"},
                                   files={"file": ("hostile.zip", handle, "application/zip")})
        assert response.status_code == 201
        hunt = wait_for_completion(client, headers, response.json()["id"])
        assert hunt["status"] == "completed"

        observations = client.get(f"/api/hunts/{hunt['id']}/observations",
                                  headers=headers).json()["items"]
        assert observations, "the planted behaviour should still be detected"
        # The payload has to survive as data, so the analyst sees what was logged.
        assert any("<script>" in item["entity"] or "<script>" in str(item["evidence"])
                   for item in observations)

        # The report renders it without failing, which is where escaping happens.
        pdf = client.get(f"/api/hunts/{hunt['id']}/report.pdf", headers=headers)
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")

        exported = client.get(f"/api/hunts/{hunt['id']}/report.json", headers=headers)
        assert exported.status_code == 200
        assert exported.json()["observations"]

    def test_the_database_is_intact_afterwards(self, workspace):
        assert workspace["client"].get("/api/hunts", headers=workspace["headers"]).status_code == 200
