"""Generated hypotheses: ATT&CK validation, the quality gate and the review queue.

The claim this file has to defend is that a hypothesis derived from an article is
executable rather than decorative. That means the technique is real, the tactic
comes from ATT&CK and not from whoever proposed it, the telemetry is something the
platform can actually ingest, and the detections are selected from the library
rather than invented.
"""

from __future__ import annotations

import uuid

import pytest

from app import attack
from app import hypotheses as service
from app.engine.catalog import BUILTIN_IDS, HYPOTHESES_BY_ID, all_hypotheses, clear_generated
from app.engine.rules import RULES_BY_ID
from app.models import GeneratedHypothesis

GOOD = dict(
    statement="Adversaries are abusing web protocols for command and control from hosts in scope.",
    technique_id="T1071.001",
    data_sources=["proxy", "dns"],
    source_url="https://thedfirreport.com/2026/03/example/",
    source_title="An example intrusion report",
    source_quote="The implant beaconed over HTTPS to a single domain every sixty seconds.",
)


def candidate(**overrides) -> service.Candidate:
    payload = {**GOOD, **overrides}
    payload["data_sources"] = tuple(payload["data_sources"])
    payload["threat_actors"] = tuple(payload.get("threat_actors", ()))
    return service.Candidate(**payload)


def _purge() -> None:
    """Both the stored candidates and the process wide registry start empty.

    The identifier of a candidate is derived from its statement and technique, so
    the same proposal in two tests is the same row. Without this, one test's
    published hypothesis is another test's surprise.
    """
    from app.database import SessionLocal, init_db

    init_db()
    session = SessionLocal()
    try:
        for row in session.query(GeneratedHypothesis).all():
            session.delete(row)
        session.commit()
        service.refresh(session, force=True)
    finally:
        session.close()
    clear_generated()


@pytest.fixture(autouse=True)
def _clean_state():
    _purge()
    yield
    _purge()


@pytest.fixture()
def db():
    from app.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# the ATT&CK reference
# ---------------------------------------------------------------------------


class TestAttackReference:
    def test_the_table_ships_with_the_repository(self):
        assert attack.REFERENCE_PATH.exists()
        assert attack.version()
        assert len(attack.tactics()) >= 10

    def test_a_known_technique_resolves(self):
        technique = attack.resolve("T1071.001")
        assert technique is not None
        assert technique.name
        assert technique.tactic
        assert technique.is_subtechnique

    def test_the_identifier_is_normalised(self):
        assert attack.resolve("t1071.001").id == "T1071.001"
        assert attack.resolve("  T1055  ").id == "T1055"

    def test_an_invented_identifier_does_not_resolve(self):
        assert attack.resolve("T9999") is None
        assert attack.resolve("T1071.999") is None

    def test_something_that_is_not_an_identifier_does_not_resolve(self):
        for value in ("", "process injection", "T107", "TA0001", "1071", "T1071.0011"):
            assert attack.resolve(value) is None, value

    def test_the_shape_check_is_only_a_shape_check(self):
        assert attack.looks_like_technique("T9999")
        assert attack.resolve("T9999") is None

    def test_a_revoked_identifier_follows_its_replacement(self):
        """ATT&CK retires identifiers. An out of date reference is not an invention."""
        revoked = attack.revoked_identifiers()
        assert revoked, "the table records no revocations at all"
        old, new = next(iter(revoked.items()))
        technique = attack.resolve(old)
        assert technique is not None
        assert technique.id == new
        assert technique.replaces == old

    def test_a_current_identifier_replaces_nothing(self):
        assert attack.resolve("T1055").replaces == ""

    def test_the_parent_of_a_sub_technique(self):
        assert attack.parent_of("T1071.001") == "T1071"
        assert attack.parent_of("T1071") == "T1071"
        assert attack.parent_of("t1071.001") == "T1071"

    def test_the_url_points_at_mitre(self):
        assert attack.resolve("T1071.001").url == "https://attack.mitre.org/techniques/T1071/001/"

    def test_every_technique_in_the_rule_library_is_real(self):
        """A rule claiming an identifier ATT&CK does not know would put an invented
        reference into a client report."""
        unknown = sorted(
            {
                rule.mitre_technique_id
                for rule in RULES_BY_ID.values()
                if rule.mitre_technique_id and attack.resolve(rule.mitre_technique_id) is None
            }
        )
        assert not unknown, f"rules reference identifiers ATT&CK does not know: {unknown}"


# ---------------------------------------------------------------------------
# selecting detections
# ---------------------------------------------------------------------------


class TestRuleMapping:
    def test_a_covered_technique_selects_rules(self):
        assert service.rules_for_technique("T1071.001")

    def test_the_selected_rules_exist(self):
        for rule_id in service.rules_for_technique("T1071.001"):
            assert rule_id in RULES_BY_ID

    def test_a_parent_and_its_children_are_selected_together(self):
        parent = set(service.rules_for_technique("T1071"))
        child = set(service.rules_for_technique("T1071.001"))
        assert parent == child, "a hypothesis should not miss a rule tagged one level away"

    def test_an_unknown_technique_selects_nothing(self):
        assert service.rules_for_technique("T9999") == ()

    def test_a_revoked_identifier_reaches_the_same_rules_as_its_replacement(self):
        revoked = attack.revoked_identifiers()
        pairs = [(old, new) for old, new in revoked.items() if service.rules_for_technique(new)]
        assert pairs, "no revoked identifier maps onto a rule, so this cannot be checked"
        old, new = pairs[0]
        assert service.rules_for_technique(old) == service.rules_for_technique(new)

    def test_the_priority_follows_the_worst_detection(self):
        critical = [rule.id for rule in RULES_BY_ID.values() if rule.severity == "critical"][:1]
        low = [rule.id for rule in RULES_BY_ID.values() if rule.severity == "low"][:1]
        assert service.priority_for(tuple(critical)) == "critical"
        assert service.priority_for(tuple(low)) == "medium"
        assert service.priority_for(()) == "medium"


# ---------------------------------------------------------------------------
# the quality gate
# ---------------------------------------------------------------------------


class TestGates:
    def test_a_sound_candidate_passes(self):
        assessment = service.assess(candidate())
        assert assessment.ready, assessment.failures
        assert assessment.technique.id == "T1071.001"
        assert assessment.data_sources == ("proxy", "dns")
        assert assessment.rule_selectors

    def test_an_invented_technique_fails(self):
        failures = service.assess(candidate(technique_id="T9999")).failures
        assert any("not in ATT&CK" in failure for failure in failures)

    def test_an_unknown_data_source_fails(self):
        failures = service.assess(candidate(data_sources=["telepathy"])).failures
        assert any("Unknown data sources" in failure for failure in failures)

    def test_no_usable_data_source_fails(self):
        failures = service.assess(candidate(data_sources=[])).failures
        assert any("No data source" in failure for failure in failures)

    def test_a_missing_source_link_fails(self):
        assert any("not referenced" in f for f in service.assess(candidate(source_url="")).failures)

    def test_a_source_link_that_is_not_a_link_fails(self):
        failures = service.assess(candidate(source_url="thedfirreport.com")).failures
        assert any("not a usable link" in failure for failure in failures)

    def test_a_statement_with_no_supporting_passage_fails(self):
        """Grounding: every claim carries a quote from the article or it is dropped."""
        failures = service.assess(candidate(source_quote="   ")).failures
        assert any("No passage" in failure for failure in failures)

    def test_an_empty_statement_fails(self):
        assert any("empty" in f for f in service.assess(candidate(statement="")).failures)

    def test_a_statement_that_says_nothing_fails(self):
        failures = service.assess(candidate(statement="Something bad happened.")).failures
        assert any("too short" in failure for failure in failures)

    def test_a_statement_longer_than_a_sentence_fails(self):
        long_text = "Adversaries are abusing web protocols for command and control. " * 3
        failures = service.assess(candidate(statement=long_text.strip())).failures
        assert any("more than one sentence" in failure for failure in failures)

    def test_an_essay_fails(self):
        failures = service.assess(candidate(statement="A" * 500)).failures
        assert any("longer than one sentence" in failure for failure in failures)

    def test_a_technique_with_no_rule_is_a_gap_and_not_a_failure(self):
        assessment = service.assess(candidate(
            statement="Adversaries are tampering with the boot process on servers in scope.",
            technique_id="T1542.003", data_sources=["linux_audit"],
        ))
        assert assessment.ready, assessment.failures
        assert assessment.detection_gap

    def test_the_same_statement_twice_is_a_duplicate(self, db):
        service.create(db, candidate())
        failures = service.assess(candidate(), service.existing_candidates(db)).failures
        assert any("Already covered by" in failure for failure in failures)

    def test_the_same_technique_over_the_same_telemetry_is_a_duplicate(self, db):
        service.create(db, candidate())
        other = candidate(statement="Attackers are using HTTPS to reach their infrastructure from the estate.")
        failures = service.assess(other, service.existing_candidates(db)).failures
        assert any("Already covered by" in failure for failure in failures)

    def test_a_rejected_candidate_does_not_block_a_new_one(self, db):
        row = service.create(db, candidate())
        row.status = "rejected"
        db.commit()
        assert service.assess(candidate(), service.existing_candidates(db)).ready


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


class TestStorage:
    def test_the_tactic_is_read_from_attack_and_not_supplied(self, db):
        row = service.create(db, candidate())
        assert row.mitre_tactic == attack.resolve("T1071.001").tactic
        assert row.mitre_technique == attack.resolve("T1071.001").name

    def test_a_candidate_lands_in_the_queue_and_not_in_the_catalogue(self, db):
        row = service.create(db, candidate())
        assert row.status == "review"
        service.refresh(db, force=True)
        assert row.hypothesis_id not in HYPOTHESES_BY_ID

    def test_a_sound_candidate_is_marked_ready(self, db):
        assert service.create(db, candidate()).quality == "ready"

    def test_a_failing_candidate_carries_its_reasons(self, db):
        row = service.create(db, candidate(technique_id="T9999", source_url=""))
        assert row.quality == "needs_attention"
        assert len(row.gate_failures) >= 2

    def test_the_same_candidate_twice_creates_one_row(self, db):
        first = service.create(db, candidate())
        second = service.create(db, candidate())
        assert first.id == second.id
        assert db.query(GeneratedHypothesis).count() == 1

    def test_the_identifier_is_stable_and_derived(self, db):
        expected = service.hypothesis_id_for(GOOD["statement"], "T1071.001")
        assert service.create(db, candidate()).hypothesis_id == expected

    def test_a_named_actor_makes_it_a_threat_intelligence_hypothesis(self, db):
        row = service.create(db, candidate(threat_actors=["FIN7"]))
        assert row.family == "cti"
        assert "FIN7" in row.name

    def test_without_an_actor_it_is_a_technique_hunt(self, db):
        assert service.create(db, candidate()).family == "technique"


class TestCatalogue:
    def test_publishing_adds_it_to_the_catalogue(self, db, workspace):
        from app.models import User

        row = service.create(db, candidate())
        user = db.query(User).first()
        service.publish(db, row, user)
        assert row.hypothesis_id in HYPOTHESES_BY_ID
        assert row.hypothesis_id in {item.id for item in all_hypotheses()}

    def test_rejecting_keeps_it_out(self, db, workspace):
        from app.models import User

        row = service.create(db, candidate())
        service.reject(db, row, db.query(User).first(), "not useful")
        assert row.hypothesis_id not in HYPOTHESES_BY_ID
        assert row.review_note == "not useful"

    def test_a_published_hypothesis_is_runnable(self, db):
        row = service.create(db, candidate())
        hypothesis = service.to_hypothesis(row)
        assert hypothesis.rules(), "a hypothesis with detections must resolve them"
        assert hypothesis.summary
        assert hypothesis.required_data_sources == ("proxy", "dns")

    def test_a_detection_gap_runs_no_rule_rather_than_every_rule(self, db):
        """Falling back to the whole statistical library would fill the report with
        observations that have nothing to do with the hypothesis."""
        row = service.create(db, candidate(
            statement="Adversaries are tampering with the boot process on servers in scope.",
            technique_id="T1542.003", data_sources=["linux_audit"],
        ))
        hypothesis = service.to_hypothesis(row)
        assert hypothesis.rule_selectors == ()
        assert hypothesis.rules() == []
        assert "no rule in the library" in hypothesis.method.lower()

    def test_a_generated_hypothesis_cannot_shadow_a_built_in_one(self):
        from app.engine.catalog import Hypothesis, register_generated

        builtin = next(iter(BUILTIN_IDS))
        original = HYPOTHESES_BY_ID[builtin]
        register_generated([Hypothesis(id=builtin, name="Impostor", family="cti", summary="",
                                      narrative="", rationale="", priority="medium")])
        assert HYPOTHESES_BY_ID[builtin] is original

    def test_registering_replaces_rather_than_accumulates(self):
        from app.engine.catalog import Hypothesis, generated_ids, register_generated

        def make(identifier):
            return Hypothesis(id=identifier, name=identifier, family="technique", summary="",
                              narrative="", rationale="", priority="medium")

        register_generated([make("gen-a"), make("gen-b")])
        assert generated_ids() == {"gen-a", "gen-b"}
        register_generated([make("gen-c")])
        assert generated_ids() == {"gen-c"}

    def test_clearing_leaves_only_the_built_in_catalogue(self):
        clear_generated()
        assert {item.id for item in all_hypotheses()} == set(BUILTIN_IDS)

    def test_the_built_in_catalogue_is_still_valid(self):
        from app.engine.catalog import validate_catalogue

        assert validate_catalogue() == []


# ---------------------------------------------------------------------------
# the API
# ---------------------------------------------------------------------------


def second_workspace(client) -> dict:
    slug = f"ws{uuid.uuid4().hex[:10]}"
    payload = client.post("/api/auth/register", json={
        "tenant_name": "Other Workspace", "tenant_slug": slug, "full_name": "Other Analyst",
        "email": f"other@{slug}.test", "password": "TestPassword123",
    }).json()
    return {"headers": {"Authorization": f"Bearer {payload['access_token']}"}, "slug": slug}


def make_member(workspace, role: str) -> dict:
    client, headers = workspace["client"], workspace["headers"]
    email = f"{role}-{uuid.uuid4().hex[:6]}@{workspace['slug']}.test"
    created = client.post("/api/admin/users", headers=headers, json={
        "email": email, "full_name": role.title(), "password": "MemberPass123", "role": role,
    })
    assert created.status_code in (200, 201), created.text
    token = client.post("/api/auth/login", json={
        "tenant_slug": workspace["slug"], "email": email, "password": "MemberPass123",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestReviewApi:
    def test_the_queue_needs_a_signed_in_user(self, client):
        assert client.get("/api/hypotheses/review").status_code == 401

    def test_the_queue_is_readable_by_an_analyst(self, workspace):
        response = workspace["client"].get("/api/hypotheses/review", headers=workspace["headers"])
        assert response.status_code == 200
        payload = response.json()
        assert payload["attack_version"] == attack.version()
        assert set(payload["counts"]) == {"review", "published", "rejected"}

    def test_a_viewer_cannot_reach_the_queue(self, workspace):
        headers = make_member(workspace, "viewer")
        assert workspace["client"].get("/api/hypotheses/review", headers=headers).status_code == 403

    def test_proposing_a_candidate_needs_an_administrator(self, workspace):
        headers = make_member(workspace, "analyst")
        response = workspace["client"].post("/api/hypotheses/candidates", headers=headers, json=GOOD)
        assert response.status_code == 403

    def test_a_candidate_is_created_with_its_derived_fields(self, workspace):
        response = workspace["client"].post(
            "/api/hypotheses/candidates", headers=workspace["headers"], json=GOOD
        )
        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["quality"] == "ready"
        assert payload["mitre_tactic"] == attack.resolve("T1071.001").tactic
        assert payload["rule_count"] >= 1
        assert payload["detection_gap"] is False
        assert payload["status"] == "review"

    def test_a_failing_candidate_reports_every_reason(self, workspace):
        response = workspace["client"].post("/api/hypotheses/candidates", headers=workspace["headers"],
            json={**GOOD, "technique_id": "T9999", "source_url": "", "data_sources": ["nonsense"]})
        payload = response.json()
        assert payload["quality"] == "needs_attention"
        assert len(payload["gate_failures"]) >= 3

    def test_a_failing_candidate_cannot_be_published(self, workspace):
        created = workspace["client"].post("/api/hypotheses/candidates", headers=workspace["headers"],
            json={**GOOD, "technique_id": "T9999"}).json()
        response = workspace["client"].post(
            f"/api/hypotheses/review/{created['id']}/publish", headers=workspace["headers"]
        )
        assert response.status_code == 409
        assert "did not pass" in response.json()["detail"]

    def test_publishing_puts_it_in_the_catalogue(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        before = len(BUILTIN_IDS)
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        assert client.post(f"/api/hypotheses/review/{created['id']}/publish",
                           headers=headers, json={"note": "checked"}).status_code == 200
        after = client.get("/api/hypotheses", headers=headers).json()
        assert after["total"] == before + 1
        assert created["hypothesis_id"] in {item["id"] for item in after["items"]}

    def test_a_published_hypothesis_is_marked_as_generated(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)
        generated = client.get("/api/hypotheses?origin=generated", headers=headers).json()
        assert created["hypothesis_id"] in {item["id"] for item in generated["items"]}
        builtin = client.get("/api/hypotheses?origin=builtin", headers=headers).json()
        assert created["hypothesis_id"] not in {item["id"] for item in builtin["items"]}

    def test_the_detail_carries_the_article_it_came_from(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)
        detail = client.get(f"/api/hypotheses/{created['hypothesis_id']}", headers=headers).json()
        assert detail["origin"] == "generated"
        assert detail["source"]["url"] == GOOD["source_url"]
        assert detail["source"]["quote"] == GOOD["source_quote"]
        assert detail["rules"]

    def test_a_built_in_hypothesis_has_no_source(self, workspace):
        detail = workspace["client"].get(
            "/api/hypotheses/math-full-spectrum", headers=workspace["headers"]
        ).json()
        assert detail["origin"] == "builtin"
        assert "source" not in detail

    def test_rejecting_keeps_it_out_of_the_catalogue(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        before = len(BUILTIN_IDS)
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        assert client.post(f"/api/hypotheses/review/{created['id']}/reject",
                           headers=headers, json={"note": "duplicate"}).status_code == 200
        assert client.get("/api/hypotheses", headers=headers).json()["total"] == before
        assert client.get(f"/api/hypotheses/{created['hypothesis_id']}",
                          headers=headers).status_code == 404

    def test_an_unknown_candidate_is_not_found(self, workspace):
        response = workspace["client"].post(
            "/api/hypotheses/review/doesnotexist/publish", headers=workspace["headers"]
        )
        assert response.status_code == 404

    def test_the_queue_can_be_filtered_by_status(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)
        published = client.get("/api/hypotheses/review?status=published", headers=headers).json()
        assert created["id"] in {item["id"] for item in published["items"]}
        pending = client.get("/api/hypotheses/review?status=review", headers=headers).json()
        assert created["id"] not in {item["id"] for item in pending["items"]}

    def test_an_unknown_status_is_rejected(self, workspace):
        response = workspace["client"].get(
            "/api/hypotheses/review?status=nonsense", headers=workspace["headers"]
        )
        assert response.status_code == 422

    def test_a_published_hypothesis_is_shared_with_every_tenant(self, workspace):
        """The decision this checks: hypotheses come from public reporting, never from
        client evidence, so there is nothing to isolate and the collector runs once."""
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)

        other = second_workspace(client)
        catalogue = client.get("/api/hypotheses", headers=other["headers"]).json()
        assert created["hypothesis_id"] in {item["id"] for item in catalogue["items"]}
        detail = client.get(f"/api/hypotheses/{created['hypothesis_id']}", headers=other["headers"])
        assert detail.status_code == 200

    def test_the_health_endpoint_counts_the_whole_catalogue(self, workspace):
        client, headers = workspace["client"], workspace["headers"]
        before = len(BUILTIN_IDS)
        assert client.get("/api/health").json()["hypotheses"] == before
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)
        assert client.get("/api/health").json()["hypotheses"] == before + 1
        assert client.get("/api/health").json()["attack_version"] == attack.version()


class TestRunningAGeneratedHypothesis:
    def test_a_hunt_runs_from_a_published_hypothesis(self, workspace, sample_archive):
        from tests.test_api import wait_for_completion

        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        client.post(f"/api/hypotheses/review/{created['id']}/publish", headers=headers)

        with open(sample_archive, "rb") as handle:
            response = client.post("/api/hunts", headers=headers,
                files={"file": ("evidence.zip", handle, "application/zip")},
                data={"hypothesis_id": created["hypothesis_id"], "title": "Generated run"})
        assert response.status_code == 201, response.text
        hunt = wait_for_completion(client, headers, response.json()["id"])
        assert hunt["status"] == "completed"
        assert hunt["observation_count"] > 0
        assert hunt["rules_evaluated"] == created["rule_count"]

    def test_a_hunt_cannot_use_a_candidate_that_was_never_published(self, workspace, sample_archive):
        client, headers = workspace["client"], workspace["headers"]
        created = client.post("/api/hypotheses/candidates", headers=headers, json=GOOD).json()
        with open(sample_archive, "rb") as handle:
            response = client.post("/api/hunts", headers=headers,
                files={"file": ("evidence.zip", handle, "application/zip")},
                data={"hypothesis_id": created["hypothesis_id"], "title": "Too early"})
        assert response.status_code == 400
