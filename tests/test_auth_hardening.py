"""Authentication hardening: enumeration, throttling and hostile upload names."""

from __future__ import annotations

import time

import pytest

from app.routers.hunts import MAX_FILENAME_LENGTH, _safe_filename
from app.throttle import SlidingWindowLimiter, account_limiter, address_limiter, client_address


class TestFilenameSanitising:
    @pytest.mark.parametrize("raw,expected", [
        ("../../../../etc/passwd.log", "passwd.log"),
        ("logs/../../x.log", "x.log"),
        ("/etc/shadow.log", "shadow.log"),
        ("normal-name.zip", "normal-name.zip"),
        ("..", "evidence.zip"),
        (".", "evidence.zip"),
        ("", "evidence.zip"),
        (None, "evidence.zip"),
    ])
    def test_names_are_reduced_to_a_safe_basename(self, raw, expected):
        assert _safe_filename(raw) == expected

    def test_long_names_are_truncated(self):
        result = _safe_filename("a" * 400 + ".log")
        assert len(result) <= MAX_FILENAME_LENGTH
        assert result.endswith(".log")

    def test_control_characters_are_removed(self):
        assert "\x00" not in _safe_filename("\x00evil\x01.log")

    def test_the_result_never_escapes_a_directory(self):
        from pathlib import Path

        for raw in ["../../x", "..\\..\\x", "/////x", "a/b/c/d.log", "~/.ssh/id_rsa"]:
            name = _safe_filename(raw)
            assert "/" not in name and "\\" not in name
            assert (Path("/base") / name).resolve().parent == Path("/base")


class TestLimiter:
    def test_allows_up_to_the_limit(self):
        limiter = SlidingWindowLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check("k")[0] is True
            limiter.record("k")
        assert limiter.check("k")[0] is False

    def test_reports_a_retry_delay(self):
        limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
        limiter.record("k")
        allowed, retry_after = limiter.check("k")
        assert allowed is False and 1 <= retry_after <= 61

    def test_the_window_expires(self):
        limiter = SlidingWindowLimiter(limit=1, window_seconds=0.2)
        limiter.record("k")
        assert limiter.check("k")[0] is False
        time.sleep(0.25)
        assert limiter.check("k")[0] is True

    def test_a_reset_clears_the_counter(self):
        limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
        limiter.record("k")
        limiter.reset("k")
        assert limiter.check("k")[0] is True

    def test_keys_are_independent(self):
        limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
        limiter.record("a")
        assert limiter.check("b")[0] is True

    def test_the_forwarded_header_is_preferred(self):
        class Request:
            headers = {"x-forwarded-for": "203.0.113.9, 10.0.0.1"}
            client = None

        assert client_address(Request()) == "203.0.113.9"

    def test_a_missing_client_is_tolerated(self):
        class Request:
            headers: dict = {}
            client = None

        assert client_address(Request()) == "unknown"


class TestLoginHardening:
    def test_repeated_failures_are_throttled(self, workspace):
        client, slug = workspace["client"], workspace["slug"]
        codes = [
            client.post("/api/auth/login", json={
                "tenant_slug": slug, "email": workspace["email"], "password": f"Wrong{index}",
            }).status_code
            for index in range(14)
        ]
        assert 429 in codes, "unlimited password guessing is allowed"
        assert codes.index(429) <= 12

    def test_the_correct_password_stays_blocked_while_throttled(self, workspace):
        client, slug = workspace["client"], workspace["slug"]
        for index in range(12):
            client.post("/api/auth/login", json={
                "tenant_slug": slug, "email": workspace["email"], "password": f"Wrong{index}"})
        response = client.post("/api/auth/login", json={
            "tenant_slug": slug, "email": workspace["email"], "password": workspace["password"]})
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    def test_a_successful_login_clears_the_counter(self, workspace):
        client, slug = workspace["client"], workspace["slug"]
        for index in range(3):
            client.post("/api/auth/login", json={
                "tenant_slug": slug, "email": workspace["email"], "password": f"Wrong{index}"})
        good = {"tenant_slug": slug, "email": workspace["email"], "password": workspace["password"]}
        assert client.post("/api/auth/login", json=good).status_code == 200
        for index in range(9):
            client.post("/api/auth/login", json={
                "tenant_slug": slug, "email": workspace["email"], "password": f"Again{index}"})
        assert client.post("/api/auth/login", json=good).status_code == 200

    def test_unknown_accounts_cost_the_same_as_wrong_passwords(self, workspace):
        """Otherwise the response time tells an attacker which accounts exist."""
        client, slug = workspace["client"], workspace["slug"]

        def average(payload, rounds=6):
            total = 0.0
            for _ in range(rounds):
                account_limiter.clear()
                address_limiter.clear()
                started = time.perf_counter()
                client.post("/api/auth/login", json=payload)
                total += time.perf_counter() - started
            return total / rounds

        known = average({"tenant_slug": slug, "email": workspace["email"], "password": "WrongPass123"})
        unknown = average({"tenant_slug": slug, "email": "nobody@nowhere.test", "password": "WrongPass123"})
        no_tenant = average({"tenant_slug": "no-such-workspace", "email": workspace["email"],
                             "password": "WrongPass123"})
        slowest = max(known, unknown, no_tenant)
        fastest = max(min(known, unknown, no_tenant), 1e-6)
        assert slowest / fastest < 3.0, (
            f"login timing leaks account existence: known {known * 1000:.0f} ms, "
            f"unknown {unknown * 1000:.0f} ms, unknown workspace {no_tenant * 1000:.0f} ms"
        )
