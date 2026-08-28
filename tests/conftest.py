"""Shared fixtures. The data directory is redirected before the app imports."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="thf-tests-"))
os.environ["THF_DATA_DIR"] = str(_TEST_DATA_DIR)
os.environ["THF_DATABASE_URL"] = f"sqlite:///{_TEST_DATA_DIR / 'test.db'}"
os.environ["THF_JWT_SECRET"] = "unit-test-secret-value-that-is-long-enough-1234567890"
os.environ["THF_SEED_DEMO"] = "0"


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return _TEST_DATA_DIR


@pytest.fixture(scope="session")
def sample_archive(tmp_path_factory) -> Path:
    from tools.generate_sample_evidence import build

    target = tmp_path_factory.mktemp("evidence") / "sample-evidence.zip"
    return build(target, seed=11)


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """The limiters are process wide, so tests must not leak state into each other."""
    from app.throttle import account_limiter, address_limiter

    account_limiter.clear()
    address_limiter.clear()
    yield
    account_limiter.clear()
    address_limiter.clear()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def workspace(client):
    """Register a fresh workspace and return the client, headers and payload."""
    import uuid

    slug = f"ws{uuid.uuid4().hex[:10]}"
    response = client.post("/api/auth/register", json={
        "tenant_name": "Test Workspace",
        "tenant_slug": slug,
        "industry": "Testing",
        "full_name": "Test Analyst",
        "email": f"analyst@{slug}.test",
        "password": "TestPassword123",
    })
    assert response.status_code == 201, response.text
    payload = response.json()
    headers = {"Authorization": f"Bearer {payload['access_token']}"}
    return {"client": client, "headers": headers, "payload": payload, "slug": slug,
            "email": f"analyst@{slug}.test", "password": "TestPassword123"}
