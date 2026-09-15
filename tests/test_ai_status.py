"""The AI status report and its endpoint.

Status is asked for on every page, so the contract is strict: it never raises, it
never blocks, and it says plainly why the layer is unavailable when it is.
"""

from __future__ import annotations

import httpx
import pytest

from app.ai.client import OllamaClient, OllamaUnavailable
from app.ai.config import AiSettings
from app.ai.status import build_status, cached_status, reset_cache

CPU_HOST = {"ram_gb": 64, "vram_gb": 0, "accelerator": "cpu"}
TINY_HOST = {"ram_gb": 2, "vram_gb": 0, "accelerator": "cpu"}


def server(models: list[str], version: str = "0.6.2"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": version})
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": name} for name in models]})
        raise AssertionError(f"unexpected call to {request.url.path}")

    return handler


def client_for(handler, settings: AiSettings | None = None) -> OllamaClient:
    settings = settings or AiSettings()
    settings.max_retries = 0
    return OllamaClient(settings, transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _clear_status_cache():
    reset_cache()
    yield
    reset_cache()


class TestStatusWithNoServer:
    def test_an_absent_server_is_reported_not_raised(self):
        def refused(request):
            raise httpx.ConnectError("connection refused")

        status = build_status(client=client_for(refused), hardware=CPU_HOST)
        assert status["reachable"] is False
        assert status["ready"] is False
        assert "not reachable" in status["degraded_reason"]

    def test_a_model_is_still_recommended_without_a_server(self):
        def refused(request):
            raise httpx.ConnectError("connection refused")

        status = build_status(client=client_for(refused), hardware=CPU_HOST)
        assert status["model"]["tag"] == "qwen3:30b-a3b"
        assert status["model"]["pull_command"] == "ollama pull qwen3:30b-a3b"

    def test_a_client_that_fails_in_an_unexpected_way_is_still_reported(self):
        class Broken:
            def version(self):
                raise ValueError("something entirely unexpected")

            def installed_models(self):
                return []

            def close(self):
                pass

        status = build_status(client=Broken(), hardware=CPU_HOST)
        assert status["reachable"] is False
        assert "could not be queried" in status["degraded_reason"]

    def test_the_layer_can_be_switched_off_entirely(self):
        settings = AiSettings()
        settings.enabled = False

        def forbidden(request):
            raise AssertionError("a disabled layer must not contact the server")

        status = build_status(settings, client=client_for(forbidden), hardware=CPU_HOST)
        assert status["enabled"] is False
        assert "disabled by configuration" in status["degraded_reason"]
        assert status["model"]["tag"]


class TestStatusWithAServer:
    def test_a_ready_host_is_reported_ready(self):
        status = build_status(
            client=client_for(server(["qwen3:30b-a3b", "nomic-embed-text", "bge-m3"])),
            hardware=CPU_HOST,
        )
        assert status["reachable"] is True
        assert status["ready"] is True
        assert status["degraded_reason"] == ""
        assert status["server_version"] == "0.6.2"

    def test_a_reachable_server_without_the_model_is_not_ready(self):
        status = build_status(client=client_for(server([])), hardware=CPU_HOST)
        assert status["reachable"] is True
        assert status["ready"] is False
        assert "is not installed" in status["degraded_reason"]

    def test_the_reason_says_what_to_run(self):
        """An operator reading the chip should not have to guess the next command."""
        status = build_status(client=client_for(server([])), hardware=CPU_HOST)
        assert "ollama pull" in status["degraded_reason"]

    def test_the_installed_models_are_listed(self):
        status = build_status(client=client_for(server(["qwen3:8b"])), hardware=CPU_HOST)
        assert status["installed_models"] == ["qwen3:8b"]
        assert status["model"]["tag"] == "qwen3:8b"
        assert status["model"]["upgrade_tag"] == "qwen3:30b-a3b"

    def test_an_embedding_model_alone_is_not_enough(self):
        status = build_status(client=client_for(server(["nomic-embed-text"])), hardware=CPU_HOST)
        assert status["ready"] is False

    def test_a_chat_model_alone_is_enough(self):
        """Both agents need the chat model. Nothing calls for an embedding yet, so
        requiring one made a working layer describe itself as degraded."""
        status = build_status(client=client_for(server(["qwen3:30b-a3b"])), hardware=CPU_HOST)
        assert status["ready"] is True
        assert status["degraded_reason"] == ""

    def test_the_embedding_model_is_offered_but_not_required(self):
        status = build_status(client=client_for(server(["qwen3:30b-a3b"])), hardware=CPU_HOST)
        assert status["embedding_model"]["required"] is False
        assert status["embedding_model"]["pull_command"]

    def test_nothing_in_the_platform_asks_for_an_embedding_yet(self):
        """If this starts failing, readiness has to account for the embedding again."""
        import ast
        from pathlib import Path

        callers = []
        for path in Path("app").rglob("*.py"):
            if path.name in ("client.py", "config.py", "status.py"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "embed":
                    callers.append(str(path))
        assert not callers, f"embeddings are used in {callers}, so readiness must require one"

    def test_a_host_that_cannot_run_anything_says_so(self):
        status = build_status(
            client=client_for(server(["qwen3:8b", "nomic-embed-text"])), hardware=TINY_HOST
        )
        assert status["ready"] is False
        assert "cannot comfortably run" in status["degraded_reason"]
        assert "GB of memory is available" in status["degraded_reason"]


class TestStatusCache:
    def test_the_status_is_cached_between_calls(self, monkeypatch):
        calls = []

        def counted(settings=None, client=None, hardware=None):
            calls.append(1)
            return {"reachable": False}

        monkeypatch.setattr("app.ai.status.build_status", counted)
        settings = AiSettings()
        settings.status_cache_seconds = 60
        cached_status(settings)
        cached_status(settings)
        assert len(calls) == 1

    def test_the_cache_can_be_cleared(self, monkeypatch):
        calls = []

        def counted(settings=None, client=None, hardware=None):
            calls.append(1)
            return {"reachable": False}

        monkeypatch.setattr("app.ai.status.build_status", counted)
        settings = AiSettings()
        settings.status_cache_seconds = 60
        cached_status(settings)
        reset_cache()
        cached_status(settings)
        assert len(calls) == 2

    def test_a_caller_cannot_corrupt_the_cached_value(self, monkeypatch):
        monkeypatch.setattr(
            "app.ai.status.build_status",
            lambda settings=None, client=None, hardware=None: {"reachable": True},
        )
        settings = AiSettings()
        settings.status_cache_seconds = 60
        first = cached_status(settings)
        first["reachable"] = "tampered"
        assert cached_status(settings)["reachable"] is True


class TestStatusEndpoint:
    def test_it_requires_authentication(self, client):
        assert client.get("/api/ai/status").status_code == 401

    def test_it_reports_the_layer_to_a_signed_in_user(self, workspace, monkeypatch):
        monkeypatch.setattr(
            "app.routers.ai.cached_status",
            lambda: build_status(client=client_for(server(["qwen3:8b", "bge-m3"])), hardware=CPU_HOST),
        )
        response = workspace["client"].get("/api/ai/status", headers=workspace["headers"])
        assert response.status_code == 200
        payload = response.json()
        assert payload["reachable"] is True
        assert payload["model"]["tag"] == "qwen3:8b"
        assert payload["hardware"]["accelerator"] == "cpu"

    def test_it_answers_even_with_no_model_server_running(self, workspace):
        """The real probe runs here against nothing, which is the common case."""
        response = workspace["client"].get("/api/ai/status", headers=workspace["headers"])
        assert response.status_code == 200
        payload = response.json()
        assert payload["ready"] is False
        assert payload["degraded_reason"]
        assert payload["model"]["pull_command"].startswith("ollama pull ")

    def test_the_probe_does_not_delay_the_response(self, workspace):
        import time

        reset_cache()
        started = time.monotonic()
        workspace["client"].get("/api/ai/status", headers=workspace["headers"])
        assert time.monotonic() - started < 5.0

    def test_no_client_data_reaches_the_payload(self, workspace):
        response = workspace["client"].get("/api/ai/status", headers=workspace["headers"])
        body = response.text.lower()
        assert workspace["slug"] not in body
        assert "password" not in body


class TestNothingDependsOnTheAiLayer:
    def test_a_hunt_does_not_import_the_ai_package(self):
        """The engine must never gain a dependency on an optional model server."""
        import ast
        from pathlib import Path

        engine = Path("app/engine")
        offenders = []
        for path in engine.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and "ai" in (node.module or "").split("."):
                    offenders.append(str(path))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if "ai" in alias.name.split("."):
                            offenders.append(str(path))
        assert not offenders, f"the engine must not import the AI layer: {offenders}"

    def test_the_unavailable_exception_is_catchable_as_the_base(self):
        assert issubclass(OllamaUnavailable, Exception)


class TestProcessorWidth:
    """Fitting in memory is not the same as being worth waiting for.

    Reported from a real machine with twenty two gigabytes and two processor
    threads: the platform chose a dense 14B because it fitted, the server took over
    three minutes to load it, and one adjudication would have taken twenty.
    """

    TWO_THREADS = {"ram_gb": 20, "total_ram_gb": 22, "vram_gb": 0,
                   "cpu_threads": 2, "accelerator": "cpu"}

    def test_a_narrow_processor_gets_a_small_model(self):
        status = build_status(
            client=client_for(server(["qwen3:14b", "qwen3:4b"])), hardware=self.TWO_THREADS
        )
        assert status["model"]["tag"] == "qwen3:4b"
        assert status["ready"] is True

    def test_the_same_memory_with_more_threads_gets_more(self):
        wide = {**self.TWO_THREADS, "cpu_threads": 8}
        status = build_status(client=client_for(server(["qwen3:14b", "qwen3:4b"])), hardware=wide)
        assert status["model"]["tag"] == "qwen3:14b"

    def test_the_processor_is_reported(self):
        status = build_status(client=client_for(server([])), hardware=self.TWO_THREADS)
        assert status["hardware"]["cpu_threads"] == 2

    def test_a_host_that_cannot_run_anything_says_why(self):
        tiny = {"ram_gb": 2, "total_ram_gb": 2, "vram_gb": 0, "cpu_threads": 1,
                "accelerator": "cpu"}
        status = build_status(client=client_for(server([])), hardware=tiny)
        assert "processor threads" in status["degraded_reason"]

    def test_a_graphics_card_makes_the_processor_irrelevant(self):
        gpu = {"ram_gb": 20, "total_ram_gb": 22, "vram_gb": 24, "cpu_threads": 2,
               "accelerator": "gpu"}
        status = build_status(client=client_for(server(["qwen3:32b"])), hardware=gpu)
        assert status["model"]["tag"] == "qwen3:32b", "the card does the work, not the processor"
