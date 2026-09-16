"""The AI layer: model selection, the Ollama client and the status endpoint.

Every test here runs with no model server and no GPU. The transport is a fake, so
the client is exercised through real httpx code paths without a single network call.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.ai.client import (
    OllamaClient,
    OllamaError,
    OllamaProtocolError,
    OllamaTimeout,
    OllamaUnavailable,
    extract_json,
    strip_reasoning,
)
from app.ai.config import (
    CHAT_MODELS,
    CPU_LADDER,
    EMBED_LADDER,
    EMBED_MODELS,
    GPU_LADDER,
    AiSettings,
    choose_chat_model,
    choose_embedding_model,
    detect_ram_gb,
    detect_vram_gb,
)


def fake_client(handler, settings: AiSettings | None = None) -> OllamaClient:
    settings = settings or AiSettings()
    settings.max_retries = 0
    return OllamaClient(settings, transport=httpx.MockTransport(handler))


def chat_response(content: str, **extra) -> httpx.Response:
    body = {
        "model": "test-model",
        "message": {"role": "assistant", "content": content},
        "prompt_eval_count": 120,
        "eval_count": 40,
        "done": True,
    }
    body.update(extra)
    return httpx.Response(200, json=body)


# ---------------------------------------------------------------------------
# the ladder
# ---------------------------------------------------------------------------


class TestModelLadder:
    def test_every_ladder_entry_is_described(self):
        for tag in GPU_LADDER:
            assert tag in CHAT_MODELS, f"{tag} is on the GPU ladder but has no description"
        for tag in CPU_LADDER:
            assert tag in CHAT_MODELS, f"{tag} is on the CPU ladder but has no description"
        for tag in EMBED_LADDER:
            assert tag in EMBED_MODELS

    def test_the_ladders_have_no_duplicates(self):
        assert len(set(GPU_LADDER)) == len(GPU_LADDER)
        assert len(set(CPU_LADDER)) == len(CPU_LADDER)

    def test_every_described_model_is_reachable_from_a_ladder(self):
        assert set(CHAT_MODELS) == set(GPU_LADDER) | set(CPU_LADDER)

    def test_memory_requirements_are_plausible(self):
        for choice in CHAT_MODELS.values():
            assert 0 < choice.min_ram_gb <= 256
            assert 0 < choice.min_vram_gb <= 256
            assert choice.licence

    def test_mixture_of_experts_models_are_flagged(self):
        assert CHAT_MODELS["qwen3:30b-a3b"].is_mixture_of_experts
        assert not CHAT_MODELS["qwen3:14b"].is_mixture_of_experts

    def test_the_cpu_ladder_prefers_a_mixture_of_experts_over_a_dense_model(self):
        """On CPU, active parameters decide the speed, so 30B A3B beats dense 32B."""
        assert CPU_LADDER.index("qwen3:30b-a3b") < CPU_LADDER.index("qwen3:32b")
        assert GPU_LADDER.index("qwen3:32b") < GPU_LADDER.index("qwen3:30b-a3b")


class TestModelSelection:
    def test_a_large_gpu_gets_the_best_model(self):
        selection = choose_chat_model([], ram_gb=128, vram_gb=80)
        assert selection.tag == "gpt-oss:120b"
        assert selection.fits

    def test_a_single_workstation_card_gets_a_model_that_fits_it(self):
        selection = choose_chat_model([], ram_gb=64, vram_gb=24)
        assert CHAT_MODELS[selection.tag].min_vram_gb <= 24
        assert selection.tag == "qwen3:32b"

    def test_a_cpu_host_with_memory_gets_the_mixture_of_experts(self):
        selection = choose_chat_model([], ram_gb=64, vram_gb=0)
        assert selection.tag == "qwen3:30b-a3b"

    def test_a_small_laptop_gets_a_small_model(self):
        selection = choose_chat_model([], ram_gb=8, vram_gb=0)
        assert CHAT_MODELS[selection.tag].min_ram_gb <= 8
        assert selection.fits

    def test_an_installed_model_is_preferred_over_a_pull(self):
        selection = choose_chat_model(["qwen3:8b"], ram_gb=64, vram_gb=0)
        assert selection.tag == "qwen3:8b"
        assert selection.installed
        assert not selection.pull_command

    def test_a_better_fitting_model_is_offered_as_an_upgrade(self):
        selection = choose_chat_model(["qwen3:8b"], ram_gb=64, vram_gb=0)
        assert selection.upgrade_tag == "qwen3:30b-a3b"

    def test_no_upgrade_is_offered_when_the_best_is_already_installed(self):
        selection = choose_chat_model(["qwen3:30b-a3b"], ram_gb=64, vram_gb=0)
        assert selection.upgrade_tag == ""

    def test_a_quantised_tag_counts_as_installed(self):
        selection = choose_chat_model(["qwen3:14b-instruct-q4_K_M"], ram_gb=16, vram_gb=0)
        assert selection.tag == "qwen3:14b"
        assert selection.installed

    def test_an_override_wins_even_when_it_is_unknown(self):
        selection = choose_chat_model([], ram_gb=8, vram_gb=0, override="some/private-model:latest")
        assert selection.tag == "some/private-model:latest"
        assert selection.choice is None
        assert "Configured explicitly" in selection.reason

    def test_an_override_is_reported_as_installed_when_it_is(self):
        selection = choose_chat_model(["mine:latest"], ram_gb=8, vram_gb=0, override="mine:latest")
        assert selection.installed

    def test_a_host_that_cannot_run_anything_is_told_so(self):
        selection = choose_chat_model([], ram_gb=2, vram_gb=0)
        assert not selection.fits
        assert not selection.usable
        assert "No model in the ladder fits" in selection.reason

    def test_the_last_resort_prefers_the_permissive_licence(self):
        selection = choose_chat_model([], ram_gb=2, vram_gb=0)
        assert CHAT_MODELS[selection.tag].licence == "Apache 2.0"
        assert selection.tag == min(
            CHAT_MODELS, key=lambda tag: CHAT_MODELS[tag].min_ram_gb
        ), "the last resort must be the least demanding entry"

    def test_an_embedding_model_is_chosen_independently(self):
        selection = choose_embedding_model([], ram_gb=64, vram_gb=0)
        assert selection.tag in EMBED_MODELS
        assert selection.pull_command.startswith("ollama pull ")

    def test_the_selection_serialises_for_the_interface(self):
        payload = choose_chat_model(["qwen3:8b"], ram_gb=64, vram_gb=0).to_dict()
        assert payload["tag"] == "qwen3:8b"
        assert payload["usable"] is True
        assert payload["mixture_of_experts"] is False
        assert payload["licence"]
        json.dumps(payload)  # must survive a JSON response


class TestHardwareDetection:
    def test_system_memory_is_detected(self):
        assert detect_ram_gb() > 0

    def test_no_gpu_probe_means_no_video_memory(self):
        assert detect_vram_gb(runner=lambda: "") == 0

    def test_a_failing_probe_is_not_an_error(self):
        def explode():
            raise OSError("nvidia-smi is not installed")

        assert detect_vram_gb(runner=explode) == 0

    def test_the_largest_card_is_reported(self):
        assert detect_vram_gb(runner=lambda: "8192\n24576\n") == 24

    def test_garbage_from_the_probe_is_ignored(self):
        assert detect_vram_gb(runner=lambda: "N/A\nfailed\n") == 0


# ---------------------------------------------------------------------------
# answer parsing
# ---------------------------------------------------------------------------


class TestAnswerParsing:
    def test_plain_json_is_parsed(self):
        assert extract_json('{"verdict": "benign"}') == {"verdict": "benign"}

    def test_a_reasoning_scratchpad_is_removed(self):
        answer = '<think>Let me consider this at length.</think>{"verdict": "suspicious"}'
        assert extract_json(answer) == {"verdict": "suspicious"}

    def test_a_code_fence_is_removed(self):
        assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_surrounding_prose_is_tolerated(self):
        assert extract_json('Here is the result: {"a": 1} Hope that helps.') == {"a": 1}

    def test_a_brace_inside_a_string_does_not_end_the_object(self):
        assert extract_json('{"command": "cmd /c echo }"}') == {"command": "cmd /c echo }"}

    def test_an_escaped_quote_inside_a_string_is_handled(self):
        assert extract_json(r'{"command": "echo \"} \" done"}')["command"] == 'echo "} " done'

    def test_a_top_level_array_is_parsed(self):
        assert extract_json('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]

    def test_an_empty_answer_is_rejected(self):
        with pytest.raises(OllamaProtocolError):
            extract_json("   ")

    def test_an_answer_without_json_is_rejected(self):
        with pytest.raises(OllamaProtocolError):
            extract_json("I cannot help with that request.")

    def test_broken_json_is_rejected_rather_than_guessed(self):
        with pytest.raises(OllamaProtocolError):
            extract_json('{"a": 1,,}')

    def test_an_unterminated_object_is_rejected(self):
        with pytest.raises(OllamaProtocolError):
            extract_json('{"a": 1')

    def test_reasoning_alone_is_stripped_to_nothing(self):
        assert strip_reasoning("<think>only thinking</think>") == ""


# ---------------------------------------------------------------------------
# the client
# ---------------------------------------------------------------------------


class TestClientIntrospection:
    def test_installed_models_are_listed(self):
        def handler(request):
            assert request.url.path == "/api/tags"
            return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}, {"name": "bge-m3"}]})

        with fake_client(handler) as client:
            assert client.installed_models() == ["qwen3:8b", "bge-m3"]

    def test_a_model_without_a_name_is_skipped(self):
        handler = lambda request: httpx.Response(200, json={"models": [{"size": 1}, {"name": "a:1"}]})
        with fake_client(handler) as client:
            assert client.installed_models() == ["a:1"]

    def test_reachability_is_a_question_not_an_exception(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        with fake_client(handler) as client:
            assert client.is_reachable() is False

    def test_a_reachable_server_reports_its_version(self):
        handler = lambda request: httpx.Response(200, json={"version": "0.6.2"})
        with fake_client(handler) as client:
            assert client.version() == "0.6.2"
            assert client.is_reachable() is True


class TestClientChat:
    def test_a_chat_call_returns_the_text_and_the_counters(self):
        with fake_client(lambda request: chat_response("hello")) as client:
            result = client.chat([{"role": "user", "content": "hi"}], model="qwen3:8b")
        assert result.text == "hello"
        assert result.prompt_tokens == 120
        assert result.completion_tokens == 40
        assert result.duration_ms >= 0

    def test_the_call_is_deterministic_by_construction(self):
        seen = {}

        def handler(request):
            seen.update(json.loads(request.content))
            return chat_response("{}")

        with fake_client(handler) as client:
            client.chat([{"role": "user", "content": "hi"}], model="qwen3:8b")
        assert seen["options"]["temperature"] == 0.0
        assert seen["options"]["seed"] == 1337
        assert seen["stream"] is False

    def test_a_schema_is_sent_as_the_format(self):
        seen = {}
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}

        def handler(request):
            seen.update(json.loads(request.content))
            return chat_response('{"verdict": "benign"}')

        with fake_client(handler) as client:
            value, result = client.chat_json(
                [{"role": "user", "content": "hi"}], model="qwen3:8b", schema=schema
            )
        assert seen["format"] == schema
        assert value == {"verdict": "benign"}
        assert result.completion_tokens == 40

    def test_a_token_budget_is_passed_through(self):
        seen = {}

        def handler(request):
            seen.update(json.loads(request.content))
            return chat_response("ok")

        with fake_client(handler) as client:
            client.chat([{"role": "user", "content": "hi"}], model="m", max_tokens=256)
        assert seen["options"]["num_predict"] == 256

    def test_an_answer_without_a_message_is_a_protocol_error(self):
        handler = lambda request: httpx.Response(200, json={"model": "m", "message": "oops"})
        with fake_client(handler) as client:
            with pytest.raises(OllamaProtocolError):
                client.chat([{"role": "user", "content": "hi"}], model="m")

    def test_a_non_json_body_is_a_protocol_error(self):
        handler = lambda request: httpx.Response(200, content=b"<html>not json</html>")
        with fake_client(handler) as client:
            with pytest.raises(OllamaProtocolError):
                client.version()


class TestClientFailures:
    def test_a_refused_connection_is_typed(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        with fake_client(handler) as client:
            with pytest.raises(OllamaUnavailable):
                client.chat([{"role": "user", "content": "hi"}], model="m")

    def test_a_timeout_is_typed_separately(self):
        def handler(request):
            raise httpx.ReadTimeout("too slow")

        with fake_client(handler) as client:
            with pytest.raises(OllamaTimeout):
                client.chat([{"role": "user", "content": "hi"}], model="m")

    def test_a_rejected_request_is_not_retried(self):
        calls = []

        def handler(request):
            calls.append(1)
            return httpx.Response(404, text="model not found")

        settings = AiSettings()
        settings.max_retries = 3
        client = OllamaClient(settings, transport=httpx.MockTransport(handler))
        with client:
            with pytest.raises(OllamaProtocolError) as error:
                client.chat([{"role": "user", "content": "hi"}], model="missing")
        assert len(calls) == 1, "a 404 will not improve by repeating it"
        assert "404" in str(error.value)

    def test_a_server_error_is_retried_then_reported(self, monkeypatch):
        monkeypatch.setattr("app.ai.client.time.sleep", lambda seconds: None)
        calls = []

        def handler(request):
            calls.append(1)
            return httpx.Response(503, text="loading model")

        settings = AiSettings()
        settings.max_retries = 2
        with OllamaClient(settings, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(OllamaError):
                client.chat([{"role": "user", "content": "hi"}], model="m")
            assert len(calls) == 3, "one attempt plus two retries"
            calls.clear()
            # A status probe must stay cheap, so it spends no retry budget at all.
            with pytest.raises(OllamaError):
                client.version()
            assert len(calls) == 1

    def test_a_transient_failure_recovers(self, monkeypatch):
        """A server coming up refuses one connection and answers the next."""
        monkeypatch.setattr("app.ai.client.time.sleep", lambda seconds: None)
        attempts = {"count": 0}

        def handler(request):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise httpx.ConnectError("not up yet")
            if request.url.path == "/api/generate":
                return httpx.Response(200, json={"model": "m", "done": True})
            return chat_response("recovered")

        settings = AiSettings()
        settings.max_retries = 2
        with OllamaClient(settings, transport=httpx.MockTransport(handler)) as client:
            result = client.chat([{"role": "user", "content": "hi"}], model="m")
        assert result.text == "recovered"
        assert attempts["count"] > 1, "it took more than one attempt to get through"


class TestClientEmbeddings:
    def test_embeddings_are_returned_per_input(self):
        def handler(request):
            payload = json.loads(request.content)
            return httpx.Response(200, json={"embeddings": [[0.1, 0.2]] * len(payload["input"])})

        with fake_client(handler) as client:
            vectors = client.embed(["a", "b"], model="bge-m3")
        assert len(vectors) == 2
        assert vectors[0] == [0.1, 0.2]

    def test_no_input_makes_no_call(self):
        def handler(request):
            raise AssertionError("the client must not call the server for an empty batch")

        with fake_client(handler) as client:
            assert client.embed([], model="bge-m3") == []

    def test_a_mismatched_count_is_a_protocol_error(self):
        handler = lambda request: httpx.Response(200, json={"embeddings": [[0.1]]})
        with fake_client(handler) as client:
            with pytest.raises(OllamaProtocolError):
                client.embed(["a", "b"], model="bge-m3")


class TestSettings:
    def test_defaults_are_safe(self):
        settings = AiSettings()
        assert settings.base_url.startswith("http://127.0.0.1")
        assert settings.connect_timeout <= 5, "a page must not wait on an absent server"
        assert settings.temperature == 0.0

    def test_the_environment_overrides_the_defaults(self, monkeypatch):
        monkeypatch.setenv("THF_OLLAMA_URL", "http://gpu-box:11434/")
        monkeypatch.setenv("THF_AI_MODEL", "qwen3:32b")
        monkeypatch.setenv("THF_AI_ENABLED", "0")
        settings = AiSettings()
        assert settings.base_url == "http://gpu-box:11434"
        assert settings.model_override == "qwen3:32b"
        assert settings.enabled is False

    def test_a_malformed_number_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("THF_AI_TIMEOUT", "not-a-number")
        monkeypatch.setenv("THF_AI_MAX_CALLS", "")
        settings = AiSettings()
        assert settings.request_timeout == 300.0
        assert settings.max_calls_per_hunt == 60


class TestAModelTheLadderDoesNotKnow:
    """The ladder is a recommendation, not a list of the only models allowed to work.

    The defect this guards was reported from a real machine: the operator pulled
    qwen3:4b, which runs perfectly, and the platform reported itself degraded
    because that tag was not on the list it happened to ship with.
    """

    def test_an_installed_model_off_the_ladder_is_used(self):
        selection = choose_chat_model(
            [{"name": "mistral-nemo:12b", "size": 7_100_000_000}], ram_gb=16, vram_gb=0
        )
        assert selection.tag == "mistral-nemo:12b"
        assert selection.usable
        assert "Installed on the server" in selection.reason

    def test_a_ladder_entry_is_still_preferred(self):
        selection = choose_chat_model(
            [{"name": "mistral-nemo:12b", "size": 7_100_000_000},
             {"name": "qwen3:8b", "size": 4_700_000_000}],
            ram_gb=16, vram_gb=0,
        )
        assert selection.tag == "qwen3:8b"

    def test_the_largest_that_fits_is_taken(self):
        selection = choose_chat_model(
            [{"name": "small:1b", "size": 900_000_000},
             {"name": "bigger:7b", "size": 4_100_000_000}],
            ram_gb=16, vram_gb=0,
        )
        assert selection.tag == "bigger:7b"

    def test_one_that_does_not_fit_is_not_taken(self):
        selection = choose_chat_model(
            [{"name": "huge:70b", "size": 40_000_000_000}], ram_gb=10, vram_gb=0
        )
        assert selection.tag != "huge:70b"
        assert not selection.installed

    def test_an_embedding_model_is_never_chosen_to_adjudicate(self):
        for name in ("bge-m3", "nomic-embed-text", "mxbai-embed-large", "all-minilm"):
            selection = choose_chat_model(
                [{"name": name, "size": 1_200_000_000}], ram_gb=16, vram_gb=0
            )
            assert selection.tag != name, f"{name} cannot answer questions"

    def test_an_embedding_model_off_the_ladder_can_still_embed(self):
        selection = choose_embedding_model(
            [{"name": "mxbai-embed-large", "size": 700_000_000}], ram_gb=16, vram_gb=0
        )
        assert selection.tag == "mxbai-embed-large"
        assert selection.usable

    def test_a_plain_list_of_names_still_works(self):
        selection = choose_chat_model(["qwen3:8b"], ram_gb=16, vram_gb=0)
        assert selection.tag == "qwen3:8b"
        assert selection.installed


class TestMemoryHeadroom:
    """What the host needs, not what the weights weigh.

    Reported from a real machine: the platform recommended a 14B on a virtual
    machine with sixteen gigabytes, and loading it killed the model server, because
    the declared requirement counted the weights and nothing else.
    """

    def test_every_entry_leaves_room_for_the_context_and_the_host(self):
        from app.ai.config import RUNTIME_OVERHEAD_GB

        for choice in CHAT_MODELS.values():
            assert choice.min_ram_gb >= choice.min_vram_gb, (
                f"{choice.tag} claims to need less system memory than video memory, "
                "but system memory also holds the operating system"
            )
            assert choice.min_ram_gb >= RUNTIME_OVERHEAD_GB

    def test_the_estimate_for_an_installed_model_includes_overhead(self):
        from app.ai.config import InstalledModel, RUNTIME_OVERHEAD_GB

        model = InstalledModel("something:7b", size_bytes=4 * 1024**3)
        assert model.estimated_ram_gb >= 4 + RUNTIME_OVERHEAD_GB

    def test_a_model_with_no_reported_size_falls_back_to_the_ladder(self):
        from app.ai.config import InstalledModel

        assert InstalledModel("qwen3:8b").estimated_ram_gb == CHAT_MODELS["qwen3:8b"].min_ram_gb

    def test_available_memory_is_what_the_choice_is_made_against(self):
        from app.ai.config import detect_available_ram_gb, detect_ram_gb

        assert detect_available_ram_gb() > 0
        assert detect_available_ram_gb() <= detect_ram_gb()

    def test_a_sixteen_gigabyte_host_with_little_free_gets_something_small(self):
        """The real case: a desktop and a browser are already using the memory."""
        selection = choose_chat_model([], ram_gb=6, vram_gb=0)
        assert CHAT_MODELS[selection.tag].min_ram_gb <= 8


class TestLoadingBeforeAnswering:
    """Loading a model is not answering a question.

    Reported from a real machine: a dense model on two processor threads took more
    than three minutes to load, the client gave up at its request timeout, and the
    server abandoned the load because the client had gone. Every retry started a
    load that could never finish, so the hunt reported that the model never answered
    while the server was busy loading it over and over.
    """

    def calls(self):
        seen: list[tuple[str, dict]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content) if request.content else {}
            seen.append((request.url.path, body))
            if request.url.path == "/api/generate":
                return httpx.Response(200, json={"model": body.get("model", ""), "done": True})
            return chat_response("{}")

        return seen, handler

    def test_the_model_is_loaded_before_the_first_question(self):
        seen, handler = self.calls()
        with fake_client(handler) as client:
            client.chat([{"role": "user", "content": "hi"}], model="qwen3:4b")
        assert [path for path, _ in seen] == ["/api/generate", "/api/chat"]

    def test_the_load_is_paid_once(self):
        seen, handler = self.calls()
        with fake_client(handler) as client:
            for _ in range(3):
                client.chat([{"role": "user", "content": "hi"}], model="qwen3:4b")
        assert [path for path, _ in seen].count("/api/generate") == 1

    def test_the_load_gets_its_own_budget(self):
        settings = AiSettings()
        assert settings.load_timeout > settings.request_timeout, (
            "a load that takes longer than an answer must not be cut off by the "
            "budget meant for the answer"
        )
        assert settings.load_timeout >= 600

    def test_the_model_is_asked_to_stay_resident(self):
        """A hunt makes several calls minutes apart and must not reload each time."""
        seen, handler = self.calls()
        with fake_client(handler) as client:
            client.chat([{"role": "user", "content": "hi"}], model="qwen3:4b")
        for path, body in seen:
            assert body.get("keep_alive"), f"{path} did not ask the server to keep the model"

    def test_a_second_model_is_loaded_in_its_turn(self):
        seen, handler = self.calls()
        with fake_client(handler) as client:
            client.chat([{"role": "user", "content": "hi"}], model="qwen3:4b")
            client.chat([{"role": "user", "content": "hi"}], model="qwen3:8b")
        loaded = [body["model"] for path, body in seen if path == "/api/generate"]
        assert loaded == ["qwen3:4b", "qwen3:8b"]

    def test_a_server_that_never_loads_is_reported_not_retried(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("still loading")

        settings = AiSettings()
        settings.max_retries = 3
        attempts = []

        def counting(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            raise httpx.ReadTimeout("still loading")

        with OllamaClient(settings, transport=httpx.MockTransport(counting)) as client:
            with pytest.raises(OllamaTimeout):
                client.chat([{"role": "user", "content": "hi"}], model="qwen3:4b")
        assert len(attempts) == 1, "a load that timed out must not be started again"


class TestAModelThatReasons:
    """Reasoning models answer in two parts, and both come out of one budget.

    Reported from a real machine: qwen3:4b produced its reasoning, spent the whole
    token budget doing it, and returned an empty answer. The platform said "the
    model returned an empty answer", which is true and useless.
    """

    def server(self, *responses):
        """Answer each chat call with the next scripted response."""
        seen: list[dict] = []
        remaining = list(responses)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content) if request.content else {}
            if request.url.path == "/api/generate":
                return httpx.Response(200, json={"model": body.get("model", ""), "done": True})
            seen.append(body)
            reply = remaining.pop(0) if remaining else responses[-1]
            if isinstance(reply, int):
                return httpx.Response(reply, text="model does not support thinking")
            return httpx.Response(200, json={
                "model": body["model"], "message": reply,
                "prompt_eval_count": 900, "eval_count": reply.get("_tokens", 100), "done": True,
            })

        return seen, handler

    def test_the_reasoning_is_asked_for_separately(self):
        seen, handler = self.server({"role": "assistant", "content": '{"a": 1}'})
        with fake_client(handler) as client:
            client.chat_json([{"role": "user", "content": "hi"}], model="qwen3:4b", schema={})
        assert seen[0]["think"] is False, "structured output does not want prose reasoning"

    def test_an_answer_that_is_all_reasoning_is_asked_again_with_room(self):
        seen, handler = self.server(
            {"role": "assistant", "content": "", "thinking": "Let me consider this at length.",
             "_tokens": 1400},
            {"role": "assistant", "content": '{"verdicts": []}'},
        )
        with fake_client(handler) as client:
            value, _ = client.chat_json(
                [{"role": "user", "content": "hi"}], model="qwen3:4b", schema={}, max_tokens=1400
            )
        assert value == {"verdicts": []}
        assert len(seen) == 2
        assert seen[1]["options"]["num_predict"] > seen[0]["options"]["num_predict"]

    def test_an_answer_cut_off_at_the_budget_is_asked_again(self):
        """No thinking reported, but it used every token it was given and said nothing."""
        seen, handler = self.server(
            {"role": "assistant", "content": "", "_tokens": 900},
            {"role": "assistant", "content": '{"a": 2}'},
        )
        with fake_client(handler) as client:
            value, _ = client.chat_json(
                [{"role": "user", "content": "hi"}], model="m", schema={}, max_tokens=900
            )
        assert value == {"a": 2}

    def test_a_model_that_only_ever_reasons_is_reported_usefully(self):
        seen, handler = self.server(
            {"role": "assistant", "content": "", "thinking": "thinking", "_tokens": 1400},
            {"role": "assistant", "content": "", "thinking": "still thinking", "_tokens": 4200},
        )
        with fake_client(handler) as client:
            with pytest.raises(OllamaProtocolError) as error:
                client.chat_json(
                    [{"role": "user", "content": "hi"}], model="qwen3:4b", schema={}, max_tokens=1400
                )
        message = str(error.value)
        assert "reasoning and no answer" in message
        assert "4200" in message, "the reader needs to know it was not silence"
        assert "qwen3:4b" in message

    def test_a_model_that_rejects_being_told_not_to_think_still_works(self):
        seen, handler = self.server(400, {"role": "assistant", "content": '{"a": 3}'})
        with fake_client(handler) as client:
            value, _ = client.chat_json([{"role": "user", "content": "hi"}], model="m", schema={})
        assert value == {"a": 3}
        assert "think" not in seen[1], "the second attempt drops what the model refused"

    def test_the_reasoning_is_kept_for_diagnosis(self):
        seen, handler = self.server(
            {"role": "assistant", "content": '{"a": 1}', "thinking": "a short thought"}
        )
        with fake_client(handler) as client:
            _, result = client.chat_json([{"role": "user", "content": "hi"}], model="m", schema={})
        assert result.thinking == "a short thought"

    def test_a_good_answer_costs_one_call(self):
        seen, handler = self.server({"role": "assistant", "content": '{"a": 1}'})
        with fake_client(handler) as client:
            client.chat_json([{"role": "user", "content": "hi"}], model="m", schema={})
        assert len(seen) == 1
