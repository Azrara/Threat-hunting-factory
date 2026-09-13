"""A small, strict client for a local Ollama server.

Three properties matter more than features here:

* **It fails fast and predictably.** A missing model server must never make a hunt
  hang, so connect attempts are short and every failure is a typed exception.
* **It is deterministic.** Temperature zero and a fixed seed, so the same prompt on
  the same model gives the same answer and an AI observation can be defended.
* **It is testable without a model.** The HTTP transport is injectable, so the whole
  agent layer is exercised in the suite with no server and no GPU.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import AiSettings, ai_settings

# Reasoning models wrap their scratchpad in these. It must never reach a JSON parser.
_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class OllamaError(RuntimeError):
    """Base class so a caller can degrade on anything this client raises."""


class OllamaUnavailable(OllamaError):
    """The server could not be reached at all."""


class OllamaTimeout(OllamaError):
    """The server accepted the request but did not answer in time."""


class OllamaProtocolError(OllamaError):
    """The server answered with something this client cannot use."""


@dataclass
class ChatResult:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def strip_reasoning(text: str) -> str:
    """Remove a reasoning scratchpad and any code fence around the payload."""
    cleaned = _THINK_RE.sub("", text or "").strip()
    fenced = _FENCE_RE.search(cleaned)
    if fenced:
        cleaned = fenced.group(1).strip()
    return cleaned


def extract_json(text: str) -> Any:
    """Parse the JSON value in a model answer, tolerating a little surrounding prose.

    Schema bound output should make this trivial, but a small model occasionally
    adds a sentence before the object. One balanced scan recovers that case without
    accepting arbitrary rubbish.
    """
    cleaned = strip_reasoning(text)
    if not cleaned:
        raise OllamaProtocolError("The model returned an empty answer")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    candidate = _first_balanced(cleaned)
    if candidate is None:
        raise OllamaProtocolError("The model answer contained no JSON value")
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as error:
        raise OllamaProtocolError(f"The model answer was not valid JSON: {error}") from error


def _first_balanced(text: str) -> str | None:
    """Return the first balanced ``{...}`` or ``[...]`` run, ignoring braces in strings."""
    openers = {"{": "}", "[": "]"}
    start = next((index for index, char in enumerate(text) if char in openers), None)
    if start is None:
        return None
    closer = openers[text[start]]
    opener = text[start]
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


class OllamaClient:
    """Talks to one Ollama server. Not thread safe by itself, cheap to construct."""

    def __init__(
        self,
        settings: AiSettings | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings or ai_settings
        timeout = httpx.Timeout(
            self.settings.request_timeout,
            connect=self.settings.connect_timeout,
        )
        self._http = httpx.Client(
            base_url=self.settings.base_url,
            timeout=timeout,
            transport=transport,
        )

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "OllamaClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport --------------------------------------------------------

    def _request(self, method: str, path: str, payload: dict | None = None, *, retries: int | None = None) -> dict:
        attempts = self.settings.max_retries if retries is None else retries
        delay = 0.5
        last: Exception | None = None
        for attempt in range(attempts + 1):
            try:
                response = self._http.request(method, path, json=payload)
            except httpx.TimeoutException as error:
                last = OllamaTimeout(f"{self.settings.base_url} did not answer in time")
                last.__cause__ = error
            except httpx.HTTPError as error:
                last = OllamaUnavailable(f"{self.settings.base_url} is not reachable: {error}")
                last.__cause__ = error
            else:
                if response.status_code >= 500:
                    # A server side error is worth one more try.
                    last = OllamaError(f"The model server returned {response.status_code}")
                elif response.status_code >= 400:
                    # A client side error will not improve by repeating it.
                    raise OllamaProtocolError(
                        f"The model server rejected the request with {response.status_code}: "
                        f"{response.text[:200]}"
                    )
                else:
                    try:
                        return response.json()
                    except ValueError as error:
                        raise OllamaProtocolError("The model server answered with non JSON") from error
            if attempt < attempts:
                time.sleep(delay)
                delay *= 2
        raise last if last is not None else OllamaUnavailable("The model server is not reachable")

    # -- introspection ----------------------------------------------------

    def installed_models(self) -> list[str]:
        payload = self._request("GET", "/api/tags", retries=0)
        models = payload.get("models") or []
        return [str(entry.get("name", "")) for entry in models if entry.get("name")]

    def version(self) -> str:
        payload = self._request("GET", "/api/version", retries=0)
        return str(payload.get("version", ""))

    def is_reachable(self) -> bool:
        try:
            self.version()
        except OllamaError:
            return False
        return True

    # -- inference --------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str,
        schema: dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ChatResult:
        options: dict[str, Any] = {
            "temperature": self.settings.temperature if temperature is None else temperature,
            "seed": self.settings.seed,
            "num_ctx": self.settings.context_tokens,
        }
        if max_tokens:
            options["num_predict"] = max_tokens
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        if schema is not None:
            payload["format"] = schema

        started = time.monotonic()
        body = self._request("POST", "/api/chat", payload)
        message = body.get("message") or {}
        if not isinstance(message, dict):
            raise OllamaProtocolError("The model server answered without a message")
        return ChatResult(
            text=str(message.get("content", "")),
            model=str(body.get("model", model)),
            prompt_tokens=int(body.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(body.get("eval_count", 0) or 0),
            duration_ms=int((time.monotonic() - started) * 1000),
            raw=body,
        )

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        model: str,
        schema: dict,
        max_tokens: int | None = None,
    ) -> tuple[Any, ChatResult]:
        """Ask for schema bound output and return the parsed value with the call stats."""
        result = self.chat(messages, model=model, schema=schema, max_tokens=max_tokens)
        return extract_json(result.text), result

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        if not texts:
            return []
        body = self._request("POST", "/api/embed", {"model": model, "input": texts})
        vectors = body.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise OllamaProtocolError("The model server returned an unexpected number of embeddings")
        return [[float(value) for value in vector] for vector in vectors]
