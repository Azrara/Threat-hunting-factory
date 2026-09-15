"""What the AI layer can currently do on this host.

The interface asks for this on every page, so it is cached briefly and it never
raises: an unreachable model server is a status to report, not an error to handle.
"""

from __future__ import annotations

import threading
import time

from .client import OllamaClient, OllamaError
from .config import (
    AiSettings,
    ai_settings,
    choose_chat_model,
    choose_embedding_model,
    detect_available_ram_gb,
    detect_cpu_threads,
    detect_ram_gb,
    detect_vram_gb,
)

_CACHE: dict[str, object] = {}
_LOCK = threading.Lock()


def _hardware() -> dict:
    vram = detect_vram_gb()
    total = detect_ram_gb()
    available = detect_available_ram_gb()
    return {
        # What a model could actually take, which is what the choice is made
        # against. Total memory is reported too, because an operator looking at a
        # small recommendation on a large machine deserves to see why.
        "ram_gb": available,
        "total_ram_gb": total,
        "vram_gb": vram,
        "cpu_threads": detect_cpu_threads(),
        "accelerator": "gpu" if vram else "cpu",
    }


def build_status(
    settings: AiSettings | None = None,
    client: OllamaClient | None = None,
    hardware: dict | None = None,
) -> dict:
    """Describe the AI layer. Never raises."""
    settings = settings or ai_settings
    host = hardware if hardware is not None else _hardware()
    status: dict = {
        "enabled": settings.enabled,
        "base_url": settings.base_url,
        "reachable": False,
        "server_version": "",
        "installed_models": [],
        "hardware": host,
        "degraded_reason": "",
    }

    if not settings.enabled:
        status["degraded_reason"] = "The AI layer is disabled by configuration"
        status["model"] = choose_chat_model(
            [], host["ram_gb"], host["vram_gb"], settings.model_override,
            host.get("cpu_threads", 0),
        ).to_dict()
        status["embedding_model"] = choose_embedding_model(
            [], host["ram_gb"], host["vram_gb"], settings.embedding_override
        ).to_dict()
        return status

    owned = client is None
    client = client or OllamaClient(settings)
    installed: list[dict] = []
    try:
        status["server_version"] = client.version()
        status["reachable"] = True
        installed = (
            client.installed_model_details()
            if hasattr(client, "installed_model_details")
            else [{"name": name, "size": 0} for name in client.installed_models()]
        )
    except OllamaError as error:
        status["degraded_reason"] = str(error)
    except Exception as error:  # noqa: BLE001 - status must never break a page
        status["degraded_reason"] = f"The model server could not be queried: {error}"
    finally:
        if owned:
            client.close()

    status["installed_models"] = [entry["name"] for entry in installed]
    chat = choose_chat_model(
        installed, host["ram_gb"], host["vram_gb"], settings.model_override,
        host.get("cpu_threads", 0),
    )
    embedding = choose_embedding_model(
        installed, host["ram_gb"], host["vram_gb"], settings.embedding_override
    )
    status["model"] = chat.to_dict()
    # Nothing in the platform calls for an embedding yet: the collector's relevance
    # filter is lexical and deduplication is deterministic. The choice is reported
    # so an operator can pull it ahead of the work that will need it, and it is
    # deliberately not part of readiness, because a layer that works must not
    # describe itself as degraded.
    status["embedding_model"] = {**embedding.to_dict(), "required": False}

    if status["reachable"] and not status["degraded_reason"]:
        if not chat.fits:
            status["degraded_reason"] = (
                f"This host cannot comfortably run any model in the ladder: "
                f"{host['ram_gb']} GB of memory is available and "
                f"{host.get('cpu_threads', 0)} processor threads, and the smallest "
                f"entry needs {(chat.choice.min_ram_gb if chat.choice else 0)} GB "
                f"and {(chat.choice.min_cpu_threads if chat.choice else 0)} threads"
            )
        elif not chat.installed:
            status["degraded_reason"] = (
                f"The model {chat.tag} is not installed on the server. "
                f"Run: {chat.pull_command}"
            )
    status["ready"] = bool(status["reachable"] and chat.usable)
    return status


def cached_status(settings: AiSettings | None = None) -> dict:
    """``build_status`` behind a short time to live cache."""
    settings = settings or ai_settings
    now = time.monotonic()
    with _LOCK:
        expires = float(_CACHE.get("expires", 0.0))  # type: ignore[arg-type]
        if expires > now and "value" in _CACHE:
            return dict(_CACHE["value"])  # type: ignore[arg-type]
    value = build_status(settings)
    with _LOCK:
        _CACHE["value"] = value
        _CACHE["expires"] = now + settings.status_cache_seconds
    return dict(value)


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()
