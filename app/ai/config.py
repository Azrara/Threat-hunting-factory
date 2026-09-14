"""AI layer configuration: which model to run and whether the host can run it.

The platform does not hard code one model. It ships a ranked ladder and picks the
best entry the host can actually run, because the honest answer to "which model"
depends entirely on the hardware in front of it. An operator can always override
the choice with ``THF_AI_MODEL``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

# Memory figures are indicative, for a 4 bit quantisation plus a working context of
# around 16k tokens. They are used to rank choices, not to promise a footprint.


@dataclass(frozen=True)
class ModelChoice:
    tag: str
    label: str
    parameters: str
    active_parameters: str  # differs from ``parameters`` only for mixture of experts
    min_ram_gb: int  # system memory needed to run on CPU
    min_vram_gb: int  # video memory needed to run fully on GPU
    licence: str
    note: str

    @property
    def is_mixture_of_experts(self) -> bool:
        return self.active_parameters != self.parameters


CHAT_MODELS: dict[str, ModelChoice] = {
    choice.tag: choice
    for choice in (
        ModelChoice(
            "gpt-oss:120b", "GPT OSS 120B", "120B", "5.1B", 72, 80, "Apache 2.0",
            "Best quality in this list. Needs a server class accelerator or a very large host.",
        ),
        ModelChoice(
            "qwen3:32b", "Qwen3 32B", "32B", "32B", 24, 24, "Apache 2.0",
            "Best dense model that fits a single 24 GB card. Slow on CPU.",
        ),
        ModelChoice(
            "qwen3:30b-a3b", "Qwen3 30B A3B", "30B", "3B", 22, 22, "Apache 2.0",
            "Mixture of experts: 30B of knowledge at the speed of a 3B model. "
            "The best choice when there is no GPU but plenty of memory.",
        ),
        ModelChoice(
            "gpt-oss:20b", "GPT OSS 20B", "20B", "3.6B", 16, 16, "Apache 2.0",
            "Mixture of experts, strong at structured output, fits a 16 GB host.",
        ),
        ModelChoice(
            "qwen3:14b", "Qwen3 14B", "14B", "14B", 11, 12, "Apache 2.0",
            "Dense fallback for a 12 GB card.",
        ),
        ModelChoice(
            "qwen3:8b", "Qwen3 8B", "8B", "8B", 7, 8, "Apache 2.0",
            "Runs on almost any laptop. Weakest schema adherence of the list.",
        ),
        ModelChoice(
            "llama3.1:8b", "Llama 3.1 8B", "8B", "8B", 7, 8, "Meta Llama 3.1 Community",
            "Last resort. Check the licence before shipping this to a client.",
        ),
    )
}

# Ordered best first. The two orders differ because a mixture of experts model is
# far faster than a dense model of the same size on CPU, and the difference is
# large enough to change which model is the right default.
GPU_LADDER: tuple[str, ...] = (
    "gpt-oss:120b", "qwen3:32b", "qwen3:30b-a3b", "gpt-oss:20b", "qwen3:14b", "qwen3:8b", "llama3.1:8b",
)
CPU_LADDER: tuple[str, ...] = (
    "qwen3:30b-a3b", "gpt-oss:20b", "qwen3:32b", "qwen3:14b", "qwen3:8b", "llama3.1:8b",
)

EMBED_MODELS: dict[str, ModelChoice] = {
    choice.tag: choice
    for choice in (
        ModelChoice(
            "bge-m3", "BGE M3", "568M", "568M", 3, 3, "MIT",
            "Multilingual. Preferred when threat intelligence is not only in English.",
        ),
        ModelChoice(
            "nomic-embed-text", "Nomic Embed Text", "137M", "137M", 2, 2, "Apache 2.0",
            "Small, fast, good enough for deduplication and relevance ranking.",
        ),
    )
}
EMBED_LADDER: tuple[str, ...] = ("bge-m3", "nomic-embed-text")

# A GPU below this is not worth offloading a working model onto.
MIN_USEFUL_VRAM_GB = 8


@dataclass(frozen=True)
class ModelSelection:
    """The outcome of choosing a model, including why."""

    tag: str
    choice: ModelChoice | None
    installed: bool
    fits: bool
    reason: str
    pull_command: str = ""
    # Set when a better model than the installed one would run on this host.
    upgrade_tag: str = ""

    @property
    def usable(self) -> bool:
        return self.installed and self.fits

    def to_dict(self) -> dict:
        payload = {
            "tag": self.tag,
            "installed": self.installed,
            "fits": self.fits,
            "usable": self.usable,
            "reason": self.reason,
            "pull_command": self.pull_command,
            "upgrade_tag": self.upgrade_tag,
        }
        if self.choice is not None:
            payload.update(
                {
                    "label": self.choice.label,
                    "parameters": self.choice.parameters,
                    "active_parameters": self.choice.active_parameters,
                    "mixture_of_experts": self.choice.is_mixture_of_experts,
                    "licence": self.choice.licence,
                    "note": self.choice.note,
                }
            )
        return payload


# ---------------------------------------------------------------------------
# hardware detection
# ---------------------------------------------------------------------------


def detect_ram_gb() -> int:
    """Total system memory in whole gigabytes, or 0 when it cannot be read."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(int(line.split()[1]) / (1024 * 1024))
    except (OSError, ValueError, IndexError):
        pass
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages * page_size / (1024**3))
    except (ValueError, OSError, AttributeError):
        return 0


def detect_vram_gb(runner=None) -> int:
    """Largest single GPU memory in whole gigabytes, or 0 when there is no GPU.

    Only NVIDIA is probed, through ``nvidia-smi``. Any failure means zero, which
    degrades the choice to the CPU ladder rather than breaking anything.
    """
    run = runner or _run_nvidia_smi
    try:
        output = run()
    except Exception:  # noqa: BLE001 - a probe may fail in any number of ways
        return 0
    if not output:
        return 0
    sizes = []
    for line in output.splitlines():
        value = line.strip().split()[0] if line.strip() else ""
        if value.isdigit():
            sizes.append(int(value) // 1024)
    return max(sizes) if sizes else 0


def _run_nvidia_smi() -> str:
    binary = shutil.which("nvidia-smi")
    if not binary:
        return ""
    result = subprocess.run(
        [binary, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------


def _normalise(tag: str) -> str:
    """``qwen3:14b`` and ``qwen3:14b-instruct-q4_K_M`` are the same family here."""
    return tag.split("-", 1)[0].strip().lower()


def _is_installed(tag: str, installed: list[str]) -> bool:
    wanted = _normalise(tag)
    return any(_normalise(name) == wanted for name in installed)


def choose_chat_model(
    installed: list[str],
    ram_gb: int,
    vram_gb: int,
    override: str = "",
) -> ModelSelection:
    return _choose(installed, ram_gb, vram_gb, override, CHAT_MODELS, _ladder_for(vram_gb))


def choose_embedding_model(
    installed: list[str],
    ram_gb: int,
    vram_gb: int,
    override: str = "",
) -> ModelSelection:
    return _choose(installed, ram_gb, vram_gb, override, EMBED_MODELS, EMBED_LADDER)


def _ladder_for(vram_gb: int) -> tuple[str, ...]:
    return GPU_LADDER if vram_gb >= MIN_USEFUL_VRAM_GB else CPU_LADDER


def _choose(
    installed: list[str],
    ram_gb: int,
    vram_gb: int,
    override: str,
    catalogue: dict[str, ModelChoice],
    ladder: tuple[str, ...],
) -> ModelSelection:
    if override:
        choice = catalogue.get(override)
        return ModelSelection(
            tag=override,
            choice=choice,
            installed=_is_installed(override, installed),
            fits=True,  # an explicit override is the operator's judgement, not ours
            reason="Configured explicitly through the environment",
            pull_command=f"ollama pull {override}",
        )

    on_gpu = vram_gb >= MIN_USEFUL_VRAM_GB

    def runnable(tag: str) -> bool:
        choice = catalogue[tag]
        # On a GPU the weights live in video memory. On CPU they live in system
        # memory, so the two ladders are filtered against different budgets.
        return choice.min_vram_gb <= vram_gb if on_gpu else choice.min_ram_gb <= ram_gb

    fitting = [tag for tag in ladder if runnable(tag)]

    for position, tag in enumerate(fitting):
        if _is_installed(tag, installed):
            where = f"{vram_gb} GB of video memory" if on_gpu else f"{ram_gb} GB of system memory"
            # Something better fits this host but is not pulled yet. Say so rather
            # than silently settling: pulling it is one command.
            upgrade = fitting[0] if position else ""
            return ModelSelection(
                tag=tag,
                choice=catalogue[tag],
                installed=True,
                fits=True,
                reason=f"Best installed model this host can run with {where}",
                pull_command="",
                upgrade_tag=upgrade,
            )

    if fitting:
        tag = fitting[0]
        return ModelSelection(
            tag=tag,
            choice=catalogue[tag],
            installed=False,
            fits=True,
            reason="Best model this host can run, not installed yet",
            pull_command=f"ollama pull {tag}",
        )

    # Nothing fits. Offer the least demanding entry, preferring the one earlier in
    # the ladder when two are equally light, so a permissive licence wins the tie.
    budget = (lambda tag: catalogue[tag].min_vram_gb) if on_gpu else (lambda tag: catalogue[tag].min_ram_gb)
    smallest = min(ladder, key=lambda tag: (budget(tag), ladder.index(tag)))
    return ModelSelection(
        tag=smallest,
        choice=catalogue[smallest],
        installed=_is_installed(smallest, installed),
        fits=False,
        reason=(
            "No model in the ladder fits this host. The smallest one is offered, "
            "and it will be slow or will not load at all."
        ),
        pull_command=f"ollama pull {smallest}",
    )


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


class AiSettings:
    """Runtime settings for the AI layer, resolved from the environment."""

    def __init__(self) -> None:
        self.enabled: bool = os.environ.get("THF_AI_ENABLED", "1") != "0"
        self.base_url: str = os.environ.get("THF_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        self.model_override: str = os.environ.get("THF_AI_MODEL", "").strip()
        self.embedding_override: str = os.environ.get("THF_AI_EMBED_MODEL", "").strip()
        # A connect attempt must fail fast: the interface asks for status on every
        # page and a hunt must never wait on an absent server.
        self.connect_timeout: float = _env_float("THF_AI_CONNECT_TIMEOUT", 2.0)
        self.request_timeout: float = _env_float("THF_AI_TIMEOUT", 180.0)
        self.max_retries: int = _env_int("THF_AI_MAX_RETRIES", 2)
        self.max_calls_per_hunt: int = _env_int("THF_AI_MAX_CALLS", 60)
        self.status_cache_seconds: float = _env_float("THF_AI_STATUS_CACHE_SECONDS", 30.0)
        # Fixed so that the same evidence and the same prompt give the same answer,
        # which is what makes an AI observation defensible in a report.
        self.seed: int = _env_int("THF_AI_SEED", 1337)
        self.temperature: float = _env_float("THF_AI_TEMPERATURE", 0.0)
        self.context_tokens: int = _env_int("THF_AI_CONTEXT", 16384)

        # The collector. One run a week, overnight, with nobody waiting.
        self.collector_enabled: bool = os.environ.get("THF_CTI_ENABLED", "1") != "0"
        # 0 is Monday, 6 is Sunday.
        self.collector_weekday: int = max(0, min(6, _env_int("THF_CTI_DAY", 6)))
        self.collector_hour: int = max(0, min(23, _env_int("THF_CTI_HOUR", 2)))
        # How far back the very first run looks, when there is no previous one.
        self.collector_first_run_days: int = _env_int("THF_CTI_FIRST_RUN_DAYS", 30)
        self.collector_max_articles: int = _env_int("THF_CTI_MAX_ARTICLES", 120)
        self.collector_max_candidates: int = _env_int("THF_CTI_MAX_CANDIDATES", 25)
        self.collector_max_model_calls: int = _env_int("THF_CTI_MAX_MODEL_CALLS", 400)
        self.collector_respect_robots: bool = os.environ.get("THF_CTI_ROBOTS", "1") != "0"
        # An operator who curates their own feed list does not want the shipped one
        # reappearing on every run.
        self.collector_seed_sources: bool = os.environ.get("THF_CTI_SEED_SOURCES", "1") != "0"


ai_settings = AiSettings()
