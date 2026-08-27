"""Application configuration."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value) if value else default


class Settings:
    """Runtime settings resolved from the environment with safe defaults."""

    def __init__(self) -> None:
        self.app_name = "Threat Hunting Factory"
        self.app_version = "1.0.0"
        self.data_dir: Path = _env_path("THF_DATA_DIR", BASE_DIR / "data")
        self.upload_dir: Path = self.data_dir / "uploads"
        self.database_url: str = os.environ.get(
            "THF_DATABASE_URL", f"sqlite:///{self.data_dir / 'thf.db'}"
        )
        self.jwt_secret: str = os.environ.get("THF_JWT_SECRET") or self._local_secret()
        self.jwt_algorithm: str = "HS256"
        self.jwt_ttl_minutes: int = int(os.environ.get("THF_JWT_TTL_MINUTES", "720"))
        self.web_dir: Path = BASE_DIR / "web"
        # Engine limits keep a single hunt bounded on modest hardware.
        self.max_archive_bytes: int = int(
            os.environ.get("THF_MAX_ARCHIVE_BYTES", str(512 * 1024 * 1024))
        )
        self.max_uncompressed_bytes: int = int(
            os.environ.get("THF_MAX_UNCOMPRESSED_BYTES", str(2 * 1024 * 1024 * 1024))
        )
        self.max_events: int = int(os.environ.get("THF_MAX_EVENTS", "750000"))
        self.max_observations_per_rule: int = int(
            os.environ.get("THF_MAX_OBS_PER_RULE", "50")
        )
        self.seed_demo_data: bool = os.environ.get("THF_SEED_DEMO", "1") == "1"

    def _local_secret(self) -> str:
        """Return a stable random secret persisted next to the database."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        secret_file = self.data_dir / ".jwt_secret"
        if secret_file.exists():
            value = secret_file.read_text(encoding="utf-8").strip()
            if len(value) >= 64:
                return value
        value = secrets.token_hex(48)
        secret_file.write_text(value, encoding="utf-8")
        try:
            secret_file.chmod(0o600)
        except OSError:
            pass
        return value

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
