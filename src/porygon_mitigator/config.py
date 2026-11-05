"""Runtime settings from environment variables. Nothing here is ever written to disk or logged."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from porygon_mitigator import __version__

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "medium"
DEFAULT_MAX_SOURCES = 8
USER_AGENT = f"porygon-mitigator/{__version__}"


def package_data_dir() -> Path:
    """The packaged data directory (seed cache and catalogue indexes)."""
    return Path(str(resources.files("porygon_mitigator") / "data"))


def _is_site_packages(path: Path) -> bool:
    parts = {part.lower() for part in path.resolve().parts}
    return "site-packages" in parts or "dist-packages" in parts


def running_from_checkout() -> bool:
    """True when the package is imported from a source checkout (editable install), not an installed wheel."""
    data = package_data_dir()
    return not _is_site_packages(data) and (data.parents[2] / "pyproject.toml").exists()


def user_cache_dir() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "porygon-mitigator" / "Cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "porygon-mitigator"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "porygon-mitigator"


def repo_root() -> Path | None:
    return package_data_dir().parents[2] if running_from_checkout() else None


@dataclass
class Settings:
    model: str = field(default_factory=lambda: os.environ.get("PORYGON_MODEL", DEFAULT_MODEL))
    effort: str = field(default_factory=lambda: os.environ.get("PORYGON_EFFORT", DEFAULT_EFFORT))
    max_sources: int = field(
        default_factory=lambda: int(os.environ.get("PORYGON_MAX_SOURCES", str(DEFAULT_MAX_SOURCES)))
    )
    cache_dir_override: str | None = field(default_factory=lambda: os.environ.get("PORYGON_CACHE_DIR"))
    work_dir_override: str | None = field(default_factory=lambda: os.environ.get("PORYGON_WORK_DIR"))

    @property
    def has_anthropic_credentials(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))

    @property
    def nvd_api_key(self) -> str | None:
        return os.environ.get("NVD_API_KEY") or None

    @property
    def threat_vault_api_key(self) -> str | None:
        return os.environ.get("PALO_ALTO_THREAT_VAULT_API_KEY") or None

    def writable_cache_dir(self) -> Path:
        """Where new CVE records are written.

        PORYGON_CACHE_DIR wins. From a source checkout, new records land in the repo's own cache so they can be
        committed. An installed wheel writes to the user cache directory instead (never into site-packages).
        """
        if self.cache_dir_override:
            return Path(self.cache_dir_override).expanduser()
        if running_from_checkout():
            return package_data_dir() / "cache"
        return user_cache_dir() / "cache"

    def seed_cache_dir(self) -> Path:
        return package_data_dir() / "cache"

    def work_dir(self) -> Path:
        """Scratch space for fetched advisory text and catalogue downloads. Never committed."""
        if self.work_dir_override:
            return Path(self.work_dir_override).expanduser()
        root = repo_root()
        return (root / ".cache") if root else (user_cache_dir() / "work")


def settings() -> Settings:
    return Settings()
