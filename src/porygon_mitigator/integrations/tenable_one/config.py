"""Tenable One / Tenable VM connection settings, from environment variables only."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from porygon_mitigator import __version__

# Tenable asks integrations to identify themselves this way.
TENABLE_USER_AGENT = f"Integration/1.0 (Team Porygon; porygon-mitigator; Build/{__version__})"


@dataclass(frozen=True)
class TenableConfig:
    access_key: str = field(default_factory=lambda: os.environ.get("TENABLE_ACCESS_KEY", ""), repr=False)
    secret_key: str = field(default_factory=lambda: os.environ.get("TENABLE_SECRET_KEY", ""), repr=False)
    base_url: str = field(default_factory=lambda: os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com"))

    @property
    def configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def headers(self) -> dict[str, str]:
        return {
            "X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}",
            "User-Agent": TENABLE_USER_AGENT,
        }
