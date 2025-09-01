from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Settings:
    database_path: str = os.environ.get("VULNSCANNER_DB", "vulnscanner.db")
    nvd_api_key: str | None = os.environ.get("NVD_API_KEY")
    user_agent: str = os.environ.get(
        "VULNSCANNER_UA", "VulnScanner/0.0.1 (+https://example.local)"
    )
    # Rate limits
    nvd_max_per_30s: int = int(os.environ.get("NVD_MAX_PER_30S", "50"))
    # Delta sync window safeguard
    nvd_max_days_per_request: int = int(os.environ.get("NVD_MAX_DAYS_PER_REQUEST", "7"))
    # Cache TTLs
    osv_ttl_hours: int = int(os.environ.get("OSV_TTL_HOURS", "12"))
    kev_ttl_hours: int = int(os.environ.get("KEV_TTL_HOURS", "24"))
    epss_ttl_hours: int = int(os.environ.get("EPSS_TTL_HOURS", "720"))

    @property
    def nvd_time_window(self) -> timedelta:
        return timedelta(days=self.nvd_max_days_per_request)


settings = Settings()


