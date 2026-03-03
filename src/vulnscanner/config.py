from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Settings:
    database_path: str = os.environ.get("VULNSCANNER_DB", "vulnscanner.db")
    nvd_api_key: str | None = os.environ.get("NVD_API_KEY")
    user_agent: str = os.environ.get(
        "VULNSCANNER_UA",
        "VulnScanner/0.2.0 (+https://github.com/therayyanawaz/VulnScanner)",
    )
    # Rate limits (NVD API: 5/30s without key, 50/30s with key)
    nvd_max_per_30s: int = _env_int(
        "NVD_MAX_PER_30S",
        5 if os.environ.get("NVD_API_KEY") is None else 50,
    )
    # Delta sync window safeguard (smaller windows = less rate limiting issues)
    nvd_max_days_per_request: int = _env_int("NVD_MAX_DAYS_PER_REQUEST", 3)
    # Cache TTLs
    osv_ttl_hours: int = _env_int("OSV_TTL_HOURS", 12)
    osv_http_timeout_seconds: int = _env_int("OSV_HTTP_TIMEOUT_SECONDS", 60)
    osv_http_retries: int = _env_int("OSV_HTTP_RETRIES", 3)
    osv_vuln_detail_concurrency: int = _env_int("OSV_VULN_DETAIL_CONCURRENCY", 20)
    kev_ttl_hours: int = _env_int("KEV_TTL_HOURS", 24)
    epss_ttl_hours: int = _env_int("EPSS_TTL_HOURS", 720)

    @property
    def nvd_time_window(self) -> timedelta:
        return timedelta(days=self.nvd_max_days_per_request)


settings = Settings()
