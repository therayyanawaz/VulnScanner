from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import httpx
from tenacity import before_sleep_log, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .config import settings
from .db import db, get_meta, set_meta

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOGGER = logging.getLogger(__name__)


@dataclass
class NvdDeltaWindow:
    start: datetime
    end: datetime

    def clamp(self, max_span: timedelta) -> list["NvdDeltaWindow"]:
        windows: list[NvdDeltaWindow] = []
        cur = self.start
        while cur < self.end:
            next_end = min(cur + max_span, self.end)
            windows.append(NvdDeltaWindow(start=cur, end=next_end))
            cur = next_end
        return windows


class RateLimiter:
    def __init__(self, max_per_30s: int) -> None:
        self.max_per_30s = max_per_30s
        self.calls: list[float] = []

    async def wait(self) -> None:
        import asyncio
        import time

        now = time.monotonic()
        window_start = now - 30.0
        self.calls = [t for t in self.calls if t >= window_start]
        if len(self.calls) >= self.max_per_30s:
            sleep_for = self.calls[0] + 30.0 - now
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
        self.calls.append(time.monotonic())


class NvdClient:
    def __init__(self) -> None:
        headers = {"User-Agent": settings.user_agent}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        self.client = httpx.AsyncClient(headers=headers, timeout=60)
        self.rate_limiter = RateLimiter(settings.nvd_max_per_30s)

    async def aclose(self) -> None:
        await self.client.aclose()

    @retry(
        reraise=True,
        retry=retry_if_exception_type((httpx.HTTPError,)),
        wait=wait_exponential(multiplier=2, min=5, max=120),  # More conservative for rate limits
        stop=stop_after_attempt(5),
        before_sleep=before_sleep_log(LOGGER, logging.WARNING),
    )
    async def fetch_page(
        self, start: datetime, end: datetime, start_index: int = 0
    ) -> dict[str, Any]:
        await self.rate_limiter.wait()
        params = {
            "lastModStartDate": _format_nvd_datetime(start),
            "lastModEndDate": _format_nvd_datetime(end),
            "startIndex": str(start_index),
            "resultsPerPage": "2000",
        }
        resp = await self.client.get(NVD_BASE, params=params)
        if resp.status_code == 404:
            # No CVEs in this time range
            return {"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}
        elif resp.status_code == 429:
            # Rate limited - add extra delay before raising
            sleep_for = _retry_after_seconds(resp.headers.get("Retry-After"), default_seconds=30)
            LOGGER.warning("Rate limited by NVD API. Waiting %s seconds before retry.", sleep_for)
            await asyncio.sleep(sleep_for)
        resp.raise_for_status()
        return resp.json()


async def sync_nvd_delta(
    since: datetime | None = None, until: datetime | None = None
) -> dict[str, int]:
    # Determine window
    now = datetime.now(timezone.utc)
    last = since or _get_last_mod_time() or (now - timedelta(days=1))
    end = until or now
    if last >= end:
        return {"cves": 0, "pages": 0}

    client = NvdClient()
    saved = 0
    pages = 0
    try:
        for window in NvdDeltaWindow(last, end).clamp(settings.nvd_time_window):
            start_index = 0
            total_results = None
            while True:
                data = await client.fetch_page(window.start, window.end, start_index)
                pages += 1
                total_results = total_results or int(data.get("totalResults", 0))
                vulnerabilities: Iterable[dict[str, Any]] = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                count = _save_vulnerabilities(vulnerabilities)
                saved += count
                # pagination
                results_per_page = int(data.get("resultsPerPage", 0) or 2000)
                if start_index + results_per_page >= total_results:
                    break
                start_index += results_per_page
        _set_last_mod_time(end)
        return {"cves": saved, "pages": pages}
    finally:
        await client.aclose()


def _save_vulnerabilities(vulns: Iterable[dict[str, Any]]) -> int:
    count = 0
    with db() as conn:
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            last_mod = cve.get("lastModified") or item.get("lastModified")
            if not cve_id or not last_mod:
                continue
            # Normalize datetime string
            modified_at = _normalize_iso8601(last_mod)
            conn.execute(
                """
                INSERT INTO cves (cve_id, source, json, modified)
                VALUES (?, 'NVD', ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    json=excluded.json,
                    modified=excluded.modified
                """,
                (cve_id, _json_dumps(item), modified_at),
            )
            count += 1
    return count


def _normalize_iso8601(value: str) -> str:
    # Ensure Z suffix
    if value.endswith("Z"):
        return value
    try:
        dt = datetime.fromisoformat(value)
    except Exception:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _json_dumps(data: Any) -> str:
    import json

    return json.dumps(data, separators=(",", ":"), sort_keys=False)


def _get_last_mod_time() -> datetime | None:
    raw = get_meta("nvd_last_mod")
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _set_last_mod_time(dt: datetime) -> None:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    set_meta("nvd_last_mod", dt.isoformat())


def _retry_after_seconds(value: str | None, default_seconds: int) -> int:
    if value is None:
        return default_seconds
    try:
        seconds = int(value)
        return seconds if seconds > 0 else default_seconds
    except ValueError:
        return default_seconds


def _format_nvd_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")
