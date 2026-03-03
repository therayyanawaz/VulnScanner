from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .config import settings
from .db import db, get_meta, set_meta

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def sync_kev(force: bool = False) -> dict[str, int | bool]:
    now = datetime.now(timezone.utc)
    if not force and _is_fresh_enough(now):
        return {"skipped": True, "kev_records": 0, "matched_cves": 0}

    response = httpx.get(KEV_FEED_URL, timeout=60, headers={"User-Agent": settings.user_agent})
    response.raise_for_status()
    payload = response.json()
    entries = _extract_kev_entries(payload)

    cve_ids = [entry["cveID"] for entry in entries]
    with db() as conn:
        for entry in entries:
            cve_id = entry["cveID"]
            conn.execute(
                """
                INSERT INTO kev (cve_id, json, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    json=excluded.json,
                    fetched_at=excluded.fetched_at
                """,
                (cve_id, json.dumps(entry, separators=(",", ":")), now.isoformat()),
            )
        conn.execute("UPDATE cves SET is_known_exploited=0")
        conn.executemany(
            "UPDATE cves SET is_known_exploited=1 WHERE cve_id=?", ((cve_id,) for cve_id in cve_ids)
        )
        matched = conn.execute("SELECT COUNT(*) FROM cves WHERE is_known_exploited=1").fetchone()[0]

    set_meta("kev_last_sync", now.isoformat())
    return {"skipped": False, "kev_records": len(entries), "matched_cves": int(matched)}


def _extract_kev_entries(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    entries: list[dict[str, Any]] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        entries.append(item)
    return entries


def _is_fresh_enough(now: datetime) -> bool:
    raw = get_meta("kev_last_sync")
    if not raw:
        return False
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    except Exception:
        return False
    return (now - dt) < timedelta(hours=settings.kev_ttl_hours)
