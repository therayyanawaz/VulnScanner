from __future__ import annotations

import csv
import gzip
from datetime import datetime, timedelta, timezone
from io import StringIO

import httpx

from .config import settings
from .db import db, get_meta, set_meta

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def sync_epss(force: bool = False) -> dict[str, int | bool]:
    now = datetime.now(timezone.utc)
    if not force and _is_fresh_enough(now):
        return {"skipped": True, "epss_records": 0, "matched_cves": 0}

    response = httpx.get(
        EPSS_CSV_URL,
        timeout=120,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    )
    response.raise_for_status()
    rows = list(_iter_epss_rows(response.content))

    with db() as conn:
        batch_size = 5000
        for start in range(0, len(rows), batch_size):
            chunk = rows[start : start + batch_size]
            conn.executemany(
                """
                INSERT INTO epss (cve_id, score, percentile, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    score=excluded.score,
                    percentile=excluded.percentile,
                    fetched_at=excluded.fetched_at
                """,
                (
                    (cve_id, score, percentile, now.isoformat())
                    for cve_id, score, percentile in chunk
                ),
            )

        conn.execute("UPDATE cves SET epss_score=NULL, epss_percentile=NULL")
        conn.execute("""
            UPDATE cves
            SET
                epss_score = (SELECT e.score FROM epss e WHERE e.cve_id = cves.cve_id),
                epss_percentile = (SELECT e.percentile FROM epss e WHERE e.cve_id = cves.cve_id)
            WHERE cve_id IN (SELECT cve_id FROM epss)
            """)
        matched = conn.execute("SELECT COUNT(*) FROM cves WHERE epss_score IS NOT NULL").fetchone()[
            0
        ]

    set_meta("epss_last_sync", now.isoformat())
    return {"skipped": False, "epss_records": len(rows), "matched_cves": int(matched)}


def _iter_epss_rows(content: bytes) -> list[tuple[str, float, float]]:
    decompressed = gzip.decompress(content).decode("utf-8", errors="replace")
    filtered_lines = [
        line for line in decompressed.splitlines() if line and not line.startswith("#")
    ]
    reader = csv.DictReader(StringIO("\n".join(filtered_lines)))
    rows: list[tuple[str, float, float]] = []
    for item in reader:
        cve_id = str(item.get("cve") or item.get("CVE") or "").strip()
        score_raw = str(item.get("epss") or "").strip()
        percentile_raw = str(item.get("percentile") or "").strip()
        if not cve_id or not score_raw or not percentile_raw:
            continue
        try:
            score = float(score_raw)
            percentile = float(percentile_raw)
        except ValueError:
            continue
        rows.append((cve_id, score, percentile))
    return rows


def _is_fresh_enough(now: datetime) -> bool:
    raw = get_meta("epss_last_sync")
    if not raw:
        return False
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    except Exception:
        return False
    return (now - dt) < timedelta(hours=settings.epss_ttl_hours)
