from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .db import db
from .config import settings


def cache_osv_result(ecosystem: str, package: str, version: str, payload: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO osv_cache (ecosystem, package, version, fetched_at, json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, package, version) DO UPDATE SET
                fetched_at=excluded.fetched_at,
                json=excluded.json
            """,
            (ecosystem, package, version, now.isoformat(), json_dumps(payload)),
        )


def get_cached_osv(ecosystem: str, package: str, version: str) -> dict[str, Any] | None:
    ttl = timedelta(hours=settings.osv_ttl_hours)
    threshold = datetime.now(timezone.utc) - ttl
    with db() as conn:
        row = conn.execute(
            "SELECT fetched_at, json FROM osv_cache WHERE ecosystem=? AND package=? AND version=?",
            (ecosystem, package, version),
        ).fetchone()
        if not row:
            return None
        fetched_at = datetime.fromisoformat(row[0])
        if fetched_at < threshold:
            return None
        return json_loads(row[1])


def json_dumps(data: Any) -> str:
    import json

    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def json_loads(s: str) -> Any:
    import json

    return json.loads(s)


