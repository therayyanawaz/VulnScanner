from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    json BLOB NOT NULL,
    modified TIMESTAMP NOT NULL,
    is_known_exploited INTEGER DEFAULT 0,
    epss_score REAL,
    epss_percentile REAL
);

-- package+version caching for OSV lookups
CREATE TABLE IF NOT EXISTS osv_cache (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    json BLOB NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    json BLOB NOT NULL,
    fetched_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    score REAL NOT NULL,
    percentile REAL NOT NULL,
    fetched_at TIMESTAMP NOT NULL
);
"""


def ensure_database() -> None:
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(settings.database_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    ensure_database()
    conn = sqlite3.connect(settings.database_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def get_meta(key: str) -> str | None:
    with db() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None


def set_meta(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
