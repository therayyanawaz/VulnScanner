from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import vulnscanner.epss as epss


def test_iter_epss_rows_parses_valid_records() -> None:
    csv_text = "\n".join(
        [
            "#model_version:v1,score_date:2026-03-03T00:00:00Z",
            "date,cve,epss,percentile",
            "2026-03-03,CVE-2024-0001,0.123,0.456",
            "2026-03-03,CVE-2024-0002,not-a-float,0.9",
            "2026-03-03,,0.5,0.9",
        ]
    )
    rows = epss._iter_epss_rows(gzip.compress(csv_text.encode("utf-8")))
    assert rows == [("CVE-2024-0001", 0.123, 0.456)]


def test_epss_freshness_true(monkeypatch) -> None:
    now = datetime(2026, 3, 3, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(epss, "settings", SimpleNamespace(epss_ttl_hours=24))
    monkeypatch.setattr(epss, "get_meta", lambda _k: (now - timedelta(hours=1)).isoformat())
    assert epss._is_fresh_enough(now) is True


def test_epss_freshness_false(monkeypatch) -> None:
    now = datetime(2026, 3, 3, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(epss, "settings", SimpleNamespace(epss_ttl_hours=24))
    monkeypatch.setattr(epss, "get_meta", lambda _k: (now - timedelta(hours=30)).isoformat())
    assert epss._is_fresh_enough(now) is False
