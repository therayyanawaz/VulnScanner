from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import vulnscanner.kev as kev


def test_extract_kev_entries_filters_invalid_items() -> None:
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "vendorProject": "demo"},
            {"vendorProject": "missing-cve"},
            "invalid",
        ]
    }
    entries = kev._extract_kev_entries(payload)
    assert entries == [{"cveID": "CVE-2024-0001", "vendorProject": "demo"}]


def test_is_fresh_enough_true(monkeypatch) -> None:
    now = datetime(2026, 3, 3, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(kev, "settings", SimpleNamespace(kev_ttl_hours=24))
    monkeypatch.setattr(kev, "get_meta", lambda _k: (now - timedelta(hours=1)).isoformat())
    assert kev._is_fresh_enough(now) is True


def test_is_fresh_enough_false_for_stale_timestamp(monkeypatch) -> None:
    now = datetime(2026, 3, 3, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(kev, "settings", SimpleNamespace(kev_ttl_hours=24))
    monkeypatch.setattr(kev, "get_meta", lambda _k: (now - timedelta(hours=48)).isoformat())
    assert kev._is_fresh_enough(now) is False
