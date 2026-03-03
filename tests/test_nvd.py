from __future__ import annotations

from datetime import datetime, timedelta, timezone

import vulnscanner.nvd as nvd


def test_normalize_iso8601_preserves_z_suffix() -> None:
    assert nvd._normalize_iso8601("2024-08-01T00:00:00Z") == "2024-08-01T00:00:00Z"


def test_normalize_iso8601_converts_offset_to_utc() -> None:
    assert nvd._normalize_iso8601("2024-08-01T05:30:00+05:30") == "2024-08-01T00:00:00Z"


def test_retry_after_seconds_parsing() -> None:
    assert nvd._retry_after_seconds("45", default_seconds=30) == 45
    assert nvd._retry_after_seconds("0", default_seconds=30) == 30
    assert nvd._retry_after_seconds("not-int", default_seconds=30) == 30
    assert nvd._retry_after_seconds(None, default_seconds=30) == 30


def test_format_nvd_datetime_normalizes_timezone() -> None:
    offset = timezone(timedelta(hours=5, minutes=30))
    ts = datetime(2024, 8, 1, 5, 30, 0, tzinfo=offset)
    assert nvd._format_nvd_datetime(ts) == "2024-08-01T00:00:00"


def test_get_last_mod_time_parses_z_value(monkeypatch) -> None:
    monkeypatch.setattr(nvd, "get_meta", lambda _k: "2024-08-01T00:00:00Z")
    parsed = nvd._get_last_mod_time()
    assert parsed == datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
