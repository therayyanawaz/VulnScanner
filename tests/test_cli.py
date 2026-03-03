from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnscanner.cli import _parse_dt


def test_parse_dt_accepts_zulu_time() -> None:
    parsed = _parse_dt("2024-08-01T00:00:00Z")
    assert parsed == datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_dt_normalizes_offset_time() -> None:
    parsed = _parse_dt("2024-08-01T05:30:00+05:30")
    assert parsed == datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_dt_requires_timezone() -> None:
    with pytest.raises(ValueError):
        _parse_dt("2024-08-01T00:00:00")


def test_parse_dt_rejects_empty_value() -> None:
    with pytest.raises(ValueError):
        _parse_dt("   ")
