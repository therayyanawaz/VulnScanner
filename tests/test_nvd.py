from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

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
    assert nvd._format_nvd_datetime(ts) == "2024-08-01T00:00:00Z"


def test_get_last_mod_time_parses_z_value(monkeypatch) -> None:
    monkeypatch.setattr(nvd, "get_meta", lambda _k: "2024-08-01T00:00:00Z")
    parsed = nvd._get_last_mod_time()
    assert parsed == datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_should_fail_empty_sync_for_long_zero_result_window() -> None:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 2, 15, tzinfo=timezone.utc)
    assert nvd._should_fail_empty_sync(start, end, saved=0, pages=15) is True


def test_should_not_fail_empty_sync_for_short_window() -> None:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 1, 5, tzinfo=timezone.utc)
    assert nvd._should_fail_empty_sync(start, end, saved=0, pages=3) is False


def test_extract_nvd_error_message_prefers_json_message() -> None:
    request = httpx.Request("GET", "https://example.test")
    response = httpx.Response(404, json={"message": "Invalid apiKey"}, request=request)
    assert nvd._extract_nvd_error_message(response) == "Invalid apiKey"


def test_extract_nvd_error_message_falls_back_to_text() -> None:
    request = httpx.Request("GET", "https://example.test")
    response = httpx.Response(404, text="upstream outage", request=request)
    assert nvd._extract_nvd_error_message(response) == "upstream outage"


def test_treat_404_as_empty_result_without_api_key() -> None:
    assert nvd._treat_404_as_empty_result(False, None) is True
    assert nvd._treat_404_as_empty_result(False, "anything") is True


def test_treat_404_as_empty_result_with_api_key_only_for_no_result_text() -> None:
    assert nvd._treat_404_as_empty_result(True, "No results found for query") is True
    assert nvd._treat_404_as_empty_result(True, "Invalid apiKey") is False
    assert nvd._treat_404_as_empty_result(True, None) is False


def test_nvd_404_error_message_contains_context() -> None:
    message = nvd._nvd_404_error_message("Invalid apiKey")
    assert "HTTP 404 while using an API key" in message
    assert "Invalid apiKey" in message


def test_is_suspicious_empty_page() -> None:
    assert nvd._is_suspicious_empty_page(10, 0) is True
    assert nvd._is_suspicious_empty_page(10, 10) is False
    assert nvd._is_suspicious_empty_page(0, 0) is False


def test_sync_nvd_delta_fails_for_long_zero_result_window(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        async def fetch_page(self, *_args, **_kwargs):
            return {"totalResults": 0, "resultsPerPage": 2000, "vulnerabilities": []}

        async def aclose(self) -> None:
            return None

    set_calls: list[datetime] = []
    monkeypatch.setattr(nvd, "NvdClient", _Client)
    monkeypatch.setattr(nvd, "_set_last_mod_time", lambda dt: set_calls.append(dt))

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 2, 15, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError, match="zero CVEs over a long time window"):
        asyncio.run(nvd.sync_nvd_delta(since=start, until=end))
    assert set_calls == []


def test_sync_nvd_delta_fails_on_suspicious_empty_page(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        async def fetch_page(self, *_args, **_kwargs):
            return {"totalResults": 10, "resultsPerPage": 2000, "vulnerabilities": []}

        async def aclose(self) -> None:
            return None

    set_calls: list[datetime] = []
    monkeypatch.setattr(nvd, "NvdClient", _Client)
    monkeypatch.setattr(nvd, "_set_last_mod_time", lambda dt: set_calls.append(dt))

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(hours=6)
    with pytest.raises(RuntimeError, match="empty vulnerabilities page"):
        asyncio.run(nvd.sync_nvd_delta(since=start, until=end))
    assert set_calls == []


def test_sync_nvd_delta_allows_short_empty_window(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        async def fetch_page(self, *_args, **_kwargs):
            return {"totalResults": 0, "resultsPerPage": 2000, "vulnerabilities": []}

        async def aclose(self) -> None:
            return None

    set_calls: list[datetime] = []
    monkeypatch.setattr(nvd, "NvdClient", _Client)
    monkeypatch.setattr(nvd, "_set_last_mod_time", lambda dt: set_calls.append(dt))

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(hours=6)
    stats = asyncio.run(nvd.sync_nvd_delta(since=start, until=end))
    assert stats == {"cves": 0, "pages": 1}
    assert set_calls == [end]
