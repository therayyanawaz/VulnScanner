from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

import vulnscanner.cli as cli
from vulnscanner.cli import _parse_dt, _render_scan_result, _resolve_scan_policy, main
from vulnscanner.osv import ScanFinding, ScanResult


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


def test_parse_dt_accepts_now_keyword() -> None:
    now = datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc)
    parsed = _parse_dt("now", now=now)
    assert parsed == now


def test_parse_dt_accepts_relative_days() -> None:
    now = datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc)
    parsed = _parse_dt("7d", now=now)
    assert parsed == datetime(2026, 2, 24, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_dt_accepts_relative_hours_with_word_unit() -> None:
    now = datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc)
    parsed = _parse_dt("12 hours", now=now)
    assert parsed == datetime(2026, 3, 3, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_dt_accepts_today_and_yesterday() -> None:
    now = datetime(2026, 3, 3, 12, 34, 56, tzinfo=timezone.utc)
    today = _parse_dt("today", now=now)
    yesterday = _parse_dt("yesterday", now=now)
    assert today == datetime(2026, 3, 3, 0, 0, 0, tzinfo=timezone.utc)
    assert yesterday == datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_dt_rejects_unknown_relative_value() -> None:
    with pytest.raises(ValueError):
        _parse_dt("xyz")


def test_resolve_scan_policy_none_keeps_inputs() -> None:
    resolved = _resolve_scan_policy("none", "high", True, 0.8)
    assert resolved == ("high", True, 0.8)


def test_resolve_scan_policy_balanced_sets_defaults() -> None:
    resolved = _resolve_scan_policy("balanced", None, False, None)
    assert resolved == ("critical", False, 0.9)


def test_resolve_scan_policy_strict_preserves_explicit_overrides() -> None:
    resolved = _resolve_scan_policy("strict", "critical", True, 0.95)
    assert resolved == ("critical", True, 0.95)


def test_render_scan_result_csv_markdown_and_sarif() -> None:
    result = ScanResult(
        dependencies_total=1,
        cache_hits=0,
        cache_misses=1,
        findings=(
            ScanFinding(
                vuln_id="OSV-1",
                package="demo",
                ecosystem="npm",
                version="1.2.3",
                severity="high",
                aliases=("CVE-2024-0001",),
                summary="Sample summary",
                cve_id="CVE-2024-0001",
                is_known_exploited=True,
                epss_score=0.8,
                epss_percentile=0.95,
            ),
        ),
    )
    csv_out = _render_scan_result(result, "csv")
    md_out = _render_scan_result(result, "markdown")
    sarif_out = _render_scan_result(result, "sarif")
    sarif_data = json.loads(sarif_out)
    assert "id,package,ecosystem,version,severity" in csv_out
    assert "OSV-1,demo,npm,1.2.3,high,CVE-2024-0001,true,0.800000,0.950000" in csv_out
    assert md_out.startswith("# Dependency Scan Report")
    assert "| high | OSV-1 | demo@1.2.3 | CVE-2024-0001 | yes | 0.80000 |" in md_out
    assert sarif_data["version"] == "2.1.0"
    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnScanner"
    assert run["results"][0]["ruleId"] == "OSV-1"
    assert run["results"][0]["level"] == "error"


def test_scan_deps_help_includes_no_network_option() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", "--help"])
    assert result.exit_code == 0
    assert "--no-network" in result.output
    assert "--strict-cache" in result.output


def test_scan_deps_no_network_warns_on_cache_miss(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    async def _fake_scan(path, allow_network=True):
        assert path == manifest
        assert allow_network is False
        return ScanResult(dependencies_total=1, cache_hits=0, cache_misses=1, findings=())

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--no-network"])
    assert result.exit_code == 0
    assert "Cache-only mode skipped live OSV lookups for 1 dependencies" in result.output


def test_scan_deps_strict_cache_requires_no_network(tmp_path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--strict-cache"])
    assert result.exit_code != 0
    assert "--strict-cache requires --no-network" in result.output


def test_scan_deps_strict_cache_fails_on_cache_miss(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    async def _fake_scan(path, allow_network=True):
        assert path == manifest
        assert allow_network is False
        return ScanResult(dependencies_total=1, cache_hits=0, cache_misses=2, findings=())

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--no-network", "--strict-cache"])
    assert result.exit_code != 0
    assert "Policy failed: cache_miss=2" in result.output
