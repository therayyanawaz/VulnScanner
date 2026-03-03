from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnscanner.cli import _parse_dt, _render_scan_result, _resolve_scan_policy
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


def test_resolve_scan_policy_none_keeps_inputs() -> None:
    resolved = _resolve_scan_policy("none", "high", True, 0.8)
    assert resolved == ("high", True, 0.8)


def test_resolve_scan_policy_balanced_sets_defaults() -> None:
    resolved = _resolve_scan_policy("balanced", None, False, None)
    assert resolved == ("critical", False, 0.9)


def test_resolve_scan_policy_strict_preserves_explicit_overrides() -> None:
    resolved = _resolve_scan_policy("strict", "critical", True, 0.95)
    assert resolved == ("critical", True, 0.95)


def test_render_scan_result_csv_and_markdown() -> None:
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
    assert "id,package,ecosystem,version,severity" in csv_out
    assert "OSV-1,demo,npm,1.2.3,high,CVE-2024-0001,true,0.800000,0.950000" in csv_out
    assert md_out.startswith("# Dependency Scan Report")
    assert "| high | OSV-1 | demo@1.2.3 | CVE-2024-0001 | yes | 0.80000 |" in md_out
