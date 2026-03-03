from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscanner.osv import (
    Dependency,
    ScanFinding,
    ScanResult,
    _derive_npm_name_from_path,
    _extract_cve_ids,
    _extract_severity,
    filter_findings,
    parse_dependency_manifest,
    policy_failures,
    should_fail,
)


def test_parse_package_lock_v2(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 2,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.11"},
                    "node_modules/@types/node": {"version": "20.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    deps = parse_dependency_manifest(path)
    assert Dependency("npm", "lodash", "4.17.11") in deps
    assert Dependency("npm", "@types/node", "20.0.0") in deps
    assert len(deps) == 2


def test_parse_requirements_txt(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        "\n".join(
            [
                "flask==3.0.3",
                "uvicorn==0.30.1",
                "invalid>=1.0.0",
                "-r extras.txt",
            ]
        ),
        encoding="utf-8",
    )
    deps = parse_dependency_manifest(path)
    assert deps == [
        Dependency("PyPI", "flask", "3.0.3"),
        Dependency("PyPI", "uvicorn", "0.30.1"),
    ]


def test_parse_pipfile_lock(tmp_path: Path) -> None:
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        json.dumps(
            {
                "_meta": {"hash": {"sha256": "demo"}},
                "default": {
                    "flask": {"version": "==3.0.3"},
                    "requests": {"version": ">=2.0.0"},
                },
                "develop": {
                    "pytest": {"version": "==8.3.0"},
                    "black": {"version": "===24.8.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    deps = parse_dependency_manifest(path)
    assert Dependency("PyPI", "flask", "3.0.3") in deps
    assert Dependency("PyPI", "pytest", "8.3.0") in deps
    assert Dependency("PyPI", "black", "24.8.0") in deps
    assert Dependency("PyPI", "requests", "2.0.0") not in deps
    assert len(deps) == 3


def test_parse_unsupported_manifest_lists_supported(tmp_path: Path) -> None:
    path = tmp_path / "pom.xml"
    path.write_text("<project/>", encoding="utf-8")
    with pytest.raises(ValueError, match=r"Supported: package-lock\.json, Pipfile\.lock, \*\.txt"):
        parse_dependency_manifest(path)


def test_derive_npm_name_from_path() -> None:
    assert _derive_npm_name_from_path("node_modules/lodash") == "lodash"
    assert _derive_npm_name_from_path("node_modules/@scope/pkg") == "@scope/pkg"
    assert _derive_npm_name_from_path("packages/local") is None


def test_extract_severity_prefers_highest() -> None:
    vuln = {
        "database_specific": {"severity": "Medium"},
        "ecosystem_specific": {"severity": "critical"},
        "severity": [{"type": "CVSS_V3", "score": "high"}],
    }
    assert _extract_severity(vuln) == "critical"


def test_extract_cve_ids_from_vuln_and_aliases() -> None:
    cves = _extract_cve_ids("GHSA-xxxx-yyyy", ["CVE-2024-0001", "cve-2024-0002", "CVE-2024-0001"])
    assert cves == ["CVE-2024-0001", "CVE-2024-0002"]


def test_should_fail_threshold_logic() -> None:
    result = ScanResult(
        dependencies_total=1,
        cache_hits=0,
        cache_misses=1,
        findings=(
            ScanFinding(
                vuln_id="OSV-1",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="high",
                aliases=(),
                summary="",
            ),
        ),
    )
    assert should_fail(result, "high") is True
    assert should_fail(result, "critical") is False


def test_scan_result_enrichment_counters() -> None:
    result = ScanResult(
        dependencies_total=1,
        cache_hits=0,
        cache_misses=1,
        findings=(
            ScanFinding(
                vuln_id="OSV-1",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="high",
                aliases=(),
                summary="",
                cve_id="CVE-2024-0001",
                is_known_exploited=True,
                epss_score=0.45,
            ),
            ScanFinding(
                vuln_id="OSV-2",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="low",
                aliases=(),
                summary="",
            ),
        ),
    )
    assert result.known_exploited_findings == 1
    assert result.epss_enriched_findings == 1


def test_filter_findings_applies_all_filters() -> None:
    result = ScanResult(
        dependencies_total=2,
        cache_hits=1,
        cache_misses=1,
        findings=(
            ScanFinding(
                vuln_id="A",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="high",
                aliases=(),
                summary="",
                is_known_exploited=True,
                epss_score=0.9,
            ),
            ScanFinding(
                vuln_id="B",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="medium",
                aliases=(),
                summary="",
                is_known_exploited=False,
                epss_score=0.3,
            ),
            ScanFinding(
                vuln_id="C",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="critical",
                aliases=(),
                summary="",
                is_known_exploited=False,
                epss_score=0.95,
            ),
        ),
    )
    filtered = filter_findings(result, min_severity="high", kev_only=True, epss_min=0.5)
    assert len(filtered.findings) == 1
    assert filtered.findings[0].vuln_id == "A"


def test_filter_findings_rejects_invalid_severity() -> None:
    result = ScanResult(dependencies_total=0, cache_hits=0, cache_misses=0, findings=())
    with pytest.raises(ValueError):
        filter_findings(result, min_severity="invalid")


def test_policy_failures_combined() -> None:
    result = ScanResult(
        dependencies_total=1,
        cache_hits=0,
        cache_misses=1,
        findings=(
            ScanFinding(
                vuln_id="A",
                package="demo",
                ecosystem="npm",
                version="1.0.0",
                severity="high",
                aliases=(),
                summary="",
                is_known_exploited=True,
                epss_score=0.7,
            ),
        ),
    )
    failures = policy_failures(result, severity_threshold="medium", fail_on_kev=True, fail_on_epss=0.5)
    assert failures == ["severity>=medium", "known_exploited", "epss>=0.5"]
