from __future__ import annotations

import json
from pathlib import Path

from vulnscanner.osv import (
    Dependency,
    ScanFinding,
    ScanResult,
    _derive_npm_name_from_path,
    _extract_severity,
    parse_dependency_manifest,
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
