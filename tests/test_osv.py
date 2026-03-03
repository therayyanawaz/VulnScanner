from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import vulnscanner.osv as osv
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


def test_parse_poetry_lock(tmp_path: Path) -> None:
    path = tmp_path / "poetry.lock"
    path.write_text(
        "\n".join(
            [
                '[[package]]',
                'name = "requests"',
                'version = "2.32.3"',
                "",
                "[[package]]",
                'name = "urllib3"',
                'version = "2.2.2"',
                "",
                "[[package]]",
                'name = "requests"',
                'version = "2.32.3"',
            ]
        ),
        encoding="utf-8",
    )

    deps = parse_dependency_manifest(path)
    assert Dependency("PyPI", "requests", "2.32.3") in deps
    assert Dependency("PyPI", "urllib3", "2.2.2") in deps
    assert len(deps) == 2


def test_parse_uv_lock(tmp_path: Path) -> None:
    path = tmp_path / "uv.lock"
    path.write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "httpx"',
                'version = "0.27.0"',
                "",
                "[[package]]",
                'name = "anyio"',
                'version = "4.4.0"',
            ]
        ),
        encoding="utf-8",
    )

    deps = parse_dependency_manifest(path)
    assert Dependency("PyPI", "httpx", "0.27.0") in deps
    assert Dependency("PyPI", "anyio", "4.4.0") in deps
    assert len(deps) == 2


def test_parse_poetry_lock_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "poetry.lock"
    path.write_text("[[package]\nname='broken'\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"Invalid TOML manifest: poetry\.lock"):
        parse_dependency_manifest(path)


def test_parse_unsupported_manifest_lists_supported(tmp_path: Path) -> None:
    path = tmp_path / "pom.xml"
    path.write_text("<project/>", encoding="utf-8")
    with pytest.raises(
        ValueError,
        match=r"Supported: package-lock\.json, poetry\.lock, uv\.lock, Pipfile\.lock, \*\.txt",
    ):
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


class _FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self) -> dict[str, object]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code < 400:
            return
        raise RuntimeError(f"status={self.status_code}")


class _FakeBatchClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses
        self.calls = 0

    async def post(self, _url: str, json: dict[str, object]) -> _FakeResponse:
        _ = json
        response = self._responses[self.calls]
        self.calls += 1
        return response


class _FakeDetailClient:
    def __init__(self, responses_by_vuln: dict[str, list[_FakeResponse]]) -> None:
        self._responses_by_vuln = responses_by_vuln
        self._calls: dict[str, int] = {}

    async def get(self, url: str) -> _FakeResponse:
        vuln_id = url.rsplit("/", 1)[-1]
        responses = self._responses_by_vuln[vuln_id]
        idx = self._calls.get(vuln_id, 0)
        self._calls[vuln_id] = idx + 1
        if idx >= len(responses):
            return responses[-1]
        return responses[idx]


def test_query_osv_batch_retries_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(osv, "settings", SimpleNamespace(osv_http_retries=2))
    monkeypatch.setattr(osv.asyncio, "sleep", _no_sleep)
    client = _FakeBatchClient(
        [
            _FakeResponse(status_code=429, headers={"Retry-After": "0"}),
            _FakeResponse(status_code=200, payload={"results": [{"vulns": [{"id": "OSV-1"}]}]}),
        ]
    )
    deps = [Dependency(ecosystem="npm", name="demo", version="1.0.0")]
    results = asyncio.run(osv._query_osv_batch(client, deps))
    assert client.calls == 2
    assert results == [{"vulns": [{"id": "OSV-1"}]}]


def test_fetch_vuln_detail_chunk_handles_retries_and_skips_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(
        osv,
        "settings",
        SimpleNamespace(osv_http_retries=2, osv_vuln_detail_concurrency=2),
    )
    monkeypatch.setattr(osv.asyncio, "sleep", _no_sleep)
    client = _FakeDetailClient(
        {
            "OSV-1": [
                _FakeResponse(status_code=503),
                _FakeResponse(status_code=200, payload={"id": "OSV-1", "summary": "ok"}),
            ],
            "OSV-2": [_FakeResponse(status_code=404)],
            "OSV-3": [_FakeResponse(status_code=503), _FakeResponse(status_code=503)],
        }
    )
    payloads = asyncio.run(osv._fetch_vuln_detail_chunk(client, ["OSV-1", "OSV-2", "OSV-3"]))
    assert payloads == {"OSV-1": {"id": "OSV-1", "summary": "ok"}}


def test_retry_delay_seconds_parsing() -> None:
    assert osv._retry_delay_seconds("4", 0.5) == 4
    assert osv._retry_delay_seconds("not-a-number", 0.5) == 0.5
    assert osv._retry_delay_seconds(None, 0.5) == 0.5


def test_scan_dependency_manifest_no_network_skips_live_osv_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    def _no_cache(*_args, **_kwargs):
        return None

    class _FailingAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            _ = args, kwargs
            raise AssertionError("network client should not be created in --no-network mode")

    monkeypatch.setattr(osv, "get_cached_osv", _no_cache)
    monkeypatch.setattr(osv.httpx, "AsyncClient", _FailingAsyncClient)

    result = asyncio.run(osv.scan_dependency_manifest(manifest, allow_network=False))
    assert result.dependencies_total == 1
    assert result.cache_hits == 0
    assert result.cache_misses == 1
    assert result.findings == ()


def test_scan_dependency_manifest_no_network_uses_cached_query_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    def _cached_query(*_args, **_kwargs):
        return {
            "vulns": [
                {
                    "id": "OSV-1",
                    "summary": "From cache",
                    "database_specific": {"severity": "high"},
                    "aliases": ["CVE-2024-0001"],
                }
            ]
        }

    def _no_cached_detail(*_args, **_kwargs):
        return None

    monkeypatch.setattr(osv, "get_cached_osv", _cached_query)
    monkeypatch.setattr(osv, "get_cached_osv_vuln", _no_cached_detail)
    monkeypatch.setattr(osv, "_load_cve_enrichment", lambda _cves: {})

    result = asyncio.run(osv.scan_dependency_manifest(manifest, allow_network=False))
    assert result.dependencies_total == 1
    assert result.cache_hits == 1
    assert result.cache_misses == 0
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vuln_id == "OSV-1"
    assert finding.summary == "From cache"
    assert finding.severity == "high"
