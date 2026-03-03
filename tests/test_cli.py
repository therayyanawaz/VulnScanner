from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

import vulnscanner.cli as cli
from vulnscanner.cli import _parse_dt, _render_scan_result, _resolve_scan_policy, _select_output_findings, main
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
    assert "--top" in result.output
    assert "--summary-only" in result.output
    assert "--sort-by" in result.output
    assert "--baseline" in result.output
    assert "--save-baseline" in result.output
    assert "--new-only" in result.output
    assert "--fail-on-new-only" in result.output


def test_root_help_supports_short_h() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["-h"])
    assert result.exit_code == 0
    assert "Core workflow:" in result.output
    assert "scan-deps" in result.output


def test_scan_deps_help_supports_short_h() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", "-h"])
    assert result.exit_code == 0
    assert "Scan a dependency manifest" in result.output
    assert "--strict-cache" in result.output


def test_man_page_exists_with_expected_sections() -> None:
    man_path = Path("docs/man/vulnscanner.1")
    assert man_path.exists() is True
    text = man_path.read_text(encoding="utf-8")
    assert ".SH NAME" in text
    assert ".SH COMMANDS" in text
    assert ".SH EXIT CODES" in text


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
    assert result.exit_code == cli.EXIT_STRICT_CACHE_MISS
    assert "Policy failed: cache_miss=2" in result.output


def test_scan_deps_policy_failure_uses_policy_exit_code(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=0,
            findings=(
                ScanFinding(
                    vuln_id="OSV-CRIT",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="critical",
                    aliases=(),
                    summary="Critical issue",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--fail-on", "high"])
    assert result.exit_code == cli.EXIT_POLICY_FAILED
    assert "Policy failed: severity>=high" in result.output


def test_scan_deps_runtime_failure_uses_scan_failed_exit_code(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    async def _boom(path, allow_network=True):
        _ = path, allow_network
        raise RuntimeError("upstream unavailable")

    monkeypatch.setattr(cli, "scan_dependency_manifest", _boom)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest)])
    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "Dependency scan failed: upstream unavailable" in result.output


def test_scan_deps_new_only_requires_baseline(tmp_path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--new-only"])
    assert result.exit_code != 0
    assert "--new-only requires --baseline" in result.output


def test_scan_deps_fail_on_new_only_requires_baseline(tmp_path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--fail-on-new-only"])
    assert result.exit_code != 0
    assert "--fail-on-new-only requires --baseline" in result.output


def test_select_output_findings_supports_sort_and_limits() -> None:
    result = ScanResult(
        dependencies_total=3,
        cache_hits=0,
        cache_misses=3,
        findings=(
            ScanFinding(
                vuln_id="OSV-B",
                package="zzz",
                ecosystem="npm",
                version="1.0.0",
                severity="medium",
                aliases=(),
                summary="",
                epss_score=0.9,
            ),
            ScanFinding(
                vuln_id="OSV-A",
                package="aaa",
                ecosystem="npm",
                version="1.0.0",
                severity="critical",
                aliases=(),
                summary="",
                epss_score=0.2,
            ),
            ScanFinding(
                vuln_id="OSV-C",
                package="mmm",
                ecosystem="npm",
                version="1.0.0",
                severity="high",
                aliases=(),
                summary="",
                epss_score=None,
            ),
        ),
    )
    sev = _select_output_findings(result, top=2, summary_only=False, sort_by="severity")
    pkg = _select_output_findings(result, top=3, summary_only=False, sort_by="package")
    epss = _select_output_findings(result, top=3, summary_only=False, sort_by="epss")
    summary = _select_output_findings(result, top=3, summary_only=True, sort_by="severity")
    top_zero = _select_output_findings(result, top=0, summary_only=False, sort_by="severity")

    assert [item.vuln_id for item in sev] == ["OSV-A", "OSV-C"]
    assert [item.vuln_id for item in pkg] == ["OSV-A", "OSV-C", "OSV-B"]
    assert [item.vuln_id for item in epss] == ["OSV-B", "OSV-A", "OSV-C"]
    assert summary == ()
    assert top_zero == ()


def test_scan_deps_top_limits_table_rows(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=1,
            findings=(
                ScanFinding(
                    vuln_id="OSV-CRIT",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="critical",
                    aliases=(),
                    summary="Critical issue",
                ),
                ScanFinding(
                    vuln_id="OSV-LOW",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="low",
                    aliases=(),
                    summary="Low issue",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--format", "table", "--top", "1"])
    assert result.exit_code == 0
    assert "OSV-CRIT" in result.output
    assert "OSV-LOW" not in result.output
    assert "Displayed findings: 1 of 2" in result.output


def test_scan_deps_baseline_new_only_filters_results(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "OSV-OLD",
                        "package": "demo",
                        "version": "1.0.0",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=0,
            findings=(
                ScanFinding(
                    vuln_id="OSV-OLD",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="high",
                    aliases=(),
                    summary="Existing issue",
                ),
                ScanFinding(
                    vuln_id="OSV-NEW",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="critical",
                    aliases=(),
                    summary="New issue",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan-deps", str(manifest), "--baseline", str(baseline), "--new-only", "--format", "table"],
    )
    assert result.exit_code == 0
    assert "OSV-NEW" in result.output
    assert "OSV-OLD" not in result.output
    assert "Baseline comparison: 1 new / 2 current findings" in result.output


def test_scan_deps_baseline_uses_ecosystem_when_available(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "OSV-SHARED",
                        "package": "demo",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=0,
            findings=(
                ScanFinding(
                    vuln_id="OSV-SHARED",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="high",
                    aliases=(),
                    summary="Cross-ecosystem finding",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan-deps", str(manifest), "--baseline", str(baseline), "--new-only", "--format", "table"],
    )
    assert result.exit_code == 0
    assert "OSV-SHARED" in result.output
    assert "Baseline comparison: 1 new / 1 current findings" in result.output


def test_scan_deps_invalid_baseline_uses_scan_failed_exit_code(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}", encoding="utf-8")

    async def _fake_scan(path, allow_network=True):
        _ = path, allow_network
        return ScanResult(dependencies_total=0, cache_hits=0, cache_misses=0, findings=())

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--baseline", str(baseline)])
    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "Invalid baseline file:" in result.output


def test_scan_deps_save_baseline_writes_json(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")
    baseline_out = tmp_path / "out" / "baseline.json"

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=1,
            findings=(
                ScanFinding(
                    vuln_id="OSV-1",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="high",
                    aliases=("CVE-2024-0001",),
                    summary="Demo finding",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(main, ["scan-deps", str(manifest), "--save-baseline", str(baseline_out)])
    assert result.exit_code == 0
    assert "Baseline saved to" in result.output
    payload = json.loads(baseline_out.read_text(encoding="utf-8"))
    assert payload["dependencies_total"] == 1
    assert payload["findings_total"] == 1
    assert payload["findings"][0]["id"] == "OSV-1"


def test_scan_deps_fail_on_new_only_uses_diff_for_policy(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.3\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "OSV-OLD",
                        "package": "demo",
                        "version": "1.0.0",
                        "ecosystem": "PyPI",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    async def _fake_scan(path, allow_network=True):
        _ = allow_network
        assert path == manifest
        return ScanResult(
            dependencies_total=1,
            cache_hits=0,
            cache_misses=0,
            findings=(
                ScanFinding(
                    vuln_id="OSV-OLD",
                    package="demo",
                    ecosystem="PyPI",
                    version="1.0.0",
                    severity="critical",
                    aliases=(),
                    summary="Existing critical",
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_dependency_manifest", _fake_scan)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan-deps",
            str(manifest),
            "--baseline",
            str(baseline),
            "--fail-on-new-only",
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 0
    assert "Baseline comparison: 0 new / 1 current findings" in result.output


def test_state_show_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "nvd_last_mod": "2026-03-03T00:00:00+00:00",
        "kev_last_sync": None,
        "epss_last_sync": "2026-03-02T00:00:00+00:00",
    }
    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "get_meta", lambda key: values[key])
    runner = CliRunner()
    result = runner.invoke(main, ["state", "show", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["nvd_last_mod"] == "2026-03-03T00:00:00+00:00"
    assert data["kev_last_sync"] is None
    assert data["epss_last_sync"] == "2026-03-02T00:00:00+00:00"


def test_state_reset_all_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []
    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "delete_meta", lambda key: deleted.append(key))
    runner = CliRunner()
    result = runner.invoke(main, ["state", "reset"])
    assert result.exit_code == 0
    assert deleted == ["nvd_last_mod", "kev_last_sync", "epss_last_sync"]
    assert "Reset state keys: nvd_last_mod, kev_last_sync, epss_last_sync" in result.output


def test_state_reset_selected_key(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []
    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "delete_meta", lambda key: deleted.append(key))
    runner = CliRunner()
    result = runner.invoke(main, ["state", "reset", "--key", "kev_last_sync"])
    assert result.exit_code == 0
    assert deleted == ["kev_last_sync"]


def test_kev_sync_failure_uses_sync_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def _broken_sync(force: bool = False):
        _ = force
        raise RuntimeError("feed down")

    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "sync_kev", _broken_sync)
    runner = CliRunner()
    result = runner.invoke(main, ["kev-sync"])
    assert result.exit_code == cli.EXIT_SYNC_FAILED
    assert "KEV sync failed: feed down" in result.output


def test_nvd_sync_shows_zero_result_recovery_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _broken_sync(*_args, **_kwargs):
        raise RuntimeError("NVD sync returned zero CVEs over a long time window.")

    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "sync_nvd_delta", _broken_sync)
    runner = CliRunner()
    result = runner.invoke(main, ["nvd-sync", "--since", "90d"])
    assert result.exit_code == cli.EXIT_SYNC_FAILED
    assert "NVD returned 0 CVEs for a long sync window" in result.output
    assert "vulnscanner nvd-sync --since 90d" in result.output
    assert "vulnscanner kev-sync --force" in result.output
    assert "vulnscanner epss-sync --force" in result.output
    assert "Sync failed: NVD sync returned zero CVEs over a long time window." in result.output


def test_cache_stats_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    counts = {
        "cves": 10,
        "osv_cache": 3,
        "osv_vuln_cache": 4,
        "kev": 5,
        "epss": 6,
    }

    class _Cursor:
        def __init__(self, value: int) -> None:
            self._value = value

        def fetchone(self) -> tuple[int]:
            return (self._value,)

    class _Conn:
        def execute(self, query: str):
            table = query.split("FROM", 1)[1].strip()
            return _Cursor(counts[table])

    @contextmanager
    def _fake_db():
        yield _Conn()

    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "db", _fake_db)
    runner = CliRunner()
    result = runner.invoke(main, ["cache", "stats", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload == counts


def test_cache_clear_defaults_to_osv_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []
    deleted_meta: list[str] = []

    class _Conn:
        def execute(self, query: str):
            executed.append(query)
            return None

    @contextmanager
    def _fake_db():
        yield _Conn()

    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "db", _fake_db)
    monkeypatch.setattr(cli, "delete_meta", lambda key: deleted_meta.append(key))
    runner = CliRunner()
    result = runner.invoke(main, ["cache", "clear"])
    assert result.exit_code == 0
    assert executed == ["DELETE FROM osv_cache", "DELETE FROM osv_vuln_cache"]
    assert deleted_meta == []


def test_cache_clear_all_resets_enrichment_and_meta(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []
    deleted_meta: list[str] = []

    class _Conn:
        def execute(self, query: str):
            executed.append(query)
            return None

    @contextmanager
    def _fake_db():
        yield _Conn()

    monkeypatch.setattr(cli, "ensure_database", lambda: None)
    monkeypatch.setattr(cli, "db", _fake_db)
    monkeypatch.setattr(cli, "delete_meta", lambda key: deleted_meta.append(key))
    runner = CliRunner()
    result = runner.invoke(main, ["cache", "clear", "--all"])
    assert result.exit_code == 0
    assert "DELETE FROM osv_cache" in executed
    assert "DELETE FROM osv_vuln_cache" in executed
    assert "DELETE FROM kev" in executed
    assert "DELETE FROM epss" in executed
    assert "UPDATE cves SET is_known_exploited=0" in executed
    assert "UPDATE cves SET epss_score=NULL, epss_percentile=NULL" in executed
    assert deleted_meta == ["kev_last_sync", "epss_last_sync"]
