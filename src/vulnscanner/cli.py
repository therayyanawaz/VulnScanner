from __future__ import annotations

import asyncio
import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import click

from .db import delete_meta, ensure_database, get_meta
from .epss import sync_epss
from .kev import sync_kev
from .nvd import sync_nvd_delta
from .osv import ScanFinding, ScanResult, filter_findings, policy_failures, scan_dependency_manifest


@click.group()
def main() -> None:
    """VulnScanner CLI"""


STATE_META_KEYS = ("nvd_last_mod", "kev_last_sync", "epss_last_sync")

EXIT_POLICY_FAILED = 10
EXIT_STRICT_CACHE_MISS = 11
EXIT_SYNC_FAILED = 12
EXIT_SCAN_FAILED = 13


class ExitCodedClickException(click.ClickException):
    exit_code = 1


class PolicyFailedError(ExitCodedClickException):
    exit_code = EXIT_POLICY_FAILED


class StrictCacheMissError(ExitCodedClickException):
    exit_code = EXIT_STRICT_CACHE_MISS


class SyncFailedError(ExitCodedClickException):
    exit_code = EXIT_SYNC_FAILED


class ScanFailedError(ExitCodedClickException):
    exit_code = EXIT_SCAN_FAILED


@main.command("nvd-sync")
@click.option("--since", "since_str", type=str, default=None, help="ISO8601 start time")
@click.option("--until", "until_str", type=str, default=None, help="ISO8601 end time (default now)")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def nvd_sync(since_str: Optional[str], until_str: Optional[str], debug: bool) -> None:
    if debug:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    # Show rate limiting info
    from .config import settings
    if settings.nvd_api_key:
        click.echo(f"🔑 Using API key, rate limit: {settings.nvd_max_per_30s}/30s")
    else:
        click.echo(f"⚠️ No API key - rate limit: {settings.nvd_max_per_30s}/30s")
        click.echo("💡 Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
    ensure_database()
    since = _parse_datetime_option(since_str, "--since")
    until = _parse_datetime_option(until_str, "--until")
    if since and until and since >= until:
        raise click.BadParameter("--since must be earlier than --until")
    click.echo(f"🚀 Syncing from {since} to {until}")
    try:
        stats = asyncio.run(sync_nvd_delta(since, until))
        click.echo(f"✅ Sync complete: {stats['cves']} CVEs, {stats['pages']} pages")
    except Exception as e:
        if "429" in str(e):
            click.echo("💡 You're being rate limited. Try:")
            click.echo("   1. Get a free NVD API key (see link above)")
            click.echo("   2. Set it: export NVD_API_KEY=your_key_here")
            click.echo("   3. Or wait a few minutes and try again")
        if debug:
            raise
        raise SyncFailedError(f"Sync failed: {e}") from e


@main.command("scan-deps")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "markdown", "sarif"]),
    default="table",
)
@click.option("--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option(
    "--top",
    type=click.IntRange(min=0),
    default=20,
    show_default=True,
    help="Max findings shown in table/markdown detail sections (0 hides detail rows)",
)
@click.option(
    "--summary-only",
    is_flag=True,
    help="Show only summary metrics in table/markdown outputs",
)
@click.option(
    "--sort-by",
    type=click.Choice(["severity", "epss", "package", "id"], case_sensitive=False),
    default="severity",
    show_default=True,
    help="Sort field for table/markdown finding rows",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to previous JSON scan report for finding-diff comparisons",
)
@click.option(
    "--new-only",
    is_flag=True,
    help="With --baseline, include only findings not present in the baseline report",
)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if a finding is at or above this severity",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Only include findings at or above this severity in output and policy checks",
)
@click.option("--kev-only", is_flag=True, help="Only include findings that are marked as known exploited")
@click.option(
    "--epss-min",
    type=click.FloatRange(min=0.0, max=1.0),
    default=None,
    help="Only include findings with EPSS score at or above this value",
)
@click.option("--fail-on-kev", is_flag=True, help="Exit with code 1 if any displayed finding is known exploited")
@click.option(
    "--fail-on-epss",
    type=click.FloatRange(min=0.0, max=1.0),
    default=None,
    help="Exit with code 1 if any displayed finding has EPSS score at or above this value",
)
@click.option(
    "--policy",
    type=click.Choice(["none", "balanced", "strict"], case_sensitive=False),
    default="none",
    help="Apply preset policy defaults (can be overridden by explicit fail options)",
)
@click.option(
    "--no-network",
    is_flag=True,
    help="Cache-only mode: do not query live OSV APIs for missing cache entries",
)
@click.option(
    "--strict-cache",
    is_flag=True,
    help="Fail when cache misses are detected (requires --no-network)",
)
@click.option("--debug", is_flag=True, help="Enable debug logging")
def scan_deps(
    manifest_path: Path,
    output_format: str,
    output_path: Path | None,
    top: int,
    summary_only: bool,
    sort_by: str,
    baseline_path: Path | None,
    new_only: bool,
    fail_on: str | None,
    min_severity: str | None,
    kev_only: bool,
    epss_min: float | None,
    fail_on_kev: bool,
    fail_on_epss: float | None,
    policy: str,
    no_network: bool,
    strict_cache: bool,
    debug: bool,
) -> None:
    if debug:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    if strict_cache and not no_network:
        raise click.BadParameter("--strict-cache requires --no-network", param_hint="--strict-cache")
    if new_only and baseline_path is None:
        raise click.BadParameter("--new-only requires --baseline", param_hint="--new-only")

    try:
        result = asyncio.run(scan_dependency_manifest(manifest_path, allow_network=not no_network))
        result = filter_findings(
            result,
            min_severity=min_severity.lower() if min_severity else None,
            kev_only=kev_only,
            epss_min=epss_min,
        )
    except Exception as exc:
        if debug:
            raise
        raise ScanFailedError(f"Dependency scan failed: {exc}") from exc

    baseline_new_count: int | None = None
    baseline_total_count: int | None = None
    rendered_result = result
    policy_result = result
    if baseline_path is not None:
        try:
            baseline_keys = _load_baseline_finding_keys(baseline_path)
        except ValueError as exc:
            raise ScanFailedError(f"Invalid baseline file: {exc}") from exc
        diffed = _filter_new_findings(result, baseline_keys)
        baseline_new_count = len(diffed.findings)
        baseline_total_count = len(result.findings)
        if new_only:
            rendered_result = diffed
            policy_result = diffed

    rendered = _render_scan_result(
        rendered_result,
        output_format,
        top=top,
        summary_only=summary_only,
        sort_by=sort_by.lower(),
    )
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"📝 Report written to {output_path}")
    else:
        click.echo(rendered)

    if baseline_new_count is not None and baseline_total_count is not None:
        click.echo(f"Baseline comparison: {baseline_new_count} new / {baseline_total_count} current findings")

    if no_network and result.cache_misses > 0:
        click.echo(
            "⚠️ Cache-only mode skipped live OSV lookups for "
            f"{result.cache_misses} dependencies"
        )

    fail_on, fail_on_kev, fail_on_epss = _resolve_scan_policy(
        policy=policy.lower(),
        fail_on=fail_on.lower() if fail_on else None,
        fail_on_kev=fail_on_kev,
        fail_on_epss=fail_on_epss,
    )
    failures = policy_failures(
        policy_result,
        severity_threshold=fail_on,
        fail_on_kev=fail_on_kev,
        fail_on_epss=fail_on_epss,
    )
    strict_cache_failure = strict_cache and result.cache_misses > 0
    if strict_cache_failure:
        failures.append(f"cache_miss={result.cache_misses}")
    if failures:
        message = f"Policy failed: {', '.join(failures)}"
        if strict_cache_failure and len(failures) == 1:
            raise StrictCacheMissError(message)
        raise PolicyFailedError(message)


@main.command("kev-sync")
@click.option("--force", is_flag=True, help="Bypass TTL and refresh KEV feed now")
def kev_sync(force: bool) -> None:
    ensure_database()
    try:
        stats = sync_kev(force=force)
    except Exception as exc:
        raise SyncFailedError(f"KEV sync failed: {exc}") from exc

    if bool(stats["skipped"]):
        click.echo("✅ KEV sync skipped: cache is still fresh")
        return
    click.echo(
        "✅ KEV sync complete: "
        f"{stats['kev_records']} KEV records, {stats['matched_cves']} CVEs marked exploited"
    )


@main.command("epss-sync")
@click.option("--force", is_flag=True, help="Bypass TTL and refresh EPSS feed now")
def epss_sync(force: bool) -> None:
    ensure_database()
    try:
        stats = sync_epss(force=force)
    except Exception as exc:
        raise SyncFailedError(f"EPSS sync failed: {exc}") from exc

    if bool(stats["skipped"]):
        click.echo("✅ EPSS sync skipped: cache is still fresh")
        return
    click.echo(
        "✅ EPSS sync complete: "
        f"{stats['epss_records']} EPSS records, {stats['matched_cves']} CVEs enriched"
    )


@main.group("state")
def state() -> None:
    """Inspect or reset sync checkpoint state."""


@state.command("show")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
)
def state_show(output_format: str) -> None:
    ensure_database()
    values = {key: get_meta(key) for key in STATE_META_KEYS}
    if output_format.lower() == "json":
        click.echo(json.dumps(values, indent=2))
        return
    lines = ["Sync state:"]
    for key in STATE_META_KEYS:
        lines.append(f"- {key}: {values.get(key) or '<unset>'}")
    click.echo("\n".join(lines))


@state.command("reset")
@click.option(
    "--key",
    "keys",
    multiple=True,
    type=click.Choice(list(STATE_META_KEYS), case_sensitive=False),
    help="State key(s) to reset. Omit to reset all state keys.",
)
def state_reset(keys: tuple[str, ...]) -> None:
    ensure_database()
    targets = [item.lower() for item in keys] if keys else list(STATE_META_KEYS)
    for key in targets:
        delete_meta(key)
    click.echo(f"✅ Reset state keys: {', '.join(targets)}")


def _render_scan_result(
    result: ScanResult,
    output_format: str,
    *,
    top: int = 20,
    summary_only: bool = False,
    sort_by: str = "severity",
) -> str:
    if output_format == "json":
        return json.dumps(result.as_dict(), indent=2)
    if output_format == "csv":
        return _render_csv(result)
    if output_format == "markdown":
        return _render_markdown(result, top=top, summary_only=summary_only, sort_by=sort_by)
    if output_format == "sarif":
        return _render_sarif(result)
    display_findings = _select_output_findings(
        result,
        top=top,
        summary_only=summary_only,
        sort_by=sort_by,
    )
    lines = [
        f"Dependencies scanned: {result.dependencies_total}",
        f"Cache hits: {result.cache_hits}",
        f"Cache misses: {result.cache_misses}",
        f"Findings: {len(result.findings)}",
        f"Known exploited findings: {result.known_exploited_findings}",
        f"EPSS-enriched findings: {result.epss_enriched_findings}",
    ]
    counts = result.severity_counts
    lines.append(
        "Severity counts: "
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} unknown={counts['unknown']}"
    )
    if summary_only:
        return "\n".join(lines)
    if display_findings:
        lines.append("")
        lines.append("Top findings:")
        for finding in display_findings:
            extras: list[str] = []
            if finding.cve_id:
                extras.append(f"CVE={finding.cve_id}")
            if finding.is_known_exploited:
                extras.append("KEV=yes")
            if finding.epss_score is not None:
                extras.append(f"EPSS={finding.epss_score:.5f}")
            suffix = f" [{', '.join(extras)}]" if extras else ""
            lines.append(
                f"- [{finding.severity}] {finding.vuln_id} "
                f"{finding.package}@{finding.version} ({finding.ecosystem}){suffix}"
            )
    if len(display_findings) < len(result.findings):
        lines.append("")
        lines.append(
            f"Displayed findings: {len(display_findings)} of {len(result.findings)} "
            f"(sorted by {sort_by}, top={top})"
        )
    return "\n".join(lines)


def _render_csv(result: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "package",
            "ecosystem",
            "version",
            "severity",
            "cve_id",
            "is_known_exploited",
            "epss_score",
            "epss_percentile",
            "aliases",
            "summary",
        ]
    )
    for finding in result.findings:
        writer.writerow(
            [
                finding.vuln_id,
                finding.package,
                finding.ecosystem,
                finding.version,
                finding.severity,
                finding.cve_id or "",
                "true" if finding.is_known_exploited is True else "false",
                "" if finding.epss_score is None else f"{finding.epss_score:.6f}",
                "" if finding.epss_percentile is None else f"{finding.epss_percentile:.6f}",
                ";".join(finding.aliases),
                finding.summary,
            ]
        )
    return output.getvalue().rstrip("\n")


def _render_markdown(
    result: ScanResult,
    *,
    top: int = 20,
    summary_only: bool = False,
    sort_by: str = "severity",
) -> str:
    display_findings = _select_output_findings(
        result,
        top=top,
        summary_only=summary_only,
        sort_by=sort_by,
    )
    lines = [
        "# Dependency Scan Report",
        "",
        f"- Dependencies scanned: **{result.dependencies_total}**",
        f"- Findings: **{len(result.findings)}**",
        f"- Known exploited findings: **{result.known_exploited_findings}**",
        f"- EPSS-enriched findings: **{result.epss_enriched_findings}**",
        "",
    ]
    counts = result.severity_counts
    lines.append(
        "| Critical | High | Medium | Low | Unknown |\n"
        "| ---: | ---: | ---: | ---: | ---: |\n"
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['unknown']} |"
    )
    lines.append("")
    lines.append(f"- Findings displayed: **{len(display_findings)}** (sorted by `{sort_by}`, top `{top}`)")
    if summary_only:
        return "\n".join(lines)
    lines.append("")
    lines.append(
        "| Severity | ID | Package | CVE | KEV | EPSS | Summary |\n"
        "| --- | --- | --- | --- | --- | --- | --- |"
    )
    for finding in display_findings:
        summary = finding.summary.replace("\n", " ").strip()
        if len(summary) > 120:
            summary = summary[:117] + "..."
        lines.append(
            "| "
            f"{finding.severity} | "
            f"{finding.vuln_id} | "
            f"{finding.package}@{finding.version} | "
            f"{finding.cve_id or ''} | "
            f"{'yes' if finding.is_known_exploited else 'no'} | "
            f"{'' if finding.epss_score is None else f'{finding.epss_score:.5f}'} | "
            f"{summary} |"
        )
    return "\n".join(lines)


def _select_output_findings(
    result: ScanResult,
    *,
    top: int,
    summary_only: bool,
    sort_by: str,
) -> tuple[ScanFinding, ...]:
    if summary_only or top <= 0 or not result.findings:
        return tuple()
    sorted_findings = _sort_findings(result.findings, sort_by)
    return tuple(sorted_findings[:top])


def _sort_findings(findings: tuple[ScanFinding, ...], sort_by: str) -> list[ScanFinding]:
    severity_order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if sort_by == "severity":
        return sorted(
            findings,
            key=lambda item: (
                -severity_order.get(item.severity.lower(), 0),
                item.vuln_id.lower(),
                item.package.lower(),
                item.version.lower(),
            ),
        )
    if sort_by == "epss":
        return sorted(
            findings,
            key=lambda item: (
                item.epss_score is None,
                -(item.epss_score if item.epss_score is not None else 0.0),
                -severity_order.get(item.severity.lower(), 0),
                item.vuln_id.lower(),
            ),
        )
    if sort_by == "package":
        return sorted(
            findings,
            key=lambda item: (
                item.package.lower(),
                item.version.lower(),
                -severity_order.get(item.severity.lower(), 0),
                item.vuln_id.lower(),
            ),
        )
    if sort_by == "id":
        return sorted(
            findings,
            key=lambda item: (
                item.vuln_id.lower(),
                item.package.lower(),
                item.version.lower(),
            ),
        )
    raise ValueError(f"Unsupported sort field: {sort_by}")


def _load_baseline_finding_keys(path: Path) -> tuple[set[tuple[str, str, str, str]], set[tuple[str, str, str]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot parse JSON from {path}") from exc
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError("missing findings array")
    keyed_with_ecosystem: set[tuple[str, str, str, str]] = set()
    keyed_legacy: set[tuple[str, str, str]] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        vuln_id = item.get("id")
        package = item.get("package")
        version = item.get("version")
        ecosystem = item.get("ecosystem")
        if not isinstance(vuln_id, str) or not isinstance(package, str) or not isinstance(version, str):
            continue
        if isinstance(ecosystem, str):
            keyed_with_ecosystem.add((vuln_id, package, version, ecosystem))
        else:
            keyed_legacy.add((vuln_id, package, version))
    return keyed_with_ecosystem, keyed_legacy


def _filter_new_findings(
    result: ScanResult,
    baseline_keys: tuple[set[tuple[str, str, str, str]], set[tuple[str, str, str]]],
) -> ScanResult:
    baseline_with_ecosystem, baseline_legacy = baseline_keys

    def is_in_baseline(finding: ScanFinding) -> bool:
        ecosystem_key = (finding.vuln_id, finding.package, finding.version, finding.ecosystem)
        if ecosystem_key in baseline_with_ecosystem:
            return True
        legacy_key = (finding.vuln_id, finding.package, finding.version)
        return legacy_key in baseline_legacy

    filtered = tuple(
        finding
        for finding in result.findings
        if not is_in_baseline(finding)
    )
    return ScanResult(
        dependencies_total=result.dependencies_total,
        cache_hits=result.cache_hits,
        cache_misses=result.cache_misses,
        findings=filtered,
    )


def _render_sarif(result: ScanResult) -> str:
    rules_by_id: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []

    for finding in result.findings:
        level = _sarif_level(finding.severity)
        rule_id = finding.vuln_id
        if rule_id not in rules_by_id:
            description = finding.summary.strip() if finding.summary.strip() else finding.vuln_id
            properties: dict[str, object] = {
                "severity": finding.severity,
                "ecosystem": finding.ecosystem,
            }
            if finding.cve_id:
                properties["cve"] = finding.cve_id
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": level},
                "properties": properties,
            }

        detail_parts = [f"[{finding.severity}] {finding.package}@{finding.version} ({finding.ecosystem})"]
        if finding.cve_id:
            detail_parts.append(f"CVE={finding.cve_id}")
        if finding.is_known_exploited:
            detail_parts.append("KEV=yes")
        if finding.epss_score is not None:
            detail_parts.append(f"EPSS={finding.epss_score:.5f}")
        message = " ".join(detail_parts)
        if finding.summary.strip():
            message = f"{message} - {finding.summary.strip()}"

        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "kind": "package",
                                "name": f"{finding.package}@{finding.version}",
                                "fullyQualifiedName": f"{finding.ecosystem}/{finding.package}",
                            }
                        ]
                    }
                ],
                "partialFingerprints": {
                    "vulnscannerFindingId": (
                        f"{finding.ecosystem}:{finding.package}:{finding.version}:{finding.vuln_id}"
                    )
                },
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnScanner",
                        "informationUri": "https://github.com/therayyanawaz/VulnScanner",
                        "rules": sorted(rules_by_id.values(), key=lambda item: str(item["id"])),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def _sarif_level(severity: str) -> str:
    lowered = severity.lower()
    if lowered in {"critical", "high"}:
        return "error"
    if lowered == "medium":
        return "warning"
    return "note"


def _resolve_scan_policy(
    policy: str,
    fail_on: str | None,
    fail_on_kev: bool,
    fail_on_epss: float | None,
) -> tuple[str | None, bool, float | None]:
    if policy == "none":
        return fail_on, fail_on_kev, fail_on_epss
    if policy == "balanced":
        return fail_on or "critical", fail_on_kev, fail_on_epss if fail_on_epss is not None else 0.9
    if policy == "strict":
        return fail_on or "high", fail_on_kev, fail_on_epss if fail_on_epss is not None else 0.7
    raise ValueError(f"Unsupported policy: {policy}")


def _parse_datetime_option(value: str | None, option_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return _parse_dt(value)
    except ValueError as exc:
        raise click.BadParameter(
            "must be ISO8601 with timezone (e.g. 2024-08-01T00:00:00Z) or a relative value (e.g. 7d, 12h, today, yesterday, now)",
            param_hint=option_name,
        ) from exc


def _parse_dt(s: str, *, now: datetime | None = None) -> datetime:
    raw = s.strip()
    if not raw:
        raise ValueError("empty datetime")

    now_utc = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    relative = _parse_relative_datetime(raw, now_utc)
    if relative is not None:
        return relative

    iso_value = raw
    if iso_value.endswith("Z"):
        iso_value = iso_value[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso_value)
    if dt.tzinfo is None:
        raise ValueError("timezone offset required")
    return dt.astimezone(timezone.utc)


def _parse_relative_datetime(value: str, now_utc: datetime) -> datetime | None:
    lowered = value.strip().lower()
    if lowered == "now":
        return now_utc
    day_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    if lowered == "today":
        return day_start
    if lowered == "yesterday":
        return day_start - timedelta(days=1)

    match = re.match(r"^(?P<count>\d+)\s*(?P<unit>[a-zA-Z]+)$", lowered)
    if not match:
        return None

    count = int(match.group("count"))
    unit = match.group("unit")

    if unit in {"m", "min", "mins", "minute", "minutes"}:
        return now_utc - timedelta(minutes=count)
    if unit in {"h", "hr", "hrs", "hour", "hours"}:
        return now_utc - timedelta(hours=count)
    if unit in {"d", "day", "days"}:
        return now_utc - timedelta(days=count)
    if unit in {"w", "week", "weeks"}:
        return now_utc - timedelta(weeks=count)
    return None


if __name__ == "__main__":
    main()
