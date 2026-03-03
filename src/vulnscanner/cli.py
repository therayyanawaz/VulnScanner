from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from .db import ensure_database
from .epss import sync_epss
from .kev import sync_kev
from .nvd import sync_nvd_delta
from .osv import ScanResult, scan_dependency_manifest, should_fail


@click.group()
def main() -> None:
    """VulnScanner CLI"""


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
        raise click.ClickException(f"Sync failed: {e}") from e


@main.command("scan-deps")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if a finding is at or above this severity",
)
@click.option("--debug", is_flag=True, help="Enable debug logging")
def scan_deps(
    manifest_path: Path,
    output_format: str,
    output_path: Path | None,
    fail_on: str | None,
    debug: bool,
) -> None:
    if debug:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    try:
        result = asyncio.run(scan_dependency_manifest(manifest_path))
    except Exception as exc:
        if debug:
            raise
        raise click.ClickException(f"Dependency scan failed: {exc}") from exc

    rendered = _render_scan_result(result, output_format)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"📝 Report written to {output_path}")
    else:
        click.echo(rendered)

    if should_fail(result, fail_on):
        raise click.ClickException(f"Policy failed: found vulnerabilities at/above '{fail_on.lower()}'")


@main.command("kev-sync")
@click.option("--force", is_flag=True, help="Bypass TTL and refresh KEV feed now")
def kev_sync(force: bool) -> None:
    ensure_database()
    try:
        stats = sync_kev(force=force)
    except Exception as exc:
        raise click.ClickException(f"KEV sync failed: {exc}") from exc

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
        raise click.ClickException(f"EPSS sync failed: {exc}") from exc

    if bool(stats["skipped"]):
        click.echo("✅ EPSS sync skipped: cache is still fresh")
        return
    click.echo(
        "✅ EPSS sync complete: "
        f"{stats['epss_records']} EPSS records, {stats['matched_cves']} CVEs enriched"
    )


def _render_scan_result(result: ScanResult, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result.as_dict(), indent=2)
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
    if result.findings:
        lines.append("")
        lines.append("Top findings:")
        for finding in result.findings[:20]:
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
    return "\n".join(lines)


def _parse_datetime_option(value: str | None, option_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return _parse_dt(value)
    except ValueError as exc:
        raise click.BadParameter(
            "must be ISO8601 with timezone, e.g. 2024-08-01T00:00:00Z",
            param_hint=option_name,
        ) from exc


def _parse_dt(s: str) -> datetime:
    s = s.strip()
    if not s:
        raise ValueError("empty datetime")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError("timezone offset required")
    return dt.astimezone(timezone.utc)


if __name__ == "__main__":
    main()
