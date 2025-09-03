from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

import click

from .db import ensure_database
from .nvd import sync_nvd_delta


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
    since = _parse_dt(since_str) if since_str else None
    until = _parse_dt(until_str) if until_str else None
    click.echo(f"🚀 Syncing from {since} to {until}")
    try:
        stats = asyncio.run(sync_nvd_delta(since, until))
        click.echo(f"✅ Sync complete: {stats['cves']} CVEs, {stats['pages']} pages")
    except Exception as e:
        click.echo(f"❌ Sync failed: {e}")
        if "429" in str(e):
            click.echo("💡 You're being rate limited. Try:")
            click.echo("   1. Get a free NVD API key (see link above)")
            click.echo("   2. Set it: export NVD_API_KEY=your_key_here")
            click.echo("   3. Or wait a few minutes and try again")
        raise


def _parse_dt(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


if __name__ == "__main__":
    main()
