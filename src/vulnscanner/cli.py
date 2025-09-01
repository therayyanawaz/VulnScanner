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
    ensure_database()
    since = _parse_dt(since_str) if since_str else None
    until = _parse_dt(until_str) if until_str else None
    click.echo(f"Syncing from {since} to {until}")
    stats = asyncio.run(sync_nvd_delta(since, until))
    click.echo(f"Synced: {stats}")


def _parse_dt(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


if __name__ == "__main__":
    main()


