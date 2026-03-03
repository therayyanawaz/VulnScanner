from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .caching import cache_osv_result, cache_osv_vuln, get_cached_osv, get_cached_osv_vuln
from .config import settings
from .db import db

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found]

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_RETRY_BACKOFF_SECONDS = 0.5
MAX_RETRY_BACKOFF_SECONDS = 8.0
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str

    @property
    def cache_key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class ScanFinding:
    vuln_id: str
    package: str
    ecosystem: str
    version: str
    severity: str
    aliases: tuple[str, ...]
    summary: str
    cve_id: str | None = None
    is_known_exploited: bool | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "severity": self.severity,
            "aliases": list(self.aliases),
            "summary": self.summary,
            "cve_id": self.cve_id,
            "is_known_exploited": self.is_known_exploited,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
        }


@dataclass(frozen=True)
class ScanResult:
    dependencies_total: int
    cache_hits: int
    cache_misses: int
    findings: tuple[ScanFinding, ...]

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for finding in self.findings:
            sev = finding.severity if finding.severity in counts else "unknown"
            counts[sev] += 1
        return counts

    @property
    def known_exploited_findings(self) -> int:
        return sum(1 for finding in self.findings if finding.is_known_exploited is True)

    @property
    def epss_enriched_findings(self) -> int:
        return sum(1 for finding in self.findings if finding.epss_score is not None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dependencies_total": self.dependencies_total,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "findings_total": len(self.findings),
            "severity_counts": self.severity_counts,
            "known_exploited_findings": self.known_exploited_findings,
            "epss_enriched_findings": self.epss_enriched_findings,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def parse_dependency_manifest(path: str | Path) -> list[Dependency]:
    manifest = Path(path)
    if not manifest.exists() or not manifest.is_file():
        raise FileNotFoundError(str(manifest))
    lower_name = manifest.name.lower()
    if lower_name.endswith("package-lock.json"):
        return _parse_package_lock(manifest)
    if lower_name == "yarn.lock":
        return _parse_yarn_lock(manifest)
    if lower_name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(manifest)
    if lower_name == "poetry.lock":
        return _parse_poetry_lock(manifest)
    if lower_name == "uv.lock":
        return _parse_uv_lock(manifest)
    if lower_name == "pipfile.lock":
        return _parse_pipfile_lock(manifest)
    if lower_name.endswith(".txt"):
        return _parse_requirements(manifest)
    raise ValueError(
        "Unsupported manifest: "
        f"{manifest.name}. Supported: package-lock.json, yarn.lock, pnpm-lock.yaml, "
        "poetry.lock, uv.lock, Pipfile.lock, *.txt"
    )


async def scan_dependency_manifest(path: str | Path, allow_network: bool = True) -> ScanResult:
    dependencies = parse_dependency_manifest(path)
    if not dependencies:
        return ScanResult(dependencies_total=0, cache_hits=0, cache_misses=0, findings=tuple())

    cached_payloads: dict[tuple[str, str, str], dict[str, Any]] = {}
    uncached: list[Dependency] = []
    cache_hits = 0
    for dep in dependencies:
        cached = get_cached_osv(dep.ecosystem, dep.name, dep.version)
        if cached is None:
            uncached.append(dep)
            continue
        cache_hits += 1
        cached_payloads[dep.cache_key] = cached

    if uncached and allow_network:
        async with httpx.AsyncClient(
            timeout=settings.osv_http_timeout_seconds,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            for chunk in _chunked(uncached, size=200):
                results = await _query_osv_batch(client, chunk)
                for dep, result in zip(chunk, results):
                    normalized = _normalize_query_result(result)
                    cache_osv_result(dep.ecosystem, dep.name, dep.version, normalized)
                    cached_payloads[dep.cache_key] = normalized

    vuln_details = await _load_vulnerability_details(cached_payloads, allow_network=allow_network)

    raw_entries: list[tuple[Dependency, str, dict[str, Any], list[str]]] = []
    all_cve_ids: set[str] = set()
    for dep in dependencies:
        result = cached_payloads.get(dep.cache_key, {"vulns": []})
        for vuln in result.get("vulns", []):
            vuln_id = str(vuln.get("id", "unknown"))
            detailed = vuln_details.get(vuln_id) or vuln
            cve_ids = _extract_cve_ids(vuln_id, detailed.get("aliases"))
            all_cve_ids.update(cve_ids)
            raw_entries.append((dep, vuln_id, detailed, cve_ids))

    cve_enrichment = _load_cve_enrichment(all_cve_ids)
    findings: list[ScanFinding] = []
    for dep, vuln_id, detailed, cve_ids in raw_entries:
        enrichment = next((cve_enrichment[cve] for cve in cve_ids if cve in cve_enrichment), None)
        primary_cve = cve_ids[0] if cve_ids else None
        is_known_exploited: bool | None = None
        epss_score: float | None = None
        epss_percentile: float | None = None
        if enrichment is not None:
            is_known_exploited, epss_score, epss_percentile = enrichment
        findings.append(
            ScanFinding(
                vuln_id=vuln_id,
                package=dep.name,
                ecosystem=dep.ecosystem,
                version=dep.version,
                severity=_extract_severity(detailed),
                aliases=tuple(str(a) for a in detailed.get("aliases", []) if isinstance(a, str)),
                summary=str(detailed.get("summary", "") or ""),
                cve_id=primary_cve,
                is_known_exploited=is_known_exploited,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
            )
        )

    findings.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 0), reverse=True)
    return ScanResult(
        dependencies_total=len(dependencies),
        cache_hits=cache_hits,
        cache_misses=len(uncached),
        findings=tuple(findings),
    )


def should_fail(result: ScanResult, threshold: str | None) -> bool:
    if threshold is None:
        return False
    normalized = threshold.lower()
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Unsupported threshold: {threshold}")
    min_level = SEVERITY_ORDER[normalized]
    return any(SEVERITY_ORDER.get(item.severity, 0) >= min_level for item in result.findings)


def filter_findings(
    result: ScanResult,
    min_severity: str | None = None,
    kev_only: bool = False,
    epss_min: float | None = None,
) -> ScanResult:
    if min_severity is not None:
        normalized = min_severity.lower()
        if normalized not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported min_severity: {min_severity}")
        min_level = SEVERITY_ORDER[normalized]
    else:
        min_level = None

    findings = list(result.findings)
    if min_level is not None:
        findings = [item for item in findings if SEVERITY_ORDER.get(item.severity, 0) >= min_level]
    if kev_only:
        findings = [item for item in findings if item.is_known_exploited is True]
    if epss_min is not None:
        findings = [
            item for item in findings if item.epss_score is not None and item.epss_score >= epss_min
        ]

    return ScanResult(
        dependencies_total=result.dependencies_total,
        cache_hits=result.cache_hits,
        cache_misses=result.cache_misses,
        findings=tuple(findings),
    )


def policy_failures(
    result: ScanResult,
    severity_threshold: str | None = None,
    fail_on_kev: bool = False,
    fail_on_epss: float | None = None,
) -> list[str]:
    failures: list[str] = []
    if should_fail(result, severity_threshold):
        assert severity_threshold is not None
        failures.append(f"severity>={severity_threshold.lower()}")
    if fail_on_kev and any(item.is_known_exploited is True for item in result.findings):
        failures.append("known_exploited")
    if fail_on_epss is not None:
        if any(
            item.epss_score is not None and item.epss_score >= fail_on_epss
            for item in result.findings
        ):
            failures.append(f"epss>={fail_on_epss}")
    return failures


async def _query_osv_batch(
    client: httpx.AsyncClient, deps: list[Dependency]
) -> list[dict[str, Any]]:
    payload = {
        "queries": [
            {
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": dep.version,
            }
            for dep in deps
        ]
    }
    attempts = max(settings.osv_http_retries, 1)
    backoff_seconds = DEFAULT_RETRY_BACKOFF_SECONDS
    for attempt in range(1, attempts + 1):
        try:
            response = await client.post(OSV_BATCH_URL, json=payload)
        except httpx.HTTPError:
            if attempt == attempts:
                raise
            await asyncio.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2, MAX_RETRY_BACKOFF_SECONDS)
            continue

        if response.status_code in RETRYABLE_STATUS_CODES and attempt < attempts:
            retry_after = _retry_delay_seconds(response.headers.get("Retry-After"), backoff_seconds)
            await asyncio.sleep(retry_after)
            backoff_seconds = min(backoff_seconds * 2, MAX_RETRY_BACKOFF_SECONDS)
            continue

        response.raise_for_status()
        data = response.json()
        raw_results = data.get("results", []) if isinstance(data, dict) else []
        results = list(raw_results) if isinstance(raw_results, list) else []
        if len(results) < len(deps):
            results.extend({} for _ in range(len(deps) - len(results)))
        return results

    raise RuntimeError("OSV batch query failed after retries")


def _normalize_query_result(result: dict[str, Any] | Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"vulns": []}
    vulns = result.get("vulns")
    if not isinstance(vulns, list):
        return {"vulns": []}
    return {"vulns": vulns}


def _extract_cve_ids(vuln_id: str, aliases: Any) -> list[str]:
    raw_values: list[Any] = [vuln_id]
    if isinstance(aliases, list):
        raw_values.extend(aliases)
    cves: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        if not isinstance(value, str):
            continue
        candidate = value.strip().upper()
        if not candidate.startswith("CVE-"):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        cves.append(candidate)
    return cves


def _load_cve_enrichment(cve_ids: set[str]) -> dict[str, tuple[bool, float | None, float | None]]:
    if not cve_ids:
        return {}
    ordered = sorted(cve_ids)
    placeholders = ",".join("?" for _ in ordered)
    query = f"""
        SELECT cve_id, is_known_exploited, epss_score, epss_percentile
        FROM cves
        WHERE cve_id IN ({placeholders})
    """
    with db() as conn:
        rows = conn.execute(query, ordered).fetchall()
    return {
        str(cve_id): (bool(is_known_exploited), epss_score, epss_percentile)
        for cve_id, is_known_exploited, epss_score, epss_percentile in rows
    }


async def _load_vulnerability_details(
    query_payloads: dict[tuple[str, str, str], dict[str, Any]],
    allow_network: bool = True,
) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    vuln_ids: set[str] = set()
    for payload in query_payloads.values():
        for vuln in payload.get("vulns", []):
            vuln_id = vuln.get("id")
            if isinstance(vuln_id, str) and vuln_id:
                vuln_ids.add(vuln_id)

    pending: list[str] = []
    for vuln_id in vuln_ids:
        cached = get_cached_osv_vuln(vuln_id)
        if cached is not None:
            details[vuln_id] = cached
            continue
        pending.append(vuln_id)

    if not pending or not allow_network:
        return details

    async with httpx.AsyncClient(
        timeout=settings.osv_http_timeout_seconds,
        headers={"User-Agent": settings.user_agent},
    ) as client:
        for chunk in _chunked_strings(pending, size=100):
            responses = await _fetch_vuln_detail_chunk(client, chunk)
            for vuln_id, payload in responses.items():
                details[vuln_id] = payload
                cache_osv_vuln(vuln_id, payload)
    return details


async def _fetch_vuln_detail_chunk(
    client: httpx.AsyncClient, vuln_ids: list[str]
) -> dict[str, dict[str, Any]]:
    concurrency = max(settings.osv_vuln_detail_concurrency, 1)
    semaphore = asyncio.Semaphore(concurrency)
    payloads: dict[str, dict[str, Any]] = {}

    async def fetch_one(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
        async with semaphore:
            payload = await _fetch_vuln_detail_with_retry(client, vuln_id)
            return vuln_id, payload

    results = await asyncio.gather(*(fetch_one(vuln_id) for vuln_id in vuln_ids))
    for vuln_id, payload in results:
        if payload is not None:
            payloads[vuln_id] = payload
    return payloads


async def _fetch_vuln_detail_with_retry(
    client: httpx.AsyncClient, vuln_id: str
) -> dict[str, Any] | None:
    attempts = max(settings.osv_http_retries, 1)
    backoff_seconds = DEFAULT_RETRY_BACKOFF_SECONDS
    url = OSV_VULN_URL.format(vuln_id=vuln_id)

    for attempt in range(1, attempts + 1):
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            if attempt == attempts:
                LOGGER.warning("OSV detail lookup failed for %s: %s", vuln_id, exc)
                return None
            await asyncio.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2, MAX_RETRY_BACKOFF_SECONDS)
            continue

        status = response.status_code
        if status == 404:
            return None
        if status in RETRYABLE_STATUS_CODES:
            if attempt == attempts:
                LOGGER.warning("OSV detail lookup failed for %s with status %s", vuln_id, status)
                return None
            retry_after = _retry_delay_seconds(response.headers.get("Retry-After"), backoff_seconds)
            await asyncio.sleep(retry_after)
            backoff_seconds = min(backoff_seconds * 2, MAX_RETRY_BACKOFF_SECONDS)
            continue
        if status >= 400:
            LOGGER.warning("OSV detail lookup failed for %s with status %s", vuln_id, status)
            return None

        data = response.json()
        if isinstance(data, dict):
            return data
        LOGGER.warning("OSV detail lookup returned non-object payload for %s", vuln_id)
        return None

    return None


def _retry_delay_seconds(retry_after_value: str | None, default_seconds: float) -> float:
    if retry_after_value is None:
        return default_seconds
    try:
        parsed = float(retry_after_value)
    except ValueError:
        return default_seconds
    return parsed if parsed > 0 else default_seconds


def _extract_severity(vuln: dict[str, Any]) -> str:
    candidates: list[str] = []
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        candidates.extend(_severity_from_value(db_specific.get("severity")))
    ecosystem_specific = vuln.get("ecosystem_specific")
    if isinstance(ecosystem_specific, dict):
        candidates.extend(_severity_from_value(ecosystem_specific.get("severity")))
    for score_entry in vuln.get("severity", []):
        if isinstance(score_entry, dict):
            candidates.extend(_severity_from_value(score_entry.get("score")))
            candidates.extend(_severity_from_value(score_entry.get("type")))
    if not candidates:
        return "unknown"
    best = "unknown"
    for item in candidates:
        if SEVERITY_ORDER[item] > SEVERITY_ORDER[best]:
            best = item
    return best


def _severity_from_value(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    lowered = value.strip().lower()
    matches: list[str] = []
    for name in ("critical", "high", "medium", "low"):
        if name in lowered:
            matches.append(name)
    return matches


def _parse_package_lock(path: Path) -> list[Dependency]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return []
    data = loaded
    dependencies: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, metadata in packages.items():
            if not pkg_path or not isinstance(metadata, dict):
                continue
            version = metadata.get("version")
            if not isinstance(version, str):
                continue
            name = metadata.get("name")
            if not isinstance(name, str):
                name = _derive_npm_name_from_path(str(pkg_path))
            if not name:
                continue
            dependencies.append(Dependency(ecosystem="npm", name=name, version=version))
        return _dedupe_dependencies(dependencies)

    root_dependencies = data.get("dependencies")
    if isinstance(root_dependencies, dict):
        _walk_npm_tree(root_dependencies, dependencies)
        return _dedupe_dependencies(dependencies)

    return []


def _parse_yarn_lock(path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    selectors: list[str] = []
    version: str | None = None
    key_line = re.compile(r"^([^\s].*):\s*$")
    version_line = re.compile(r'^\s{2}version(?:\s+|:\s*)"?([^"\s]+)"?\s*$')

    def flush() -> None:
        nonlocal selectors, version
        if version is None:
            selectors = []
            return
        if not _is_scanable_version(version):
            selectors = []
            version = None
            return
        for selector in selectors:
            name = _parse_yarn_selector_name(selector)
            if name:
                dependencies.append(Dependency(ecosystem="npm", name=name, version=version))
        selectors = []
        version = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        matched_key = key_line.match(line)
        if matched_key:
            flush()
            raw_key = matched_key.group(1).strip().strip('"').strip("'")
            if raw_key == "__metadata":
                selectors = []
                continue
            selectors = [part.strip().strip('"').strip("'") for part in raw_key.split(",")]
            continue
        matched_version = version_line.match(line)
        if matched_version:
            version = matched_version.group(1).strip()
    flush()
    return _dedupe_dependencies(dependencies)


def _parse_yarn_selector_name(selector: str) -> str | None:
    value = selector.strip()
    match = re.match(r"^(@[^/]+/[^@]+|[^@]+)@", value)
    if not match:
        return None
    return match.group(1)


def _parse_pnpm_lock(path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    in_packages = False
    top_level_line = re.compile(r"^[A-Za-z0-9_-]+:\s*$")
    package_key_line = re.compile(r"^\s{2}([^:][^#]*):\s*$")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            if top_level_line.match(line):
                in_packages = line.strip() == "packages:"
            else:
                in_packages = False
            continue
        if not in_packages:
            continue
        key_match = package_key_line.match(line)
        if not key_match:
            continue
        key = key_match.group(1).strip().strip('"').strip("'")
        parsed = _parse_pnpm_package_key(key)
        if parsed is None:
            continue
        dependencies.append(Dependency(ecosystem="npm", name=parsed[0], version=parsed[1]))
    return _dedupe_dependencies(dependencies)


def _parse_pnpm_package_key(key: str) -> tuple[str, str] | None:
    value = key.lstrip("/")
    scoped = re.match(r"^(@[^/]+/[^@]+)@([^(/]+)", value)
    if scoped is not None:
        name, version = scoped.group(1), scoped.group(2)
    else:
        normal = re.match(r"^([^@/][^@]*)@([^(/]+)", value)
        if normal is None:
            return None
        name, version = normal.group(1), normal.group(2)
    if not _is_scanable_version(version):
        return None
    return name, version


def _is_scanable_version(version: str) -> bool:
    lowered = version.strip().lower()
    if not lowered:
        return False
    disallowed_prefixes = ("workspace:", "file:", "link:", "portal:", "patch:")
    if lowered.startswith(disallowed_prefixes):
        return False
    return True


def _walk_npm_tree(tree: dict[str, Any], sink: list[Dependency]) -> None:
    for package_name, metadata in tree.items():
        if not isinstance(metadata, dict):
            continue
        version = metadata.get("version")
        if isinstance(package_name, str) and isinstance(version, str):
            sink.append(Dependency(ecosystem="npm", name=package_name, version=version))
        children = metadata.get("dependencies")
        if isinstance(children, dict):
            _walk_npm_tree(children, sink)


def _derive_npm_name_from_path(package_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    tail = package_path.rsplit(marker, 1)[-1]
    parts = [part for part in tail.split("/") if part]
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _parse_requirements(path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        candidate = line.split(maxsplit=1)[0].strip()
        if not candidate:
            continue
        match = re.match(
            r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.!+\-]+)$",
            candidate,
        )
        if not match:
            continue
        package, version = match.groups()
        dependencies.append(Dependency(ecosystem="PyPI", name=package.lower(), version=version))
    return _dedupe_dependencies(dependencies)


def _parse_poetry_lock(path: Path) -> list[Dependency]:
    data = _parse_toml_document(path)
    return _extract_pypi_toml_packages(data)


def _parse_uv_lock(path: Path) -> list[Dependency]:
    data = _parse_toml_document(path)
    return _extract_pypi_toml_packages(data)


def _extract_pypi_toml_packages(data: dict[str, Any]) -> list[Dependency]:
    dependencies: list[Dependency] = []
    packages = data.get("package")
    if not isinstance(packages, list):
        return dependencies
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        dependencies.append(Dependency(ecosystem="PyPI", name=name, version=version))
    return _dedupe_dependencies(dependencies)


def _parse_pipfile_lock(path: Path) -> list[Dependency]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return []
    data = loaded
    dependencies: list[Dependency] = []
    for section in ("default", "develop"):
        packages = data.get(section)
        if not isinstance(packages, dict):
            continue
        for package, metadata in packages.items():
            if not isinstance(package, str) or not isinstance(metadata, dict):
                continue
            raw_version = metadata.get("version")
            if not isinstance(raw_version, str):
                continue
            version = _parse_exact_locked_version(raw_version)
            if version is None:
                continue
            dependencies.append(Dependency(ecosystem="PyPI", name=package, version=version))
    return _dedupe_dependencies(dependencies)


def _parse_exact_locked_version(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    match = re.match(r"^={2,3}\s*([A-Za-z0-9_.!+\-]+)$", cleaned)
    if not match:
        return None
    return match.group(1)


def _parse_toml_document(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    try:
        data = tomllib.loads(raw)
    except Exception as exc:
        raise ValueError(f"Invalid TOML manifest: {path.name}") from exc
    if not isinstance(data, dict):
        return {}
    return data


def _dedupe_dependencies(items: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Dependency] = []
    for item in items:
        key = item.cache_key
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _chunked(items: list[Dependency], size: int) -> list[list[Dependency]]:
    if size <= 0:
        raise ValueError("size must be > 0")
    return [items[i : i + size] for i in range(0, len(items), size)]


def _chunked_strings(items: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        raise ValueError("size must be > 0")
    return [items[i : i + size] for i in range(0, len(items), size)]
