from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Callable

import pytest
from click.testing import CliRunner

import vulnscanner.cli as cli
from vulnscanner.cli import main
from vulnscanner.osv import Dependency, parse_dependency_manifest


def _rand_token(rng: random.Random, *, min_len: int = 1, max_len: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    size = rng.randint(min_len, max_len)
    return "".join(rng.choice(alphabet) for _ in range(size))


def _rand_package_name(rng: random.Random, *, scoped: bool = False) -> str:
    if scoped:
        return f"@{_rand_token(rng, min_len=3, max_len=8)}/{_rand_token(rng, min_len=3, max_len=8)}"
    return _rand_token(rng, min_len=3, max_len=12)


def _rand_version(rng: random.Random) -> str:
    return f"{rng.randint(0, 20)}.{rng.randint(0, 30)}.{rng.randint(0, 40)}"


def _assert_dependency_contract(deps: list[Dependency]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for dep in deps:
        assert isinstance(dep.ecosystem, str)
        assert dep.ecosystem in {"npm", "PyPI"}
        assert isinstance(dep.name, str) and dep.name.strip()
        assert isinstance(dep.version, str) and dep.version.strip()
        assert dep.cache_key not in seen
        seen.add(dep.cache_key)


CaseBuilder = Callable[[random.Random, int], tuple[str, type[BaseException] | None]]


def _build_requirements_case(
    rng: random.Random, _index: int
) -> tuple[str, type[BaseException] | None]:
    lines: list[str] = []
    for _ in range(rng.randint(3, 30)):
        package = _rand_package_name(rng)
        version = _rand_version(rng)
        mode = rng.randint(0, 9)
        if mode == 0:
            lines.append(f"{package}=={version}")
        elif mode == 1:
            lines.append(f"{package}[socks]=={version} ; python_version >= '3.10'")
        elif mode == 2:
            lines.append(
                f"{package.upper()}=={version} --hash=sha256:{_rand_token(rng, min_len=12, max_len=24)}"
            )
        elif mode == 3:
            lines.append(f"{package}>={version}")
        elif mode == 4:
            lines.append(f"# {package} comment")
        elif mode == 5:
            lines.append("-r extras.txt")
        elif mode == 6:
            lines.append("--index-url https://example.org/simple")
        elif mode == 7:
            lines.append(f"{package}=== {version}")
        elif mode == 8:
            lines.append("   ")
        else:
            lines.append(f"{_rand_token(rng)}==")
    return "\n".join(lines) + "\n", None


def _build_yarn_case(rng: random.Random, _index: int) -> tuple[str, type[BaseException] | None]:
    lines: list[str] = []
    if rng.random() < 0.2:
        lines.extend(["__metadata:", "  version: 8", ""])

    disallowed_versions = ["workspace:*", "file:../pkg", "link:../pkg", "portal:pkg", "patch:pkg"]
    for _ in range(rng.randint(1, 20)):
        scoped = rng.random() < 0.25
        pkg_a = _rand_package_name(rng, scoped=scoped)
        if rng.random() < 0.25:
            pkg_b = _rand_package_name(rng, scoped=False)
            key = f'"{pkg_a}@^1.0.0, {pkg_b}@~2.0.0":'
        else:
            key = f'"{pkg_a}@^1.0.0":'
        lines.append(key)
        if rng.random() < 0.85:
            version = _rand_version(rng) if rng.random() < 0.8 else rng.choice(disallowed_versions)
            if rng.random() < 0.5:
                lines.append(f'  version "{version}"')
            else:
                lines.append(f"  version: {version}")
        if rng.random() < 0.2:
            lines.append(f"  resolved {_rand_token(rng)}")
        if rng.random() < 0.2:
            lines.append("# interleaved comment")
        lines.append("")

    return "\n".join(lines), None


def _build_pnpm_case(rng: random.Random, _index: int) -> tuple[str, type[BaseException] | None]:
    lines = ["lockfileVersion: '9.0'"]
    if rng.random() < 0.5:
        lines.extend(["importers:", "  .: {}"])

    lines.append("packages:")
    prefixes = ["", "/", ""]
    for _ in range(rng.randint(1, 30)):
        scoped = rng.random() < 0.3
        name = _rand_package_name(rng, scoped=scoped)
        mode = rng.randint(0, 7)
        if mode == 0:
            key = f"{rng.choice(prefixes)}{name}@{_rand_version(rng)}"
        elif mode == 1:
            key = f"{rng.choice(prefixes)}{name}@{_rand_version(rng)}(react@18.2.0)"
        elif mode == 2:
            key = f"{rng.choice(prefixes)}{name}@workspace:*"
        elif mode == 3:
            key = f"{rng.choice(prefixes)}{name}@link:../{_rand_token(rng)}"
        elif mode == 4:
            key = f"{rng.choice(prefixes)}{name}@file:../{_rand_token(rng)}.tgz"
        elif mode == 5:
            key = f"{rng.choice(prefixes)}{name}@portal:{_rand_token(rng)}"
        elif mode == 6:
            key = f"{rng.choice(prefixes)}{name}@patch:{_rand_token(rng)}"
        else:
            key = f"@@@{_rand_token(rng)}"

        if rng.random() < 0.4:
            lines.append(f"  '{key}':")
        else:
            lines.append(f"  {key}:")
        lines.append("    resolution: {integrity: sha512-demo}")

    return "\n".join(lines) + "\n", None


def _build_package_lock_case(
    rng: random.Random, _index: int
) -> tuple[str, type[BaseException] | None]:
    mode = rng.randint(0, 7)
    if mode == 0:
        return '{"broken": [}', json.JSONDecodeError
    if mode == 1:
        return "[1,2,3]", None
    if mode == 2:
        return "42", None

    payload: dict[str, object] = {
        "name": "fuzz",
        "lockfileVersion": 2,
        "requires": True,
    }
    if mode in {3, 4, 5}:
        packages: dict[str, object] = {"": {"name": "fuzz", "version": "1.0.0"}}
        for _ in range(rng.randint(0, 20)):
            scoped = rng.random() < 0.2
            name = _rand_package_name(rng, scoped=scoped)
            key = f"node_modules/{name}"
            if rng.random() < 0.2:
                key = _rand_token(rng)
            entry_mode = rng.randint(0, 4)
            if entry_mode == 0:
                packages[key] = {"version": _rand_version(rng)}
            elif entry_mode == 1:
                packages[key] = {"name": name, "version": _rand_version(rng)}
            elif entry_mode == 2:
                packages[key] = {"name": name}
            elif entry_mode == 3:
                packages[key] = {"version": rng.randint(1, 100)}
            else:
                packages[key] = "invalid"
        payload["packages"] = packages
    else:
        deps: dict[str, object] = {}
        for _ in range(rng.randint(0, 12)):
            name = _rand_package_name(rng, scoped=rng.random() < 0.2)
            dep_mode = rng.randint(0, 2)
            if dep_mode == 0:
                deps[name] = {"version": _rand_version(rng)}
            elif dep_mode == 1:
                deps[name] = {
                    "version": _rand_version(rng),
                    "dependencies": {
                        _rand_package_name(rng): {"version": _rand_version(rng)},
                        _rand_token(rng): "junk",
                    },
                }
            else:
                deps[name] = "invalid"
        payload["dependencies"] = deps

    return json.dumps(payload), None


def _build_pipfile_case(rng: random.Random, _index: int) -> tuple[str, type[BaseException] | None]:
    mode = rng.randint(0, 6)
    if mode == 0:
        return "{invalid-json", json.JSONDecodeError
    if mode == 1:
        return "[]", None

    payload: dict[str, object] = {"_meta": {"hash": {"sha256": "demo"}}}
    for section in ("default", "develop"):
        if rng.random() < 0.8:
            entries: dict[str, object] = {}
            for _ in range(rng.randint(0, 12)):
                name = _rand_package_name(rng)
                version_mode = rng.randint(0, 5)
                if version_mode == 0:
                    version = f"=={_rand_version(rng)}"
                elif version_mode == 1:
                    version = f"=== {_rand_version(rng)}"
                elif version_mode == 2:
                    version = f">={_rand_version(rng)}"
                elif version_mode == 3:
                    version = ""
                elif version_mode == 4:
                    version = _rand_token(rng)
                else:
                    entries[name] = {"version": 42}
                    continue
                entries[name] = {"version": version}
            payload[section] = entries
        else:
            payload[section] = ["not-a-dict"]

    return json.dumps(payload), None


def _build_toml_case(rng: random.Random, _index: int) -> tuple[str, type[BaseException] | None]:
    mode = rng.randint(0, 5)
    if mode == 0:
        return "[[package]\nname='broken'", ValueError
    if mode == 1:
        return "[package\nname='bad'", ValueError

    if mode == 2:
        return "package = ['bad-shape']\n", None

    lines: list[str] = []
    for _ in range(rng.randint(0, 20)):
        lines.extend(
            [
                "[[package]]",
                f'name = "{_rand_package_name(rng)}"',
                f'version = "{_rand_version(rng)}"',
                "",
            ]
        )
    return "\n".join(lines), None


@pytest.mark.parametrize(
    ("manifest_name", "builder", "iterations", "seed"),
    [
        ("requirements.txt", _build_requirements_case, 300, 20260303),
        ("yarn.lock", _build_yarn_case, 220, 20260304),
        ("pnpm-lock.yaml", _build_pnpm_case, 220, 20260305),
        ("package-lock.json", _build_package_lock_case, 180, 20260306),
        ("Pipfile.lock", _build_pipfile_case, 180, 20260307),
        ("poetry.lock", _build_toml_case, 180, 20260308),
        ("uv.lock", _build_toml_case, 180, 20260309),
    ],
)
def test_generated_manifest_parsing_matrix(
    tmp_path: Path,
    manifest_name: str,
    builder: CaseBuilder,
    iterations: int,
    seed: int,
) -> None:
    rng = random.Random(seed)
    for index in range(iterations):
        case_dir = tmp_path / f"case_{index:04d}"
        case_dir.mkdir(parents=True, exist_ok=True)
        path = case_dir / manifest_name
        content, expected_exception = builder(rng, index)
        path.write_text(content, encoding="utf-8")

        if expected_exception is None:
            deps = parse_dependency_manifest(path)
            _assert_dependency_contract(deps)
            continue

        with pytest.raises(expected_exception):
            parse_dependency_manifest(path)


@pytest.mark.parametrize(
    "manifest_name,payload",
    [
        ("package-lock.json", "[]"),
        ("package-lock.json", "42"),
        ("Pipfile.lock", "[]"),
        ("Pipfile.lock", "null"),
    ],
)
def test_json_manifest_non_object_roots_do_not_crash(
    tmp_path: Path, manifest_name: str, payload: str
) -> None:
    path = tmp_path / manifest_name
    path.write_text(payload, encoding="utf-8")
    assert parse_dependency_manifest(path) == []


@pytest.mark.parametrize(
    ("manifest_name", "builder", "seed"),
    [
        ("package-lock.json", _build_package_lock_case, 20260401),
        ("Pipfile.lock", _build_pipfile_case, 20260402),
        ("poetry.lock", _build_toml_case, 20260403),
        ("uv.lock", _build_toml_case, 20260404),
    ],
)
def test_cli_generated_malformed_structured_manifests_fail_cleanly(
    tmp_path: Path,
    manifest_name: str,
    builder: CaseBuilder,
    seed: int,
) -> None:
    rng = random.Random(seed)
    runner = CliRunner()

    for index in range(40):
        content = ""
        expected_exception: type[BaseException] | None = None
        while expected_exception is None:
            content, expected_exception = builder(rng, index)

        case_dir = tmp_path / f"bad_case_{index:03d}"
        case_dir.mkdir(parents=True, exist_ok=True)
        path = case_dir / manifest_name
        path.write_text(content, encoding="utf-8")
        result = runner.invoke(main, ["scan-deps", str(path), "--no-network"])
        assert result.exit_code == cli.EXIT_SCAN_FAILED
        assert "Dependency scan failed:" in result.output


@pytest.mark.parametrize(
    ("manifest_name", "builder", "seed"),
    [
        ("requirements.txt", _build_requirements_case, 20260501),
        ("yarn.lock", _build_yarn_case, 20260502),
        ("pnpm-lock.yaml", _build_pnpm_case, 20260503),
    ],
)
def test_cli_generated_text_manifests_do_not_crash(
    tmp_path: Path,
    manifest_name: str,
    builder: CaseBuilder,
    seed: int,
) -> None:
    rng = random.Random(seed)
    runner = CliRunner()

    for index in range(60):
        case_dir = tmp_path / f"txt_case_{index:03d}"
        case_dir.mkdir(parents=True, exist_ok=True)
        path = case_dir / manifest_name
        content, expected_exception = builder(rng, index)
        assert expected_exception is None
        path.write_text(content, encoding="utf-8")

        result = runner.invoke(main, ["scan-deps", str(path), "--no-network", "--summary-only"])
        assert result.exit_code == 0
        assert "Dependencies scanned:" in result.output
