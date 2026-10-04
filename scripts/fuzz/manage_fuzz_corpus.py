#!/usr/bin/env python3
"""Maintain fuzz corpus metadata and archives.

This script ensures corpus directories exist for all fuzz targets,
captures per-target statistics, appends them to a history log, and
archives the current corpus with simple generation control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, NoReturn

if TYPE_CHECKING:
    from collections.abc import Iterator

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - older Python fallback
    import tomli as tomllib  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[2]
FUZZ_DIR = ROOT / "fuzz"
CORPUS_ROOT = FUZZ_DIR / "corpus"
META_DIR = FUZZ_DIR / "corpus_meta"
ARCHIVE_DIR = FUZZ_DIR / "corpus_archive"
CRASH_ROOT = FUZZ_DIR / "artifacts"
HISTORY_FILE = META_DIR / "history.jsonl"
MAX_SAMPLE_FILES = 10
MIN_FUZZ_SECONDS = 30
WATCHDOG_GRACE_SECONDS = 30
EVIDENCE_ERROR = 2


def invalid(message: str) -> NoReturn:
    raise ValueError(message)


def optional_path_from_env(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


RUN_ARTIFACT_DIR = optional_path_from_env("FUZZ_RUN_ARTIFACT_DIR")
HISTORY_OUT_DIR = optional_path_from_env("FUZZ_HISTORY_DIR")


def parse_env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


@dataclass
class CorpusStat:
    name: str
    file_count: int
    size_bytes: int
    latest_mtime: float | None

    def as_dict(self) -> dict:
        latest_iso = (
            datetime.fromtimestamp(self.latest_mtime, tz=UTC).isoformat()
            if self.latest_mtime is not None
            else None
        )
        return {
            "name": self.name,
            "files": self.file_count,
            "size_bytes": self.size_bytes,
            "latest_mtime": latest_iso,
        }


@dataclass
class CrashStat:
    name: str
    file_count: int
    size_bytes: int
    latest_mtime: float | None
    sample_files: list[str]

    def as_dict(self) -> dict:
        latest_iso = (
            datetime.fromtimestamp(self.latest_mtime, tz=UTC).isoformat()
            if self.latest_mtime is not None
            else None
        )
        return {
            "name": self.name,
            "files": self.file_count,
            "size_bytes": self.size_bytes,
            "latest_mtime": latest_iso,
            "sample_files": self.sample_files,
        }


def load_targets() -> list[str]:
    cargo_toml = FUZZ_DIR / "Cargo.toml"
    if not cargo_toml.exists():
        print("fuzz/Cargo.toml not found; run from repository root", file=sys.stderr)
        raise SystemExit(1)

    data = tomllib.loads(evidence_text(cargo_toml))
    bins = data.get("bin", [])
    names = [b["name"] for b in bins]
    if (
        not names
        or len(names) != len(set(names))
        or any(
            not isinstance(name, str) or not re.fullmatch(r"fuzz_[a-z0-9_]+", name)
            for name in names
        )
    ):
        invalid("fuzz manifest must contain distinct, nonempty fuzz target names")
    return sorted(names)


def ensure_directories(targets: list[str]) -> None:
    validate_collection_roots()
    CORPUS_ROOT.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    for target in targets:
        path = CORPUS_ROOT / target
        if not path.is_symlink():
            path.mkdir(parents=True, exist_ok=True)


def gather_stats(targets: list[str]) -> list[CorpusStat]:
    validate_collection_roots()
    stats: list[CorpusStat] = []
    for target in targets:
        path = CORPUS_ROOT / target
        file_count = 0
        size_bytes = 0
        latest_mtime: float | None = None
        if path.exists() and not path.is_symlink():
            for file in path.rglob("*"):
                if not file.is_symlink() and file.is_file():
                    file_count += 1
                    stat = file.stat()
                    size_bytes += stat.st_size
                    if latest_mtime is None or stat.st_mtime > latest_mtime:
                        latest_mtime = stat.st_mtime
        stats.append(CorpusStat(target, file_count, size_bytes, latest_mtime))
    return stats


def append_history(stats: list[CorpusStat]) -> None:
    record = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "targets": [s.as_dict() for s in stats],
    }
    limit = parse_env_int("CORPUS_HISTORY_KEEP", 0)

    if limit > 0:
        lines: list[str] = []
        if HISTORY_FILE.exists():
            lines = evidence_text(HISTORY_FILE).splitlines()
        lines.append(json.dumps(record, ensure_ascii=False))
        lines = lines[-limit:]
        with HISTORY_FILE.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    else:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def create_archive() -> Path | None:
    validate_collection_roots()
    keep_archives = parse_env_int("CORPUS_ARCHIVE_KEEP", 3)
    if keep_archives <= 0:
        return None

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = ARCHIVE_DIR / f"{timestamp}.tar.gz"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "w:gz", dereference=False) as tar:
        if CORPUS_ROOT.exists():
            archive_raw_tree(tar, CORPUS_ROOT, "corpus")

    archives = sorted(ARCHIVE_DIR.glob("*.tar.gz"))
    excess = len(archives) - keep_archives
    for old in archives[:-keep_archives] if excess > 0 else []:
        old.unlink()

    return archive_path


def gather_crash_stats() -> list[CrashStat]:
    validate_collection_roots()
    stats: list[CrashStat] = []
    if not CRASH_ROOT.exists():
        return stats

    for target_dir in sorted(CRASH_ROOT.iterdir()):
        if target_dir.is_symlink() or not target_dir.is_dir():
            continue
        file_count = 0
        size_bytes = 0
        latest_mtime: float | None = None
        samples: list[str] = []
        for file in sorted(target_dir.rglob("*")):
            if file.is_symlink() or not file.is_file():
                continue
            file_count += 1
            stat = file.stat()
            size_bytes += stat.st_size
            if len(samples) < MAX_SAMPLE_FILES:
                samples.append(file.relative_to(target_dir).as_posix())
            if latest_mtime is None or stat.st_mtime > latest_mtime:
                latest_mtime = stat.st_mtime
        stats.append(CrashStat(target_dir.name, file_count, size_bytes, latest_mtime, samples))
    return stats


def copy_into(path: Path, dest_dir: Path | None) -> Path | None:
    if dest_dir is None:
        return None
    dest_path = dest_dir / path.name
    validate_regular_destination(dest_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    copy_evidence_file(str(path), str(dest_path))
    return dest_path


def archive_crashes(stats: list[CrashStat], dest_dir: Path | None) -> Path | None:
    validate_collection_roots()
    total = sum(s.file_count for s in stats)
    if total == 0:
        return None

    target_dir = dest_dir or META_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = target_dir / f"crashes_{timestamp}.tar.gz"
    with tarfile.open(archive_path, "w:gz", dereference=False) as tar:
        for stat in stats:
            if stat.file_count > 0:
                archive_raw_tree(tar, CRASH_ROOT / stat.name, stat.name)
    return archive_path


def write_run_summary(
    stats: list[CorpusStat],
    crash_stats: list[CrashStat],
    corpus_archive: Path | None,
    crash_archive: Path | None,
    execution: dict | None = None,
) -> None:
    summary = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "targets": [s.as_dict() for s in stats],
        "crashes": [c.as_dict() for c in crash_stats],
        "corpus_archive": corpus_archive.name if corpus_archive else None,
        "crash_archive": crash_archive.name if crash_archive else None,
    }

    if execution is not None:
        summary["execution"] = execution
        summary["status"] = execution["status"]
    META_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = META_DIR / "latest_run.json"
    write_json(summary_path, summary)

    if RUN_ARTIFACT_DIR is not None:
        RUN_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        write_json(RUN_ARTIFACT_DIR / "run_summary.json", summary)

    if HISTORY_OUT_DIR is not None:
        HISTORY_OUT_DIR.mkdir(parents=True, exist_ok=True)
        with (HISTORY_OUT_DIR / "fuzz_runs.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary, ensure_ascii=False) + "\n")


def collect_corpus(execution: dict | None = None) -> None:
    validate_collection_roots()
    validate_collection_history(RUN_ARTIFACT_DIR)
    for route in (RUN_ARTIFACT_DIR, HISTORY_OUT_DIR):
        if route is not None:
            validate_evidence_route(route)
    if HISTORY_OUT_DIR is not None:
        validate_regular_destination(HISTORY_OUT_DIR / "fuzz_runs.jsonl")
    targets = load_targets()
    ensure_directories(targets)
    stats = gather_stats(targets)
    append_history(stats)
    total_files = sum(s.file_count for s in stats)
    archive = create_archive() if total_files > 0 else None
    if execution is not None and total_files > 0 and archive is None:
        invalid("required fuzz corpus preservation cannot disable archiving")
    crash_stats = gather_crash_stats()
    crash_archive = archive_crashes(crash_stats, RUN_ARTIFACT_DIR)

    archive_copy = copy_into(archive, RUN_ARTIFACT_DIR) if archive and RUN_ARTIFACT_DIR else archive
    if archive and HISTORY_OUT_DIR:
        copy_into(archive, HISTORY_OUT_DIR)
    if crash_archive and HISTORY_OUT_DIR:
        copy_into(crash_archive, HISTORY_OUT_DIR)

    write_run_summary(stats, crash_stats, archive_copy or archive, crash_archive, execution)

    summary_lines = [
        "[INFO] Fuzz corpus summary:",
        *(f"  - {s.name}: files={s.file_count} size={s.size_bytes}B" for s in stats),
    ]
    if archive is not None:
        summary_lines.append(f"  - archive: {archive.name}")
    total_crashes = sum(c.file_count for c in crash_stats)
    if total_crashes > 0:
        affected = len([c for c in crash_stats if c.file_count > 0])
        summary_lines.append(f"  - crashes: {total_crashes} files across {affected} targets")

    print("\n".join(summary_lines))


REQUIRED_TARGETS = (
    "fuzz_bearer_token",
    "fuzz_dpop_proof",
    "fuzz_pkce_verifier",
    "fuzz_jose_parsing",
    "fuzz_ffi_parsers",
    "fuzz_introspection",
    "fuzz_par",
)


def tool_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def digest(path: Path) -> str:
    return evidence_digest(path)


def write_json(path: Path, data: dict) -> None:
    # The destination's parent is owned by the caller's approved evidence route.
    # Refuse aliases before creating our exclusive temporary file; an old fixed
    # execution.tmp/run_summary.tmp is never opened or removed.
    parent = path.parent
    if parent.resolve() != parent.absolute() or not parent.is_dir():
        invalid("fuzz receipt parent is not an owned directory")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        invalid("fuzz receipt destination is not a regular file")
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(data, indent=2) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def seconds(value: str, name: str) -> int:
    match = re.fullmatch(r"([0-9]{1,8})([sSmMhH]?)", value)
    if not match:
        invalid(f"{name} must be a positive integer duration (s, m or h)")
    number = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2].lower()]
    if number <= 0:
        invalid(f"{name} must be positive")
    return number


def selected_targets() -> list[str]:
    selected = os.environ.get("FUZZ_TARGETS", " ".join(REQUIRED_TARGETS)).split()
    if not selected or len(selected) != len(set(selected)):
        invalid("FUZZ_TARGETS must be nonempty and contain no duplicates")
    if set(load_targets()) != set(REQUIRED_TARGETS):
        invalid("fuzz manifest differs from the required seven-target inventory")
    if any(name not in REQUIRED_TARGETS for name in selected):
        invalid("FUZZ_TARGETS contains an unknown target")
    if os.environ.get("CI") == "true" and set(selected) != set(REQUIRED_TARGETS):
        invalid("CI requires the full seven-target fuzz inventory")
    return selected


def capture(argv: list[str]) -> dict:
    path = shutil.which(argv[0])
    result = {"argv": argv, "path": path, "exit_code": None, "output": ""}
    if path is None:
        return result
    result["sha256"] = tool_digest(Path(path))
    try:
        # Only the fixed version/identity commands and configured native compilers are used.
        process = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=10, check=False
        )
        result.update(exit_code=process.returncode, output=process.stdout + process.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    return result


def required_source(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
        invalid(f"required fuzz input is missing or not a repository regular file: {path}")
    return path


def selected_sources(selected: list[str]) -> list[Path]:
    manifest = tomllib.loads(evidence_text(FUZZ_DIR / "Cargo.toml"))
    binaries = {entry["name"]: entry for entry in manifest["bin"]}
    paths = []
    for name in selected:
        value = binaries[name].get("path")
        if not isinstance(value, str) or not value:
            invalid(f"fuzz target {name} has no declared source path")
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".rs":
            invalid(f"fuzz target {name} has an unsafe source path")
        paths.append(required_source(FUZZ_DIR / relative))
    return paths


GIT_IDENTITY_OVERRIDES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
)


def validate_compiler_environment() -> None:
    # Cargo can bypass the PATH compiler or RUSTFLAGS through these inputs.
    # Presence, including an empty value, is unsupported; never disclose values.
    for name in (
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ALIAS_FUZZ",
    ):
        if name in os.environ:
            invalid(f"inherited {name} override is not supported for fuzz execution or cleanup")


def validate_git_environment() -> None:
    # Do not sanitize an override after using it to discover ROOT or record HEAD.
    if any(name in os.environ for name in GIT_IDENTITY_OVERRIDES) or any(
        name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")) for name in os.environ
    ):
        invalid("inherited Git identity overrides are not supported for fuzz execution or cleanup")


def source_exclusions() -> set[Path]:
    # Identified runtime/build outputs only. Everything else, including ignored
    # and untracked files, is an input until its ownership is explicitly known.
    excluded = {
        ROOT / ".git",
        ROOT / "target",
        FUZZ_DIR / "target",
        *(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta")),
        ROOT / "artifacts/security",
        ROOT / "result",
        ROOT / "result-server",
    }
    for name, default in (
        ("CARGO_TARGET_DIR", "target/security-suite"),
        ("CARGO_HOME", ""),
        ("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
        ("FUZZ_RUN_ARTIFACT_DIR", ""),
        ("FUZZ_HISTORY_DIR", ""),
    ):
        value = os.environ.get(name, default)
        if not value:
            continue
        path = repository_path(Path(value))
        if not path.is_relative_to(ROOT):
            continue
        if (
            path == ROOT
            or any(
                overlaps(path, ROOT / source)
                for source in CACHE_SOURCE_ROOTS
                if source not in {".git", "artifacts"}
            )
            or overlaps(path, FUZZ_DIR / "fuzz_targets")
            or any(
                overlaps(path, ROOT / relative)
                for relative in (
                    "artifacts/karamel",
                    "artifacts/ct",
                    "fuzz/Cargo.toml",
                    "fuzz/Cargo.lock",
                )
            )
        ):
            invalid("fuzz runtime output overlaps local source inputs")
        excluded.add(path)
    if "CARGO_TARGET_DIR" in os.environ:
        directory = (
            RUN_ARTIFACT_DIR
            or repository_path(
                Path(os.environ.get("SECURITY_ARTIFACT_DIR") or "artifacts/security/latest")
            )
            / "fuzz"
        )
        # A supported cache alias may point elsewhere inside the checkout. Only
        # the protected-path-validated canonical destination is an output.
        excluded.add(configured_cache(directory))
    return excluded


KANI_OUTPUT_POINTER = "crates/kani-harness/kani"
KANI_OUTPUT_TARGET = "result/bin/cargo-kani"
KANI_OUTPUT_MODE = 0o777


def local_fuzz_manifests(inventory: dict[str, dict[str, Any]], excluded: set[Path]) -> set[Path]:
    pending = [FUZZ_DIR / "Cargo.toml"]
    visited = set()
    while pending:
        manifest = pending.pop()
        if manifest in visited:
            continue
        visited.add(manifest)
        document = tomllib.loads(evidence_text(manifest))
        for route in cargo_path_values(document):
            check_local_cargo_path(manifest, route, inventory, excluded)
            target = (manifest.parent / route).resolve()
            if target.is_relative_to(ROOT / "crates/kani-harness"):
                invalid("Kani output pointer became relevant to the fuzz dependency closure")
            if target.is_dir():
                pending.append(target / "Cargo.toml")
    return visited


def kani_output_pointer() -> dict[str, Any] | None:
    # If the retired workspace-excluded launcher is present, retain its exact
    # literal bytes/mode without traversing its tool output. Absence is valid.
    manifest = tomllib.loads(evidence_text(ROOT / "Cargo.toml"))
    if "crates/kani-harness" not in manifest.get("workspace", {}).get("exclude", []):
        invalid("Kani output pointer is no longer workspace-excluded")
    path = ROOT / KANI_OUTPUT_POINTER
    if not path.exists() and not path.is_symlink():
        return None
    if (
        not path.is_symlink()
        or os.fsencode(path.readlink()) != os.fsencode(KANI_OUTPUT_TARGET)
        or stat.S_IMODE(path.lstat().st_mode) != KANI_OUTPUT_MODE
    ):
        invalid("root-reviewed Kani output pointer is missing or changed")
    return {
        "type": "unrelated-tool-output-pointer",
        "mode": KANI_OUTPUT_MODE,
        "git_mode": "120000",
        "target": KANI_OUTPUT_TARGET,
        "sha256": hashlib.sha256(os.fsencode(path.readlink())).hexdigest(),
    }


def validate_kani_output_relevance(
    inventory: dict[str, dict[str, Any]], excluded: set[Path]
) -> None:
    packages = {manifest.parent for manifest in local_fuzz_manifests(inventory, excluded)}
    for relative, record in inventory.items():
        if record["type"] != "file":
            continue
        candidate = ROOT / relative
        if candidate.is_relative_to(ROOT / ".cargo"):
            if b"kani-harness" in evidence_snapshot(candidate):
                invalid("Cargo configuration references the Kani output pointer")
        elif (
            any(candidate.is_relative_to(package) for package in packages)
            and candidate.suffix in {".rs", ".toml", ".c", ".h", ".sh", ".py"}
            and b"kani-harness" in evidence_snapshot(candidate)
        ):
            invalid("local fuzz source/build input references the Kani output pointer")
    if any("kani-harness" in value for value in os.environ.values()):
        invalid("build environment references the Kani output pointer")


def source_hashes(selected: list[str]) -> dict[str, dict[str, Any]]:
    validate_git_environment()
    required = [
        ROOT / path
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "fuzz/Cargo.toml",
            "fuzz/Cargo.lock",
            "flake.lock",
            "rust-toolchain.toml",
            "scripts/security/run_security_suite.sh",
            "scripts/fuzz/manage_fuzz_corpus.py",
        )
    ]
    required.extend(selected_sources(selected))
    excluded = source_exclusions()
    for path in required:
        required_source(path)
        if any(path.is_relative_to(output) for output in excluded):
            invalid("required fuzz source is excluded by a runtime output")
    pointer = kani_output_pointer()
    inventory = local_source_inventory(excluded, pointer)
    validate_local_cargo_paths(inventory, excluded)
    validate_kani_output_relevance(inventory, excluded)
    return dict(sorted(inventory.items()))


def local_source_inventory(
    excluded: set[Path], pointer: dict[str, Any] | None
) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}

    # os.walk does not silently follow symlink directories or discard their
    # identity. Errors are fatal, and directory records detect empty additions.
    def traversal_error(error: OSError) -> NoReturn:
        raise error

    for base, directories, files in os.walk(ROOT, followlinks=False, onerror=traversal_error):
        directory = Path(base)
        directories[:] = [name for name in directories if directory / name not in excluded]
        for name in sorted([*directories, *files]):
            path = directory / name
            if path in excluded:
                continue
            relative = path.relative_to(ROOT).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if relative != KANI_OUTPUT_POINTER or pointer is None:
                    invalid(f"symlink or external local source input is not supported: {relative}")
                inventory[relative] = pointer
                continue
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                inventory[relative] = {"type": "directory", "mode": mode}
            elif stat.S_ISREG(info.st_mode):
                inventory[relative] = {
                    "type": "file",
                    "mode": mode,
                    "sha256": evidence_digest(path, info),
                }
            else:
                invalid(f"special local source input is not supported: {relative}")
    return inventory


def inherited_cargo_dependencies(document: dict[str, Any]) -> list[Any]:
    inherited_values = []
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, dependency in document.get(table, {}).items():
            if not isinstance(dependency, dict) or dependency.get("workspace") is not True:
                continue
            workspace = tomllib.loads(evidence_text(ROOT / "Cargo.toml"))
            inherited = workspace.get("workspace", {}).get("dependencies", {}).get(name)
            if inherited is None or (isinstance(inherited, dict) and inherited.get("workspace")):
                invalid("unresolved inherited local Cargo dependency")
            if isinstance(inherited, dict) and "path" in inherited:
                inherited = {**inherited, "path": str(ROOT / inherited["path"])}
            inherited_values.append(inherited)
    return inherited_values


def cargo_path_values(document: dict[str, Any]) -> list[str]:
    paths = []
    pending: list[Any] = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
            pending.extend(inherited_cargo_dependencies(value))
            if "path" in value:
                route = value["path"]
                if not isinstance(route, str) or not route:
                    invalid("malformed local Cargo source path")
                paths.append(route)
        elif isinstance(value, list):
            pending.extend(value)
    return paths


def check_local_cargo_path(
    manifest: Path, route: str, inventory: dict[str, dict[str, Any]], excluded: set[Path]
) -> None:
    target = manifest.parent / route
    resolved = target.resolve()
    if (
        not resolved.is_relative_to(ROOT)
        or not target.exists()
        or any(resolved.is_relative_to(output) for output in excluded)
        or (target.is_dir() and not (target / "Cargo.toml").is_file())
    ):
        invalid("external, missing or excluded local Cargo source path")
    if resolved.relative_to(ROOT).as_posix() not in inventory:
        invalid("local Cargo source path is absent from the input inventory")


def validate_local_cargo_paths(inventory: dict[str, dict[str, Any]], excluded: set[Path]) -> None:
    # Reject external/missing local Cargo paths; manifests cannot introduce an
    # excluded output or another repository as unrecorded implementation.
    for relative, record in inventory.items():
        if record["type"] != "file" or Path(relative).name != "Cargo.toml":
            continue
        manifest = ROOT / relative
        document = tomllib.loads(evidence_text(manifest))
        for route in cargo_path_values(document):
            check_local_cargo_path(manifest, route, inventory, excluded)


# Source roots are disjoint from supported build caches, including fuzz/target.
# Root-level regular inputs are also protected; unknown output directories are
# not promoted to source roots merely because a prior build created them.
CACHE_SOURCE_ROOTS = (
    ".cargo",
    ".flakehub",
    ".git",
    ".github",
    "artifacts",
    "assets",
    "c",
    "ci",
    "crates",
    "db",
    "dev-tools",
    "docs",
    "examples",
    "fstar",
    "generated",
    "include",
    "infra",
    "nix",
    "proofs",
    "scripts",
    "spec",
    "supply-chain",
    "tests",
    "xtask",
)


def repository_path(path: Path) -> Path:
    return (path if path.is_absolute() else ROOT / path).resolve()


def overlaps(left: Path, right: Path) -> bool:
    return left.is_relative_to(right) or right.is_relative_to(left)


def git_metadata_paths() -> list[Path]:  # noqa: PLR0912 - validate Git metadata pointers
    validate_git_environment()
    git_entry = ROOT / ".git"
    if not git_entry.exists():
        if git_entry.is_symlink():
            invalid("fuzz cache cannot resolve Git metadata pointer")
        return []
    if git_entry.is_file():
        record = evidence_text(git_entry).removesuffix("\n")
        if (
            not record.startswith("gitdir: ")
            or not record[len("gitdir: ") :]
            or record.endswith("\r")
        ):
            invalid("fuzz cache cannot resolve Git metadata pointer")
        git_dir = Path(record[len("gitdir: ") :])
        git_dir = (git_dir if git_dir.is_absolute() else ROOT / git_dir).resolve()
    elif git_entry.is_dir():
        git_dir = git_entry.resolve()
    else:
        invalid("fuzz cache cannot resolve Git metadata entry")
    if not git_dir.is_dir():
        invalid("fuzz cache Git metadata pointer does not name a directory")
    paths = [git_dir]
    common_file = git_dir / "commondir"
    if common_file.exists() or common_file.is_symlink():
        record = evidence_text(common_file).removesuffix("\n")
        if not record or record.endswith("\r"):
            invalid("fuzz cache cannot resolve shared Git metadata pointer")
        common_dir = Path(record)
        common_dir = (common_dir if common_dir.is_absolute() else git_dir / common_dir).resolve()
        if not common_dir.is_dir():
            invalid("fuzz cache shared Git metadata pointer does not name a directory")
        paths.append(common_dir)
    return paths


def effective_cargo_home() -> Path:
    path = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    return path if path.is_absolute() else ROOT / path


def cache_protected_paths(directory: Path) -> list[Path]:
    evidence_root = repository_path(directory).parent
    paths = [ROOT / name for name in CACHE_SOURCE_ROOTS]
    paths.extend(git_metadata_paths())
    paths.extend(path for path in ROOT.iterdir() if path.is_file())
    paths.extend(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta", "fuzz_targets"))
    paths.extend(selected_sources(selected_targets()))
    paths.extend([FUZZ_DIR / "Cargo.toml", FUZZ_DIR / "Cargo.lock", evidence_root])
    paths.append(effective_cargo_home())
    paths.append(
        repository_path(Path(os.environ.get("SECURITY_HISTORY_DIR", "artifacts/security/history")))
    )
    return [path.resolve() for path in paths]


def configured_cache(directory: Path) -> Path:
    validate_compiler_environment()
    base = repository_path(Path(os.environ["CARGO_TARGET_DIR"]))
    cache = (base / "fuzz").resolve()
    # Descendant caches are allowed; the workspace and fuzz root themselves,
    # or any ancestor that can remove them, are never cleanup destinations.
    if any(root.is_relative_to(path) for root in (ROOT, FUZZ_DIR) for path in (base, cache)):
        invalid("fuzz cache cannot be a workspace root or ancestor")
    if any(
        overlaps(output, path)
        for output in (base, cache)
        for path in cache_protected_paths(directory)
    ):
        invalid("fuzz cache overlaps protected source, raw, evidence or Cargo home paths")
    if cache.exists() and not cache.is_dir():
        invalid("fuzz cache is not a directory")
    return cache


def lexical_directory(path: Path) -> Path:
    path = path if path.is_absolute() else ROOT / path
    if ".." in path.parts:
        invalid("owned directory route cannot contain parent traversal")
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            invalid("owned directory route cannot contain symlink components")
        if component.exists() and not component.is_dir():
            invalid("owned directory route contains a special or nondirectory component")
    return path


def validate_regular_destination(path: Path) -> None:
    lexical_directory(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        invalid("owned output destination cannot be a symlink or special entry")
    if path.exists():
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_nlink != 1:
            invalid("owned output destination must be unaliased and producer-owned")


def validate_evidence_route(directory: Path) -> Path:
    path = lexical_directory(directory)
    protected = [ROOT, FUZZ_DIR, *git_metadata_paths()]
    # ROOT/FUZZ_DIR ancestors are forbidden; their supported output descendants
    # must also be disjoint from source, Git metadata and every raw root.
    if any(root.is_relative_to(path) for root in protected):
        invalid("fuzz evidence route overlaps repository or metadata")
    sources = [ROOT / name for name in CACHE_SOURCE_ROOTS if name != "artifacts"]
    sources.extend(ROOT / name for name in ("artifacts/ct", "artifacts/karamel"))
    sources.extend(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta", "fuzz_targets"))
    sources.extend([FUZZ_DIR / "Cargo.toml", FUZZ_DIR / "Cargo.lock", *git_metadata_paths()])
    sources.extend(entry for entry in ROOT.iterdir() if entry.is_file())
    if any(overlaps(path, source) for source in sources):
        invalid("fuzz evidence route overlaps source, raw or metadata paths")
    return path


def validate_fuzz_logs(directory: Path) -> None:
    directory = directory if directory.is_absolute() else ROOT / directory
    for name in ("run.log", "cargo-fuzz-help.log"):
        validate_regular_destination(directory / name)
    for target in selected_targets():
        for name in ("build.log", "run.log"):
            validate_regular_destination(directory / target / name)


def validate_collection_history(directory: Path | None) -> None:
    collection_routes = [
        lexical_directory(route) for route in (directory, RUN_ARTIFACT_DIR) if route is not None
    ]
    for name, default in (
        ("FUZZ_HISTORY_DIR", ""),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
    ):
        if value := os.environ.get(name, default):
            history = lexical_directory(Path(value))
            if any(overlaps(collection, history) for collection in collection_routes):
                invalid("fuzz collection and history directories overlap")


def validate_preflight(directory: Path) -> Path:
    validate_compiler_environment()
    validate_git_environment()
    validate_collection_roots()
    for target in selected_targets():
        for root in ("corpus", "artifacts"):
            lexical_directory(FUZZ_DIR / root / target)
    routes = [directory]
    for name, default in (
        ("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
        ("FUZZ_RUN_ARTIFACT_DIR", ""),
        ("FUZZ_HISTORY_DIR", ""),
    ):
        if value := os.environ.get(name, default):
            routes.append(Path(value))
    for route in routes:
        validate_evidence_route(route)
    validate_collection_history(directory)
    artifact = Path(os.environ.get("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"))
    artifact = artifact if artifact.is_absolute() else ROOT / artifact
    validate_evidence_route(artifact / "summary")
    validate_regular_destination(artifact / "summary/security.log")
    validate_fuzz_logs(directory)
    for name in ("collection.ok", "execution.json", "run_summary.json", "collection-summary.json"):
        validate_regular_destination(lexical_directory(directory) / name)
    for name, default in (
        ("FUZZ_HISTORY_DIR", ""),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
    ):
        if value := os.environ.get(name, default):
            path = Path(value)
            path = path if path.is_absolute() else ROOT / path
            validate_regular_destination(path / "fuzz_runs.jsonl")
    validate_evidence_route(effective_cargo_home())
    cache = configured_cache(directory)
    lexical_directory(Path(os.environ["CARGO_TARGET_DIR"]))
    lexical_directory(cache)
    effective_native_commands()
    source_hashes(selected_targets())
    return cache


def validate_native_configuration() -> dict[str, str]:
    # Cargo merges configuration from the invocation directory, ancestors and
    # Cargo home. Only the tracked repository config is modeled here.
    extra = [FUZZ_DIR / ".cargo/config", FUZZ_DIR / ".cargo/config.toml", ROOT / ".cargo/config"]
    for parent in ROOT.parents:
        extra.extend(parent / ".cargo" / name for name in ("config", "config.toml"))
    cargo_home = effective_cargo_home()
    extra.extend(cargo_home / name for name in ("config", "config.toml"))
    if any(path.exists() or path.is_symlink() for path in extra):
        invalid("unmodeled external or nested Cargo compiler configuration")
    config_path = ROOT / ".cargo/config.toml"
    config = (
        tomllib.loads(evidence_text(required_source(config_path))) if config_path.exists() else {}
    )
    if "fuzz" in config.get("alias", {}):
        invalid("Cargo fuzz alias is not supported for fuzz execution or cleanup")
    forced = {
        "CC_x86_64_unknown_linux_gnu": "cc",
        "CXX_x86_64_unknown_linux_gnu": "c++",
        "AR_x86_64_unknown_linux_gnu": "ar",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "cc",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR": "ar",
    }
    if config.get("build") or any(
        name not in forced or value != {"value": forced[name], "force": True}
        for name, value in config.get("env", {}).items()
    ):
        invalid("unmodeled Cargo compiler configuration")
    supported_target = {"linker": "cc", "rustflags": ["-Clink-self-contained=no"]}
    if any(
        name != "x86_64-unknown-linux-gnu" or value != supported_target
        for name, value in config.get("target", {}).items()
    ):
        invalid("unmodeled Cargo target compiler configuration")
    return forced


def validate_native_overrides(expected: dict[str, str]) -> None:
    for name, value in os.environ.items():
        if (
            name.startswith(
                (
                    "CC_",
                    "CXX_",
                    "AR_",
                    "CARGO_TARGET_",
                    "TARGET_CC",
                    "TARGET_CXX",
                    "TARGET_AR",
                    "HOST_CC",
                    "HOST_CXX",
                    "HOST_AR",
                )
            )
            and name not in expected
            and name != "CARGO_TARGET_DIR"
        ):
            invalid("unmodeled native compiler environment override")
        if name in expected:
            actual = shutil.which(value) if value else None
            selected = shutil.which(expected[name])
            if (
                actual is None
                or selected is None
                or Path(actual).resolve() != Path(selected).resolve()
            ):
                invalid("native compiler override differs from effective supported tool")


def effective_native_commands(target: str | None = None) -> dict[str, str]:
    machine = platform.machine()
    expected_target = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "aarch64": "aarch64-unknown-linux-gnu",
    }.get(machine)
    if sys.platform != "linux" or expected_target is None or target not in (None, expected_target):
        invalid("unmodeled native fuzz compiler target")
    forced = validate_native_configuration()
    expected = {
        "CC": "cc",
        "CXX": "c++",
        "AR": "ar",
        "CC_FOR_BUILD": "cc",
        "CXX_FOR_BUILD": "c++",
        "AR_FOR_BUILD": "ar",
        **forced,
    }
    if expected_target == "aarch64-unknown-linux-gnu":
        expected.update(
            {
                "CC_aarch64_unknown_linux_gnu": "cc",
                "CXX_aarch64_unknown_linux_gnu": "c++",
                "AR_aarch64_unknown_linux_gnu": "ar",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "cc",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": "ar",
            }
        )
    validate_native_overrides(expected)
    return {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"}


def prepared_source_inputs(cache: Path, selected: list[str]) -> dict[str, dict[str, Any]]:
    # Include newly created cache ancestors in both full source snapshots.
    cache.mkdir(parents=True, exist_ok=True)
    return source_hashes(selected)


def preparation_tools() -> tuple[dict, str]:
    native = effective_native_commands()
    tools = {
        name: capture(argv)
        for name, argv in {
            "rustc": ["rustc", "-vV"],
            "cargo": ["cargo", "--version"],
            "cargo_fuzz": ["cargo-fuzz", "--version"],
            "timeout": ["timeout", "--version"],
            **{name: [command, "--version"] for name, command in native.items()},
        }.items()
    }
    host = re.search(r"^host: (\S+)$", tools["rustc"]["output"], re.MULTILINE)
    target = host[1] if host and tools["rustc"]["exit_code"] == 0 else "missing"
    if target != "missing":
        effective_native_commands(target)
    return tools, target


def prepare_run(directory: Path) -> None:
    validate_compiler_environment()
    validate_git_environment()
    cache = validate_preflight(directory)
    selected = selected_targets()
    total = os.environ.get("FUZZ_TOTAL_TIMEOUT", "")
    maximum = os.environ.get("FUZZ_MAX_TOTAL", "30")
    watchdog = os.environ.get("FUZZ_TIMEOUT", "60s")
    if not maximum or not watchdog or (os.environ.get("FUZZ_LONG") == "1" and not total):
        invalid("fuzz budgets must be nonempty")
    if os.environ.get("FUZZ_LONG") == "1":
        maximum = "" if maximum == "auto" else maximum
        watchdog = "" if watchdog == "auto" else watchdog
    if maximum and not re.fullmatch(r"[0-9]{1,8}", maximum):
        invalid("FUZZ_MAX_TOTAL must be positive integer seconds")
    internal = seconds(total, "FUZZ_TOTAL_TIMEOUT") // len(selected) if total else int(maximum)
    if maximum:
        if int(maximum) < MIN_FUZZ_SECONDS:
            invalid("FUZZ_MAX_TOTAL must allocate at least 30 seconds per target")
        internal = min(internal, int(maximum))
    if internal < MIN_FUZZ_SECONDS:
        invalid("fuzz allocation must allow at least 30 seconds per target")
    external = seconds(watchdog, "FUZZ_TIMEOUT") if watchdog else internal + WATCHDOG_GRACE_SECONDS
    if external < internal + WATCHDOG_GRACE_SECONDS:
        invalid("fuzz watchdog must allow at least 30 seconds of grace")
    inputs = prepared_source_inputs(cache, selected)
    tools, target = preparation_tools()
    data = {
        "schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "started_at": datetime.now(tz=UTC).isoformat(),
        "status": "incomplete",
        "coverage": "full" if set(selected) == set(REQUIRED_TARGETS) else "local-subset",
        "required_targets": list(REQUIRED_TARGETS),
        "selected_targets": selected,
        "internal_seconds": internal,
        "watchdog_seconds": external,
        "kill_grace_seconds": 10,
        "aggregate_internal_allocation": seconds(total, "FUZZ_TOTAL_TIMEOUT") if total else None,
        "target_triple": target,
        "target_dir": str(cache),
        "profile": "release with debug assertions",
        "sanitizer": "address",
        "source": {
            "commit": capture(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
            "tree": capture(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"]),
            "files": inputs,
        },
        "tools": tools,
        "targets": [
            {"name": name, "build": {"status": "not-run"}, "run": {"status": "not-run"}}
            for name in selected
        ],
    }
    write_json(directory / "execution.json", data)
    print(internal, external, target)


def load_execution(directory: Path) -> dict:
    validate_compiler_environment()
    data = json.loads(evidence_text(directory / "execution.json"))
    if (
        data["schema_version"] != 1
        or data["selected_targets"] != selected_targets()
        or data["required_targets"] != list(REQUIRED_TARGETS)
        or [row["name"] for row in data["targets"]] != data["selected_targets"]
        or not isinstance(data["internal_seconds"], int)
        or data["internal_seconds"] < MIN_FUZZ_SECONDS
        or not isinstance(data["watchdog_seconds"], int)
        or data["watchdog_seconds"] < data["internal_seconds"] + WATCHDOG_GRACE_SECONDS
    ):
        invalid("malformed fuzz execution inventory or limits")
    return data


def record_environment(directory: Path) -> None:
    data = load_execution(directory)
    native = effective_native_commands(data["target_triple"])
    for name, command in native.items():
        current = capture([command, "--version"])
        if current != data["tools"][name] or current.get("exit_code") != 0:
            invalid("effective native compiler identity changed or unavailable")
    data["effective_native_commands"] = native
    data["environment"] = {
        name: os.environ.get(name)
        for name in (
            "CC",
            "CXX",
            "CFLAGS",
            "CXXFLAGS",
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
            "ASAN_OPTIONS",
            "LSAN_OPTIONS",
            "NIX_CFLAGS_COMPILE",
            "NIX_LDFLAGS",
            "LIBRARY_PATH",
            "LD_LIBRARY_PATH",
            "PKG_CONFIG_PATH",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_JOBS",
        )
    }
    write_json(directory / "execution.json", data)


def record_target(directory: Path, name: str, phase: str, exit_code: int) -> bool:
    data = load_execution(directory)
    row = next(row for row in data["targets"] if row["name"] == name)
    log = directory / name / f"{phase}.log"
    command = [
        "cargo",
        "fuzz",
        "build" if phase == "build" else "run",
        "--target-dir",
        data["target_dir"],
        "--target",
        data["target_triple"],
        name,
    ]
    if phase == "run":
        command = [
            "timeout",
            "--kill-after=10s",
            f"{data['watchdog_seconds']}s",
            *command,
            "--",
            f"-max_total_time={data['internal_seconds']}",
        ]
    log_snapshot = evidence_snapshot(log)
    record = {
        "status": "failed",
        "exit_code": exit_code,
        "argv": command,
        "log": str(log.resolve()),
        "log_sha256": hashlib.sha256(log_snapshot).hexdigest(),
    }
    binary = Path(data["target_dir"]) / data["target_triple"] / "release" / name
    if exit_code == 0:
        try:
            if not binary.is_file() or not os.access(binary, os.X_OK) or binary.stat().st_size == 0:
                invalid("built fuzz executable is missing or empty")
            record["executable"] = str(binary)
            record["executable_sha256"] = compiled_artifact_digest(directory, data, name, binary)
            if phase == "run":
                if (
                    row["build"].get("status") != "passed"
                    or record["executable_sha256"] != row["build"]["executable_sha256"]
                ):
                    invalid("run executable differs from the successful build")
                completion = re.search(
                    r"^Done ([0-9]+) runs in ([0-9]+) second",
                    log_snapshot.decode("utf-8"),
                    re.MULTILINE,
                )
                if (
                    not completion
                    or int(completion[1]) <= 0
                    or int(completion[2]) < data["internal_seconds"]
                ):
                    invalid("libFuzzer normal bounded completion evidence is missing")
                record["completed_runs"] = int(completion[1])
                record["reported_seconds"] = int(completion[2])
            record["status"] = "passed"
        except ValueError as error:
            record["error"] = str(error)
    row[phase] = record
    write_json(directory / "execution.json", data)
    return record["status"] == "passed"


def validate_phase(
    directory: Path, row: dict, phase: str, data: dict[str, Any] | None = None
) -> bool:
    record = row[phase]
    if record["status"] not in ("not-run", "passed", "failed"):
        invalid("malformed fuzz execution status")
    if record["status"] == "not-run":
        return False
    log = directory / row["name"] / f"{phase}.log"
    if record["log"] != str(log.resolve()) or record["log_sha256"] != digest(log):
        invalid("fuzz execution log is missing or changed")
    if record["status"] == "passed":
        current = load_execution(directory) if data is None else data
        if (
            record["exit_code"] != 0
            or compiled_artifact_digest(directory, current, row["name"], Path(record["executable"]))
            != record["executable_sha256"]
        ):
            invalid("fuzz executable or exit evidence is inconsistent")
    return record["status"] == "passed"


def finish_run(directory: Path, exit_code: int) -> bool:
    data = load_execution(directory)
    if source_hashes(data["selected_targets"]) != data["source"]["files"]:
        invalid("fuzz source identity changed during execution")
    passed = exit_code == 0
    for row in data["targets"]:
        for phase in ("build", "run"):
            if not validate_phase(directory, row, phase, data):
                passed = False
        if row["run"]["status"] == "passed" and (
            row["run"]["completed_runs"] <= 0
            or row["run"]["reported_seconds"] < data["internal_seconds"]
        ):
            invalid("fuzz completion is empty or incomplete")
    data.update(
        status="awaiting-cleanup" if passed else "failed",
        exit_code=exit_code,
        finished_at=datetime.now(tz=UTC).isoformat(),
    )
    write_json(directory / "execution.json", data)
    collect_corpus(data)
    # This marker authorizes cleanup only after summary/history/archive writes succeeded.
    if exit_code != EVIDENCE_ERROR:
        collected_summary = directory / "collection-summary.json"
        summary = json.loads(evidence_text(directory / "run_summary.json"))
        if summary["execution"] != data or summary["status"] != data["status"]:
            invalid("fuzz run summary differs from the verified execution")
        write_json(collected_summary, summary)
        collected_snapshot = evidence_snapshot(collected_summary)
        if json.loads(collected_snapshot.decode("utf-8")) != summary:
            invalid("fuzz collection summary write did not preserve the verified execution")
        write_json(
            directory / "collection.ok",
            {
                "run_id": data["run_id"],
                "summary_file": "collection-summary.json",
                "summary_sha256": hashlib.sha256(collected_snapshot).hexdigest(),
            },
        )
    return passed


def collected_execution(directory: Path) -> dict:
    data = load_execution(directory)
    summary_path = directory / "run_summary.json"
    summary = json.loads(evidence_text(summary_path))
    marker = json.loads(evidence_text(directory / "collection.ok"))
    collected_summary = directory / "collection-summary.json"
    collected_snapshot = evidence_snapshot(collected_summary)
    if (
        summary["execution"] != data
        or summary != json.loads(collected_snapshot.decode("utf-8"))
        or marker["run_id"] != data["run_id"]
        or marker["summary_file"] != "collection-summary.json"
        or marker["summary_sha256"] != hashlib.sha256(collected_snapshot).hexdigest()
    ):
        invalid("fuzz collection receipt is missing or inconsistent")
    return data


def cleanup_result(directory: Path, exit_code: int) -> None:
    data = collected_execution(directory)
    summary_path = directory / "run_summary.json"
    summary = json.loads(evidence_text(summary_path))
    data["cleanup_exit_code"] = exit_code
    # Stage success is recorded only after the required cleanup has a receipt.
    data["status"] = (
        "passed" if data["status"] == "awaiting-cleanup" and exit_code == 0 else "failed"
    )
    summary.update(execution=data, status=data["status"])
    write_json(directory / "execution.json", data)
    write_json(summary_path, summary)
    if load_execution(directory) != data or json.loads(evidence_text(summary_path)) != summary:
        invalid("fuzz cleanup receipt write did not preserve the final execution")


RECOVERY_RAW_NAMES = ("corpus", "artifacts", "corpus_archive")
RECOVERY_EVIDENCE_NAMES = (
    "execution.json",
    "run_summary.json",
    "collection.ok",
    "collection-summary.json",
)


def owned_raw_root(name: str) -> Path:
    path = FUZZ_DIR / name
    if FUZZ_DIR.resolve() != FUZZ_DIR or path.is_symlink() or path.resolve() != path:
        invalid("fuzz recovery requires owned raw directory roots")
    if path.exists() and not path.is_dir():
        invalid("fuzz recovery raw root is not a directory")
    return path


def validate_collection_roots() -> None:
    # Check all roots before collection can create directories or inspect raw input.
    # Nested symlinks are archive entries, never inputs to statistics or traversal.
    for name in (*RECOVERY_RAW_NAMES, "corpus_meta"):
        owned_raw_root(name)
    for name in ("history.jsonl", "latest_run.json"):
        validate_regular_destination(META_DIR / name)


def recovery_directory(directory: Path, run_id: str, *, create: bool = False) -> Path:
    if str(uuid.UUID(run_id)) != run_id:
        invalid("malformed fuzz recovery run ID")
    owned = directory.resolve()
    configured_cache(directory)
    if any(owned.is_relative_to(FUZZ_DIR / name) for name in (*RECOVERY_RAW_NAMES, "target")):
        invalid("fuzz recovery evidence must be outside transient output roots")
    container = owned / "cleanup-recovery"
    recovery = container / run_id
    if container.is_symlink() or recovery.is_symlink():
        invalid("fuzz recovery directory cannot be a symlink")
    if create:
        recovery.mkdir(parents=True, exist_ok=False)
    if not recovery.is_dir() or recovery.resolve() != recovery:
        invalid("fuzz recovery directory is unavailable or unsafe")
    return recovery


def evidence_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_mode,
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def validate_compiled_directories(path: Path) -> None:
    release = path.parent
    cache = release.parent.parent
    deps = release / "deps"
    for directory in (cache, release.parent, release, deps):
        lexical_directory(directory)
        if directory.exists() and directory.stat().st_uid != os.geteuid():
            invalid("compiled artifact directories must be producer-owned")


def compiled_artifact_graph(path: Path, info: os.stat_result) -> dict[Path, os.stat_result]:
    validate_compiled_directories(path)
    deps = path.parent / "deps"
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink not in (1, 2)
        or info.st_size == 0
        or not info.st_mode & 0o111
        or not os.access(path, os.X_OK)
    ):
        invalid("compiled artifact must be a stable owned executable")
    graph = {path: info}
    if deps.exists():
        pattern = re.escape(path.name.replace("-", "_")) + r"-[0-9a-f]{16}"
        for peer in deps.iterdir():
            if not re.fullmatch(pattern, peer.name):
                continue
            peer_info = peer.lstat()
            if not stat.S_ISREG(peer_info.st_mode):
                invalid("compiled artifact peer must be a regular file")
            if (peer_info.st_dev, peer_info.st_ino) == (info.st_dev, info.st_ino):
                if evidence_state(peer_info) != evidence_state(info):
                    invalid("compiled artifact peer metadata differs")
                graph[peer] = peer_info
    if len(graph) != info.st_nlink:
        invalid("compiled artifact has an unaccounted or unsupported alias")
    return graph


def compiled_artifact_digest(directory: Path, data: dict[str, Any], name: str, path: Path) -> str:
    cache = configured_cache(directory)
    effective_native_commands(data["target_triple"])
    if (
        data["target_dir"] != str(cache)
        or name not in REQUIRED_TARGETS
        or name not in selected_targets()
        or name not in data["selected_targets"]
        or path != cache / data["target_triple"] / "release" / name
    ):
        invalid("compiled artifact path differs from the current selected output")
    before = path.lstat()
    graph = compiled_artifact_graph(path, before)
    with ExitStack() as stack:
        streams = {}
        for route, expected in graph.items():
            descriptor = os.open(route, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            content = stack.enter_context(os.fdopen(descriptor, "rb"))
            if evidence_state(os.fstat(content.fileno())) != evidence_state(expected):
                invalid("compiled artifact changed before reading")
            streams[route] = content
        value = hashlib.sha256()
        while block := streams[path].read(1024 * 1024):
            value.update(block)
        current_graph = compiled_artifact_graph(path, path.lstat())
        if current_graph.keys() != graph.keys() or any(
            evidence_state(current_graph[route]) != evidence_state(expected)
            or evidence_state(os.fstat(streams[route].fileno())) != evidence_state(expected)
            for route, expected in graph.items()
        ):
            invalid("compiled artifact or its peer changed while reading")
    return value.hexdigest()


@contextmanager
def open_evidence_file(path: Path, expected: os.stat_result | None = None) -> Iterator[BinaryIO]:
    lexical_directory(path.parent)
    before = path.lstat() if expected is None else expected
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as content:
        opened = os.fstat(content.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or evidence_state(opened) != evidence_state(before)
        ):
            invalid("evidence file must be a stable, unaliased regular file")
        yield content
        after = os.fstat(content.fileno())
        lexical_directory(path.parent)
        current = path.lstat()
        if evidence_state(after) != evidence_state(opened) or evidence_state(
            current
        ) != evidence_state(opened):
            invalid("evidence file changed while being read")


def evidence_snapshot(path: Path, expected: os.stat_result | None = None) -> bytes:
    with open_evidence_file(path, expected) as content:
        return content.read()


def evidence_text(path: Path) -> str:
    return evidence_snapshot(path).decode("utf-8")


def evidence_digest(path: Path, expected: os.stat_result | None = None) -> str:
    with open_evidence_file(path, expected) as content:
        value = hashlib.sha256()
        while block := content.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def copy_evidence_file(source: str, destination: str) -> str:
    path, output = Path(source), Path(destination)
    validate_regular_destination(output)
    with open_evidence_file(path) as content:
        source_info = os.fstat(content.fileno())
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
        )
        with os.fdopen(descriptor, "wb") as copied:
            opened = os.fstat(copied.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                invalid("evidence copy destination must be an unaliased regular file")
            if (opened.st_dev, opened.st_ino) == (source_info.st_dev, source_info.st_ino):
                invalid("evidence copy source and destination are the same file")
            current = output.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                invalid("evidence copy destination changed before writing")
            os.ftruncate(copied.fileno(), 0)
            shutil.copyfileobj(content, copied)
            copied.flush()
            current = output.lstat()
            after = os.fstat(copied.fileno())
            if (
                after.st_nlink != 1
                or after.st_size != source_info.st_size
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                invalid("evidence copy destination changed while writing")
            os.fchmod(copied.fileno(), stat.S_IMODE(source_info.st_mode))
            os.utime(copied.fileno(), ns=(source_info.st_atime_ns, source_info.st_mtime_ns))
    return str(output)


def raw_inventory(directory: Path) -> dict:
    inventory = {}
    if not stat.S_ISDIR(directory.lstat().st_mode):
        invalid("fuzz evidence inventory requires a regular directory root")

    def traversal_error(error: OSError) -> NoReturn:
        raise error

    for base, directories, files in os.walk(directory, followlinks=False, onerror=traversal_error):
        for entry in sorted([*directories, *files]):
            path = Path(base) / entry
            name = path.relative_to(directory).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                inventory[name] = {"type": "symlink", "target": str(path.readlink())}
            elif stat.S_ISREG(info.st_mode):
                inventory[name] = {"type": "file", "sha256": evidence_digest(path, info)}
            elif stat.S_ISDIR(info.st_mode):
                inventory[name] = {"type": "directory"}
            else:
                invalid("fuzz recovery encountered a special filesystem entry")
    return dict(sorted(inventory.items()))


def copy_raw_backups(recovery: Path) -> dict:
    raw = recovery / "raw"
    raw.mkdir()
    records = {}
    for name in RECOVERY_RAW_NAMES:
        source = owned_raw_root(name)
        present = source.exists()
        inventory = raw_inventory(source) if present else {}
        if present:
            shutil.copytree(source, raw / name, symlinks=True, copy_function=copy_evidence_file)
            if raw_inventory(raw / name) != inventory or raw_inventory(source) != inventory:
                invalid("fuzz raw evidence changed during recovery copy")
        records[name] = {"present": present, "inventory": inventory}
    return records


def backup_cleanup(directory: Path) -> str:
    data = collected_execution(directory)
    if data["status"] != "awaiting-cleanup":
        invalid("only successful current fuzz execution can prepare cleanup")
    if data["target_dir"] != str(configured_cache(directory)):
        invalid("fuzz cleanup cache differs from current execution")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = directory / name
        snapshots[name] = evidence_snapshot(path)
    recovery = recovery_directory(directory, data["run_id"], create=True)
    evidence = recovery / "evidence"
    evidence.mkdir()
    for name, content in snapshots.items():
        (evidence / name).write_bytes(content)
    records = copy_raw_backups(recovery)
    if any(evidence_snapshot(directory / name) != content for name, content in snapshots.items()):
        invalid("fuzz collection evidence changed during recovery copy")
    if source_hashes(data["selected_targets"]) != data["source"]["files"]:
        invalid("fuzz source identity changed before cleanup")
    write_json(
        recovery / "backup-ready.json",
        {
            "run_id": data["run_id"],
            "source": data["source"]["files"],
            "raw": records,
            "evidence": {name: digest(evidence / name) for name in snapshots},
        },
    )
    return data["run_id"]


def validate_raw_backups(recovery: Path, manifest: dict) -> None:
    for name, record in manifest["raw"].items():
        source = recovery / "raw" / name
        if not isinstance(record["present"], bool) or source.is_symlink():
            invalid("fuzz recovery raw presence or root is unsafe")
        if source.exists() != record["present"]:
            invalid("fuzz recovery raw copy presence changed")
        if record["present"] and (
            not source.is_dir() or raw_inventory(source) != record["inventory"]
        ):
            invalid("fuzz recovery raw copy is missing or changed")


def load_cleanup_backup(directory: Path, run_id: str) -> tuple[Path, dict, dict]:
    recovery = recovery_directory(directory, run_id)
    manifest_path = recovery / "backup-ready.json"
    if manifest_path.is_symlink():
        invalid("fuzz recovery manifest cannot be a symlink")
    manifest = json.loads(evidence_text(manifest_path))
    if manifest["run_id"] != run_id or set(manifest["raw"]) != set(RECOVERY_RAW_NAMES):
        invalid("fuzz recovery manifest does not bind the current run")
    for name in ("raw", "evidence"):
        container = recovery / name
        if container.is_symlink() or not container.is_dir() or container.resolve() != container:
            invalid("fuzz recovery container is missing or unsafe")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = recovery / "evidence" / name
        snapshot = evidence_snapshot(path)
        if hashlib.sha256(snapshot).hexdigest() != manifest["evidence"][name]:
            invalid("fuzz recovery evidence is missing or changed")
        snapshots[name] = snapshot
    data = json.loads(snapshots["execution.json"])
    marker = json.loads(snapshots["collection.ok"])
    if (
        data["run_id"] != run_id
        or marker["run_id"] != run_id
        or data["source"]["files"] != manifest["source"]
        or marker["summary_sha256"] != manifest["evidence"]["collection-summary.json"]
    ):
        invalid("fuzz recovery identity or collection receipt is inconsistent")
    validate_raw_backups(recovery, manifest)
    return recovery, manifest, snapshots


def restore_raw_copy(recovery: Path, manifest: dict) -> None:
    for name, record in manifest["raw"].items():
        destination = owned_raw_root(name)
        if destination.exists() and any(path.is_symlink() for path in destination.rglob("*")):
            invalid("fuzz restoration refuses existing symlink traversal")
        if record["present"]:
            shutil.copytree(
                recovery / "raw" / name,
                destination,
                symlinks=True,
                dirs_exist_ok=True,
                copy_function=copy_evidence_file,
            )
            if raw_inventory(destination) != record["inventory"]:
                invalid("fuzz restored evidence differs from its recovery copy")
        elif destination.exists():
            invalid("fuzz restoration found unexpected raw output")


def restore_cleanup(directory: Path, run_id: str, exit_code: int, reason: str) -> bool:
    if reason not in ("removal", "receipt"):
        invalid("unknown fuzz cleanup recovery reason")
    recovery, manifest, snapshots = load_cleanup_backup(directory, run_id)
    report = {
        "run_id": run_id,
        "reason": reason,
        "status": "restored",
        "cleanup_exit_code": exit_code,
    }
    try:
        restore_raw_copy(recovery, manifest)
    except (OSError, ValueError) as error:
        report.update(status="failed", error=str(error))
        print(
            f"[security] fuzz raw restoration failed; recovery copies retained: {error}",
            file=sys.stderr,
        )
    data = json.loads(snapshots["execution.json"])
    summary = json.loads(snapshots["run_summary.json"])
    data.update(status="failed", cleanup_exit_code=exit_code, cleanup_recovery=report)
    summary.update(status="failed", execution=data)
    try:
        for name in RECOVERY_EVIDENCE_NAMES:
            if (directory / name).is_symlink():
                invalid("fuzz evidence restoration refuses existing symlink traversal")
        for name in ("collection.ok", "collection-summary.json"):
            validate_regular_destination(directory / name)
        for name in ("collection.ok", "collection-summary.json"):
            (directory / name).write_bytes(snapshots[name])
        write_json(directory / "execution.json", data)
        write_json(directory / "run_summary.json", summary)
    except (OSError, ValueError) as error:
        report.update(status="failed", evidence_error=str(error))
        print(
            f"[security] fuzz evidence restoration failed; original evidence retained: {error}",
            file=sys.stderr,
        )
    # Preserve the verified backup and append recovery disposition, even after failure.
    write_json(recovery / f"recovery-result-{uuid.uuid4()}.json", report)
    return report["status"] == "restored"


def execution_cache(directory: Path) -> Path:
    data = load_execution(directory)
    cache = configured_cache(directory)
    if data["target_dir"] != str(cache):
        invalid("fuzz cache differs from the current execution")
    return cache


def cleanup_cache(directory: Path, run_id: str) -> Path:
    data = collected_execution(directory)
    recovery, manifest, snapshots = load_cleanup_backup(directory, run_id)
    cache = execution_cache(directory)
    if not cache.is_dir():
        invalid("fuzz current build cache is missing")
    saved = json.loads(snapshots["execution.json"])
    if data != saved or source_hashes(data["selected_targets"]) != manifest["source"]:
        invalid("fuzz cleanup cache is not bound to current recovery evidence")
    if data["target_dir"] != str(cache) or overlaps(cache, recovery):
        invalid("fuzz cleanup cache differs from current execution or overlaps recovery")
    return cache


UPLOAD_ROOTS = (
    "artifacts/security/latest",
    "artifacts/security/history",
    "fuzz/artifacts",
    "fuzz/corpus",
    "fuzz/corpus_archive",
    "fuzz/corpus_meta",
    "artifacts/sbom",
    "security-artifacts/security_status.jsonl",
)


def upload_inventory() -> dict:
    # Validate every root before any nested content hash/read.
    for name in UPLOAD_ROOTS:
        source = ROOT / name
        lexical_directory(source.parent)
        if source.is_symlink():
            invalid("upload evidence root cannot be a symlink")
        if source.exists() and not (
            source.is_dir()
            or (source.is_file() and name == "security-artifacts/security_status.jsonl")
        ):
            invalid("upload evidence root has an unsupported type")
    inventories = {}
    for name in UPLOAD_ROOTS:
        source = ROOT / name
        if not source.exists():
            inventories[name] = {"present": False}
        elif source.is_dir():
            inventories[name] = {
                "present": True,
                "type": "directory",
                "entries": raw_inventory(source),
            }
        else:
            inventories[name] = {"present": True, "type": "file", "sha256": evidence_digest(source)}
    return inventories


def add_evidence_entry(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    before = path.lstat()
    if stat.S_ISREG(before.st_mode):
        with open_evidence_file(path, before) as content:
            info = tar.gettarinfo(str(path), arcname=arcname)
            if not info.isfile() or info.size != os.fstat(content.fileno()).st_size:
                invalid("upload entry changed before archiving")
            tar.addfile(info, content)
    else:
        info = tar.gettarinfo(str(path), arcname=arcname)
        if (stat.S_ISDIR(before.st_mode) and info.isdir()) or (
            stat.S_ISLNK(before.st_mode) and info.issym()
        ):
            tar.addfile(info)
        else:
            invalid("upload encountered a changed or special entry")


def archive_raw_tree(tar: tarfile.TarFile, source: Path, arcname: str) -> None:
    inventory = raw_inventory(source)
    add_evidence_entry(tar, source, arcname)
    for entry in inventory:
        add_evidence_entry(tar, source / entry, arcname + "/" + entry)
    if raw_inventory(source) != inventory:
        invalid("raw evidence changed during archiving")


def add_upload_entry(tar: tarfile.TarFile, path: Path) -> None:
    add_evidence_entry(tar, path, path.relative_to(ROOT).as_posix())


def write_upload_archive(stream: BinaryIO, inventories: dict) -> None:
    with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as tar:
        for name, record in inventories.items():
            if not record["present"]:
                continue
            source = ROOT / name
            add_upload_entry(tar, source)
            if record["type"] == "directory":
                for entry in record["entries"]:
                    add_upload_entry(tar, source / entry)


def package_upload(directory: Path) -> None:
    cargo_home = lexical_directory(effective_cargo_home())
    if any(overlaps(cargo_home, ROOT / name) for name in UPLOAD_ROOTS) or overlaps(
        cargo_home, lexical_directory(directory)
    ):
        invalid("upload paths overlap Cargo home")
    output = lexical_directory(directory)
    if any(overlaps(output, ROOT / name) for name in UPLOAD_ROOTS):
        invalid("upload output overlaps evidence source")
    if not output.is_relative_to(ROOT / "artifacts") or output == ROOT / "artifacts":
        invalid("upload output must be a dedicated repository artifacts directory")
    if output.exists() and (output.stat().st_uid != os.geteuid() or any(output.iterdir())):
        invalid("upload output must be empty and owned by the producer")
    inventories = upload_inventory()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "security-evidence.tar.gz"
    manifest = output / "manifest.json"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".archive-", dir=output)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            write_upload_archive(stream, inventories)
        if upload_inventory() != inventories:
            invalid("upload evidence changed during packaging")
        temporary.replace(archive)
        write_json(
            manifest,
            {
                "schema_version": 1,
                "producer_uid": os.geteuid(),
                "stage": os.environ.get("SECURITY_UPLOAD_STAGE", "unknown"),
                "stage_outcome": os.environ.get("SECURITY_UPLOAD_OUTCOME", "unknown"),
                "roots": inventories,
                "archive": {"path": archive.name, "sha256": digest(archive)},
            },
        )
        for path in (archive, manifest):
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid():
                invalid("upload output must be a producer-owned regular file")
    finally:
        temporary.unlink(missing_ok=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--validate-git-environment", action="store_true")
    actions.add_argument("--validate-cache", type=Path)
    actions.add_argument("--validate-preflight", type=Path)
    actions.add_argument("--package-upload", type=Path)
    actions.add_argument("--cleanup-cache", nargs=2, metavar=("DIR", "RUN_ID"))
    actions.add_argument("--execution-cache", type=Path)
    actions.add_argument("--prepare-run", type=Path)
    actions.add_argument("--record-environment", type=Path)
    actions.add_argument("--record-target", nargs=4, metavar=("DIR", "TARGET", "PHASE", "EXIT"))
    actions.add_argument("--finish-run", nargs=2, metavar=("DIR", "EXIT"))
    actions.add_argument("--cleanup-result", nargs=2, metavar=("DIR", "EXIT"))
    actions.add_argument("--backup-cleanup", type=Path)
    actions.add_argument("--restore-cleanup", nargs=4, metavar=("DIR", "RUN_ID", "EXIT", "REASON"))
    return parser.parse_args()


def cleanup_action(args: argparse.Namespace) -> int | None:
    result = None
    if args.validate_git_environment:
        validate_git_environment()
        result = 0
    elif args.validate_preflight:
        validate_preflight(args.validate_preflight)
        result = 0
    elif args.validate_cache:
        configured_cache(args.validate_cache)
        result = 0
    elif args.execution_cache:
        print(str(execution_cache(args.execution_cache)) + "\n.", end="")
        result = 0
    elif args.cleanup_cache:
        directory, run_id = args.cleanup_cache
        print(str(cleanup_cache(Path(directory), run_id)) + "\n.", end="")
        result = 0
    elif args.cleanup_result:
        directory, code = args.cleanup_result
        cleanup_result(Path(directory), int(code))
        result = 0
    elif args.backup_cleanup:
        print(backup_cleanup(args.backup_cleanup))
        result = 0
    elif args.restore_cleanup:
        directory, run_id, code, reason = args.restore_cleanup
        result = (
            0 if restore_cleanup(Path(directory), run_id, int(code), reason) else EVIDENCE_ERROR
        )
    return result


def validate_action_routes(args: argparse.Namespace) -> None:
    for name in (
        "prepare_run",
        "record_environment",
        "execution_cache",
        "validate_cache",
        "validate_preflight",
        "backup_cleanup",
    ):
        action = getattr(args, name)
        if action is not None:
            setattr(args, name, validate_evidence_route(action))
            validate_collection_roots()
    for name in (
        "cleanup_cache",
        "record_target",
        "finish_run",
        "cleanup_result",
    ):
        action = getattr(args, name)
        if action is not None:
            action[0] = str(validate_evidence_route(Path(action[0])))
            validate_collection_roots()
    if args.restore_cleanup is not None:
        # Raw-root failures belong to restore_cleanup's recovery error handler.
        args.restore_cleanup[0] = str(validate_evidence_route(Path(args.restore_cleanup[0])))


def record_target_action(action: list[str]) -> int:
    directory, name, phase, code = action
    if phase not in ("build", "run"):
        invalid("unknown execution phase")
    return 0 if record_target(Path(directory), name, phase, int(code)) else 1


def main() -> int:
    args = parse_arguments()
    result = 0
    try:
        if args.package_upload:
            package_upload(args.package_upload)
            return 0
        validate_compiler_environment()
        validate_action_routes(args)
        recovery_result = cleanup_action(args)
        if recovery_result is not None:
            result = recovery_result
        elif args.prepare_run:
            prepare_run(args.prepare_run)
        elif args.record_environment:
            record_environment(args.record_environment)
        elif args.record_target:
            result = record_target_action(args.record_target)
        elif args.finish_run:
            directory, code = args.finish_run
            result = 0 if finish_run(Path(directory), int(code)) else 1
        else:
            collect_corpus()
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"[security] fuzz evidence failed: {error}", file=sys.stderr)
        result = EVIDENCE_ERROR
    return result


if __name__ == "__main__":
    raise SystemExit(main())
