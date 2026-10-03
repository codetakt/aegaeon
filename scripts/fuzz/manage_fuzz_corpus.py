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
import re
import shutil
import subprocess
import sys
import tarfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

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
    return Path(value)


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

    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
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
    CORPUS_ROOT.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    for target in targets:
        (CORPUS_ROOT / target).mkdir(parents=True, exist_ok=True)


def gather_stats(targets: list[str]) -> list[CorpusStat]:
    stats: list[CorpusStat] = []
    for target in targets:
        path = CORPUS_ROOT / target
        file_count = 0
        size_bytes = 0
        latest_mtime: float | None = None
        if path.exists():
            for file in path.rglob("*"):
                if file.is_file():
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
            with HISTORY_FILE.open("r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        lines.append(json.dumps(record, ensure_ascii=False))
        lines = lines[-limit:]
        with HISTORY_FILE.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    else:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def create_archive() -> Path | None:
    keep_archives = parse_env_int("CORPUS_ARCHIVE_KEEP", 3)
    if keep_archives <= 0:
        return None

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = ARCHIVE_DIR / f"{timestamp}.tar.gz"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "w:gz") as tar:
        if CORPUS_ROOT.exists():
            tar.add(CORPUS_ROOT, arcname="corpus")

    archives = sorted(ARCHIVE_DIR.glob("*.tar.gz"))
    excess = len(archives) - keep_archives
    for old in archives[:-keep_archives] if excess > 0 else []:
        old.unlink()

    return archive_path


def gather_crash_stats() -> list[CrashStat]:
    stats: list[CrashStat] = []
    if not CRASH_ROOT.exists():
        return stats

    for target_dir in sorted(CRASH_ROOT.iterdir()):
        if not target_dir.is_dir():
            continue
        file_count = 0
        size_bytes = 0
        latest_mtime: float | None = None
        samples: list[str] = []
        for file in sorted(target_dir.rglob("*")):
            if not file.is_file():
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
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / path.name
    if dest_path.exists() and not dest_path.is_file():
        message = f"archive destination is not a file: {dest_path}"
        raise OSError(message)
    shutil.copy2(path, dest_path)
    return dest_path


def archive_crashes(stats: list[CrashStat], dest_dir: Path | None) -> Path | None:
    total = sum(s.file_count for s in stats)
    if total == 0:
        return None

    target_dir = dest_dir or META_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = target_dir / f"crashes_{timestamp}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for stat in stats:
            if stat.file_count > 0:
                tar.add(CRASH_ROOT / stat.name, arcname=stat.name)
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
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    if RUN_ARTIFACT_DIR is not None:
        RUN_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        (RUN_ARTIFACT_DIR / "run_summary.json").write_bytes(summary_path.read_bytes())

    if HISTORY_OUT_DIR is not None:
        HISTORY_OUT_DIR.mkdir(parents=True, exist_ok=True)
        with (HISTORY_OUT_DIR / "fuzz_runs.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary, ensure_ascii=False) + "\n")


def collect_corpus(execution: dict | None = None) -> None:
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


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


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
    result["sha256"] = digest(Path(path))
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
    manifest = tomllib.loads((FUZZ_DIR / "Cargo.toml").read_text(encoding="utf-8"))
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


def source_hashes(selected: list[str]) -> dict:
    source_files = [
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
    source_files = [required_source(path) for path in source_files]
    source_files.extend(selected_sources(selected))
    source_files.extend(
        required_source(path) for path in sorted((FUZZ_DIR / "fuzz_targets").glob("*.rs"))
    )
    return {str(path.relative_to(ROOT)): digest(path) for path in source_files}


def prepare_run(directory: Path) -> None:
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
    tools = {
        name: capture(argv)
        for name, argv in {
            "rustc": ["rustc", "-vV"],
            "cargo": ["cargo", "--version"],
            "cargo_fuzz": ["cargo-fuzz", "--version"],
            "timeout": ["timeout", "--version"],
            "cc": [os.environ.get("CC") or "cc", "--version"],
            "cxx": [os.environ.get("CXX") or "c++", "--version"],
        }.items()
    }
    host = re.search(r"^host: (\S+)$", tools["rustc"]["output"], re.MULTILINE)
    target = host[1] if host and tools["rustc"]["exit_code"] == 0 else "missing"
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
        "target_dir": str(Path(os.environ["CARGO_TARGET_DIR"]).resolve() / "fuzz"),
        "profile": "release with debug assertions",
        "sanitizer": "address",
        "source": {
            "commit": capture(["git", "rev-parse", "HEAD"]),
            "tree": capture(["git", "rev-parse", "HEAD^{tree}"]),
            "files": source_hashes(selected),
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
    data = json.loads((directory / "execution.json").read_text(encoding="utf-8"))
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
    record = {
        "status": "failed",
        "exit_code": exit_code,
        "argv": command,
        "log": str(log.resolve()),
        "log_sha256": digest(log),
    }
    binary = Path(data["target_dir"]) / data["target_triple"] / "release" / name
    if exit_code == 0:
        try:
            if not binary.is_file() or not os.access(binary, os.X_OK) or binary.stat().st_size == 0:
                invalid("built fuzz executable is missing or empty")
            record["executable"] = str(binary)
            record["executable_sha256"] = digest(binary)
            if phase == "run":
                if (
                    row["build"].get("status") != "passed"
                    or record["executable_sha256"] != row["build"]["executable_sha256"]
                ):
                    invalid("run executable differs from the successful build")
                completion = re.search(
                    r"^Done ([0-9]+) runs in ([0-9]+) second", log.read_text(), re.MULTILINE
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


def validate_phase(directory: Path, row: dict, phase: str) -> bool:
    record = row[phase]
    if record["status"] not in ("not-run", "passed", "failed"):
        invalid("malformed fuzz execution status")
    if record["status"] == "not-run":
        return False
    log = directory / row["name"] / f"{phase}.log"
    if record["log"] != str(log.resolve()) or record["log_sha256"] != digest(log):
        invalid("fuzz execution log is missing or changed")
    if record["status"] == "passed" and (
        record["exit_code"] != 0
        or digest(Path(record["executable"])) != record["executable_sha256"]
    ):
        invalid("fuzz executable or exit evidence is inconsistent")
    return record["status"] == "passed"


def finish_run(directory: Path, exit_code: int) -> bool:
    data = load_execution(directory)
    passed = exit_code == 0
    for row in data["targets"]:
        for phase in ("build", "run"):
            if not validate_phase(directory, row, phase):
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
        collected_summary.write_bytes((directory / "run_summary.json").read_bytes())
        write_json(
            directory / "collection.ok",
            {
                "run_id": data["run_id"],
                "summary_file": "collection-summary.json",
                "summary_sha256": digest(collected_summary),
            },
        )
    return passed


def collected_execution(directory: Path) -> dict:
    data = load_execution(directory)
    summary_path = directory / "run_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    marker = json.loads((directory / "collection.ok").read_text(encoding="utf-8"))
    collected_summary = directory / "collection-summary.json"
    if (
        summary["execution"] != data
        or summary != json.loads(collected_summary.read_text(encoding="utf-8"))
        or marker["run_id"] != data["run_id"]
        or marker["summary_file"] != "collection-summary.json"
        or marker["summary_sha256"] != digest(collected_summary)
    ):
        invalid("fuzz collection receipt is missing or inconsistent")
    return data


def cleanup_result(directory: Path, exit_code: int) -> None:
    data = collected_execution(directory)
    summary_path = directory / "run_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    data["cleanup_exit_code"] = exit_code
    # Stage success is recorded only after the required cleanup has a receipt.
    data["status"] = (
        "passed" if data["status"] == "awaiting-cleanup" and exit_code == 0 else "failed"
    )
    summary.update(execution=data, status=data["status"])
    write_json(directory / "execution.json", data)
    write_json(summary_path, summary)
    if (
        load_execution(directory) != data
        or json.loads(summary_path.read_text(encoding="utf-8")) != summary
    ):
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


def recovery_directory(directory: Path, run_id: str, *, create: bool = False) -> Path:
    if str(uuid.UUID(run_id)) != run_id:
        invalid("malformed fuzz recovery run ID")
    owned = directory.resolve()
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


def raw_inventory(directory: Path) -> dict:
    inventory = {}
    for path in sorted(directory.rglob("*")):
        name = path.relative_to(directory).as_posix()
        if path.is_symlink():
            inventory[name] = {"type": "symlink", "target": str(path.readlink())}
        elif path.is_file():
            inventory[name] = {"type": "file", "sha256": digest(path)}
        elif path.is_dir():
            inventory[name] = {"type": "directory"}
        else:
            invalid("fuzz recovery encountered a special filesystem entry")
    return inventory


def copy_raw_backups(recovery: Path) -> dict:
    raw = recovery / "raw"
    raw.mkdir()
    records = {}
    for name in RECOVERY_RAW_NAMES:
        source = owned_raw_root(name)
        present = source.exists()
        inventory = raw_inventory(source) if present else {}
        if present:
            shutil.copytree(source, raw / name, symlinks=True)
            if raw_inventory(raw / name) != inventory or raw_inventory(source) != inventory:
                invalid("fuzz raw evidence changed during recovery copy")
        records[name] = {"present": present, "inventory": inventory}
    return records


def backup_cleanup(directory: Path) -> str:
    data = collected_execution(directory)
    if data["status"] != "awaiting-cleanup":
        invalid("only successful current fuzz execution can prepare cleanup")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            invalid("fuzz collection evidence must be regular files")
        snapshots[name] = path.read_bytes()
    recovery = recovery_directory(directory, data["run_id"], create=True)
    evidence = recovery / "evidence"
    evidence.mkdir()
    for name, content in snapshots.items():
        (evidence / name).write_bytes(content)
    records = copy_raw_backups(recovery)
    if any((directory / name).read_bytes() != content for name, content in snapshots.items()):
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
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["run_id"] != run_id or set(manifest["raw"]) != set(RECOVERY_RAW_NAMES):
        invalid("fuzz recovery manifest does not bind the current run")
    for name in ("raw", "evidence"):
        container = recovery / name
        if container.is_symlink() or not container.is_dir() or container.resolve() != container:
            invalid("fuzz recovery container is missing or unsafe")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = recovery / "evidence" / name
        if path.is_symlink() or not path.is_file() or digest(path) != manifest["evidence"][name]:
            invalid("fuzz recovery evidence is missing or changed")
        snapshots[name] = path.read_bytes()
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
            shutil.copytree(recovery / "raw" / name, destination, symlinks=True, dirs_exist_ok=True)
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
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
    if args.cleanup_result:
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


def main() -> int:
    args = parse_arguments()
    result = 0
    try:
        recovery_result = cleanup_action(args)
        if recovery_result is not None:
            result = recovery_result
        elif args.prepare_run:
            prepare_run(args.prepare_run)
        elif args.record_environment:
            record_environment(args.record_environment)
        elif args.record_target:
            directory, name, phase, code = args.record_target
            if phase not in ("build", "run"):
                invalid("unknown execution phase")
            result = 0 if record_target(Path(directory), name, phase, int(code)) else 1
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
