#!/usr/bin/env python3
"""Maintain fuzz corpus metadata and archives.

This script ensures corpus directories exist for all fuzz targets,
captures per-target statistics, appends them to a history log, and
archives the current corpus with simple generation control.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tarfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - older Python fallback
    import tomli as tomllib  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]
FUZZ_DIR = ROOT / "fuzz"
CORPUS_ROOT = FUZZ_DIR / "corpus"
META_DIR = FUZZ_DIR / "corpus_meta"
ARCHIVE_DIR = FUZZ_DIR / "corpus_archive"
CRASH_ROOT = FUZZ_DIR / "artifacts"
HISTORY_FILE = META_DIR / "history.jsonl"
MAX_SAMPLE_FILES = 10


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
    names = [b.get("name", "") for b in bins if b.get("name", "").startswith("fuzz_")]
    return sorted(set(filter(None, names)))


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

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    archive_path = ARCHIVE_DIR / f"{timestamp}.tar.gz"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "w:gz") as tar:
        if CORPUS_ROOT.exists():
            tar.add(CORPUS_ROOT, arcname="corpus")

    archives = sorted(ARCHIVE_DIR.glob("*.tar.gz"))
    excess = len(archives) - keep_archives
    for old in archives[:-keep_archives] if excess > 0 else []:
        with suppress(OSError):
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
    try:
        shutil.copy2(path, dest_path)
    except OSError:
        return None
    return dest_path


def archive_crashes(stats: list[CrashStat], dest_dir: Path | None) -> Path | None:
    total = sum(s.file_count for s in stats)
    if total == 0:
        return None

    target_dir = dest_dir or META_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
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
) -> None:
    summary = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "targets": [s.as_dict() for s in stats],
        "crashes": [c.as_dict() for c in crash_stats],
        "corpus_archive": corpus_archive.name if corpus_archive else None,
        "crash_archive": crash_archive.name if crash_archive else None,
    }

    META_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = META_DIR / "latest_run.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    if RUN_ARTIFACT_DIR is not None:
        RUN_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(summary_path, RUN_ARTIFACT_DIR / "run_summary.json")

    if HISTORY_OUT_DIR is not None:
        HISTORY_OUT_DIR.mkdir(parents=True, exist_ok=True)
        with (HISTORY_OUT_DIR / "fuzz_runs.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary, ensure_ascii=False) + "\n")


def main() -> None:
    targets = load_targets()
    if not targets:
        print("[WARN] No fuzz targets discovered; skipping corpus maintenance", flush=True)
        return

    ensure_directories(targets)
    stats = gather_stats(targets)
    append_history(stats)
    total_files = sum(s.file_count for s in stats)
    archive = create_archive() if total_files > 0 else None
    crash_stats = gather_crash_stats()
    crash_archive = archive_crashes(crash_stats, RUN_ARTIFACT_DIR)

    archive_copy = copy_into(archive, RUN_ARTIFACT_DIR) if archive and RUN_ARTIFACT_DIR else archive
    if archive and HISTORY_OUT_DIR:
        copy_into(archive, HISTORY_OUT_DIR)
    if crash_archive and HISTORY_OUT_DIR:
        copy_into(crash_archive, HISTORY_OUT_DIR)

    write_run_summary(stats, crash_stats, archive_copy or archive, crash_archive)

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


if __name__ == "__main__":
    main()
