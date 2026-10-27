"""Collect corpus/crash statistics and preserve run evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from fuzz_support.archives import (
    write_exclusive_archive,
)
from fuzz_support.filesystem import (
    ARCHIVE_DIR,
    CORPUS_ROOT,
    CRASH_ROOT,
    HISTORY_FILE,
    HISTORY_OUT_DIR,
    MAX_SAMPLE_FILES,
    META_DIR,
    RUN_ARTIFACT_DIR,
    copy_evidence_file,
    evidence_text,
    invalid,
    parse_env_int,
    validate_collection_history,
    validate_collection_roots,
    validate_regular_destination,
    write_json,
)
from fuzz_support.source import (
    load_targets,
    validate_evidence_route,
)


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

    roots = [(CORPUS_ROOT, "corpus")] if CORPUS_ROOT.exists() else []
    write_exclusive_archive(archive_path, roots, keep_archives)

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
    roots = [(CRASH_ROOT / entry.name, entry.name) for entry in stats if entry.file_count > 0]
    write_exclusive_archive(archive_path, roots)
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
