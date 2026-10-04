"""Bind required fuzz build/run results to source, commands and executables."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fuzz_support.collection import (
    collect_corpus,
)
from fuzz_support.filesystem import (
    EVIDENCE_ERROR,
    MIN_FUZZ_SECONDS,
    REQUIRED_TARGETS,
    ROOT,
    WATCHDOG_GRACE_SECONDS,
    capture,
    digest,
    evidence_snapshot,
    evidence_state,
    evidence_text,
    invalid,
    lexical_directory,
    seconds,
    write_json,
)
from fuzz_support.source import (
    configured_cache,
    effective_native_commands,
    prepared_source_inputs,
    selected_targets,
    source_hashes,
    validate_compiler_environment,
    validate_git_environment,
    validate_preflight,
)


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


def execution_cache(directory: Path) -> Path:
    data = load_execution(directory)
    cache = configured_cache(directory)
    if data["target_dir"] != str(cache):
        invalid("fuzz cache differs from the current execution")
    return cache
