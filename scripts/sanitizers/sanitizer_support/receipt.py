"""Replay the controller's own admission rules without launching commands."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sanitizer_options import cargo_flags

from sanitizer_support.core import Settings, duration, parse_json, require, selection
from sanitizer_support.evidence import checked_summary, replace_summary
from sanitizer_support.execution import Supervisor

if TYPE_CHECKING:
    from sanitizer_support.evidence import Directory


class Replay(Supervisor):
    """Use the same orchestration with bound raw streams instead of process launches."""

    def __init__(self, directory: Directory, commands: list[dict[str, Any]]) -> None:
        require(isinstance(commands, list) and commands, "Missing sanitizer commands")
        super().__init__(directory.path, {"commands": [], "units": []})
        self.evidence.directory = directory
        self.records = iter(commands)

    def save(self) -> None:
        # Validation computes a projection; it never writes a successful receipt.
        pass

    def command(
        self,
        args: list[str],
        _environment: dict[str, str],
        seconds: float,
        phase: str,
        *,
        echo: bool = False,
    ) -> str:
        del echo
        record = next(self.records, None)
        require(isinstance(record, dict), "Missing completed sanitizer command")
        self.counter += 1
        require(
            record.get("phase") == phase
            and record.get("args") == args
            and record.get("status") == "completed"
            and type(record.get("deadline_seconds")) in {int, float}
            and record["deadline_seconds"] == seconds
            and type(record.get("exit_code")) is int
            and record["exit_code"] == 0
            and record.get("timed_out") is False
            and record.get("lingering_descendants") is False,
            "Incomplete or unrelated sanitizer command",
        )
        prefix = f"{self.counter:03d}-{phase}"
        for channel in ("stdout", "stderr"):
            name = f"{prefix}.{channel}.log"
            require(record.get(channel) == str(self.artifacts / name), "Unbound command log")
            raw = self.evidence.read(name)
            if channel == "stdout":
                output = raw
        return output


def reject_completed(directory: Directory, error: Exception) -> None:
    """Preserve rejected success bytes, then leave an explicit failed current result."""
    with directory.open() as descriptor:
        _, raw, receipt = checked_summary(descriptor)
        if receipt.get("status") != "completed":
            return
        name = "rejected-summary-" + secrets.token_hex(16) + ".json"
        archived = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=descriptor,
        )
        with os.fdopen(archived, "wb") as stream:
            stream.write(raw)
        receipt.update(
            status="failed",
            stage="receipt-admission",
            exit_code=1,
            error=str(error),
            rejected_summary=name,
        )
        replace_summary(descriptor, receipt)


def admitted_settings(summary: dict[str, Any], directory: Directory, target_root: Path) -> Settings:
    fields = summary.get("settings")
    require(
        isinstance(fields, dict) and all(isinstance(value, str) for value in fields.values()),
        "Missing controller settings",
    )
    settings = Settings(**fields)
    require(
        settings.artifact_text == str(directory.path) and settings.target_text == str(target_root),
        "Controller output routes mismatch",
    )
    packages = selection(os.environ.get("SANITIZER_TARGETS") or "ffi", "package")
    sanitizers = selection(os.environ.get("SANITIZERS") or "address", "sanitizer")
    require(
        selection(settings.package_text, "package") == packages
        and selection(settings.sanitizer_text, "sanitizer") == sanitizers,
        "Controller selection mismatch",
    )
    require(
        cargo_flags(settings.extra_text, settings.build_extra_text)
        == cargo_flags(
            os.environ.get("SANITIZER_CARGO_FLAGS", ""),
            os.environ.get("SANITIZER_BUILD_EXTRA_ARGS", ""),
        ),
        "Controller options mismatch",
    )
    fallback = os.environ.get("SANITIZER_TIMEOUT") or "120"
    require(
        duration(settings.build_limit_text)
        == duration(os.environ.get("SANITIZER_BUILD_TIMEOUT") or fallback)
        and duration(settings.run_limit_text)
        == duration(os.environ.get("SANITIZER_RUN_TIMEOUT") or fallback)
        and duration(settings.grace_text)
        == duration(os.environ.get("SANITIZER_TIMEOUT_KILL") or "130"),
        "Controller deadline mismatch",
    )
    require(
        settings.host not in {".", ".."}
        and settings.host
        and Path(settings.host).name == settings.host
        and summary.get("host") == settings.host,
        "Invalid native host",
    )
    require(Path(settings.cargo).is_absolute(), "Unbound Cargo route")
    return settings


def validate_completed(directory: Directory, snapshot: str, target_root: Path) -> None:
    with directory.open() as descriptor:
        info, raw, summary = checked_summary(descriptor)
    initial = parse_json(snapshot)
    require(
        [info.st_dev, info.st_ino] != initial["identity"]
        and raw != bytes.fromhex(initial["content"]),
        "Sanitizer launcher did not replace its initialization receipt",
    )
    require(
        summary.get("invocation") == {**directory.binding(), "initial_summary": initial},
        "Sanitizer receipt belongs to another invocation",
    )
    require(
        summary.get("status") == "completed"
        and type(summary.get("exit_code")) is int
        and summary["exit_code"] == 0
        and not {"error", "logging_error", "preflight_phase", "cleanup_exit_code"}.intersection(
            summary
        ),
        "Missing normal sanitizer completion",
    )
    workspace = Path.cwd().resolve()
    require(summary.get("workspace") == str(workspace), "Sanitizer workspace mismatch")
    settings = admitted_settings(summary, directory, target_root)
    replay = Replay(directory, summary.get("commands"))
    replay.execute(settings, workspace)
    require(next(replay.records, None) is None, "Unexpected extra sanitizer commands")
    require(
        all(
            summary.get(key) == value for key, value in replay.summary.items() if key != "commands"
        ),
        "Sanitizer execution projection mismatch",
    )
    with directory.open() as descriptor:
        current, current_raw, _ = checked_summary(descriptor)
    require(
        (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and current_raw == raw,
        "Sanitizer receipt changed during admission",
    )
