"""Bounded native observation protocol with retained output and strict admission."""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dudect_results import NONDETECTION, PROFILES, CaseAdmission, invalid

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import IO


class NativeError(ValueError):
    def __init__(self, code: int) -> None:
        super().__init__(f"Native dudect process failed ({code})")
        self.code = code if code > 0 else 128 - code


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            invalid(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value: str) -> Any:
    invalid(f"Non-finite JSON constant: {value}")


def load_json(data: str | bytes) -> Any:
    return json.loads(data, object_pairs_hook=strict_object, parse_constant=reject_constant)


@dataclass
class ObservationStream:
    cases: tuple[str, ...]
    profile: str
    before_observation: Callable[[], None] | None = None
    index: int = 0
    buffer: bytes = b""
    total: int = 0
    decisions: list[dict[str, Any]] = field(default_factory=list)
    histories: dict[str, list[Any]] = field(init=False)
    admission: CaseAdmission = field(init=False)

    def __post_init__(self) -> None:
        self.histories = {name: [] for name in self.cases}
        self.admission = CaseAdmission(self.cases[0], self.profile)

    def observe(self, line: bytes) -> None:
        if self.index >= len(self.cases):
            invalid("Unexpected extra native observation")
        data = load_json(line)
        self.histories[self.cases[self.index]].append(data)
        result = self.admission.admit(data)
        self.decisions.append(result)
        if result["outcome"] not in ("collecting", NONDETECTION):
            invalid(f"dudect {self.cases[self.index]}: {result['outcome']}")
        if result["outcome"] == NONDETECTION:
            self.index += 1
            if self.index < len(self.cases):
                self.admission = CaseAdmission(self.cases[self.index], self.profile)

    def consume(self, chunk: bytes, acknowledgments: IO[bytes]) -> None:
        self.total += len(chunk)
        self.buffer += chunk
        if self.total > 16 * 1024 * 1024 or len(self.buffer) > 1024 * 1024:
            invalid("Native dudect output exceeded its bound")
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if self.before_observation is not None:
                self.before_observation()
            self.observe(line)
            acknowledgments.write(b"c")
            acknowledgments.flush()

    def finish(self, code: int) -> None:
        if code:
            raise NativeError(code)
        if self.buffer or self.index != len(self.cases):
            invalid(f"Incomplete native dudect execution (exit {code})")


def receive(
    process: subprocess.Popen[bytes],
    output: IO[bytes],
    stream: ObservationStream,
    deadline: float,
    *,
    case_budget: float | None = None,
) -> None:
    if process.stdout is None or process.stdin is None:
        invalid("Native observation pipes are missing")
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                invalid("Native dudect deadline reached: inconclusive")
            for key, _ in selector.select(min(1.0, remaining)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                output.write(chunk)
                output.flush()
                if case_budget is not None and time.monotonic() >= deadline:
                    invalid("Native dudect case deadline reached: inconclusive")
                previous_case = stream.index
                stream.consume(chunk, process.stdin)
                if case_budget is not None and previous_case < stream.index < len(stream.cases):
                    completed = time.monotonic()
                    if completed >= deadline:
                        invalid("Native dudect case deadline reached: inconclusive")
                    # Only a fully collected case starts the next budget.
                    # Individual looks cannot renew it, and successful process
                    # exit must fit within the final case's remaining budget.
                    deadline = completed + case_budget
    stream.finish(process.wait(timeout=max(0.001, deadline - time.monotonic())))


def terminate(process: subprocess.Popen[bytes]) -> int:
    # Always clean the owned group, including children surviving the leader.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    code = process.wait()
    if process.stdin is not None:
        process.stdin.close()
    if process.stdout is not None:
        process.stdout.close()
    return code


def run_native(
    root: Path,
    evidence: Path,
    binary: Path,
    cases: tuple[str, ...],
    profile: str,
) -> dict[str, list[Any]]:
    label = binary.name.removesuffix("_timing_test")
    stream = ObservationStream(cases, profile)
    argv = [str(binary), profile]
    status: dict[str, Any] = {"argv": argv, "accepted": False}
    started = time.monotonic()
    budget = PROFILES[profile][2]
    process = None
    try:
        with (
            (evidence / f"{label}.stdout").open("wb") as output,
            (evidence / f"{label}.stderr").open("wb") as errors,
        ):
            process = subprocess.Popen(  # noqa: S603 - explicit argv for the compiled binary
                argv,
                cwd=root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                start_new_session=True,
            )
            receive(process, output, stream, started + budget)
            status["accepted"] = True
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        status["error"] = str(error)
        raise
    finally:
        if process is not None:
            status["exit"] = terminate(process)
        status["elapsed_seconds"] = time.monotonic() - started
        records = {
            "process": status,
            "observations": stream.histories,
            "decisions": stream.decisions,
        }
        for suffix, value in records.items():
            (evidence / f"{label}.{suffix}.json").write_text(
                json.dumps(value, allow_nan=False) + "\n",
                encoding="utf-8",
            )
    return stream.histories
