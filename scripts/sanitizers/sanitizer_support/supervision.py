"""Own command streams, deadlines, process groups and bound execution receipts."""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO

from sanitizer_support.core import Failure, Interrupted, failure, require
from sanitizer_support.evidence import EvidenceStore


def group_alive(pgid: int) -> bool:
    # A reparented zombie has exited; it is not a running descendant. Linux is
    # also the platform of the existing lib/linux ASan runtime configuration.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def terminate(process: subprocess.Popen[bytes], grace: float) -> bool:
    try:
        active = group_alive(process.pid)
        if active:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            deadline = time.monotonic() + grace
            while group_alive(process.pid) and time.monotonic() < deadline:
                time.sleep(0.01)
            if group_alive(process.pid):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while group_alive(process.pid) and time.monotonic() < deadline:
                time.sleep(0.01)
        process.wait(timeout=5)
        require(not group_alive(process.pid), "Sanitizer descendants survived cleanup")
    except Exception:
        # Failed /proc inspection cannot skip stopping our owned process group.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise
    return active


def interrupted(signum: int, _frame: object) -> None:
    raise Interrupted(signum)


class CommandSupervisor:
    """Own capture, process cleanup and evidence for each command."""

    def __init__(self, artifacts: Path, summary: dict[str, Any], kill_grace: float = 1) -> None:
        self.artifacts = artifacts
        self.summary = summary
        self.kill_grace = kill_grace
        self.counter = 0
        self.evidence = EvidenceStore(artifacts)

    def save(self) -> None:
        self.evidence.save(self.summary)

    def capture(
        self,
        process: subprocess.Popen[bytes],
        streams: tuple[BinaryIO, BinaryIO],
        record: dict[str, Any],
        started: float,
        *,
        echo: bool,
    ) -> None:
        """Drain both pipes while enforcing one deadline and descendant cleanup."""
        with selectors.DefaultSelector() as selector:
            for pipe, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() - started >= record["deadline_seconds"]:
                    record["timed_out"] = True
                    terminate(process, self.kill_grace)
                    # Failure keeps the captured prefix. An escaped pipe holder
                    # cannot extend the command deadline by withholding EOF.
                    break
                if process.poll() is not None and group_alive(process.pid):
                    record["lingering_descendants"] = terminate(process, self.kill_grace)
                for key, _ in selector.select(0.02):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    index = int(key.data == "stderr")
                    streams[index].write(data)
                    if echo:
                        output = sys.stderr.buffer if index else sys.stdout.buffer
                        output.write(data)
                        output.flush()
            process.wait(timeout=5)

    def finish_command(
        self, record: dict[str, Any], error: Exception | None, original_status: int | None
    ) -> None:
        status, phase = record.get("exit_code"), record["phase"]
        timed_out, lingering = record["timed_out"], record["lingering_descendants"]
        record["status"] = (
            "failed" if error or timed_out or lingering or status != 0 else "completed"
        )
        # Child termination during cleanup must not replace the signal that
        # interrupted supervision. Other cleanup errors preserve an observed
        # child failure, including errors raised by our own cleanup checks.
        if isinstance(error, Interrupted):
            failure_status = error.status
        elif error:
            failure_status = original_status or getattr(error, "status", 1)
        else:
            failure_status = status or 1
        if timed_out:
            failure_status = 124
        try:
            self.save()
        except Exception as save_error:
            message = f"{phase} evidence write failed: {save_error}"
            raise Failure(
                message,
                getattr(save_error, "status", 1)
                if record["status"] == "completed"
                else failure_status,
            ) from save_error
        if timed_out:
            failure(f"{phase} exceeded its deadline", 124)
        if error:
            failure(f"{phase} capture/cleanup failed: {error}", failure_status)
        if status != 0:
            failure(f"{phase} failed with exit {status}", status or 1)
        require(not lingering, f"{phase} left running descendants")

    def command(
        self,
        args: list[str],
        environment: dict[str, str],
        seconds: float,
        phase: str,
        *,
        echo: bool = False,
    ) -> str:
        self.counter += 1
        prefix = self.artifacts / f"{self.counter:03d}-{phase}"
        record = {
            "args": args,
            "phase": phase,
            "deadline_seconds": seconds,
            "status": "not-started",
            "timed_out": False,
            "lingering_descendants": False,
        }
        self.summary["commands"].append(record)
        process = None
        started = time.monotonic()
        error = None
        original_status = None
        try:
            with (
                self.evidence.log(prefix.with_suffix(".stdout.log").name) as out,
                self.evidence.log(prefix.with_suffix(".stderr.log").name) as err,
            ):
                process = subprocess.Popen(  # noqa: S603 - admitted Cargo/test/tool argv, no shell
                    args,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                record.update(pid=process.pid, status="running")
                self.capture(process, (out, err), record, started, echo=echo)
        except Exception as caught:  # noqa: BLE001 - every capture/interruption failure requires cleanup
            original_status = process.poll() if process is not None else None
            error = caught
        finally:
            if process is not None:
                original_status = process.poll() if original_status is None else original_status
                try:
                    # One final cleanup also catches descendants that closed their
                    # output before a normal leader exited; keep its observed status.
                    record["lingering_descendants"] = (
                        terminate(process, self.kill_grace) or record["lingering_descendants"]
                    )
                except Exception as caught:  # noqa: BLE001 - retain a previously observed exit
                    error = error or caught
                record["exit_code"] = process.poll()
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        pipe.close()
            record.update(
                elapsed_seconds=time.monotonic() - started,
                stdout=str(prefix.with_suffix(".stdout.log")),
                stderr=str(prefix.with_suffix(".stderr.log")),
            )
        self.finish_command(record, error, original_status)
        return self.evidence.read(prefix.with_suffix(".stdout.log").name)
