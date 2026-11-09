"""Bound one Python test controller and its orphaned children on Linux.

The single-thread supervisor is a subreaper with no other child producers.
Recovery uses pidfds for its direct children, including adopted separate sessions.
This test-only boundary does not guarantee recovery after supervisor or OS failure.
"""

from __future__ import annotations

# ruff: noqa: EM101, TRY003, TRY301 - fixed fixture errors stay inside the owning cleanup boundary.
import ctypes
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLEANUP_SECONDS = 5
MAX_OUTPUT = 4 * 1024 * 1024
MAX_CHILDREN = 64
STOP = False


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def interrupted(_signum, _frame):
    global STOP  # noqa: PLW0603 - record-only supervisor cancellation.
    STOP = True


def identity(pid):
    directory = Path("/proc") / str(pid)
    fields = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
    return {
        "pid": pid,
        "ppid": int(fields[1]),
        "group": int(fields[2]),
        "session": int(fields[3]),
        "starttime": fields[19],
        "uid": directory.stat().st_uid,
        "state": fields[0],
    }


def pin_child(pid):
    descriptor = os.pidfd_open(pid)
    try:
        watcher = select.poll()
        watcher.register(descriptor, select.POLLIN)
        row = identity(pid)
        if row["ppid"] != os.getpid() or row["uid"] != os.getuid():
            raise RuntimeError("fixture child ownership mismatch")
        other = identity(pid)
        if any(row[key] != other[key] for key in row if key != "state"):
            raise RuntimeError("fixture child identity changed")
        # An exited task can no longer be confused with a reused numeric PID.
        row["exited"] = bool(watcher.poll(0))
        return descriptor, row  # noqa: TRY300 - validation remains inside the FD guard.
    except BaseException:
        os.close(descriptor)
        raise


def signal_owned(descriptor, signum):
    try:
        signal.pidfd_send_signal(descriptor, signum)
    except ProcessLookupError:
        watcher = select.poll()
        watcher.register(descriptor, select.POLLIN)
        if not watcher.poll(0):
            raise
        return False
    return True


def children():
    path = Path(f"/proc/self/task/{os.getpid()}/children")
    return [int(value) for value in path.read_text().split()]


def reap(record, deadline):
    # Only after Popen.wait(): never steal the controller's exit status.
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("fixture reap deadline")
        if len(record["reaped"]) >= MAX_CHILDREN:
            if children():
                raise RuntimeError("fixture reaped-child inventory exceeded")
            return
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if not pid:
            return
        record["reaped"].append({"pid": pid, "wait_status": status})


def recover_children(record, deadline):  # noqa: PLR0912 - one bounded adoption/reaping loop.
    seen = set()
    while True:
        reap(record, deadline)
        pending = children()
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("fixture child recovery deadline")
        for pid in pending:
            if pid in seen:
                continue
            if len(seen) >= MAX_CHILDREN:
                raise RuntimeError("fixture child recovery inventory exceeded")
            try:
                descriptor, row = pin_child(pid)
            except ProcessLookupError:
                continue
            try:
                record["owned_children"].append(row)
                if not row["exited"]:
                    record["live_descendants_before_recovery"].append(row)
                    if signal_owned(descriptor, signal.SIGKILL):
                        record["signals"].append({"pid": pid, "signal": "SIGKILL"})
                seen.add(pid)
            finally:
                os.close(descriptor)
        time.sleep(0.01)


def supervise(directory):  # noqa: C901, PLR0912, PLR0915 - one controller and recovery boundary.
    request = json.loads((directory / "request.json").read_text())
    record = {
        "supervisor": os.getpid(),
        "timeout": request["timeout"],
        "timed_out": False,
        "cleanup_confirmed": False,
        "owned_children": [],
        "reaped": [],
        "signals": [],
        "live_descendants_before_recovery": [],
        "errors": [],
        "controller_returncode": None,
        "observed_controller_returncode": None,
    }
    process = descriptor = None
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "fixture subreaper setup failed")
        with (
            (directory / "stdout").open("wb") as output,
            (directory / "stderr").open("wb") as error,
        ):
            os.fchmod(output.fileno(), 0o600)
            os.fchmod(error.fileno(), 0o600)
            process = subprocess.Popen(  # noqa: S603 - exact test-supplied argv, no shell.
                request["argv"], stdout=output, stderr=error, start_new_session=True
            )
            descriptor, record["controller_identity"] = pin_child(process.pid)
            save(directory / "started.json", record)
            deadline = time.monotonic() + request["timeout"]
            marker = request.get("force_timeout_after_ready")
            record["forced_timeout_ready"] = False
            while process.poll() is None:
                if STOP:
                    raise InterruptedError("fixture supervisor cancellation")
                if output.tell() + error.tell() > MAX_OUTPUT:
                    raise RuntimeError("fixture output exceeded its bound")
                if marker and not record["forced_timeout_ready"] and Path(marker).is_file():
                    record["forced_timeout_ready"] = True
                    deadline = min(deadline, time.monotonic() + 0.1)
                if time.monotonic() >= deadline:
                    record["timed_out"] = True
                    raise subprocess.TimeoutExpired(request["argv"], request["timeout"])
                time.sleep(0.01)
            record["observed_controller_returncode"] = process.returncode
    except BaseException as failure:  # noqa: BLE001 - persist the original error before recovery.
        record["errors"].append({"type": type(failure).__name__, "message": str(failure)})
    finally:
        deadline = time.monotonic() + CLEANUP_SECONDS
        try:
            if process is not None:
                if process.poll() is None:
                    if descriptor is None:
                        # No numeric-PID fallback after an ownership failure.
                        raise RuntimeError("controller ownership was not pinned")
                    if signal_owned(descriptor, signal.SIGKILL):
                        record["signals"].append({"pid": process.pid, "signal": "SIGKILL"})
                record["controller_returncode"] = process.wait(
                    timeout=max(0, deadline - time.monotonic())
                )
            recover_children(record, deadline)
            record["remaining_children"] = children()
            if record["remaining_children"]:
                raise RuntimeError("fixture children remain after recovery")
            record["cleanup_confirmed"] = True
        except BaseException as failure:  # noqa: BLE001 - unresolved cleanup remains a failed record.
            record["errors"].append({"type": type(failure).__name__, "message": str(failure)})
        finally:
            if descriptor is not None:
                os.close(descriptor)
            save(directory / "result.json", record)
    return 0 if record["cleanup_confirmed"] else 1


def run_fixture(  # noqa: C901, PLR0912, PLR0915 - one supervisor ownership/error boundary.
    argv, *, timeout, record_directory=None, force_timeout_after_ready=None
):
    """Return the original result, or raise its timeout after confirmed recovery."""
    directory = record_directory or Path(tempfile.mkdtemp(prefix="aeg-fixture-owner-"))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    save(
        directory / "request.json",
        {
            "argv": list(map(str, argv)),
            "timeout": timeout,
            "force_timeout_after_ready": str(force_timeout_after_ready)
            if force_timeout_after_ready
            else None,
        },
    )
    with (directory / "supervisor.log").open("wb") as log:
        os.fchmod(log.fileno(), 0o600)
        supervisor = subprocess.Popen(  # noqa: S603 - fixed test-only supervisor.
            [sys.executable, __file__, "--supervise", str(directory)], stdout=log, stderr=log
        )
        descriptor = None
        try:
            try:
                descriptor = os.pidfd_open(supervisor.pid)
            except BaseException as primary:
                primary.add_note(f"fixture supervisor pin failed; recovery evidence: {directory}")
                try:
                    # The exclusive supervisor has its own deadline. Without a
                    # pin, wait for that cleanup; never substitute numeric kill.
                    supervisor.wait(timeout=timeout + CLEANUP_SECONDS + 5)
                    result = json.loads((directory / "result.json").read_text())
                    primary.fixture_recovery = result
                    primary.add_note(
                        f"cleanup after pin failure confirmed: {result['cleanup_confirmed']}"
                    )
                except BaseException as cleanup:  # noqa: BLE001 - preserve the pin failure.
                    primary.add_note(f"fixture supervisor unconfirmed: {type(cleanup).__name__}")
                raise
            try:
                supervisor.wait(timeout=timeout + CLEANUP_SECONDS + 5)
            except BaseException as primary:
                primary.add_note(f"fixture supervisor recovery evidence: {directory}")
                # Keep the subreaper alive to reclaim its children. Never kill it
                # merely to meet an outer timeout and silently orphan its work.
                try:
                    signal_owned(descriptor, signal.SIGTERM)
                    supervisor.wait(timeout=CLEANUP_SECONDS + 2)
                    result = json.loads((directory / "result.json").read_text())
                    primary.fixture_recovery = result
                    primary.add_note(
                        f"cooperative fixture cleanup confirmed: {result['cleanup_confirmed']}"
                    )
                except BaseException as cleanup:  # noqa: BLE001 - keep the original interruption.
                    primary.add_note(
                        f"fixture supervisor unconfirmed: {type(cleanup).__name__}; {directory}"
                    )
                raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
    record = json.loads((directory / "result.json").read_text())
    streams = []
    for name in ("stdout", "stderr"):
        if (directory / name).exists():
            with (directory / name).open("rb") as stream:
                streams.append(stream.read(MAX_OUTPUT).decode(errors="replace"))
        else:
            streams.append("")
    failure = None
    if record["timed_out"]:
        failure = subprocess.TimeoutExpired(argv, timeout, output=streams[0], stderr=streams[1])
    elif record["errors"] or record["live_descendants_before_recovery"]:
        if record["observed_controller_returncode"] not in (None, 0):
            failure = subprocess.CalledProcessError(
                record["observed_controller_returncode"], argv, *streams
            )
        else:
            explanation = record["errors"][0] if record["errors"] else "unexpected live descendants"
            failure = RuntimeError(f"fixture supervisor failure: {explanation}")
    if not record["cleanup_confirmed"]:
        if failure is None:
            failure = RuntimeError("fixture cleanup remains unconfirmed")
        failure.add_note("owned resources remain unconfirmed")
    if failure is not None:
        failure.fixture_recovery = record
        failure.add_note(f"fixture recovery evidence: {directory}")
        if record["errors"] or record["live_descendants_before_recovery"]:
            raise failure from RuntimeError(
                "fixture recovery diagnostics retained in fixture_recovery"
            )
        raise failure
    result = subprocess.CompletedProcess(argv, record["controller_returncode"], *streams)
    if record_directory is None:
        shutil.rmtree(directory)
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--supervise":
        raise SystemExit("private fixture supervisor invocation required")
    raise SystemExit(supervise(Path(sys.argv[2])))
