# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Retire an identified, owned Linux guard using a pinned process descriptor.

Resource termination must already be independently verified by the caller.
An observed exit is not an exit-code claim or evidence that a deadline fired.
"""

import math
import json
import os
from pathlib import Path
import select
import signal


def start_ticks(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


class OwnedProcess:
    def __init__(self, pid, script, expected_start_ticks):
        self.pid = pid
        self.script = os.fsencode(script)
        self.returncode = None
        self.fd = os.pidfd_open(pid)
        try:
            if self.poll() is not None:
                raise ProcessLookupError("Owned process exited before attachment")  # noqa: TRY301 -- failure capture preserves partial evidence
            observed_start = start_ticks(pid)
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if observed_start != str(expected_start_ticks) or self.script not in command:
                raise ValueError("Owned process identity mismatch")  # noqa: TRY301 -- failure capture preserves partial evidence
            if self.poll() is not None:
                raise ProcessLookupError("Owned process exited during attachment")  # noqa: TRY301 -- failure capture preserves partial evidence
        except BaseException:
            self.close()
            raise

    def poll(self):
        if self.fd is None:
            raise ValueError("Owned process descriptor is closed")
        # Unlike repeated /proc reads, descriptor readiness also handles an
        # exit between the state read and disappearance of cmdline.
        if select.select([self.fd], [], [], 0)[0]:
            self.returncode = "EXIT_OBSERVED_NOT_CHILD"
        return self.returncode

    def terminate(self):
        if self.poll() is not None:
            return
        try:
            signal.pidfd_send_signal(self.fd, signal.SIGTERM)
        except ProcessLookupError:
            if self.poll() is None:
                raise

    def wait(self, timeout):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Finite positive exit-confirmation timeout required")
        if self.poll() is None:  # noqa: SIM102 -- retain separately checked process identity conditions
            if not select.select([self.fd], [], [], timeout)[0]:
                raise TimeoutError("Owned process exit remains unconfirmed")
        return self.poll()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def attach_guard(receipt_path, expected_script):
    """Attach only to a guard identified by a new launch-time receipt.

    Old receipts without start ticks cannot be upgraded by looking up a PID.
    """
    receipt = json.loads(Path(receipt_path).read_bytes())
    if (
        receipt.get("schema") != "owned-guard-process/1"
        or receipt.get("script") != str(expected_script)
        or type(receipt.get("pid")) is not int
        or receipt["pid"] <= 0
        or not isinstance(receipt.get("start_ticks"), str)
        or not receipt["start_ticks"].isdecimal()
    ):
        raise ValueError("Invalid launch-time guard identity")
    return OwnedProcess(receipt["pid"], expected_script, receipt["start_ticks"])


def retire_guard(guard, *, actual_termination_verified, timeout=15):
    """Called after the orchestrator independently verifies cloud termination."""
    if actual_termination_verified is not True:
        raise ValueError("Resource termination must be independently verified")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Finite positive exit-confirmation timeout required")
    guard.terminate()
    observed = guard.wait(timeout)
    return {
        "actual_termination_verified": True,
        "guard_exit": observed,
        "deadline_firing_claimed": False,
        "guard_exit_code_known": False,
    }
