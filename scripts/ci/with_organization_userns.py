#!/usr/bin/env python3
"""Qualify the Nix fixture namespace and scope any AppArmor grant to its tool."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "validation"))
from database_execution import stop_process_group

_cancellation: RuntimeError | None = None
_cleaning = False
_unconfirmed_groups: set[int] = set()

CHECK = ".#checks.x86_64-linux.organizations-production-runtime"
RESTRICTION = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
UNSHARE = re.compile(r"/nix/store/[0-9a-z]{32}-util-linux-[A-Za-z0-9.+_-]+/bin/unshare")


def execute(command: list[str], *, timeout: int = 120) -> dict[str, Any]:
    # File-backed capture separates leader exit from inherited output handles.
    # An outer group cancellation cannot kill the policy controller mid-removal.
    check_cancellation()
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors, start_new_session=True)
        _unconfirmed_groups.add(process.pid)
        try:
            status = wait_command(process, timeout=timeout)
        finally:
            stop_owned(process, grace=0)
        output.seek(0)
        errors.seek(0)
        return {
            "command": command,
            "returncode": status,
            "stdout": output.read().decode(),
            "stderr": errors.read().decode(),
        }


def check_cancellation() -> None:
    if _cancellation is not None and not _cleaning:
        raise _cancellation


def wait_command(process: subprocess.Popen[bytes], *, timeout: float | None = None) -> int:
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        check_cancellation()
        status = process.poll()
        if status is not None:
            return status
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, cast("float", timeout))
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.05 if remaining is None else min(0.05, remaining))


def stop_owned(process: subprocess.Popen[bytes], *, grace: float) -> None:
    stop_process_group(process, grace=grace)
    _unconfirmed_groups.discard(process.pid)


def restriction() -> str:
    return RESTRICTION.read_text().strip() if RESTRICTION.exists() else "absent"


def probe() -> dict[str, Any]:
    # Realize missing prerequisites, then ALWAYS execute on this host even when
    # another host has already built the same probe. No substitute is evidence.
    command = ["nix", "build", CHECK + ".namespaceProbe", "--no-link", "--builders", "", "-L"]
    results = [execute(command)]
    if results[0]["returncode"] == 0:
        results.append(execute([*command, "--rebuild"]))
    return {"passed": len(results) == 2 and results[-1]["returncode"] == 0, "attempts": results}


def profile_text(executable: str, name: str) -> str:
    # Reject policy syntax, globs and aliases; the attachment is one pinned Nix
    # executable, not every process, every unshare version or the Nix daemon.
    if not UNSHARE.fullmatch(executable) or not re.fullmatch(r"aegaeon-userns-[0-9a-f]{32}", name):
        raise ValueError("invalid namespace executable or profile name")
    return f'abi <abi/4.0>,\nprofile {name} "{executable}" flags=(unconfined) {{\n  userns,\n}}\n'


def profiles(*, timeout: int = 120) -> set[str]:
    result = execute(
        ["sudo", "-n", "cat", "/sys/kernel/security/apparmor/profiles"], timeout=timeout
    )
    if result["returncode"] != 0:
        raise RuntimeError("cannot inspect existing AppArmor profiles")
    return set(result["stdout"].splitlines())


def present(name: str, *, timeout: int = 120) -> bool:
    return any(line.startswith(name + " (") for line in profiles(timeout=timeout))


def prepare(policy: Path, name: str, record: dict[str, Any]) -> None:
    record["before"] = probe()
    if record["before"]["passed"]:
        return
    errors = "\n".join(r["stderr"] for r in record["before"]["attempts"])
    if record["restriction_before"] != "1" or "uid_map: Operation not permitted" not in errors:
        raise RuntimeError("namespace probe failed outside the supported AppArmor restriction")
    resolved = execute(["nix", "eval", "--raw", CHECK + ".namespaceUnshare"])
    if resolved["returncode"] != 0:
        raise RuntimeError("cannot resolve the fixture's pinned namespace executable")
    executable = resolved["stdout"].strip()
    text = profile_text(executable, name)
    if not Path(executable).is_file() or Path(executable).is_symlink():
        raise ValueError("namespace executable is missing or is an alias")
    if present(name):
        raise RuntimeError("refusing to replace an existing AppArmor profile")
    policy.write_text(text)
    policy.chmod(0o600)
    record.update(
        profile=name,
        executable=executable,
        profile_sha256=hashlib.sha256(text.encode()).hexdigest(),
    )
    # Add, never replace. No persistent /etc file or sysctl change.
    record["install_attempted"] = True
    record["install"] = execute(
        ["sudo", "-n", "apparmor_parser", "--skip-cache", "--add", str(policy)]
    )
    if record["install"]["returncode"] != 0:
        raise RuntimeError("AppArmor profile installation failed")
    record["profile_installed"] = True
    if not present(name):
        raise RuntimeError("installed AppArmor profile is absent")
    record["after"] = probe()
    if not record["after"]["passed"]:
        raise RuntimeError("namespace remains unavailable with the scoped profile")


def cleanup(policy: Path, name: str, record: dict[str, Any]) -> None:
    # An interrupted parser may have loaded the policy before replying. Inspect
    # only our fresh name, whose absence was confirmed before the add attempt.
    if record.get("install_attempted"):
        if present(name, timeout=5):
            record["remove"] = execute(
                ["sudo", "-n", "apparmor_parser", "--skip-cache", "--remove", str(policy)],
                timeout=5,
            )
            record["profile_removed"] = record["remove"]["returncode"] == 0 and not present(
                name, timeout=5
            )
            if not record["profile_removed"]:
                raise RuntimeError("temporary AppArmor profile was not removed")
        record["profile_absent"] = True
    record["restriction_after"] = restriction()
    if record["restriction_after"] != record["restriction_before"]:
        raise RuntimeError("host user namespace restriction changed during validation")


def run_command(command: list[str]) -> int:
    check_cancellation()
    process = subprocess.Popen(command, start_new_session=True)
    _unconfirmed_groups.add(process.pid)
    try:
        return wait_command(process)
    finally:
        # The observer has ten seconds plus bounded confirmation for its nested
        # Nix group. Let it finish before removing the scoped policy.
        stop_owned(process, grace=15)


def require_confirmed_groups(record: dict[str, Any], primary_error: BaseException | None) -> None:
    if _unconfirmed_groups:
        # Retaining policy bytes after unloading does not protect live work.
        record["policy_removal_deferred"] = "owned process group cleanup is unconfirmed"
        if primary_error is not None:
            raise primary_error
        raise RuntimeError(record["policy_removal_deferred"])


def finish_cleanup(
    policy: Path, name: str, record: dict[str, Any], primary_error: BaseException | None = None
) -> None:
    global _cleaning  # noqa: PLW0603 - cleanup owns the process-wide cancellation phase.
    # The handler never raises, including before this phase transition.
    _cleaning = True
    cleanup_error = None
    try:
        require_confirmed_groups(record, primary_error)
        cleanup(policy, name, record)
    except BaseException as error:
        cleanup_error = error
        raise
    finally:
        _cleaning = False
        record["unconfirmed_groups"] = sorted(_unconfirmed_groups)
        try:
            retain_or_remove_policy(policy, name, record)
        except OSError as error:
            record["policy_recovery_error"] = str(error)
            # Preserve a failed removal/inspection over evidence I/O.
            if cleanup_error is None:
                raise


def run(command: list[str], report: Path) -> int:
    record: dict[str, Any] = {"restriction_before": restriction(), "command": command}
    name = "aegaeon-userns-" + uuid.uuid4().hex
    # Failed removal must retain the exact nonce policy and recovery information.
    temporary = Path(tempfile.mkdtemp(prefix="aegaeon-userns-"))
    policy = temporary / "profile"
    primary_error = None
    try:
        try:
            check_cancellation()
            prepare(policy, name, record)
            # The build still runs as the invoking user through Nix's normal
            # sandbox. Every acceptance case and failure rule is retained.
            record["command_returncode"] = run_command(command)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            finish_cleanup(policy, name, record, primary_error)
        check_cancellation()
        return int(record["command_returncode"])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
        print(f"Organizations namespace qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        if _cancellation is not None:
            record["cancellation"] = str(_cancellation)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(record, indent=2) + "\n")


def retain_or_remove_policy(policy: Path, name: str, record: dict[str, Any]) -> None:
    if record.get("install_attempted") and (
        not record.get("profile_absent") or _unconfirmed_groups
    ):
        record["recovery"] = {
            "profile": name,
            "policy_path": str(policy),
            "remove_command": [
                "sudo",
                "-n",
                "apparmor_parser",
                "--skip-cache",
                "--remove",
                str(policy),
            ],
            "unconfirmed_groups": sorted(_unconfirmed_groups),
            "confirmation_required": (
                "Confirm all listed owned process groups have terminated before running "
                "remove_command. Then confirm this exact profile is absent and the "
                "restriction is unchanged."
            ),
        }
        record["recovery"]["policy_sha256"] = hashlib.sha256(policy.read_bytes()).hexdigest()
        recovery = policy.parent / "recovery.json"
        recovery.write_text(json.dumps(record["recovery"], indent=2) + "\n")
        recovery.chmod(0o600)
    else:
        policy.unlink(missing_ok=True)
        policy.parent.rmdir()


def interrupted(signum: int, _frame: object) -> None:
    global _cancellation  # noqa: PLW0603 - one process-wide installed handler.
    # Record only: asynchronous exceptions can skip even a finally-block entry.
    # Work propagates this request at owned waiting boundaries; cleanup finishes.
    if _cancellation is None:
        _cancellation = RuntimeError(f"interrupted by signal {signum}")
    # SIGKILL/host loss still relies on the ephemeral runner's destruction.


def main() -> int:
    global _cancellation  # noqa: PLW0603 - reset before command startup.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    _cancellation = None
    _unconfirmed_groups.clear()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    return run(command, args.report)


if __name__ == "__main__":
    raise SystemExit(main())
