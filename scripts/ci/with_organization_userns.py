#!/usr/bin/env python3
"""Qualify the Nix fixture namespace and scope any AppArmor grant to its tool."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "validation"))
from database_execution import stop_process_group

CHECK = ".#checks.x86_64-linux.organizations-production-runtime"
RESTRICTION = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
UNSHARE = re.compile(r"/nix/store/[0-9a-z]{32}-util-linux-[A-Za-z0-9.+_-]+/bin/unshare")


def execute(command: list[str], *, timeout: int = 120) -> dict[str, Any]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


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
    if record.get("install_attempted") and present(name, timeout=5):
        record["remove"] = execute(
            ["sudo", "-n", "apparmor_parser", "--skip-cache", "--remove", str(policy)],
            timeout=5,
        )
        record["profile_removed"] = record["remove"]["returncode"] == 0 and not present(
            name, timeout=5
        )
        if not record["profile_removed"]:
            raise RuntimeError("temporary AppArmor profile was not removed")
    record["restriction_after"] = restriction()
    if record["restriction_after"] != record["restriction_before"]:
        raise RuntimeError("host user namespace restriction changed during validation")


def run_command(command: list[str]) -> int:
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait()
    finally:
        # The observer has ten seconds plus bounded confirmation for its nested
        # Nix group. Let it finish before removing the scoped policy.
        stop_process_group(process, grace=15)


def run(command: list[str], report: Path) -> int:
    record: dict[str, Any] = {"restriction_before": restriction(), "command": command}
    name = "aegaeon-userns-" + uuid.uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="aegaeon-userns-") as temporary:
            policy = Path(temporary) / "profile"
            try:
                prepare(policy, name, record)
                # The build still runs as the invoking user through Nix's normal
                # sandbox. Every acceptance case and failure rule is retained.
                record["command_returncode"] = run_command(command)
            finally:
                cleanup(policy, name, record)
        return int(record["command_returncode"])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
        print(f"Organizations namespace qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(record, indent=2) + "\n")


def interrupted(signum: int, _frame: object) -> None:
    # Repeated termination must not abort bounded nested/policy cleanup.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    # SIGKILL/host loss still relies on the ephemeral runner's destruction.
    # Capture subprocesses use selectors, which may swallow InterruptedError.
    raise RuntimeError(f"interrupted by signal {signum}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    return run(command, args.report)


if __name__ == "__main__":
    raise SystemExit(main())
