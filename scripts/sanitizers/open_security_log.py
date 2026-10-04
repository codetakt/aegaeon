#!/usr/bin/env python3
"""Open a no-follow owned security log before truncating, then retain its fd.

The resumed shell revalidates the inherited descriptor against the same lexical
leaf and truncates it once before logging. The initial opener preserves existing
bytes until that admission. An environment marker never skips the opener.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

BOUND_RECOVERY = r"""
set -euo pipefail
source "$1"
ROOT=$2
SANITIZER_ARTIFACT_DIR=$3
evidence_binding=$4
target=$5
cleanup_binding=$6
fail() { echo "[security] $*" >&2; }
preflight_route "$SANITIZER_ARTIFACT_DIR"
[[ $PREFLIGHT_ROUTE == "$SANITIZER_ARTIFACT_DIR" ]]
sanitizer_validate_output "$SANITIZER_ARTIFACT_DIR" "$ROOT"
preflight_route "$target"
[[ $PREFLIGHT_ROUTE == "$target" ]]
sanitizer_validate_output "$target" "$ROOT"
sanitizer_validate_pair "$target" "${SANITIZER_ARTIFACT_DIR%/*}" cleanup
python3 -I - "$SANITIZER_ARTIFACT_DIR" "$evidence_binding" "$target" "$cleanup_binding" <<'CONTEXT'
import json
import sys
evidence, evidence_binding, target, cleanup_binding = sys.argv[1:]
if (json.loads(evidence_binding)["target"] != evidence
        or json.loads(cleanup_binding)["target"] != target):
    raise ValueError("Security log cleanup context does not match admitted paths")
CONTEXT
cleanup_status=0
sanitizer_target_binding cleanup "$cleanup_binding" || cleanup_status=$?
sanitizer_target_binding validate "$evidence_binding"
preflight_receipt shared-log-open 1 1 "$cleanup_status"
"""


def recover_bound_outputs(bash: str, context: list[str]) -> bool:
    root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(  # noqa: S603 - fixed code/helper and admitted structured paths/bindings
            [
                bash,
                "--noprofile",
                "--norc",
                "-p",
                "-c",
                BOUND_RECOVERY,
                "security-log-cleanup",
                str(root / "scripts/sanitizers/sanitizer_paths.sh"),
                str(root),
                *context,
            ],
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def checked_log(path: str, inherited: int | None = None) -> int:  # noqa: PLR0912, PLR0915 - complete descriptor boundary
    route = Path(path)
    if not route.is_absolute() or any(part in (".", "..") for part in route.parts):
        message = "invalid security log route"
        raise ValueError(message)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    fd = None
    try:
        for name in route.parts[1:-1]:
            child = os.open(name, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        if os.fstat(parent).st_uid != os.getuid():
            message = "security log parent ownership differs"
            raise ValueError(message)
        if inherited is None:
            fd = os.open(
                route.name,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=parent,
            )
        else:
            fd = os.dup(inherited)
        opened = os.fstat(fd)
        current = os.stat(route.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            message = "security log leaf ownership/type/identity differs"
            raise ValueError(message)
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (
            descriptor_flags & os.O_ACCMODE not in (os.O_WRONLY, os.O_RDWR)
            or not descriptor_flags & os.O_APPEND
        ):
            message = "security log descriptor must be writable and append-only"
            raise ValueError(message)
        if inherited is not None:
            os.ftruncate(fd, 0)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def main() -> int:  # noqa: C901, PLR0912, PLR0915 - complete validate/open/exec/recovery boundary
    fd = None
    bash = None
    context = None
    try:
        operation, path, *arguments = sys.argv[1:]
        if operation == "validate" and len(arguments) == 1:
            descriptor = int(arguments[0])
            if descriptor < 0 or str(descriptor) != arguments[0]:
                message = "invalid inherited log descriptor"
                raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
            os.close(checked_log(path, descriptor))
            return 0
        if operation == "open-exec-bound":
            if len(arguments) < 5 or arguments[4] != "--":  # noqa: PLR2004 - four context fields and separator
                message = "invalid bound security log context"
                raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
            context, arguments = arguments[:4], arguments[5:]
        elif operation != "open-exec":
            message = "invalid security log operation"
            raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
        bash = shutil.which("bash")
        if bash is None:
            message = "security wrapper interpreter unavailable"
            raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
        fd = checked_log(path)
        os.set_inheritable(fd, True)  # noqa: FBT003 - positional-only OS descriptor API
        environment = dict(os.environ)
        environment["SANITIZER_SECURITY_LOG_FD"] = str(fd)
        if context is not None:
            environment["SANITIZER_EVIDENCE_BINDING"] = context[1]
        wrapper = Path(__file__).resolve().parents[2] / "scripts/security/run_security_suite.sh"
        os.execve(bash, [bash, str(wrapper), *arguments], environment)  # noqa: S606 - fixed wrapper, structured argv
    except (OSError, ValueError):
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        print("[security] safe log descriptor unavailable (exit=1)", file=sys.stderr)
        if context is not None and (bash is None or not recover_bound_outputs(bash, context)):
            print("[security] bound cleanup/evidence recovery unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
