#!/usr/bin/env python3
"""Open a no-follow owned security log before truncating, then retain its fd.

The resumed shell revalidates the inherited descriptor against the same lexical
leaf and truncates it once before logging. The initial opener preserves existing
bytes until that admission. An environment marker never skips the opener.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import stat
import sys
from pathlib import Path


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


def main() -> int:
    try:
        operation, path, *arguments = sys.argv[1:]
        if operation == "validate" and len(arguments) == 1:
            descriptor = int(arguments[0])
            if descriptor < 0 or str(descriptor) != arguments[0]:
                message = "invalid inherited log descriptor"
                raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
            os.close(checked_log(path, descriptor))
            return 0
        if operation != "open-exec":
            message = "invalid security log operation"
            raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
        fd = checked_log(path)
        os.set_inheritable(fd, True)  # noqa: FBT003 - positional-only OS descriptor API
        environment = dict(os.environ)
        environment["SANITIZER_SECURITY_LOG_FD"] = str(fd)
        wrapper = Path(__file__).resolve().parents[2] / "scripts/security/run_security_suite.sh"
        bash = shutil.which("bash")
        if bash is None:
            message = "security wrapper interpreter unavailable"
            raise ValueError(message)  # noqa: TRY301 - sanitized operation boundary
        os.execve(bash, [bash, str(wrapper), *arguments], environment)  # noqa: S606 - fixed wrapper, structured argv
    except (OSError, ValueError):
        print("[security] safe log descriptor unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
