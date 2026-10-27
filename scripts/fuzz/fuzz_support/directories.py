"""Keep nested filesystem operations attached to their observed parent inodes."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from typing import TYPE_CHECKING

from fuzz_support.filesystem import invalid

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


def directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode)


@contextmanager
def bound_child_directory(
    parent: int,
    name: str,
    check_parent: Callable[[], None],
) -> Iterator[tuple[int, Callable[[], None]]]:
    """Recheck the observed ancestor chain before each nested operation."""
    check_parent()
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        identity = directory_identity(before)

        def check() -> None:
            check_parent()
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                directory_identity(current) != identity
                or directory_identity(os.fstat(descriptor)) != identity
            ):
                invalid("fuzz nested directory identity changed")

        check()
        yield descriptor, check
        check()
    finally:
        os.close(descriptor)
