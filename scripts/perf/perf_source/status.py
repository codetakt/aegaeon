"""Prior-status retention and ordered status writes."""

from __future__ import annotations

import os
import pathlib
import stat
import tempfile
from typing import TYPE_CHECKING

from .boundaries import (
    checked_output,
    output_boundaries,
    output_path,
    output_roles,
    private_root,
    reject_supplier_overlap,
)
from .git_source import git_domain
from .io import (
    canonical,
    fail,
    stamp,
)

if TYPE_CHECKING:
    from .dependencies import Dependencies


def status_boundary(
    root: pathlib.Path,
    artifact: str,
    *,
    evidence: pathlib.Path | None = None,
    runtime: Dependencies,
) -> pathlib.Path:
    directory = checked_output(root, artifact, directory=True)
    reject_supplier_overlap(root, [directory, directory / "source-status.json"], runtime=runtime)
    output_roles(
        root,
        evidence if evidence is not None else directory / "source",
        [(str(directory), True)],
        directory / "source-status.json",
        runtime=runtime,
    )
    parent = directory.parent
    while not parent.exists():
        parent = parent.parent
    if parent.lstat().st_uid != os.geteuid():
        fail("status parent is not owned")
    path = directory / "source-status.json"
    domain = git_domain(root, runtime=runtime)
    for name in domain["index"]:
        source = root / name
        if (
            source == directory
            or source.is_relative_to(directory)
            or directory.is_relative_to(source)
        ):
            fail("status boundary overlaps tracked source")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if info.st_uid != os.geteuid() or not (
            stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        ):
            fail("status leaf is not an owned regular file or literal link")
    return path


def write_status(path: pathlib.Path, stage: str, exit_status: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".source-status-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical({"stage": stage, "exit_status": exit_status}))
            stream.flush()
            os.fsync(stream.fileno())
        pathlib.Path(temporary).replace(path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)


def status_geometry(
    root: pathlib.Path,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies,
) -> None:
    # The shared admission checks kinds, ownership and link counts as well as
    # geometry. Prior status links are retained separately, never opened for writes.
    output_boundaries(root, git_domain(root, runtime=runtime), evidence, outputs, runtime=runtime)
    private_root(
        root,
        [evidence.parent] + [output_path(root, value) for value, directory in outputs if directory],
        runtime=runtime,
    )


def retain_status(
    root: pathlib.Path,
    path: pathlib.Path,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies,
) -> None:
    if not (path.exists() or path.is_symlink()):
        return
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raw = os.readlink(path).encode("utf-8")  # noqa: PTH115 - literal prior link
        kind = "link"
    else:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read()
            if stamp(opened) != stamp(os.fstat(stream.fileno())) or stamp(opened) != stamp(before):
                fail("prior status changed while being read")
        kind = "raw"
    if stamp(before) != stamp(path.lstat()):
        fail("prior status changed while being preserved")
    temporary_root = private_root(
        root,
        [evidence.parent] + [output_path(root, value) for value, directory in outputs if directory],
        runtime=runtime,
    )
    private = pathlib.Path(tempfile.mkdtemp(prefix="aegaeon-perf-status-", dir=temporary_root))
    retained = private / ("source-status." + kind)
    with retained.open("xb") as stream:
        stream.write(raw)
    retained.chmod(0o600)


def initialize_status(
    root: pathlib.Path,
    artifact: str,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies,
) -> None:
    path = status_boundary(root, artifact, evidence=evidence, runtime=runtime)
    output_roles(root, evidence, outputs, path, runtime=runtime)
    status_geometry(root, outputs, evidence, runtime=runtime)
    retain_status(root, path, outputs, evidence, runtime=runtime)
    write_status(path, "paths", 1)
