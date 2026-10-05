"""Source, output and immutable supplier geometry."""

from __future__ import annotations

import os
import pathlib
import stat
import tempfile
from typing import TYPE_CHECKING, Any

from .io import (
    LEGACY,
    ancestors,
    fail,
)

if TYPE_CHECKING:
    import argparse

    from .dependencies import Dependencies


def output_path(root: pathlib.Path, value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute():
        path = root / path
    path = path.absolute()
    if ".." in path.parts:
        fail("output path contains traversal")
    ancestors(path)
    return path


def checked_output(root: pathlib.Path, value: str, *, directory: bool) -> pathlib.Path:
    path = output_path(root, value)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        mode = info.st_mode
        if (
            not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode))
            or info.st_uid != os.geteuid()
            or (not directory and info.st_nlink != 1)
        ):
            fail("output is not an owned regular path")
    if path == root or root.is_relative_to(path):
        fail("output overlaps source root")
    if path.is_relative_to(root):
        relative = path.relative_to(root).as_posix()
        allowed = relative.startswith("artifacts/perf/") or relative == "artifacts/perf"
        if not allowed and (directory or relative not in LEGACY):
            fail("output is outside the reserved performance domain")
    return path


def reject_supplier_overlap(
    root: pathlib.Path, paths: list[pathlib.Path], *, runtime: Dependencies
) -> None:
    if runtime.supplier is None:
        return
    inputs = [output_path(root, str(path)) for path in runtime.supplier.input_paths()]
    for value in paths:
        path = output_path(root, str(value))
        if any(path.is_relative_to(source) or source.is_relative_to(path) for source in inputs):
            fail("output overlaps immutable supplier input")


def output_roles(
    root: pathlib.Path,
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    status: pathlib.Path | None = None,
    *,
    runtime: Dependencies,
) -> None:
    destinations = [(output_path(root, value), directory) for value, directory in outputs]
    status = status or evidence.parent / "source-status.json"
    reject_supplier_overlap(
        root, [evidence, status, *(path for path, _ in destinations)], runtime=runtime
    )
    # Cargo can write throughout either tree, including dependency sidecars and caches.
    # Output directories may contain other report roles, but may never contain Cargo.
    targets = [root / "target", *cargo_outputs(root, runtime=runtime)]
    for path in [evidence, status, *(path for path, _ in destinations)]:
        if any(path.is_relative_to(target) or target.is_relative_to(path) for target in targets):
            fail("output overlaps Cargo target tree")
    for position, (path, directory) in enumerate(destinations):
        if (
            path == evidence
            or path.is_relative_to(evidence)
            or (not directory and evidence.is_relative_to(path))
        ):
            fail("output collides with source evidence")
        if (
            path == status
            or path.is_relative_to(status)
            or (not directory and status.is_relative_to(path))
        ):
            fail("output collides with source status")
        for other, other_directory in destinations[:position]:
            if (
                path == other
                or (not directory and other.is_relative_to(path))
                or (not other_directory and path.is_relative_to(other))
            ):
                fail("output roles collide")


def private_root(
    root: pathlib.Path, forbidden: list[pathlib.Path], *, runtime: Dependencies
) -> pathlib.Path:
    temporary = output_path(root, os.environ.get("TMPDIR") or tempfile.gettempdir())
    reject_supplier_overlap(root, [temporary], runtime=runtime)
    if (
        temporary.is_symlink()
        or not temporary.is_dir()
        or temporary.is_relative_to(root)
        or any(temporary.is_relative_to(path) for path in forbidden)
    ):
        fail("private retention must be outside source and uploads")
    return temporary


def declared_outputs(
    root: pathlib.Path, args: argparse.Namespace, *, runtime: Dependencies
) -> list[tuple[str, bool]]:
    outputs = [(name, False) for name in args.output_file] + [
        (name, True) for name in args.output_directory
    ]
    reports = [name for name in (args.report_file, args.legacy_report_file) if name is not None]
    if (
        args.report_file is not None
        and args.legacy_report_file is not None
        and (output_path(root, args.report_file) == output_path(root, args.legacy_report_file))
    ):
        reports.pop()
    outputs.extend((name, False) for name in reports)
    if args.artifact_directory:
        artifact = output_path(root, args.artifact_directory)
        output_roles(
            root,
            output_path(root, args.evidence),
            outputs,
            artifact / "source-status.json",
            runtime=runtime,
        )
        private_root(root, [artifact], runtime=runtime)
    return outputs


def output_boundaries(
    root: pathlib.Path,
    domain: dict[str, Any],
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    *,
    runtime: Dependencies,
) -> None:
    """Admit every write destination before retention, status or build effects."""
    output_roles(root, evidence, outputs, runtime=runtime)
    paths = [checked_output(root, str(evidence), directory=True)]
    paths.extend((checked_output(root, value, directory=is_dir) for value, is_dir in outputs))
    for path, directory in [
        (root / "target", True),
        (root / "artifacts/perf", True),
        *((root / name, False) for name in LEGACY),
    ]:
        ancestors(path)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (
                not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or info.st_uid != os.geteuid()
                or (not directory and info.st_nlink != 1)
            ):
                fail("reserved output path is not owned and regular")
        paths.append(path)
    paths.extend(cargo_outputs(root, runtime=runtime))
    reject_source_overlap(root, domain, paths, runtime=runtime)


def reject_source_overlap(
    root: pathlib.Path, domain: dict[str, Any], paths: list[pathlib.Path], *, runtime: Dependencies
) -> None:
    reject_supplier_overlap(root, paths, runtime=runtime)
    for path in paths:
        if path == root or root.is_relative_to(path):
            fail("output overlaps source root")
        for name in domain["index"]:
            source = root / name
            if source == path or source.is_relative_to(path) or path.is_relative_to(source):
                fail("output boundary overlaps tracked source")


def cargo_outputs(root: pathlib.Path, *, runtime: Dependencies) -> list[pathlib.Path]:
    target = os.environ.get("CARGO_TARGET_DIR") or str(root / "target")
    path = output_path(root, target)
    reject_supplier_overlap(root, [path], runtime=runtime)
    if path.exists() and (
        not stat.S_ISDIR(path.lstat().st_mode) or path.lstat().st_uid != os.geteuid()
    ):
        fail("Cargo output is not an owned regular directory")
    if path.is_symlink() or (path.is_relative_to(root) and path != root / "target"):
        fail("Cargo output must use the default tree or be outside source")
    if path == root or root.is_relative_to(path):
        fail("Cargo output overlaps source")
    return [path]


def require_fresh_outputs(root: pathlib.Path, paths: list[str]) -> None:
    for value in paths:
        path = checked_output(root, value, directory=False)
        if path.exists() or path.is_symlink():
            fail("run output already exists")
