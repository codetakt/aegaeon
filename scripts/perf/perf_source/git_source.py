"""Complete tracked source projection and private Git object records."""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .boundaries import private_root
from .dependencies import environment
from .io import (
    LEGACY,
    MANDATORY,
    MODES,
    ancestors,
    digest,
    fail,
    stamp,
)

if TYPE_CHECKING:
    from .dependencies import Dependencies


def root_path(value: str, *, runtime: Dependencies) -> pathlib.Path:
    root = pathlib.Path(value).absolute()
    ancestors(root)
    if not root.is_dir() or root.is_symlink() or root != root.resolve():
        fail("source is not a regular directory")
    actual = runtime.command(root, "rev-parse", "--show-toplevel").decode().strip()
    if pathlib.Path(actual).resolve() != root.resolve():
        fail("source must be the Git worktree root")
    if runtime.command(root, "rev-parse", "--show-object-format").strip() != b"sha1":
        fail("unsupported Git object format")
    return root


def git_domain(root: pathlib.Path, *, runtime: Dependencies) -> dict[str, Any]:
    head = runtime.command(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    entries: dict[str, dict[str, str]] = {}
    raw = runtime.command(root, "ls-files", "--stage", "-z")
    for item in raw.split(b"\x00"):
        if not item:
            continue
        meta, encoded = item.split(b"\t", 1)
        mode, blob, stage = meta.decode("ascii").split()
        name = encoded.decode("utf-8")
        path = pathlib.PurePosixPath(name)
        if (
            stage != "0"
            or mode not in MODES
            or name in entries
            or path.is_absolute()
            or (".." in path.parts)
            or (str(path) != name)
            or (name == ".git")
            or name.startswith(".git/")
        ):
            fail("unsupported or conflicted tracked path")
        entries[name] = {"git_mode": mode, "git_blob": blob}
    if not entries.keys() >= MANDATORY:
        fail("mandatory tracked source input is missing")
    return {"head": head, "index": entries}


def unexpected_paths(root: pathlib.Path, domain: dict[str, Any]) -> None:
    tracked = set(domain["index"])
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = pathlib.Path(current)
        for name in list(dirs):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if relative in {".git", "target", "artifacts/perf"}:
                dirs.remove(name)
            elif path.is_symlink():
                dirs.remove(name)
                files.append(name)
        for name in files:
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if relative == ".git" or relative in LEGACY:
                continue
            if relative not in tracked:
                fail("untracked source input is present")


def read_source(
    root: pathlib.Path, domain: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, bytes]]:
    files: dict[str, Any] = {}
    contents: dict[str, bytes] = {}
    for name in sorted(domain["index"]):
        path = root / name
        ancestors(path)
        before = path.lstat()
        link: str | None = None
        if stat.S_ISLNK(before.st_mode):
            link = os.readlink(path)  # noqa: PTH115 - preserve literal link spelling
            raw = link.encode("utf-8")
            mode = "120000"
        elif stat.S_ISREG(before.st_mode):
            mode = "100755" if before.st_mode & 0o111 else "100644"
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                opened = os.fstat(stream.fileno())
                raw = stream.read()
                closed = os.fstat(stream.fileno())
            if stamp(opened) != stamp(closed) or stamp(opened) != stamp(before):
                fail("source changed while being read")
        else:
            fail("tracked source is not a regular file or literal link")
        after = path.lstat()
        if stamp(before) != stamp(after) or before.st_mode != MODES[mode]:
            fail("source changed or has noncanonical mode")
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\x00" + raw, usedforsecurity=False
        ).hexdigest()
        files[name] = {
            "bytes": len(raw),
            "filesystem_mode": before.st_mode,
            "git_blob": blob,
            "git_mode": mode,
            "sha256": digest(raw),
            "symlink": link,
        }
        contents[name] = raw
    validate_source_links(files)
    return (files, contents)


def source_link_target(name: str, target: str, files: dict[str, Any]) -> str:
    if target.endswith(("/", "/.")):
        fail("source link target requires a directory")
    link = pathlib.PurePosixPath(target)
    if link.is_absolute():
        fail("source link target is outside frozen tracked source")
    directories = {""} | {
        str(parent) for path in files for parent in pathlib.PurePosixPath(path).parents
    }
    parts = list(pathlib.PurePosixPath(name).parent.parts)
    for index, part in enumerate(link.parts):
        if part == "..":
            if not parts:
                fail("source link target is outside frozen tracked source")
            parts.pop()
        else:
            parts.append(part)
        if index + 1 < len(link.parts) and "/".join(parts) not in directories:
            fail("source link ancestor is not a frozen tracked directory")
    resolved = "/".join(parts)
    if resolved not in files:
        fail("source link target is not a frozen tracked file")
    return resolved


def validate_source_links(files: dict[str, Any]) -> None:
    for original in files:
        name = original
        entry = files[name]
        seen: set[str] = set()
        while entry["symlink"] is not None:
            if name in seen:
                fail("source link cycle is not admitted")
            seen.add(name)
            name = source_link_target(name, entry["symlink"], files)
            entry = files[name]
        if entry["git_mode"] not in {"100644", "100755"}:
            fail("source link terminal is not a frozen tracked regular file")


@dataclass(frozen=True, slots=True)
class Snapshot:
    root: pathlib.Path
    domain: dict[str, Any]
    files: dict[str, Any]
    contents: dict[str, bytes]


def write_blobs(
    snapshot: Snapshot, private: pathlib.Path, env: dict[str, str], *, runtime: Dependencies
) -> list[bytes]:
    raw_directory = private / "preimages"
    raw_directory.mkdir(mode=0o700)
    members = list(snapshot.files.items())
    records = []
    batch_size = 128
    for start in range(0, len(members), batch_size):
        batch = members[start : start + batch_size]
        preimages = []
        for offset, (name, _entry) in enumerate(batch):
            path = raw_directory / f"{start + offset:08d}"
            path.write_bytes(snapshot.contents[name])
            path.chmod(0o600)
            preimages.append(str(path))
        blobs = (
            runtime.command(
                snapshot.root, "hash-object", "--no-filters", "-w", "--", *preimages, env=env
            )
            .decode("ascii")
            .splitlines()
        )
        if len(blobs) != len(batch):
            fail("Git blob batch did not return every selected preimage")
        for (name, entry), blob in zip(batch, blobs, strict=True):
            if blob != entry["git_blob"]:
                fail("Git blob binding failed")
            records.append(f"{entry['git_mode']} {blob}\t{name}\0".encode())
    return records


def private_tree(
    snapshot: Snapshot, forbidden: list[pathlib.Path], *, runtime: Dependencies
) -> tuple[str, bytes, pathlib.Path]:
    root, domain, files, contents = (
        snapshot.root,
        snapshot.domain,
        snapshot.files,
        snapshot.contents,
    )
    temporary_root = private_root(root, forbidden, runtime=runtime)
    private = pathlib.Path(tempfile.mkdtemp(prefix="aegaeon-perf-source-", dir=temporary_root))
    if private.is_relative_to(root):
        fail("private source preimages must be outside source")
    objects = private / "objects"
    objects.mkdir()
    env = environment()
    env.update(
        GIT_INDEX_FILE=str(private / "index"),
        GIT_OBJECT_DIRECTORY=str(objects),
        GIT_ALTERNATE_OBJECT_DIRECTORIES=runtime.command(root, "rev-parse", "--git-path", "objects")
        .decode()
        .strip(),
    )
    alternate = pathlib.Path(env["GIT_ALTERNATE_OBJECT_DIRECTORIES"])
    if not alternate.is_absolute():
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(root / alternate)
    records = write_blobs(snapshot, private, env, runtime=runtime)
    runtime.command(root, "read-tree", "--empty", env=env)
    runtime.command(root, "update-index", "-z", "--index-info", env=env, data=b"".join(records))
    tree = runtime.command(root, "write-tree", env=env).decode().strip()
    patch = runtime.command(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--full-index",
        domain["head"],
        tree,
        "--",
        env=env,
    )
    retain_preimages(private, files, contents, patch)
    return (tree, patch, private)


def retain_preimages(
    private: pathlib.Path, files: dict[str, Any], contents: dict[str, bytes], patch: bytes
) -> None:
    (private / "source.patch").write_bytes(patch)
    with tarfile.open(private / "source.tar", "w") as archive:
        for name, entry in files.items():
            info = tarfile.TarInfo(name)
            info.mode = entry["filesystem_mode"] & 0o777
            if entry["symlink"] is not None:
                info.type = tarfile.SYMTYPE
                info.linkname = entry["symlink"]
                archive.addfile(info)
            else:
                info.size = entry["bytes"]
                archive.addfile(info, io.BytesIO(contents[name]))
    for current, _dirs, names in os.walk(private):
        pathlib.Path(current).chmod(0o700)
        for name in names:
            (pathlib.Path(current) / name).chmod(0o600)
