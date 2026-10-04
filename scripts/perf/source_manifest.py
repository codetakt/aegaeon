"""Freeze and verify complete tracked source for the shared performance runner."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Never

MODES = {
    "100644": stat.S_IFREG | 0o644,
    "100755": stat.S_IFREG | 0o755,
    "120000": stat.S_IFLNK | 0o777,
}
MANDATORY = {
    "Cargo.toml",
    "Cargo.lock",
    "flake.nix",
    "flake.lock",
    "rust-toolchain.toml",
    "scripts/perf/run_load_tests.sh",
    "scripts/perf/source_manifest.py",
}
SHA256_LENGTH = 64
LEGACY = {"artifacts/load-test-report.json", "artifacts/policy-mixed-report.json"}


class SourceError(RuntimeError):
    """A source or evidence boundary was not established."""


def fail(message: str) -> Never:
    raise SourceError(message)


def stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def environment() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    return env


def command(
    root: pathlib.Path, *args: str, env: dict[str, str] | None = None, data: bytes | None = None
) -> bytes:
    git = shutil.which("git")
    if git is None:
        fail("Git executable is unavailable")
    result = subprocess.run(  # noqa: S603 - fixed Git plumbing, no shell execution
        [
            git,
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(root),
            *args,
        ],
        input=data,
        capture_output=True,
        env=env or environment(),
        check=False,
    )
    if result.returncode:
        fail("Git source inspection failed")
    return result.stdout


def ancestors(path: pathlib.Path) -> None:
    for parent in reversed(path.parents):
        if (parent.exists() or parent.is_symlink()) and not stat.S_ISDIR(parent.lstat().st_mode):
            fail("path ancestor is not a regular directory")


def root_path(value: str) -> pathlib.Path:
    root = pathlib.Path(value).absolute()
    ancestors(root)
    if not root.is_dir() or root.is_symlink() or root != root.resolve():
        fail("source is not a regular directory")
    actual = command(root, "rev-parse", "--show-toplevel").decode().strip()
    if pathlib.Path(actual).resolve() != root.resolve():
        fail("source must be the Git worktree root")
    if command(root, "rev-parse", "--show-object-format").strip() != b"sha1":
        fail("unsupported Git object format")
    return root


def git_domain(root: pathlib.Path) -> dict[str, Any]:
    head = command(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    entries: dict[str, dict[str, str]] = {}
    raw = command(root, "ls-files", "--stage", "-z")
    for item in raw.split(b"\0"):
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
            or ".." in path.parts
            or str(path) != name
            or name == ".git"
            or name.startswith(".git/")
        ):
            fail("unsupported or conflicted tracked path")
        entries[name] = {"git_mode": mode, "git_blob": blob}
    if not entries.keys() >= MANDATORY:
        fail("mandatory tracked source input is missing")
    return {"head": head, "index": entries}


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


def output_roles(
    root: pathlib.Path,
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    status: pathlib.Path | None = None,
) -> None:
    destinations = [(output_path(root, value), directory) for value, directory in outputs]
    status = status or evidence.parent / "source-status.json"
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


def private_root(root: pathlib.Path, forbidden: list[pathlib.Path]) -> pathlib.Path:
    temporary = output_path(root, os.environ.get("TMPDIR") or tempfile.gettempdir())
    if (
        temporary.is_symlink()
        or not temporary.is_dir()
        or temporary.is_relative_to(root)
        or any(temporary.is_relative_to(path) for path in forbidden)
    ):
        fail("private retention must be outside source and uploads")
    return temporary


def declared_outputs(root: pathlib.Path, args: argparse.Namespace) -> list[tuple[str, bool]]:
    outputs = [(name, False) for name in args.output_file] + [
        (name, True) for name in args.output_directory
    ]
    reports = [name for name in (args.report_file, args.legacy_report_file) if name is not None]
    # Only these two declared report roles may intentionally share one leaf.
    if (
        args.report_file is not None
        and args.legacy_report_file is not None
        and output_path(root, args.report_file) == output_path(root, args.legacy_report_file)
    ):
        reports.pop()
    outputs.extend((name, False) for name in reports)
    if args.artifact_directory:
        artifact = output_path(root, args.artifact_directory)
        output_roles(
            root, output_path(root, args.evidence), outputs, artifact / "source-status.json"
        )
        private_root(root, [artifact])
    return outputs


def output_boundaries(
    root: pathlib.Path,
    domain: dict[str, Any],
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
) -> None:
    output_roles(root, evidence, outputs)
    paths = [checked_output(root, str(evidence), directory=True)]
    paths.extend(checked_output(root, value, directory=is_dir) for value, is_dir in outputs)
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
    paths.extend(cargo_outputs(root))
    reject_source_overlap(root, domain, paths)


def reject_source_overlap(
    root: pathlib.Path, domain: dict[str, Any], paths: list[pathlib.Path]
) -> None:
    for path in paths:
        if path == root or root.is_relative_to(path):
            fail("output overlaps source root")
        for name in domain["index"]:
            source = root / name
            if source == path or source.is_relative_to(path) or path.is_relative_to(source):
                fail("output boundary overlaps tracked source")


def cargo_outputs(root: pathlib.Path) -> list[pathlib.Path]:
    target = os.environ.get("CARGO_TARGET_DIR")
    if target:
        path = output_path(root, target)
        if path.exists() and (
            not stat.S_ISDIR(path.lstat().st_mode) or path.lstat().st_uid != os.geteuid()
        ):
            fail("Cargo output is not an owned regular directory")
        if path.is_symlink() or (path.is_relative_to(root) and path != root / "target"):
            fail("custom Cargo output must be outside source")
        if path == root or root.is_relative_to(path):
            fail("Cargo output overlaps source")
        return [path]
    return []


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
            b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
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
    return files, contents


def publish(path: pathlib.Path, raw: bytes) -> None:
    ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".source-publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        pathlib.Path(temporary).chmod(0o444)
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        pathlib.Path(temporary).unlink()


def load_json(path: pathlib.Path) -> tuple[bytes, Any]:
    ancestors(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o222:
        fail("frozen evidence is not an owned read-only regular file")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("duplicate JSON field")
            result[key] = value
        return result

    return raw, json.loads(raw, object_pairs_hook=unique)


def private_tree(
    root: pathlib.Path,
    domain: dict[str, Any],
    files: dict[str, Any],
    contents: dict[str, bytes],
    forbidden: list[pathlib.Path],
) -> tuple[str, bytes, pathlib.Path]:
    temporary_root = private_root(root, forbidden)
    private = pathlib.Path(tempfile.mkdtemp(prefix="aegaeon-perf-source-", dir=temporary_root))
    if private.is_relative_to(root):
        fail("private source preimages must be outside source")
    objects = private / "objects"
    objects.mkdir()
    env = environment()
    env.update(
        GIT_INDEX_FILE=str(private / "index"),
        GIT_OBJECT_DIRECTORY=str(objects),
        GIT_ALTERNATE_OBJECT_DIRECTORIES=command(root, "rev-parse", "--git-path", "objects")
        .decode()
        .strip(),
    )
    alternate = pathlib.Path(env["GIT_ALTERNATE_OBJECT_DIRECTORIES"])
    if not alternate.is_absolute():
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(root / alternate)
    records = []
    for name, entry in files.items():
        blob = (
            command(
                root, "hash-object", "--no-filters", "-w", "--stdin", env=env, data=contents[name]
            )
            .decode()
            .strip()
        )
        if blob != entry["git_blob"]:
            fail("Git blob binding failed")
        records.append(f"{entry['git_mode']} {blob}\t{name}\0".encode())
    command(root, "read-tree", "--empty", env=env)
    command(root, "update-index", "-z", "--index-info", env=env, data=b"".join(records))
    tree = command(root, "write-tree", env=env).decode().strip()
    patch = command(
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
    return tree, patch, private


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


def freeze(root: pathlib.Path, evidence: pathlib.Path, outputs: list[tuple[str, bool]]) -> str:
    domain = git_domain(root)
    output_boundaries(root, domain, evidence, outputs)
    evidence.mkdir(parents=True, exist_ok=False)
    unexpected_paths(root, domain)
    files, contents = read_source(root, domain)
    forbidden = [evidence.parent] + [
        checked_output(root, path, directory=True) for path, is_dir in outputs if is_dir
    ]
    tree, patch, private = private_tree(root, domain, files, contents, forbidden)
    unexpected_paths(root, domain)
    if git_domain(root) != domain or read_source(root, domain)[0] != files:
        fail("source changed during freeze")
    publish(evidence / "TRACKED-PATHS.json", canonical(domain))
    publish(evidence / "OUTPUTS.json", canonical(outputs))
    manifest = {
        "candidate_tree": tree,
        "files": files,
        "patch_sha256": digest(patch),
        "source_base_commit": domain["head"],
    }
    raw = canonical(manifest)
    publish(evidence / "SOURCE-MANIFEST.json", raw)
    origin = {
        "source_manifest_sha256": digest(raw),
        "source_archive_sha256": digest((private / "source.tar").read_bytes()),
        "patch_sha256": digest(patch),
        "tracked_domain_sha256": digest((evidence / "TRACKED-PATHS.json").read_bytes()),
        "outputs_sha256": digest((evidence / "OUTPUTS.json").read_bytes()),
    }
    publish(evidence / "ORIGIN.json", canonical(origin))
    (private / "LOCATION.json").write_bytes(
        canonical({"evidence": str(evidence), "origin": origin})
    )
    (private / "LOCATION.json").chmod(0o600)
    verify(root, evidence, digest(raw))
    return digest(raw)


def verify(root: pathlib.Path, evidence: pathlib.Path, expected: str) -> dict[str, Any]:
    raw, manifest = load_json(evidence / "SOURCE-MANIFEST.json")
    if digest(raw) != expected or set(manifest) != {
        "candidate_tree",
        "files",
        "patch_sha256",
        "source_base_commit",
    }:
        fail("raw source manifest binding failed")
    domain_raw, domain = load_json(evidence / "TRACKED-PATHS.json")
    outputs_raw, outputs = load_json(evidence / "OUTPUTS.json")
    _, origin = load_json(evidence / "ORIGIN.json")
    if (
        origin["source_manifest_sha256"] != expected
        or origin["tracked_domain_sha256"] != digest(domain_raw)
        or origin["outputs_sha256"] != digest(outputs_raw)
        or origin["patch_sha256"] != manifest["patch_sha256"]
    ):
        fail("independent source evidence binding failed")
    if git_domain(root) != domain or domain["head"] != manifest["source_base_commit"]:
        fail("Git source domain changed")
    output_boundaries(root, domain, evidence, outputs)
    unexpected_paths(root, domain)
    files, _ = read_source(root, domain)
    if files != manifest["files"] or set(files) != set(domain["index"]):
        fail("complete source bytes, modes or links changed")
    return manifest


def executable(path: pathlib.Path) -> str:
    ancestors(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
        fail("build executable is not regular and executable")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()
    if stamp(path.lstat()) != stamp(before):
        fail("build executable changed while reading")
    return digest(raw)


def bind(
    root: pathlib.Path, evidence: pathlib.Path, expected: str, build_log: pathlib.Path, name: str
) -> str:
    verify(root, evidence, expected)
    matches: list[str] = []
    finished = []
    for line in build_log.read_text().splitlines():
        record = json.loads(line)
        target = record.get("target", {})
        if record.get("reason") == "build-finished":
            finished.append(record.get("success"))
        if (
            record.get("reason") == "compiler-artifact"
            and target.get("name") == name
            and "bin" in target.get("kind", [])
            and record.get("executable")
        ):
            matches.append(record["executable"])
    if len(matches) != 1 or finished != [True]:
        fail("build did not identify exactly one selected executable")
    path = pathlib.Path(matches[0]).absolute()
    if path.is_relative_to(root) and not path.is_relative_to(root / "target"):
        fail("build executable overlaps source")
    sha = executable(path)
    publish(
        evidence / (name + ".json"),
        canonical(
            {
                "source_manifest_sha256": expected,
                "artifact_sha256": sha,
                "executable": str(path),
                "build_success": True,
                "build_command": (
                    ["cargo", "build", "--release", "--locked", "--bin", name]
                    if name == "aegaeon-server"
                    else ["cargo", "build", "--release", "-p", "aegaeon-loadtest", "--bin", name]
                )
                + ["--message-format=json-render-diagnostics"],
            }
        ),
    )
    return str(path)


def verify_binary(root: pathlib.Path, evidence: pathlib.Path, expected: str, name: str) -> str:
    verify(root, evidence, expected)
    _, binding = load_json(evidence / (name + ".json"))
    if binding["source_manifest_sha256"] != expected:
        fail("executable source binding failed")
    path = pathlib.Path(binding["executable"])
    if executable(path) != binding["artifact_sha256"]:
        fail("built executable changed before launch")
    return str(path)


def verify_report(evidence: pathlib.Path, expected: str, report: pathlib.Path) -> None:
    _, binding = load_json(evidence / "aegaeon-loadtest.json")
    identity = json.loads(report.read_bytes()).get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("source_sha256") != expected
        or identity.get("artifact_sha256") != binding["artifact_sha256"]
    ):
        fail("report does not match source and executable observations")


def status_boundary(root: pathlib.Path, artifact: str) -> pathlib.Path:
    directory = checked_output(root, artifact, directory=True)
    parent = directory.parent
    while not parent.exists():
        parent = parent.parent
    if parent.lstat().st_uid != os.geteuid():
        fail("status parent is not owned")
    path = directory / "source-status.json"
    domain = git_domain(root)
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
    root: pathlib.Path, outputs: list[tuple[str, bool]], evidence: pathlib.Path
) -> None:
    domain = git_domain(root)
    output_roles(root, evidence, outputs)
    private_root(
        root,
        [evidence.parent] + [output_path(root, value) for value, directory in outputs if directory],
    )
    # Check real geometry before any prior-status read or private bootstrap.
    for reserved in [root / "target", root / "artifacts/perf"]:
        ancestors(reserved)
        if reserved.is_symlink():
            fail("reserved output directory is a link")
    for value, directory in outputs:
        output = output_path(root, value)
        if output.is_relative_to(root):
            relative = output.relative_to(root).as_posix()
            if not (relative == "artifacts/perf" or relative.startswith("artifacts/perf/")) and (
                directory or relative not in LEGACY
            ):
                fail("output is outside the reserved performance domain")
    reject_source_overlap(
        root,
        domain,
        [
            evidence,
            *(output_path(root, value) for value, _ in outputs),
            root / "target",
            root / "artifacts/perf",
            *(root / name for name in LEGACY),
            *cargo_outputs(root),
        ],
    )


def retain_status(
    root: pathlib.Path, path: pathlib.Path, outputs: list[tuple[str, bool]], evidence: pathlib.Path
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
    )
    private = pathlib.Path(tempfile.mkdtemp(prefix="aegaeon-perf-status-", dir=temporary_root))
    retained = private / ("source-status." + kind)
    with retained.open("xb") as stream:
        stream.write(raw)
    retained.chmod(0o600)


def initialize_status(
    root: pathlib.Path, artifact: str, outputs: list[tuple[str, bool]], evidence: pathlib.Path
) -> None:
    path = status_boundary(root, artifact)
    output_roles(root, evidence, outputs, path)
    status_geometry(root, outputs, evidence)
    retain_status(root, path, outputs, evidence)
    write_status(path, "paths", 1)


def dispatch(args: argparse.Namespace) -> None:
    root = root_path(args.root)
    if pathlib.Path(__file__).resolve() != root / "scripts/perf/source_manifest.py":
        fail("producer must be the tracked repository entrypoint")
    evidence = checked_output(root, args.evidence, directory=True)
    if args.action == "paths":
        outputs = declared_outputs(root, args)
        if args.artifact_directory:
            initialize_status(root, args.artifact_directory, outputs, evidence)
        output_boundaries(root, git_domain(root), evidence, outputs)
        require_fresh_outputs(root, args.fresh_output_file)
    elif args.action == "status":
        write_status(
            status_boundary(root, required(args.artifact_directory)),
            required(args.stage),
            args.exit_status,
        )
    elif args.action == "freeze":
        if "AEG_LOADTEST_SOURCE_SHA256" in os.environ:
            fail("caller source digest is not accepted")
        outputs = declared_outputs(root, args)
        output_boundaries(root, git_domain(root), evidence, outputs)
        require_fresh_outputs(root, args.fresh_output_file)
        print(freeze(root, evidence, outputs))
    else:
        expected = required(args.sha256)
        if len(expected) != SHA256_LENGTH or any(c not in "0123456789abcdef" for c in expected):
            fail("producer source digest is required")
        actions = {
            "verify": lambda: verify(root, evidence, expected),
            "bind": lambda: print(
                bind(
                    root,
                    evidence,
                    expected,
                    pathlib.Path(required(args.build_log)),
                    required(args.name),
                )
            ),
            "binary": lambda: print(verify_binary(root, evidence, expected, required(args.name))),
            "report": lambda: verify_report(
                evidence, expected, pathlib.Path(required(args.report))
            ),
        }
        actions[args.action]()


def required(value: str | None) -> str:
    if not value:
        fail("required producer observation is missing")
    return value


def require_fresh_outputs(root: pathlib.Path, paths: list[str]) -> None:
    for value in paths:
        path = checked_output(root, value, directory=False)
        if path.exists() or path.is_symlink():
            fail("run output already exists")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["paths", "freeze", "verify", "bind", "binary", "report", "status"]
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--artifact-directory")
    parser.add_argument("--stage")
    parser.add_argument("--exit-status", type=int, default=1)
    parser.add_argument("--output-file", action="append", default=[])
    parser.add_argument("--report-file")
    parser.add_argument("--legacy-report-file")
    parser.add_argument("--fresh-output-file", action="append", default=[])
    parser.add_argument("--output-directory", action="append", default=[])
    parser.add_argument("--build-log")
    parser.add_argument("--name", choices=["aegaeon-server", "aegaeon-loadtest"])
    parser.add_argument("--report")
    args = parser.parse_args()
    try:
        dispatch(args)
    except (OSError, ValueError, KeyError, UnicodeError, SourceError):
        print("[perf] source or executable evidence validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
