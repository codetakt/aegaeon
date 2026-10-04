"""Freeze and verify complete tracked source for the shared performance runner."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from typing import Any, Never
from urllib.parse import urlsplit

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
MAX_RUN_SECONDS = 86_400
NANOS_PER_SECOND = 1_000_000_000
UUID_VERSION = 4
ASCII_SPACE = 0x20
ASCII_DEL = 0x7F
C1_CONTROL_END = 0x9F
# Unicode White_Space beyond ASCII, matching Rust char::is_whitespace.
UNICODE_WHITESPACE = (
    "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
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
    validate_source_links(files)
    return files, contents


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

    return raw, strict_json(raw)


def strict_json(raw: bytes | str) -> object:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("duplicate JSON field")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: fail("nonfinite JSON number"),
    )


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


def admitted_executable(root: pathlib.Path, evidence: pathlib.Path, value: str) -> pathlib.Path:
    path = output_path(root, value)
    if path.is_relative_to(root) and not path.is_relative_to(root / "target"):
        fail("build executable overlaps source")
    _, outputs = load_json(evidence / "OUTPUTS.json")
    leaves = {output_path(root, destination) for destination, directory in outputs if not directory}
    leaves.update(output_path(root, name) for name in LEGACY)
    leaves.add(evidence.parent / "source-status.json")
    if path in leaves or path.is_relative_to(evidence):
        fail("build executable overlaps an output or source evidence")
    return path


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
    path = admitted_executable(root, evidence, matches[0])
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
    path = admitted_executable(root, evidence, binding["executable"])
    if executable(path) != binding["artifact_sha256"]:
        fail("built executable changed before launch")
    return str(path)


SCENARIOS = {
    "smoke": "Smoke",
    "auth-code": "AuthorizationCode",
    "introspection": "Introspection",
    "revocation": "Revocation",
    "dpop": "DPoP",
    "userinfo": "Userinfo",
    "discovery": "Discovery",
    "jwks": "Jwks",
    "par": "PAR",
    "mixed": "Mixed",
    "policy-mixed": "PolicyMixed",
    "key-rotation": "KeyRotation",
}
CONFIG_FIELDS = {
    "target_url",
    "discovery_expected_issuer",
    "workers",
    "duration",
    "target_rps",
    "warmup_duration",
    "scenario",
    "debug",
}
IDENTITY_FIELDS = {
    "source_sha256",
    "artifact_sha256",
    "config_sha256",
    "config_json",
    "report_id",
    "report_path",
    "profile_sha256",
    "session_provenance_sha256",
}


def nonsecret_url(value: str, *, issuer: bool = False) -> None:
    if any(
        ord(char) <= ASCII_SPACE
        or ASCII_DEL <= ord(char) <= C1_CONTROL_END
        or char in UNICODE_WHITESPACE
        for char in value
    ):
        fail("invocation URL has invalid or secret-bearing components")
    url = urlsplit(value)
    try:
        _ = url.port
    except ValueError:
        fail("invocation URL has invalid or secret-bearing components")
    if (
        url.scheme not in ({"https"} if issuer else {"http", "https"})
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or "?" in value
        or "#" in value
        or (issuer and value.endswith("/"))
    ):
        fail("invocation URL has invalid or secret-bearing components")


def validate_config(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != CONFIG_FIELDS:
        fail("configuration fields are missing or unknown")
    if (
        type(value["target_url"]) is not str
        or not value["target_url"]
        or (
            value["discovery_expected_issuer"] is not None
            and (
                type(value["discovery_expected_issuer"]) is not str
                or not value["discovery_expected_issuer"]
            )
        )
        or type(value["workers"]) is not int
        or not 0 < value["workers"] <= 2**32 - 1
        or type(value["target_rps"]) not in (int, float)
        or not math.isfinite(value["target_rps"])
        or value["target_rps"] <= 0
        or type(value["debug"]) is not bool
        or type(value["scenario"]) is not str
        or value["scenario"] not in SCENARIOS.values()
    ):
        fail("invalid typed configuration field")
    nonsecret_url(value["target_url"])
    if value["discovery_expected_issuer"] is not None:
        nonsecret_url(value["discovery_expected_issuer"], issuer=True)
    for name in ("duration", "warmup_duration"):
        duration = value[name]
        if (
            not isinstance(duration, dict)
            or duration.keys() != {"secs", "nanos"}
            or type(duration["secs"]) is not int
            or not 0 <= duration["secs"] <= MAX_RUN_SECONDS
            or type(duration["nanos"]) is not int
            or not 0 <= duration["nanos"] < NANOS_PER_SECOND
            or (name == "duration" and duration == {"secs": 0, "nanos": 0})
        ):
            fail("invalid typed configuration duration")
    if value["workers"] / value["target_rps"] > MAX_RUN_SECONDS:
        fail("worker pacing exceeds bound")
    return value


def invocation_config(argv: list[str]) -> tuple[dict[str, Any], str, str]:
    options: dict[str, str] = {}
    debug = False
    position = 1
    required_options = {
        "--url",
        "--workers",
        "--run-time",
        "--warmup",
        "--rps",
        "--scenario",
        "--report-file",
        "--report-id",
    }
    while position < len(argv):
        name = argv[position]
        if name == "--debug":
            if debug:
                fail("duplicate child option")
            debug = True
            position += 1
            continue
        if (
            name not in required_options | {"--discovery-expected-issuer"}
            or name in options
            or position + 1 >= len(argv)
        ):
            fail("unbound, duplicate or incomplete child option")
        options[name] = argv[position + 1]
        position += 2
    if not options.keys() >= required_options:
        fail("child invocation lacks required options")

    def duration(value: str) -> dict[str, int]:
        match = re.fullmatch(r"([0-9]+)([smh]?)", value.strip())
        if match is None:
            fail("invalid invocation duration")
        seconds = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
        return {"secs": seconds, "nanos": 0}

    report_id = options["--report-id"]
    parsed_id = uuid.UUID(report_id)
    if parsed_id.version != UUID_VERSION or str(parsed_id) != report_id:
        fail("invocation requires canonical UUIDv4")
    if re.fullmatch(r"[0-9]+", options["--workers"]) is None:
        fail("invalid worker count")
    config = validate_config(
        {
            "target_url": options["--url"],
            "discovery_expected_issuer": options.get("--discovery-expected-issuer"),
            "workers": int(options["--workers"]),
            "duration": duration(options["--run-time"]),
            "target_rps": float(options["--rps"]),
            "warmup_duration": duration(options["--warmup"]),
            "scenario": SCENARIOS[options["--scenario"]],
            "debug": debug,
        }
    )
    return config, report_id, required(options["--report-file"])


def freeze_invocation(
    root: pathlib.Path, evidence: pathlib.Path, expected: str, argv: list[str]
) -> None:
    binary = verify_binary(root, evidence, expected, "aegaeon-loadtest")
    if not argv or argv[0] != binary:
        fail("invocation executable differs from selected build")
    config, report_id, report_path = invocation_config(argv)
    require_fresh_outputs(root, [report_path])
    _, binding = load_json(evidence / "aegaeon-loadtest.json")
    publish(
        evidence / "INVOCATION.json",
        canonical(
            {
                "schema_version": 1,
                "source_sha256": expected,
                "artifact_sha256": binding["artifact_sha256"],
                "argv": argv,
                "config": config,
                "report_id": report_id,
                "report_path": report_path,
                "normalized_report_path": str(output_path(root, report_path)),
            }
        ),
    )


def verify_report(
    root: pathlib.Path, evidence: pathlib.Path, expected: str, report: pathlib.Path
) -> None:
    _, binding = load_json(evidence / "aegaeon-loadtest.json")
    _, invocation = load_json(evidence / "INVOCATION.json")
    if (
        not isinstance(invocation, dict)
        or invocation.keys()
        != {
            "schema_version",
            "source_sha256",
            "artifact_sha256",
            "argv",
            "config",
            "report_id",
            "report_path",
            "normalized_report_path",
        }
        or type(invocation["schema_version"]) is not int
        or invocation["schema_version"] != 1
        or not isinstance(invocation["argv"], list)
        or not invocation["argv"]
        or any(type(arg) is not str for arg in invocation["argv"])
        or invocation["argv"][0] != binding["executable"]
        or binding["source_manifest_sha256"] != expected
        or invocation["source_sha256"] != expected
        or invocation["artifact_sha256"] != binding["artifact_sha256"]
    ):
        fail("invocation does not match independent build observations")
    config, report_id, report_path = invocation_config(invocation["argv"])
    if (
        validate_config(invocation["config"]) != config
        or invocation["report_id"] != report_id
        or invocation["report_path"] != report_path
        or invocation["normalized_report_path"] != str(output_path(root, report_path))
        or output_path(root, str(report)) != output_path(root, report_path)
    ):
        fail("invocation record or report destination mismatch")
    report = checked_output(root, str(report), directory=False)
    before = report.lstat()
    with os.fdopen(os.open(report, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()
    if stamp(before) != stamp(report.lstat()):
        fail("report changed while reading")
    data = strict_json(raw)
    if not isinstance(data, dict):
        fail("report must be a JSON object")
    identity = data.get("identity")
    if isinstance(identity, dict):
        for name in ("profile_sha256", "session_provenance_sha256"):
            value = identity.get(name)
            if value is not None and (
                type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
            ):
                fail("invalid nullable supplier digest")
    if (
        not isinstance(identity, dict)
        or identity.keys() != IDENTITY_FIELDS
        or identity["source_sha256"] != expected
        or identity["artifact_sha256"] != binding["artifact_sha256"]
        or type(identity["config_json"]) is not str
        or digest(identity["config_json"].encode("utf-8")) != identity["config_sha256"]
        or validate_config(strict_json(identity["config_json"])) != config
        or identity["report_id"] != report_id
        or identity["report_path"] != report_path
        or type(data.get("selected_scenario")) is not str
        or data["selected_scenario"] != config["scenario"]
    ):
        fail("report differs from the independent invocation")


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
            "invocation": lambda: freeze_invocation(
                root,
                evidence,
                expected,
                args.child_args,
            ),
            "report": lambda: verify_report(
                root, evidence, expected, pathlib.Path(required(args.report))
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "urls",
            "paths",
            "freeze",
            "verify",
            "bind",
            "binary",
            "invocation",
            "report",
            "status",
        ],
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
    parser.add_argument("--url")
    parser.add_argument("--discovery-expected-issuer")
    producer_args = sys.argv[1:]
    child_args: list[str] = []
    if "--" in producer_args:
        position = producer_args.index("--")
        child_args = producer_args[position + 1 :]
        producer_args = producer_args[:position]
    args = parser.parse_args(producer_args)
    args.child_args = child_args
    if child_args and args.action != "invocation":
        parser.error("child arguments are only accepted by invocation")
    return args


def validate_requested_urls(args: argparse.Namespace) -> None:
    if args.url is not None:
        nonsecret_url(required(args.url))
    if args.discovery_expected_issuer is not None:
        nonsecret_url(required(args.discovery_expected_issuer), issuer=True)


def main() -> int:
    args = parse_arguments()
    try:
        if args.action == "urls":
            validate_requested_urls(args)
        else:
            dispatch(args)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, UnicodeError, SourceError):
        print("[perf] source or executable evidence validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
