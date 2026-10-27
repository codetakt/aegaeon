"""Shared repository paths and literal filesystem evidence operations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NoReturn

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).resolve().parents[3]

FUZZ_DIR = ROOT / "fuzz"

CORPUS_ROOT = FUZZ_DIR / "corpus"

META_DIR = FUZZ_DIR / "corpus_meta"

ARCHIVE_DIR = FUZZ_DIR / "corpus_archive"

CRASH_ROOT = FUZZ_DIR / "artifacts"

HISTORY_FILE = META_DIR / "history.jsonl"

MAX_SAMPLE_FILES = 10

MIN_FUZZ_SECONDS = 30

WATCHDOG_GRACE_SECONDS = 30

EVIDENCE_ERROR = 2


def invalid(message: str) -> NoReturn:
    raise ValueError(message)


def optional_path_from_env(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


RUN_ARTIFACT_DIR = optional_path_from_env("FUZZ_RUN_ARTIFACT_DIR")

HISTORY_OUT_DIR = optional_path_from_env("FUZZ_HISTORY_DIR")


def parse_env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


REQUIRED_TARGETS = (
    "fuzz_bearer_token",
    "fuzz_dpop_proof",
    "fuzz_pkce_verifier",
    "fuzz_jose_parsing",
    "fuzz_ffi_parsers",
    "fuzz_introspection",
    "fuzz_par",
)


def tool_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def digest(path: Path) -> str:
    return evidence_digest(path)


def write_json(path: Path, data: dict) -> None:
    # The destination's parent is owned by the caller's approved evidence route.
    # Refuse aliases before creating our exclusive temporary file; an old fixed
    # execution.tmp/run_summary.tmp is never opened or removed.
    parent = path.parent
    if parent.resolve() != parent.absolute() or not parent.is_dir():
        invalid("fuzz receipt parent is not an owned directory")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        invalid("fuzz receipt destination is not a regular file")
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(data, indent=2) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def seconds(value: str, name: str) -> int:
    match = re.fullmatch(r"([0-9]{1,8})([sSmMhH]?)", value)
    if not match:
        invalid(f"{name} must be a positive integer duration (s, m or h)")
    number = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2].lower()]
    if number <= 0:
        invalid(f"{name} must be positive")
    return number


def capture(argv: list[str]) -> dict:
    path = shutil.which(argv[0])
    result = {"argv": argv, "path": path, "exit_code": None, "output": ""}
    if path is None:
        return result
    result["sha256"] = tool_digest(Path(path))
    try:
        # Only the fixed version/identity commands and configured native compilers are used.
        process = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=10, check=False
        )
        result.update(exit_code=process.returncode, output=process.stdout + process.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    return result


GIT_IDENTITY_OVERRIDES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
)

KANI_OUTPUT_POINTER = "crates/kani-harness/kani"

KANI_OUTPUT_TARGET = "result/bin/cargo-kani"

KANI_OUTPUT_MODE = 0o777

CACHE_SOURCE_ROOTS = (
    ".cargo",
    ".flakehub",
    ".git",
    ".github",
    "artifacts",
    "assets",
    "c",
    "ci",
    "crates",
    "db",
    "dev-tools",
    "docs",
    "examples",
    "fstar",
    "generated",
    "include",
    "infra",
    "nix",
    "proofs",
    "scripts",
    "spec",
    "supply-chain",
    "tests",
    "xtask",
)


def repository_path(path: Path) -> Path:
    return (path if path.is_absolute() else ROOT / path).resolve()


def overlaps(left: Path, right: Path) -> bool:
    return left.is_relative_to(right) or right.is_relative_to(left)


def effective_cargo_home() -> Path:
    path = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    return path if path.is_absolute() else ROOT / path


def lexical_directory(path: Path) -> Path:
    path = path if path.is_absolute() else ROOT / path
    if ".." in path.parts:
        invalid("owned directory route cannot contain parent traversal")
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            invalid("owned directory route cannot contain symlink components")
        if component.exists() and not component.is_dir():
            invalid("owned directory route contains a special or nondirectory component")
    return path


def validate_cargo_home_paths(
    paths: list[Path], purpose: str, *, output: Path | None = None
) -> None:
    cargo_home = lexical_directory(effective_cargo_home())
    if any(overlaps(cargo_home, path) for path in paths) or (
        output is not None and overlaps(cargo_home, lexical_directory(output))
    ):
        invalid(f"{purpose} paths overlap Cargo home")


def validate_restore_cargo_home(directory: Path) -> None:
    validate_cargo_home_paths(
        [FUZZ_DIR / name for name in RECOVERY_RAW_NAMES], "restoration", output=directory
    )


def validate_regular_destination(path: Path) -> None:
    lexical_directory(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        invalid("owned output destination cannot be a symlink or special entry")
    if path.exists():
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_nlink != 1:
            invalid("owned output destination must be unaliased and producer-owned")


def validate_collection_history(directory: Path | None) -> None:
    collection_routes = [
        lexical_directory(route) for route in (directory, RUN_ARTIFACT_DIR) if route is not None
    ]
    for name, default in (
        ("FUZZ_HISTORY_DIR", ""),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
    ):
        if value := os.environ.get(name, default):
            history = lexical_directory(Path(value))
            if any(overlaps(collection, history) for collection in collection_routes):
                invalid("fuzz collection and history directories overlap")


RECOVERY_RAW_NAMES = ("corpus", "artifacts", "corpus_archive")

RECOVERY_EVIDENCE_NAMES = (
    "execution.json",
    "run_summary.json",
    "collection.ok",
    "collection-summary.json",
)


def owned_raw_root(name: str) -> Path:
    path = FUZZ_DIR / name
    if FUZZ_DIR.resolve() != FUZZ_DIR or path.is_symlink() or path.resolve() != path:
        invalid("fuzz recovery requires owned raw directory roots")
    if path.exists() and not path.is_dir():
        invalid("fuzz recovery raw root is not a directory")
    return path


def validate_collection_roots() -> None:
    # Check all roots before collection can create directories or inspect raw input.
    # Nested symlinks are archive entries, never inputs to statistics or traversal.
    validate_cargo_home_paths(
        [
            *(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta")),
            *(
                lexical_directory(route)
                for route in (RUN_ARTIFACT_DIR, HISTORY_OUT_DIR)
                if route is not None
            ),
        ],
        "collection",
    )
    for name in (*RECOVERY_RAW_NAMES, "corpus_meta"):
        owned_raw_root(name)
    for name in ("history.jsonl", "latest_run.json"):
        validate_regular_destination(META_DIR / name)


def evidence_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_mode,
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def open_evidence_file(path: Path, expected: os.stat_result | None = None) -> Iterator[BinaryIO]:
    lexical_directory(path.parent)
    before = path.lstat() if expected is None else expected
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as content:
        opened = os.fstat(content.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or evidence_state(opened) != evidence_state(before)
        ):
            invalid("evidence file must be a stable, unaliased regular file")
        yield content
        after = os.fstat(content.fileno())
        lexical_directory(path.parent)
        current = path.lstat()
        if evidence_state(after) != evidence_state(opened) or evidence_state(
            current
        ) != evidence_state(opened):
            invalid("evidence file changed while being read")


def evidence_snapshot(path: Path, expected: os.stat_result | None = None) -> bytes:
    with open_evidence_file(path, expected) as content:
        return content.read()


def evidence_text(path: Path) -> str:
    return evidence_snapshot(path).decode("utf-8")


def evidence_digest(path: Path, expected: os.stat_result | None = None) -> str:
    with open_evidence_file(path, expected) as content:
        value = hashlib.sha256()
        while block := content.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def copy_evidence_file(source: str, destination: str) -> str:
    path, output = Path(source), Path(destination)
    validate_regular_destination(output)
    with open_evidence_file(path) as content:
        source_info = os.fstat(content.fileno())
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
        )
        with os.fdopen(descriptor, "wb") as copied:
            opened = os.fstat(copied.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                invalid("evidence copy destination must be an unaliased regular file")
            if (opened.st_dev, opened.st_ino) == (source_info.st_dev, source_info.st_ino):
                invalid("evidence copy source and destination are the same file")
            current = output.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                invalid("evidence copy destination changed before writing")
            os.ftruncate(copied.fileno(), 0)
            shutil.copyfileobj(content, copied)
            copied.flush()
            current = output.lstat()
            after = os.fstat(copied.fileno())
            if (
                after.st_nlink != 1
                or after.st_size != source_info.st_size
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                invalid("evidence copy destination changed while writing")
            os.fchmod(copied.fileno(), stat.S_IMODE(source_info.st_mode))
            os.utime(copied.fileno(), ns=(source_info.st_atime_ns, source_info.st_mtime_ns))
    return str(output)


def raw_inventory(directory: Path) -> dict:
    inventory = {}
    if not stat.S_ISDIR(directory.lstat().st_mode):
        invalid("fuzz evidence inventory requires a regular directory root")

    def traversal_error(error: OSError) -> NoReturn:
        raise error

    for base, directories, files in os.walk(directory, followlinks=False, onerror=traversal_error):
        for entry in sorted([*directories, *files]):
            path = Path(base) / entry
            name = path.relative_to(directory).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                # Literal target spelling is evidence; Path.readlink normalizes it.
                inventory[name] = {"type": "symlink", "target": os.readlink(path)}  # noqa: PTH115
            elif stat.S_ISREG(info.st_mode):
                inventory[name] = {"type": "file", "sha256": evidence_digest(path, info)}
            elif stat.S_ISDIR(info.st_mode):
                inventory[name] = {"type": "directory"}
            else:
                invalid("fuzz recovery encountered a special filesystem entry")
    return dict(sorted(inventory.items()))


UPLOAD_ROOTS = (
    "artifacts/security/latest",
    "artifacts/security/history",
    "fuzz/artifacts",
    "fuzz/corpus",
    "fuzz/corpus_archive",
    "fuzz/corpus_meta",
    "artifacts/sbom",
    "security-artifacts/security_status.jsonl",
)
