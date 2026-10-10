# ruff: noqa: S603 - fixed compiler profiles and structured tool argv
"""Compile or load native dudect programs and admit fresh observed evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from dudect_process import NativeError, run_native
from dudect_results import LEGACY_CASES, NIX_CASES, NONDETECTION, PROFILES, validate_report

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import ModuleType
    from typing import NoReturn


class Adapter(Enum):
    SHELL = "shell"
    XTASK = "xtask"


@dataclass(frozen=True)
class Harness:
    name: str
    sources: tuple[str, ...]
    libs: tuple[str, ...]


HARNESSES = (
    Harness("compare", ("tests/constant_time/compare_timing_test.c",), ("-lm",)),
    Harness(
        "hmac",
        ("tests/constant_time/hmac_timing_test.c", "c/rsa_signatures.c", "c/jws.c"),
        ("-lmbedcrypto", "-lmbedx509", "-lm"),
    ),
    Harness(
        "ed25519",
        ("tests/constant_time/ed25519_timing_test.c", "c/rsa_signatures.c"),
        ("-lmbedcrypto", "-lmbedx509", "-lcrypto", "-lm"),
    ),
    Harness(
        "rsa",
        ("tests/constant_time/rsa_timing_test.c", "c/rsa_signatures.c"),
        ("-lmbedcrypto", "-lmbedx509", "-lcrypto", "-lm"),
    ),
    Harness("jwe", ("tests/constant_time/jwe_timing_test.c", "c/jwe.c"), ("-lcrypto", "-lm")),
)

fcntl: ModuleType | None
try:
    import fcntl as _fcntl

    fcntl = _fcntl
except ImportError:
    fcntl = None


class RunError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def fail(message: str, code: int = 1) -> NoReturn:
    raise RunError(message, code)


@dataclass(frozen=True)
class NativeFlags:
    karamel: tuple[str, ...]
    cflags: tuple[str, ...]
    libs: tuple[str, ...]


def binary_path(harness: Harness, adapter: Adapter) -> Path:
    directory = Path("target/ct") if adapter is Adapter.XTASK else Path("target")
    return directory / f"{harness.name}_timing_test"


def compiler_argv(harness: Harness, adapter: Adapter, flags: NativeFlags) -> list[str]:
    common = ["-O2", "-std=c11", "-D_DEFAULT_SOURCE", "-o", str(binary_path(harness, adapter))]
    if adapter is Adapter.XTASK:
        return [
            "gcc",
            *harness.sources,
            "-I",
            "include",
            "-I",
            "c",
            "-I",
            "tests/constant_time",
            *common,
            *flags.karamel,
            *flags.cflags,
            *harness.libs,
            *flags.libs,
        ]
    includes = ["-Iinclude", "-Ic"]
    if harness.name == "compare":
        return ["cc", *harness.sources, *includes, *common, *harness.libs]
    return [
        "cc",
        *harness.sources,
        *includes,
        *flags.karamel,
        *flags.cflags,
        *common,
        *flags.libs,
        *harness.libs,
    ]


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, allow_nan=False) + "\n", encoding="utf-8")


def run_checked(root: Path, evidence: Path, name: str, argv: Sequence[str]) -> bytes:
    stdout_path = evidence / f"{name}.stdout"
    stderr_path = evidence / f"{name}.stderr"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.run(argv, cwd=root, stdout=stdout, stderr=stderr, check=False)
    write_json(evidence / f"{name}.process.json", {"argv": list(argv), "exit": process.returncode})
    if process.returncode:
        code = process.returncode if process.returncode > 0 else 128 - process.returncode
        fail(f"{name} failed ({process.returncode}); raw output: {evidence}", code)
    return stdout_path.read_bytes()


def discover_flags(root: Path, evidence: Path) -> NativeFlags:
    krml = shutil.which("krml")
    if krml is None:
        fail("krml not found in PATH")
    prefix = Path(krml).parent.parent
    cflags = run_checked(
        root, evidence, "pkg-config-cflags", ["pkg-config", "--cflags", "evercrypt"]
    )
    libs = run_checked(
        root, evidence, "pkg-config-libs", ["pkg-config", "--libs", "--static", "evercrypt"]
    )
    return NativeFlags(
        (
            f"-I{prefix / 'include'}",
            f"-I{prefix / 'lib/krml/c'}",
            f"-I{prefix / 'lib/krml/dist/generic'}",
        ),
        tuple(shlex.split(cflags.decode("utf-8"))),
        tuple(shlex.split(libs.decode("utf-8"))),
    )


def archive_existing(path: Path, archive: Path) -> None:
    if path.is_symlink() or path.exists():
        archive.mkdir(parents=True, exist_ok=True)
        path.rename(archive / path.name)


def legacy_cases(
    root: Path, evidence: Path, adapter: Adapter, profile: str
) -> dict[str, list[object]]:
    flags = discover_flags(root, evidence)
    cases = {}
    for harness in HARNESSES:
        binary = root / binary_path(harness, adapter)
        binary.parent.mkdir(parents=True, exist_ok=True)
        archive_existing(binary, evidence / "previous-binaries")
        run_checked(
            root, evidence, f"{harness.name}-compile", compiler_argv(harness, adapter, flags)
        )
        if (
            binary.is_symlink()
            or not binary.is_file()
            or not binary.stat().st_size
            or not os.access(binary, os.X_OK)
        ):
            fail(f"Compiler did not produce a nonempty executable: {binary}")
        write_json(
            evidence / f"{harness.name}.binary.json",
            {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
        )
        cases[harness.name] = run_native(root, evidence, binary, (harness.name,), profile)[
            harness.name
        ]
    return cases


def publish(source: Path, destination: Path) -> None:
    # Atomic report replacement occurs last, after a complete accepted run.
    temporary = destination.with_name(f".{destination.name}.{source.parent.name}.tmp")
    try:
        shutil.copyfile(source, temporary)
        temporary.replace(destination)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def execute(root: Path, adapter: Adapter, profile: str, nix_binary: Path | None = None) -> int:
    if fcntl is None:
        fail("dudect requires a Unix platform with fcntl file locking")
    output = root / ("artifacts/ct/dudect" if nix_binary is None else "artifacts/ct/dudect-nix")
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".legacy-run.lock").open("a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another legacy dudect run owns the shared outputs")
        return execute_locked(root, adapter, profile, output, nix_binary)


def record_context(root: Path, evidence: Path) -> None:
    sources = [
        *root.glob("c/*"),
        *root.glob("include/*"),
        *root.glob("tests/constant_time/*"),
        root / "flake.lock",
        root / "nix/dudect.nix",
    ]
    hashes = {}
    for path in sources:
        if path.is_file():
            relative = path.relative_to(root)
            destination = evidence / "sources" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            hashes[str(relative)] = hashlib.sha256(destination.read_bytes()).hexdigest()
    write_json(
        evidence / "context.json",
        {
            "platform": platform.platform(),
            "python": sys.version,
            "tools": {name: shutil.which(name) for name in ("cc", "gcc", "krml", "pkg-config")},
            "affinity": sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else None,
            "load_average": os.getloadavg(),
            "sources": hashes,
        },
    )


def execute_locked(
    root: Path, adapter: Adapter, profile: str, output: Path, nix_binary: Path | None
) -> int:
    runs = output / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=runs))
    print(f"Dudect raw evidence: {evidence}", flush=True)
    status: dict[str, object] = {"adapter": adapter.value, "profile": profile, "accepted": False}
    try:
        for name in ("report", *LEGACY_CASES):
            archive_existing(output / f"{name}.json", evidence / "previous-results")
        for key in (
            "DUDECT_MIN_TRACES",
            "DUDECT_TAU_WARN",
            "DUDECT_TAU_FAIL",
            "DUDECT_WARN_THRESHOLD",
            "DUDECT_FAIL_THRESHOLD",
        ):
            if key in os.environ:
                fail(f"{key} is retired; select --profile pr or periodic")
        record_context(root, evidence)
        if nix_binary is not None:
            binary = nix_binary.resolve(strict=True)
            write_json(
                evidence / "binary.json",
                {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            )
            cases = run_native(root, evidence, binary, NIX_CASES, profile)
            suite = "nix"
        else:
            cases = legacy_cases(root, evidence, adapter, profile)
            suite = "legacy"
        report = {
            "schema_version": 2,
            "suite": suite,
            "profile": profile,
            "outcome": NONDETECTION,
            "cases": cases,
        }
        write_json(evidence / "report.json", report)
        validate_report(report)
        status["accepted"] = True
        write_json(evidence / "status.json", status)
        publish(evidence / "report.json", output / "report.json")
    except (RunError, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as error:
        status["accepted"] = False
        status["error"] = str(error)
        write_json(evidence / "status.json", status)
        raise
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    adapter = Adapter.SHELL
    profile = "pr"
    nix_binary = None
    try:
        if args and args[0] == "--xtask-adapter":
            adapter = Adapter.XTASK
            args.pop(0)
        if args[:1] == ["--nix-binary"] and len(args) >= 2:
            nix_binary = Path(args[1])
            args = args[2:]
        if len(args) == 2 and args[0] == "--profile" and args[1] in PROFILES:
            profile = args[1]
            args = []
        if args:
            fail("usage: dudect [--profile pr|periodic]", 2)
        return execute(Path(__file__).resolve().parents[2], adapter, profile, nix_binary)
    except (RunError, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as error:
        print(f"Dudect failed: {error}", file=sys.stderr)
        return error.code if isinstance(error, (RunError, NativeError)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
