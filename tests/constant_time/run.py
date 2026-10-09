# ruff: noqa: S603 - fixed compiler profiles and structured tool argv
"""Legacy five-harness runner; formal Nix dudect lanes are separate.

num_traces is the configured minimum batch size, not observed/admitted traces.
C schedules, statistics, maximum-p aggregation and warning policy are unchanged.
"""

from __future__ import annotations

import json
import math
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, cast

try:
    import fcntl
except ImportError:
    fcntl = None

if TYPE_CHECKING:
    from collections.abc import Sequence
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
# Existing configured batches: 200000, 200000, 20000, 100000, 100000.
CONFIGURED_MIN_BATCH = 20_000
FAIL_THRESHOLD = 0.01


@dataclass(frozen=True)
class NativeFlags:
    karamel: tuple[str, ...]
    cflags: tuple[str, ...]
    libs: tuple[str, ...]


@dataclass(frozen=True)
class Result:
    name: str
    state: int
    p_value: float
    payload: dict[str, object]

    @property
    def accepted(self) -> bool:
        return self.state == 1 and self.p_value >= FAIL_THRESHOLD


class RunError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def fail(message: str, code: int = 1) -> NoReturn:
    raise RunError(message, code)


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"Duplicate dudect JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> object:
    fail(f"Non-finite dudect JSON constant: {value}")


def finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        fail(f"Non-finite dudect JSON number: {value}")
    return number


def parse_result(name: str, stdout: bytes) -> Result:
    lines = stdout.decode("utf-8").splitlines()
    if not lines:
        fail(f"No output from dudect {name}")
    data: object = json.loads(
        lines[-1],
        object_pairs_hook=strict_object,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )
    if not isinstance(data, dict):
        fail(f"dudect {name} result must be a JSON object")
    payload = cast("dict[str, object]", data)
    state = payload.get("state")
    p_value = payload.get("p")
    if type(state) is not int or state not in (0, 1):
        fail(f"dudect {name} requires state 0 or 1")
    if type(p_value) not in (int, float):
        fail(f"dudect {name} requires a numeric p-value")
    numeric = cast("int | float", p_value)
    if not 0 <= numeric <= 1 or not math.isfinite(numeric):
        fail(f"dudect {name} requires a finite p-value in [0, 1]")
    return Result(name, state, float(numeric), payload)


def aggregate(results: Sequence[Result]) -> dict[str, object]:
    return {
        "state": int(all(result.state == 1 for result in results)),
        "p": max(result.p_value for result in results),
        "num_traces": CONFIGURED_MIN_BATCH,
        "tests": {result.name: result.payload for result in results},
    }


def binary_path(harness: Harness, adapter: Adapter) -> Path:
    directory = Path("target/ct") if adapter is Adapter.XTASK else Path("target")
    return directory / f"{harness.name}_timing_test"


def compiler_argv(harness: Harness, adapter: Adapter, flags: NativeFlags) -> list[str]:
    common = ["-O2", "-std=c11", "-o", str(binary_path(harness, adapter))]
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
        (f"-I{prefix / 'include'}",),
        tuple(shlex.split(cflags.decode("utf-8"))),
        tuple(shlex.split(libs.decode("utf-8"))),
    )


def archive_existing(path: Path, archive: Path) -> None:
    if path.is_symlink() or path.exists():
        archive.mkdir(parents=True, exist_ok=True)
        path.rename(archive / path.name)


def run_harness(
    root: Path, evidence: Path, harness: Harness, adapter: Adapter, flags: NativeFlags
) -> Result:
    binary = root / binary_path(harness, adapter)
    binary.parent.mkdir(parents=True, exist_ok=True)
    archive_existing(binary, evidence / "previous-binaries")
    run_checked(root, evidence, f"{harness.name}-compile", compiler_argv(harness, adapter, flags))
    if (
        binary.is_symlink()
        or not binary.is_file()
        or not binary.stat().st_size
        or not os.access(binary, os.X_OK)
    ):
        fail(f"Compiler did not produce a nonempty executable: {binary}")
    stdout = run_checked(root, evidence, harness.name, [str(binary)])
    result = parse_result(harness.name, stdout)
    write_json(evidence / f"{harness.name}.json", result.payload)
    return result


def publish(source: Path, destination: Path) -> None:
    # Atomic report replacement occurs last, after a complete accepted run.
    temporary = destination.with_name(f".{destination.name}.{source.parent.name}.tmp")
    try:
        shutil.copyfile(source, temporary)
        temporary.replace(destination)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def execute(root: Path, adapter: Adapter) -> int:
    if fcntl is None:
        fail("dudect requires a Unix platform with fcntl file locking")
    output = root / "artifacts/ct/dudect"
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".legacy-run.lock").open("a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another legacy dudect run owns the shared outputs")
        return execute_locked(root, adapter)


def execute_locked(root: Path, adapter: Adapter) -> int:
    output = root / "artifacts/ct/dudect"
    runs = output / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=runs))
    print(f"Legacy dudect raw evidence: {evidence}", flush=True)
    status: dict[str, object] = {"adapter": adapter.value, "accepted": False}
    try:
        for name in ("report", *(harness.name for harness in HARNESSES)):
            archive_existing(output / f"{name}.json", evidence / "previous-results")
        flags = discover_flags(root, evidence)
        results = [run_harness(root, evidence, harness, adapter, flags) for harness in HARNESSES]
        write_json(evidence / "report.json", aggregate(results))
        if not all(result.accepted for result in results):
            fail("dudect reported leakage or an individual p-value below 0.01")
        status["accepted"] = True
        write_json(evidence / "status.json", status)
        for name in (*(harness.name for harness in HARNESSES), "report"):
            publish(evidence / f"{name}.json", output / f"{name}.json")
    except (RunError, OSError, ValueError, UnicodeError) as error:
        status["accepted"] = False
        status["error"] = str(error)
        write_json(evidence / "status.json", status)
        raise
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in ([], ["--xtask-adapter"]):
        print("usage: tests/constant_time/run.sh (no options)", file=sys.stderr)
        return 2
    adapter = Adapter.XTASK if args else Adapter.SHELL
    root = Path(__file__).resolve().parents[2]
    try:
        return execute(root, adapter)
    except (RunError, OSError, ValueError, UnicodeError) as error:
        print(f"Legacy dudect failed: {error}", file=sys.stderr)
        return error.code if isinstance(error, RunError) else 1


if __name__ == "__main__":
    raise SystemExit(main())
