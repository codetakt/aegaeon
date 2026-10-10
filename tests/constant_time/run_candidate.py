# ruff: noqa: S603 - fixed native compiler/executable argv; never invokes a shell
"""Explicit inactive collector; it never publishes accepted dudect evidence."""

from __future__ import annotations

import argparse
import contextlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dudect_candidate import (
    ALPHA,
    CANDIDATE_CASES,
    COLLECTION_COMPLETE,
    CONTROL_CASES,
    NUMERICAL_SHA256,
    CandidateStream,
    canonical,
    digest,
    validate_candidate_report,
)
from dudect_diagnostics import (
    CONTEXT_NAME,
    TRACE_ENV,
    TRACE_NAME,
    RuntimeCapture,
    file_identity,
    validate_trace,
)
from dudect_process import load_json, receive, terminate
from dudect_results import BATCH_SIZE, PROFILES, STATISTICS
from dudect_support import require
from dudect_timing import TIMING_ENV, TIMING_NAME, validate_timing
from run import (
    HARNESSES,
    Adapter,
    Harness,
    RunError,
    compiler_argv,
    discover_flags,
    fail,
    run_checked,
    write_json,
)

if TYPE_CHECKING:
    from run import NativeFlags

ADDITIONS = (
    Harness(
        "compare_product_32",
        ("tests/constant_time/compare_product_timing_test.c", "c/rsa_signatures.c"),
        ("-lmbedcrypto", "-lmbedx509", "-lm"),
    ),
    Harness(
        "hmac_key_reject",
        ("tests/constant_time/hmac_key_reject_timing_test.c", "c/jws.c", "c/rsa_signatures.c"),
        ("-lmbedcrypto", "-lmbedx509", "-lm"),
    ),
    Harness(
        "jwe_key_reject",
        ("tests/constant_time/jwe_key_reject_timing_test.c", "c/jwe.c"),
        ("-lcrypto", "-lm"),
    ),
)
PROVIDER = Harness("dudect_harness", ("c/dudect_harness.c",), ("-lm",))
CONTROLS = Harness("dudect_controls", ("tests/constant_time/calibration_timing_test.c",), ("-lm",))


@dataclass(frozen=True)
class BuildInputs:
    snapshot: Path
    hashes: dict[str, str]
    contract: str
    flags: NativeFlags
    adapter: Adapter


def source_paths(root: Path) -> list[Path]:
    paths = [
        p
        for directory in ("c", "include", "tests/constant_time")
        for p in (root / directory).rglob("*")
        if p.is_file() and p.suffix in (".c", ".h", ".py", ".json")
    ]
    paths += [
        root / p
        for p in ("flake.lock", "nix/dudect.nix", "nix/evercrypt/dist.nix", "nix/karamel.nix")
    ]
    return sorted(paths)


def current_sources(root: Path) -> dict[str, str]:
    hashes = {}
    for path in source_paths(root):
        require(not path.is_symlink(), "Source symlink is not admissible")
        hashes[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return hashes


def freeze_sources(root: Path, evidence: Path) -> tuple[Path, dict[str, str]]:
    snapshot = evidence / "sources"
    hashes = {}
    for path in source_paths(root):
        require(not path.is_symlink(), "Source symlink is not admissible")
        name = path.relative_to(root).as_posix()
        data = path.read_bytes()
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o400)
        hashes[name] = digest(data)
    return snapshot, hashes


def check_contract(snapshot: Path) -> str:
    data = (snapshot / "tests/constant_time/contracts/case-contract-candidate.json").read_bytes()
    contract = load_json(data)
    expected = {f"{suite}/{name}" for suite, names in CANDIDATE_CASES.items() for name in names}
    ids = [case["stable_id"] for case in contract["cases"]]
    require(len(ids) == 21 and set(ids) == expected, "Candidate contract inventory mismatch")
    require(
        contract["schema_migration"]["candidate_version"] == 4,
        "Candidate contract version mismatch",
    )
    numerical = contract["numerical_candidate"]
    require(
        numerical["implementation_sha256"] == NUMERICAL_SHA256,
        "Numerical implementation/contract identity mismatch",
    )
    expected_numbers = {
        "measured_case_count": 21,
        "statistics": STATISTICS,
        "max_looks": 8,
        "family_alpha": 0.01,
        "per_inspection_alpha": ALPHA,
        "batch": BATCH_SIZE,
        "PR_measured_batches": PROFILES["pr"][0][-1],
        "periodic_measured_batches": PROFILES["periodic"][0][-1],
        "raw_per_class_floors": {k: v[1] for k, v in PROFILES.items()},
    }
    require(
        all(numerical.get(k) == v for k, v in expected_numbers.items()),
        "Candidate numerical contract mismatch",
    )
    return digest(data)


def build(
    inputs: BuildInputs, evidence: Path, spec: Harness, suite: str
) -> tuple[Path, dict[str, Any]]:
    snapshot, contract = inputs.snapshot, inputs.contract
    for name in (*spec.sources, "c/dudect.h", "c/dudect_report.h", "c/dudect_candidate_report.h"):
        require((snapshot / name).is_file(), f"Required native source unavailable: {name}")
    binary = evidence / spec.name
    argv = [*compiler_argv(spec, inputs.adapter, inputs.flags), "-D_GNU_SOURCE=1"]
    argv[argv.index("-o") + 1] = str(binary)
    compiler = shutil.which(argv[0])
    if compiler is None:
        fail("Candidate compiler unavailable")
    argv[0] = str(Path(compiler).resolve())
    version = run_checked(snapshot, evidence, "compiler-version", [argv[0], "--version"]).decode()
    manifest = {
        "suite": suite,
        "sources": inputs.hashes,
        "contract_sha256": contract,
        "compiler": argv[0],
        "compiler_version": version,
        "argv_before_binding": argv,
        "environment": {
            k: os.environ[k]
            for k in (
                "NIX_CFLAGS_COMPILE",
                "NIX_LDFLAGS",
                "PKG_CONFIG_PATH",
                "LIBRARY_PATH",
                "CPATH",
            )
            if k in os.environ
        },
    }
    build_hash = digest(canonical(manifest))
    argv = [
        *argv,
        "-DAEGAEON_DUDECT_CANDIDATE=1",
        f'-DAEGAEON_DUDECT_SUITE="{suite}"',
        f'-DAEGAEON_DUDECT_CONTRACT_SHA256="{contract}"',
        f'-DAEGAEON_DUDECT_BUILD_SHA256="{build_hash}"',
        f'-DAEGAEON_DUDECT_NUMERICAL_SHA256="{NUMERICAL_SHA256}"',
    ]
    write_json(evidence / "build-manifest.json", manifest)
    run_checked(snapshot, evidence, "compile", argv)
    require(
        binary.is_file()
        and not binary.is_symlink()
        and binary.stat().st_size > 0
        and os.access(binary, os.X_OK),
        "Candidate compiler did not produce an executable",
    )
    binary.chmod(0o500)
    identity = {
        "path": str(binary),
        "sha256": digest(binary.read_bytes()),
        "build_sha256": build_hash,
    }
    write_json(evidence / "binary.json", identity)
    run_checked(snapshot, evidence, "linked-libraries", ["ldd", str(binary)])
    return binary, identity


def collect(  # noqa: PLR0915 - keep the owned process/evidence lifecycle together
    snapshot: Path, evidence: Path, binary: Path, profile: str, bindings: dict[str, Any]
) -> dict[str, Any]:
    names = tuple(bindings)
    stream = CandidateStream(names, profile, bindings=bindings)
    argv = [str(binary), profile]
    status = {"argv": argv, "accepted": False, "collection_complete": False}
    process = None
    started = time.monotonic()
    diagnostics: dict[str, Any] = {}
    status["diagnostics"] = diagnostics
    try:
        with (
            (evidence / "native.stdout").open("wb") as output,
            (evidence / "native.stderr").open("wb") as errors,
            (evidence / CONTEXT_NAME).open("xb") as runtime,
            contextlib.ExitStack() as files,
        ):
            capture = RuntimeCapture(runtime)
            capture.snapshot("start")
            environment = dict(os.environ)
            environment.pop(TRACE_ENV, None)
            environment.pop(TIMING_ENV, None)
            timing = files.enter_context((evidence / TIMING_NAME).open("xb"))
            descriptors: tuple[int, ...] = (timing.fileno(),)
            environment[TIMING_ENV] = str(timing.fileno())
            if "ct_eq_128" in bindings:
                samples = files.enter_context((evidence / TRACE_NAME).open("xb"))
                descriptors = (*descriptors, samples.fileno())
                environment[TRACE_ENV] = str(samples.fileno())
            process = subprocess.Popen(
                argv,
                cwd=snapshot,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                start_new_session=True,
                env=environment,
                pass_fds=descriptors,
            )
            stream.before_observation = lambda: capture.snapshot(
                "observation",
                process.pid,
                case=names[min(stream.index, len(names) - 1)],
                look=len(stream.histories[names[min(stream.index, len(names) - 1)]]) + 1,
            )
            budget = PROFILES[profile][2]
            try:
                receive(process, output, stream, started + budget, case_budget=budget)
            finally:
                status["exit"] = terminate(process)
                capture.snapshot("end")
            diagnostics["timing"] = validate_timing(evidence / TIMING_NAME, bindings, profile)
            if "ct_eq_128" in bindings:
                diagnostics["samples"] = validate_trace(
                    evidence / TRACE_NAME, bindings["ct_eq_128"], profile
                )
            status["collection_complete"] = True
    finally:
        if process is not None and "exit" not in status:
            status["exit"] = terminate(process)
        status["elapsed_seconds"] = time.monotonic() - started
        for name, filename in (
            ("runtime", CONTEXT_NAME),
            ("samples", TRACE_NAME),
            ("timing", TIMING_NAME),
        ):
            if (evidence / filename).is_file() and name not in diagnostics:
                diagnostics[name] = file_identity(evidence / filename)
        for name, value in (
            ("process", status),
            ("observations", stream.histories),
            ("decisions", stream.decisions),
        ):
            write_json(evidence / f"{name}.json", value)
    return stream.histories


def execute_suite(
    inputs: BuildInputs, evidence: Path, args: argparse.Namespace, suite: str
) -> None:
    snapshot, contract = inputs.snapshot, inputs.contract
    cases, bindings, binaries = {}, {}, {}
    specs = (CONTROLS, *HARNESSES, *ADDITIONS) if suite == "legacy" else (CONTROLS, PROVIDER)
    for spec in specs:
        output = evidence / suite / spec.name
        output.mkdir(parents=True)
        binary, identity = build(inputs, output, spec, suite)
        names = (
            CONTROL_CASES
            if spec is CONTROLS
            else (
                (spec.name,) if suite == "legacy" else CANDIDATE_CASES["nix"][: -len(CONTROL_CASES)]
            )
        )
        current = {
            name: {
                "case_id": f"{suite}/{name}",
                "profile": args.profile,
                "contract_sha256": contract,
                "build_sha256": identity["build_sha256"],
                "numerical_sha256": NUMERICAL_SHA256,
            }
            for name in names
        }
        bindings.update(current)
        binaries.update(dict.fromkeys(names, identity))
        write_json(output / "case-bindings.json", {"bindings": current, "binary": identity})
        require(
            digest(binary.read_bytes()) == identity["sha256"],
            "Native binary changed before execution",
        )
        if args.self_test_only:
            stdout = run_checked(snapshot, output, "self-test", [str(binary), "--self-test"])
            rows = [load_json(line) for line in stdout.splitlines()]
            require(
                rows
                == [
                    {"case_id": f"{suite}/{name}", "self_test": True, "timing_executed": False}
                    for name in names
                ],
                "Incomplete native fixture self-test",
            )
        else:
            cases.update(collect(snapshot, output, binary, args.profile, current))
        require(
            digest(binary.read_bytes()) == identity["sha256"],
            "Native binary changed during execution",
        )
    if not args.self_test_only:
        expected = {"bindings": bindings, "binaries": binaries}
        report = {
            "schema_version": 4,
            "suite": suite,
            "profile": args.profile,
            "outcome": COLLECTION_COMPLETE,
            "admission": "inactive",
            **expected,
            "cases": cases,
        }
        decisions = validate_candidate_report(report, expected)
        write_json(evidence / suite / "bindings.json", expected)
        write_json(evidence / suite / "candidate-report.json", report)
        write_json(evidence / suite / "candidate-decisions.json", decisions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("legacy", "nix", "all"), required=True)
    parser.add_argument("--profile", choices=PROFILES, default="pr")
    parser.add_argument("--adapter", choices=("shell", "xtask"), default="shell")
    parser.add_argument("--self-test-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    parent = args.output or root / "artifacts/ct/dudect-candidate"
    parent.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=parent)).resolve()
    print(f"Inactive dudect candidate evidence: {evidence}", flush=True)
    status = {"accepted": False, "admission": "inactive", "self_test_only": args.self_test_only}
    try:
        write_json(
            evidence / "runtime.json",
            {
                "argv": sys.argv,
                "source_root": str(root),
                "python": sys.executable,
                "python_version": sys.version,
                "platform": platform.platform(),
                "cpu_affinity": sorted(os.sched_getaffinity(0))
                if hasattr(os, "sched_getaffinity")
                else None,
            },
        )
        snapshot, hashes = freeze_sources(root, evidence)
        contract = check_contract(snapshot)
        flags = discover_flags(snapshot, evidence)
        inputs = BuildInputs(snapshot, hashes, contract, flags, Adapter(args.adapter))
        for suite in CANDIDATE_CASES if args.suite == "all" else (args.suite,):
            execute_suite(inputs, evidence, args, suite)
        status["execution_complete"] = True
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        status["execution_complete"] = False
        status["error"] = str(error)
    write_json(evidence / "candidate-status.json", status)
    print(status, flush=True)
    return 0 if status["execution_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
