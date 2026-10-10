"""Fresh per-case timing monitoring with retained failures and bound native artifacts."""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from dudect_candidate import COLLECTION_COMPLETE, CandidateAdmission
from dudect_contract import CONTRACT_COMPLETE, assess_case, assess_collection, contract_roles
from dudect_diagnostics import validate_diagnostics
from dudect_package import build_package, checked_package, expected_bindings, import_package
from dudect_process import NativeError, load_json
from dudect_results import PROFILES
from dudect_support import require
from run import Adapter, RunError, archive_existing, fail, fcntl, publish, write_json
from run_candidate import collect, current_sources

KIND = "dudect-observation-contract/1"


def contract_at(root: Path) -> dict[str, Any]:
    contract: dict[str, Any] = load_json(
        (root / "tests/constant_time/contracts/case-contract-candidate.json").read_bytes()
    )
    return contract


def collect_package(
    evidence: Path, index: dict[str, Any], profile: str, contract: dict[str, Any]
) -> dict[str, Any]:
    expected = expected_bindings(index, profile)
    roles = contract_roles(contract)
    cases = {}
    for entry in index["executables"]:
        output = evidence / "executions" / entry["name"]
        output.mkdir(parents=True)
        bindings = {name: expected["bindings"][name] for name in entry["cases"]}
        cases.update(
            collect(
                evidence / "package/sources",
                output,
                evidence / "package" / entry["relative_binary"],
                profile,
                bindings,
            )
        )
        # Fail the current attempt before spending time on more targets when a
        # required negative/positive control or protected observation fails.
        for name in entry["cases"]:
            admission = CandidateAdmission(name, profile, binding=bindings[name])
            history = [admission.admit(row) for row in cases[name]]
            case_id = bindings[name]["case_id"]
            assess_case(case_id, roles[case_id], history, profile)
    return {
        "schema_version": 4,
        "suite": index["suite"],
        "profile": profile,
        "outcome": COLLECTION_COMPLETE,
        "admission": "inactive",
        **expected,
        "cases": cases,
    }


def validate_envelope(report: dict[str, Any]) -> None:
    require(
        isinstance(report, dict)
        and set(report)
        == {
            "schema_version",
            "kind",
            "suite",
            "profile",
            "outcome",
            "evidence_directory",
            "collection",
            "assessment",
        },
        "Complete observation-contract report required",
    )
    require(
        type(report["schema_version"]) is int and report["schema_version"] == 4,
        "Historical reports cannot admit the current observation contract",
    )
    require(
        report["kind"] == KIND and report["outcome"] == CONTRACT_COMPLETE,
        "Observation contract was not satisfied",
    )
    require(
        report["suite"] in ("legacy", "nix") and report["profile"] in ("pr", "periodic"),
        "Unknown report suite/profile",
    )
    require(
        isinstance(report["evidence_directory"], str)
        and re.fullmatch(r"runs/run-[a-z0-9_]+", report["evidence_directory"]) is not None,
        "Invalid retained evidence location",
    )


def validate_bundle(root: Path, evidence: Path, report: dict[str, Any]) -> None:
    validate_envelope(report)
    index = checked_package(evidence / "package", current_sources(root), report["suite"])
    collection = report["collection"]
    require(isinstance(collection, dict), "Missing observation collection")
    require(
        collection.get("suite") == report["suite"]
        and collection.get("profile") == report["profile"],
        "Report/collection identity mismatch",
    )
    expected = expected_bindings(index, report["profile"])
    assessment = assess_collection(collection, expected, contract_at(root))
    require(report["assessment"] == assessment, "Reported assessment does not match observations")
    for entry in index["executables"]:
        output = evidence / "executions" / entry["name"]
        process = load_json((output / "process.json").read_bytes())
        require(
            type(process.get("exit")) is int
            and process["exit"] == 0
            and process.get("collection_complete") is True,
            "Native process did not complete successfully",
        )
        validate_diagnostics(
            output,
            process,
            {name: expected["bindings"][name] for name in entry["cases"]},
            report["profile"],
        )
        observations = load_json((output / "observations.json").read_bytes())
        require(
            observations == {name: collection["cases"][name] for name in entry["cases"]},
            "Report differs from retained observations",
        )
        rows = [load_json(line) for line in (output / "native.stdout").read_bytes().splitlines()]
        require(
            rows == [row for name in entry["cases"] for row in observations[name]],
            "Report differs from native stdout",
        )


def validate_report_file(root: Path, report_path: Path) -> None:
    report = load_json(report_path.read_bytes())
    validate_envelope(report)
    relative = Path(report["evidence_directory"])
    evidence = report_path.parent / relative
    if report_path.parent.name == relative.name and report_path.parent.parent.name == "runs":
        evidence = report_path.parent
    require(not evidence.is_symlink(), "Retained evidence directory is a symlink")
    status = load_json((evidence / "status.json").read_bytes())
    require(
        isinstance(status, dict)
        and status.get("accepted") is True
        and status.get("suite") == report["suite"]
        and status.get("profile") == report["profile"],
        "Retained run did not finish successfully",
    )
    validate_bundle(root, evidence, report)


def execute(root: Path, args: argparse.Namespace, output: Path) -> int:
    if fcntl is None:
        fail("dudect requires Unix file locking")
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".legacy-run.lock").open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another dudect run owns the shared outputs")
        return execute_locked(root, args, output)


def execute_locked(root: Path, args: argparse.Namespace, output: Path) -> int:
    runs = output / "runs"
    runs.mkdir(exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=runs)).resolve()
    print(f"Dudect evidence: {evidence}", flush=True)
    status = {"suite": args.suite, "profile": args.profile, "accepted": False}
    try:
        archive_existing(output / "report.json", evidence / "previous-results")
        write_json(evidence / "status.json", status)
        require(
            not any(name.startswith("DUDECT_") for name in os.environ),
            "Retired DUDECT_* overrides cannot change the observation contract",
        )
        write_json(
            evidence / "context.json",
            {
                "argv": sys.argv,
                "source_root": str(root),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "cpu_info": Path("/proc/cpuinfo").read_text()
                if Path("/proc/cpuinfo").is_file()
                else None,
                "python": sys.version,
                "cpu_affinity": sorted(os.sched_getaffinity(0))
                if hasattr(os, "sched_getaffinity")
                else None,
                "load_average": os.getloadavg(),
                "native_package": str(args.native_package),
            },
        )
        hashes = current_sources(root)
        if args.native_package:
            index = import_package(args.native_package, evidence / "package", hashes, args.suite)
        else:
            index = build_package(root, evidence / "package", args.suite, Adapter(args.adapter))
        checked_package(evidence / "package", hashes, args.suite)
        collection = collect_package(evidence, index, args.profile, contract_at(root))
        report = {
            "schema_version": 4,
            "kind": KIND,
            "suite": args.suite,
            "profile": args.profile,
            "outcome": CONTRACT_COMPLETE,
            "evidence_directory": f"runs/{evidence.name}",
            "collection": collection,
            "assessment": assess_collection(
                collection, expected_bindings(index, args.profile), contract_at(root)
            ),
        }
        write_json(evidence / "report.json", report)
        validate_bundle(root, evidence, report)
        status["accepted"] = True
        write_json(evidence / "status.json", status)
        publish(evidence / "report.json", output / "report.json")
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        status["accepted"] = False
        status["error"] = str(error)
        write_json(evidence / "status.json", status)
        raise
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("legacy", "nix"), default="legacy")
    parser.add_argument("--profile", choices=PROFILES, default="pr")
    parser.add_argument("--adapter", choices=("shell", "xtask"), default="shell")
    parser.add_argument("--native-package", type=Path)
    parser.add_argument("--build-package", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    try:
        if args.build_package:
            require(not args.native_package and not args.output, "Conflicting build-only options")
            build_package(root, args.build_package.resolve(), args.suite, Adapter(args.adapter))
            return 0
        output = args.output or root / (
            "artifacts/ct/dudect" if args.suite == "legacy" else "artifacts/ct/dudect-nix"
        )
        return execute(root, args, output.resolve())
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Dudect failed: {error}", file=sys.stderr)
        return error.code if isinstance(error, (RunError, NativeError)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
