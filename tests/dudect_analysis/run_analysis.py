# The authenticated source bundle must be selected before native helper imports.
# ruff: noqa: E402
"""Private active analysis gate; cannot masquerade as the adopted gate envelope."""

from __future__ import annotations

import argparse
import contextlib
import signal
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source" if (HERE / "source").is_dir() else HERE.parents[1]
sys.path.insert(0, str(SOURCE / "tests/constant_time"))
import run_candidate
from analysis_contract import assess, identity
from analysis_runtime import Stream, Worker, replay
from dudect_candidate import canonical
from dudect_contract import contract_roles
from dudect_diagnostics import validate_diagnostics
from dudect_package import checked_package, expected_bindings, import_package
from dudect_process import load_json
from dudect_support import require

KIND = "dudect-enclosed-calibration-research-gate/1"


@contextlib.contextmanager
def installed(analysis):
    old_worker, old_stream = run_candidate.Worker, run_candidate.RuntimeStream
    run_candidate.Worker = lambda path, bindings, errors: Worker(
        path, bindings, errors, analysis=analysis
    )
    run_candidate.RuntimeStream = Stream
    try:
        yield
    finally:
        run_candidate.Worker, run_candidate.RuntimeStream = old_worker, old_stream


def verify(output):
    report = load_json((output / "research-report.json").read_bytes())
    require(
        report["kind"] == KIND and report["profile"] == "pr" and report["adopted"] is False,
        "Wrong research envelope",
    )
    a = report["analysis"]
    require(
        a == identity(a["mode"], a["packet"], a["unit"]),
        "Analysis implementation/dependency changed",
    )
    require(load_json((output / "analysis.json").read_bytes()) == a, "Analysis record differs")
    index = checked_package(
        output / "package", run_candidate.current_sources(SOURCE), report["suite"]
    )
    require(report["native_package"] == index, "Native package record differs")
    expected = expected_bindings(index, "pr")["bindings"]
    roles = contract_roles(
        load_json(
            (SOURCE / "tests/constant_time/contracts/case-contract-candidate.json").read_bytes()
        )
    )
    assessments = []
    for entry in index["executables"]:
        dest = output / "executions" / entry["name"]
        bindings = {n: expected[n] for n in entry["cases"]}
        process = load_json((dest / "process.json").read_bytes())
        require(
            process["exit"] == 0 and process["collection_complete"] is True,
            "Incomplete native execution",
        )
        validate_diagnostics(dest, process, bindings, "pr")
        rows = load_json((dest / "observations.json").read_bytes())
        require(
            [load_json(x) for x in (dest / "native.stdout").read_bytes().splitlines()]
            == [r for n in bindings for r in rows[n]],
            "Native output mismatch",
        )
        decisions = replay(dest, bindings, rows, a)
        for name in bindings:
            cid = bindings[name]["case_id"]
            assessments.append(assess(cid, roles[cid], [r for r in decisions if r["case"] == name]))
    require(assessments == report["assessment"], "Research role assessment changed")
    require(
        report["gate_satisfied"] == all(a["requirement_satisfied"] for a in assessments),
        "Wrong gate outcome",
    )
    return report


def execute(package, output, *, suite, mode, packet, unit):  # noqa: PLR0913 -- explicit frozen invocation
    output.mkdir(parents=True, exist_ok=False)
    analysis = identity(mode, packet, unit)
    (output / "analysis.json").write_bytes(canonical(analysis) + b"\n")
    index = import_package(
        package, output / "package", run_candidate.current_sources(SOURCE), suite
    )
    expected = expected_bindings(index, "pr")["bindings"]
    roles = contract_roles(
        load_json(
            (SOURCE / "tests/constant_time/contracts/case-contract-candidate.json").read_bytes()
        )
    )
    assessments = []
    try:
        with installed(analysis):
            for entry in index["executables"]:
                dest = output / "executions" / entry["name"]
                dest.mkdir(parents=True)
                bindings = {n: expected[n] for n in entry["cases"]}
                rows = run_candidate.collect(
                    output / "package/sources",
                    dest,
                    output / "package" / entry["relative_binary"],
                    "pr",
                    bindings,
                )
                decisions = replay(dest, bindings, rows, analysis)
                for name in bindings:
                    cid = bindings[name]["case_id"]
                    assessments.append(
                        assess(cid, roles[cid], [r for r in decisions if r["case"] == name])
                    )
                (output / "partial-assessment.json").write_bytes(canonical(assessments) + b"\n")
            # Statistical failures do not skip later scheduled cases.
        report = {
            "kind": KIND,
            "profile": "pr",
            "suite": suite,
            "analysis": analysis,
            "native_package": index,
            "assessment": assessments,
            "gate_satisfied": all(a["requirement_satisfied"] for a in assessments),
            "adopted": False,
            "product_assurance": "not_established",
        }
        (output / "research-report.json").write_bytes(canonical(report) + b"\n")
        verify(output)
        return 0 if report["gate_satisfied"] else 1
    except BaseException as error:
        (output / "execution-failure.json").write_bytes(
            canonical(
                {
                    "type": type(error).__name__,
                    "error": str(error),
                    "completed_assessments": assessments,
                }
            )
            + b"\n"
        )
        raise


def interrupted(signum, _frame):
    # Raise through execute/collect so their finally blocks close the separate
    # native and worker sessions before a supervisor forces process termination.
    message = f"Analysis interrupted by signal {signum}"
    raise InterruptedError(message)


def main():
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite", choices=["legacy", "nix"])
    parser.add_argument("--mode", choices=["interval-only", "distributed"])
    parser.add_argument("--packet")
    parser.add_argument("--unit")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        report = verify(args.output)
        return 0 if report["gate_satisfied"] else 1
    require(
        all((args.package, args.suite, args.mode, args.packet, args.unit)),
        "Missing frozen research invocation",
    )
    return execute(
        args.package,
        args.output,
        suite=args.suite,
        mode=args.mode,
        packet=args.packet,
        unit=args.unit,
    )


if __name__ == "__main__":
    raise SystemExit(main())
