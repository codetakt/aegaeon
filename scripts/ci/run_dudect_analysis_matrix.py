"""One fresh bounded matrix; environment profiles never imply production adoption."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from types import FrameType

import dudect_hosted_environment as hosted
from dudect_analysis_environment import PROFILE, check, snapshot
from verify_dudect_analysis_matrix import (
    check_analysis,
    check_matrix,
    check_report,
    pinned_inputs,
    read_json,
    require,
    sha256,
    write_json,
)

EXECUTION: dict[str, Any] = {
    "schema": "dudect-fresh-matrix/research-1",
    "environment": PROFILE,
    "maximum_seconds": 9000,
    "gap_seconds": 10,
    "replacement_trials": 0,
}


def launch(command: list[str], cpus: set[int]) -> NoReturn:
    """Expand only this child; native collector separates CPUs before measuring."""
    os.sched_setaffinity(0, cpus)
    require(os.sched_getaffinity(0) == cpus, "Wrong gate child CPU mask")
    os.execv(command[0], command)  # noqa: S606 -- fixed pinned package command


def environment(path: Path) -> None:
    value = snapshot()
    write_json(path, value)  # Preserve configuration violations before rejecting.
    check(value)


def run(plan: dict[str, Any], output: Path) -> dict[str, Any]:  # noqa: C901, PLR0912, PLR0915 -- one bounded matrix transaction
    check_matrix(plan)
    check_analysis(plan)
    is_hosted = plan["execution"] == hosted.EXECUTION
    require(is_hosted or plan["execution"] == EXECUTION, "Unreviewed execution policy")
    require(len(plan["cycles"]) == 1, "One complete CI opportunity per execution")
    command, indexes = pinned_inputs(plan)
    if is_hosted:
        require(
            [(u["compiler"], u["suite"]) for u in plan["units"]] == hosted.ORDER,
            "Wrong frozen hosted suite order",
        )
        config = plan["hosted"]
        cpus = set(config["placement"]["original"])
        require(os.sched_getaffinity(0) == cpus, "Allocation affinity changed before launch")
        require(hosted.placement(cpus) == config["placement"], "Hosted placement differs")
        require(
            set(plan["orchestration"]) == set(hosted.SOURCES), "Incomplete orchestration binding"
        )
        for name, expected in plan["orchestration"].items():
            require(
                sha256(Path(__file__).resolve().parents[2] / name) == expected,
                "Orchestration input changed",
            )
        os.sched_setaffinity(0, config["placement"]["collector"])
    else:
        cpus = {0, 1}
        os.sched_setaffinity(0, {0})

    def inspect(path: Path) -> None:
        if is_hosted:
            hosted.environment(path, config)
        else:
            environment(path)

    started = time.monotonic()
    deadline = started + EXECUTION["maximum_seconds"]
    records: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "schema": EXECUTION["schema"],
        "adopted": False,
        "ci_admission": False,
        "complete": False,
        "research_requirements_satisfied": False,
        "fresh_measurements": True,
        "environment_profile": plan["execution"]["environment"],
        "competition_exclusion_established": False,
        "units": records,
        "unstarted": [u["id"] for u in plan["units"]],
    }
    write_json(output / "summary.json", summary)
    try:
        for unit in plan["units"]:
            dest = output / unit["id"]
            dest.mkdir()
            inspect(dest / "environment-before.json")
            argv = [
                str(command),
                "--package",
                plan["native_packages"][f"{unit['compiler']}-{unit['suite']}"]["path"],
                "--output",
                str(dest / "gate"),
                "--suite",
                unit["suite"],
                "--mode",
                plan["mode"],
                "--packet",
                plan["packet"],
                "--unit",
                unit["id"],
            ]
            write_json(
                dest / "invocation.json",
                {"argv": argv, "unit": unit, "remaining_seconds": deadline - time.monotonic()},
            )
            require(time.monotonic() < deadline, "Matrix deadline reached")
            summary["unstarted"].remove(unit["id"])
            write_json(output / "summary.json", summary)
            with (
                (dest / "driver.stdout").open("xb") as stdout,
                (dest / "driver.stderr").open("xb") as stderr,
            ):
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        str(Path(__file__).resolve()),
                        "--launch-cpus",
                        ",".join(map(str, sorted(cpus))),
                        "--launch",
                        *argv,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                try:
                    code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except BaseException:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    raise
            # Keep the statistical result even if the post-execution environment fails.
            report_path = dest / "gate/research-report.json"
            report = read_json(report_path)
            check_report(report, unit, indexes[f"{unit['compiler']}-{unit['suite']}"])
            require(not (dest / "gate/execution-failure.json").exists(), "Execution failed")
            require(code == (0 if report["gate_satisfied"] else 1), "Incomplete gate execution")
            record = {
                "id": unit["id"],
                "exit": code,
                "report_sha256": sha256(report_path),
                "requirement_satisfied": report["gate_satisfied"],
                "assessment": report["assessment"],
                "environment_satisfied": False,
            }
            records.append(record)
            write_json(output / "summary.json", summary)
            inspect(dest / "environment-after.json")
            record["environment_satisfied"] = True
            write_json(output / "summary.json", summary)
            if len(records) < len(plan["units"]):
                require(time.monotonic() + EXECUTION["gap_seconds"] < deadline, "Matrix deadline")
                time.sleep(EXECUTION["gap_seconds"])
        require(time.monotonic() < deadline, "Matrix deadline exceeded")
        summary["complete"] = True
        summary["competition_exclusion_established"] = not is_hosted
        summary["research_requirements_satisfied"] = all(
            r["requirement_satisfied"] for r in records
        )
    except BaseException as error:
        summary["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        summary["elapsed_seconds"] = time.monotonic() - started
        write_json(output / "summary.json", summary)
    return summary


def cancelled(signum: int, _frame: FrameType | None) -> NoReturn:
    raise InterruptedError(f"Matrix interrupted by signal {signum}")


def main() -> int:
    if len(sys.argv) > 4 and sys.argv[1] == "--launch-cpus" and sys.argv[3] == "--launch":
        cpus = {int(c) for c in sys.argv[2].split(",")}
        require(bool(cpus) and all(0 <= c < 4096 for c in cpus), "Invalid child CPU mask")
        launch(sys.argv[4:], cpus)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Package collectors change cwd before launching native helpers.
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancelled)
    try:
        require(sha256(args.plan) == args.plan_sha256, "Plan digest differs")
        plan = read_json(args.plan)
        write_json(args.output / "plan.json", plan)
        value = run(plan, args.output)
        return 0 if value["research_requirements_satisfied"] else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        write_json(
            args.output / "execution-failure.json", {"error": str(error), "ci_admission": False}
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
