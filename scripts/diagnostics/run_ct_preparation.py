"""Execute the frozen eight-process comparison, retaining statistical failures."""
# ruff: noqa: S603 -- digest-checked interpreter and collector

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from collect_ct_preparation import interrupted
from ct_preparation_plan import GAP_SECONDS, MAXIMUM_SECONDS, ROOT, check_unit, schedule, wait_owned

sys.path.insert(0, str(ROOT / "scripts/ci"))
import dudect_hosted_environment as hosted
from verify_dudect_analysis_matrix import require, sha256, write_json


def run(plan: dict[str, Any], output: Path) -> None:  # noqa: PLR0915 -- bounded acquisition transaction
    require(
        plan["schema"] == "dudect-ct-preparation/1" and plan["ci_admission"] is False,
        "Unreviewed plan",
    )
    require(plan["order"] == schedule(plan["compiler"]), "Changed experiment order")
    require(
        plan["maximum_seconds"] == MAXIMUM_SECONDS
        and plan["gap_seconds"] == GAP_SECONDS
        and plan["replacement_trials"] == 0,
        "Changed experiment budget",
    )
    require(sha256(Path(plan["python"])) == plan["python_sha256"], "Interpreter changed")
    for name, digest in plan["orchestration"].items():
        require(sha256(ROOT / name) == digest, "Orchestration changed")
    for unit in plan["units"].values():
        check_unit(unit)
    config = plan["hosted"]
    cpus = config["placement"]["original"]
    require(sorted(os.sched_getaffinity(0)) == cpus, "Allocation affinity changed")
    os.sched_setaffinity(0, config["placement"]["collector"])
    started = time.monotonic()
    deadline = started + MAXIMUM_SECONDS
    summary: dict[str, Any] = {
        "complete": False,
        "ci_admission": False,
        "units": [],
        "unstarted": plan["order"][:],
        "fresh_measurements": True,
    }
    try:
        for name in plan["order"]:
            dest = output / name
            dest.mkdir()
            hosted.environment(dest / "environment-before.json", config)
            unit = plan["units"][name]
            check_unit(unit)
            write_json(dest / "unit.json", unit)
            seconds = min(unit["maximum_seconds"], deadline - time.monotonic())
            require(seconds > 0, "Campaign deadline reached")
            command = [
                plan["python"],
                "-B",
                str(ROOT / "scripts/diagnostics/collect_ct_preparation.py"),
                "--unit",
                str(dest / "unit.json"),
                "--output",
                str(dest / "observations"),
                "--seconds",
                str(seconds),
                "--cpus",
                ",".join(map(str, cpus)),
            ]
            write_json(dest / "invocation.json", {"argv": command})
            summary["unstarted"].remove(name)
            write_json(output / "summary.json", summary)
            with (dest / "stdout").open("xb") as stdout, (dest / "stderr").open("xb") as stderr:
                child = subprocess.Popen(
                    command,
                    stdout=stdout,
                    stderr=stderr,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                code = wait_owned(child, seconds + 15)
            require(code == 0, "Process collection failed; no replacement")
            report = json.loads((dest / "observations/research-report.json").read_text())
            summary["units"].append({"id": name, "report": report})
            write_json(output / "summary.json", summary)
            hosted.environment(dest / "environment-after.json", config)
            if name != plan["order"][-1]:
                require(time.monotonic() + GAP_SECONDS < deadline, "Campaign deadline reached")
                time.sleep(GAP_SECONDS)
        require(time.monotonic() < deadline, "Campaign deadline exceeded")
        summary["complete"] = True
    except BaseException as error:
        summary["error"] = str(error)
        raise
    finally:
        summary["elapsed_seconds"] = time.monotonic() - started
        write_json(output / "summary.json", summary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    require(sha256(args.plan) == args.plan_sha256, "Plan digest changed")
    plan = json.loads(args.plan.read_text())
    write_json(output / "plan.json", plan)
    run(plan, output)


if __name__ == "__main__":
    main()
