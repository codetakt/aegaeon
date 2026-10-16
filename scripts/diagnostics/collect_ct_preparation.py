"""Collect one research process with original case deadlines and owned cleanup."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from types import FrameType


SIGNAL_DOSE = 16


def interrupted(signum: int, _frame: FrameType | None) -> NoReturn:
    message = f"Research process interrupted by signal {signum}"
    raise TimeoutError(message)


def main() -> None:  # noqa: PLR0912, PLR0915 -- source-specific collector lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--cpus", required=True)
    args = parser.parse_args()
    unit = json.loads(args.unit.read_text())
    source = Path(unit["source"])
    sys.path.insert(0, str(source / "tests/constant_time"))
    from dudect_candidate import significant  # noqa: PLC0415 -- frozen source
    from dudect_contract import ObservationError, assess_case, contract_roles  # noqa: PLC0415
    from dudect_support import require  # noqa: PLC0415
    from run import write_json  # noqa: PLC0415
    from run_candidate import collect  # noqa: PLC0415

    require(args.seconds > 0, "No remaining process budget")
    cpus = {int(c) for c in args.cpus.split(",")}
    os.sched_setaffinity(0, cpus)
    for name in ("AEGAEON_DUDECT_PREPARATION", "AEGAEON_DUDECT_PREPARATION_SIGNAL"):
        os.environ.pop(name, None)
    os.environ.update(unit["environment"])
    args.output.mkdir()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.setitimer(signal.ITIMER_REAL, args.seconds)
    try:
        histories = collect(source, args.output, Path(unit["binary"]), "pr", unit["bindings"])
        decisions = json.loads((args.output / "effective-decisions.json").read_text())
        roles = contract_roles(
            json.loads(
                (source / "tests/constant_time/contracts/case-contract-candidate.json").read_text()
            )
        )
        assessments = []
        for name in histories:
            rows = [r for r in decisions if r["case"] == name]
            case_id = f"{unit['suite']}/{name}"
            if unit["signal"] == SIGNAL_DOSE and name == "ct_eq_128":
                assessment = {
                    "case_id": case_id,
                    "requirement": "diagnostic_raw0_signal",
                    "requirement_satisfied": any(significant(r["tests"][0]) for r in rows),
                }
            else:
                try:
                    assessment = assess_case(case_id, roles[case_id], rows, "pr")
                except ObservationError as error:
                    assessment = {
                        "case_id": case_id,
                        "requirement_satisfied": False,
                        "error": str(error),
                    }
            assessments.append(assessment)
        if unit["environment"].get("AEGAEON_DUDECT_PREPARATION"):
            mode = {"baseline": 0, "class0": 1, "uniform": 2}[
                unit["environment"]["AEGAEON_DUDECT_PREPARATION"]
            ]
            receipt = f"CT_PREPARATION mode={mode} frames=17\n"
            require(
                (args.output / "native.stderr").read_text().count(receipt) == 1,
                "Missing preparation receipt",
            )
        write_json(
            args.output / "research-report.json",
            {
                "complete": True,
                "ci_admission": False,
                "assessment": assessments,
                "requirements_satisfied": all(a["requirement_satisfied"] for a in assessments),
            },
        )
    except BaseException as error:
        write_json(
            args.output / "execution-failure.json", {"error": str(error), "ci_admission": False}
        )
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    main()
