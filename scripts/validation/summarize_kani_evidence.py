"""Write a GitHub step summary for one Kani evidence run (no admission decisions).

The run shown is the gate run when gate.json binds one; otherwise the run with the latest
recorded start time (never the lexically last directory name, which is random).
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime


def select_run(output: pathlib.Path) -> pathlib.Path | None:
    gate = output / "gate.json"
    if gate.is_file():
        record = json.loads(gate.read_text())
        evaluation = output / str(record.get("run", "")) / "evaluation.json"
        if evaluation.is_file() and hashlib.sha256(
            evaluation.read_bytes()
        ).hexdigest() == record.get("evaluation_sha256"):
            return evaluation.parent
    candidates: list[tuple[datetime, str, pathlib.Path]] = []
    for evaluation in output.glob("run-*/evaluation.json"):
        try:
            started = datetime.fromisoformat(
                str(json.loads(evaluation.read_text()).get("started_at"))
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        candidates.append((started, evaluation.parent.name, evaluation.parent))
    return max(candidates)[2] if candidates else None


def main() -> int:
    output = pathlib.Path(sys.argv[1])
    title = sys.argv[2] if len(sys.argv) > 2 else "Kani"
    lines = [f"### {title}"]
    run = select_run(output) if output.exists() else None
    if run is None:
        lines.append("⚠️ no evaluation record was produced")
    else:
        evaluation = json.loads((run / "evaluation.json").read_text())
        counts = evaluation.get("counts", {})
        gate = (output / "gate.json").exists()
        lines.append(
            f"run: {run.name} · scope: {evaluation.get('scope')} · status: "
            f"{evaluation.get('status')} · gate.json: {'present' if gate else 'absent'}"
        )
        lines.append(
            "required accepted/rejected: "
            f"{counts.get('required_accepted', 0)}/{counts.get('required_rejected', 0)} · "
            "diagnostic accepted/rejected: "
            f"{counts.get('diagnostic_accepted', 0)}/{counts.get('diagnostic_rejected', 0)} · "
            f"faults: {counts.get('faults', 0)}"
        )
        for fault in evaluation.get("faults", []):
            lines.append(f"- ⚠️ fault: {fault}")
        for result in evaluation.get("results", []):
            reasons = "; ".join(result.get("reasons", []))
            lines.append(
                f"- `{result['harness']['name']}` [{result['class']}"
                f"{'/' + result['gating'] if result.get('gating') else ''}]: {result['status']}"
                + (f" — {reasons}" if reasons else "")
            )
    text = "\n".join(lines) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
