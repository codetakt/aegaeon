# ruff: noqa: S603 - explicitly selected preserved Python source, no shell
"""Offline experimental comparison. Old artifacts and adopted CI gates are never rewritten."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from dudect_candidate import digest
from dudect_contract import ObservationError, assess_case, contract_roles
from dudect_process import load_json
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES
from dudect_sparse import BASE_CONTRACT, BASE_NUMERICAL, POLICY, POLICY_SHA256
from dudect_sparse_replay import Prefix, augment
from dudect_support import require
from dudect_timing import BATCH, input_width, validate_context, validate_header

BASELINE_SCRIPT = """
import json, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
from dudect_candidate import CandidateAdmission, canonical, digest
from dudect_diagnostics import validate_diagnostics
from dudect_process import load_json
from dudect_support import require
p = Path(sys.argv[2])
observations = load_json((p/'observations.json').read_bytes())
process = load_json((p/'process.json').read_bytes())
require(process['exit'] == 0 and process['collection_complete'], 'Incomplete original process')
decisions = []
bindings = {}
for name, rows in observations.items():
    bindings[name] = rows[0]['binding']
    admission = CandidateAdmission(name, rows[0]['profile'], binding=bindings[name])
    decisions.extend(admission.admit(row) for row in rows)
    require(decisions[-1]['collection_complete'], 'Incomplete original schedule')
saved = load_json((p/'decisions.json').read_bytes())
require(decisions == saved, 'Original decision replay mismatch')
require([load_json(line) for line in (p/'native.stdout').read_bytes().splitlines()] ==
        [row for rows in observations.values() for row in rows], 'Original stdout mismatch')
validate_diagnostics(p, process, bindings, next(iter(bindings.values()))['profile'])
print(json.dumps({'decisions_sha256': digest(canonical(decisions)), 'cases': len(observations),
                  'looks': len(decisions), 'diagnostics_validated': True}))
"""


def identity(path):
    return {"sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}


def validate_baseline(execution, source):
    # Old raw stays under its original numerical consumer; it is never rebound.
    reviewed_sources = {
        "dudect_candidate.py": "54657753d98c952dd3aa63eb175b106c09e91d78aac0583f6bde68e7e0c2062c",
        "dudect_support.py": "52da334dc862b8ee25730ba184d539a85a68cabd52f5532caec2a9efdabd391c",
        "dudect_results.py": "8d8681ad8349a11012d0d6e0e0923acb4f2e821e8b8b4331d4e8395dacb8cb98",
        "dudect_contract.py": "9f43c3a04c7dd261d1d3fd9a145746cdd738d38fe14408aa29a556d8983f60a7",
    }
    for name, expected in reviewed_sources.items():
        require(
            digest((source / name).read_bytes()) == expected,
            "Unreviewed original numerical consumer: " + name,
        )
    result = subprocess.run(
        [sys.executable, "-B", "-c", BASELINE_SCRIPT, str(source), str(execution)],
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )
    return {
        "result": json.loads(result.stdout),
        "source": str(source),
        "source_files": {p.name: identity(p) for p in sorted(source.glob("*.py"))},
    }


def role_result(binding, history, roles):
    try:
        return assess_case(
            binding["case_id"], roles[binding["case_id"]], history, binding["profile"]
        )
    except ObservationError as error:
        return {
            "case_id": binding["case_id"],
            "requirement_satisfied": False,
            "failure": str(error),
        }


def case_replay(stream, framing, rows, old):
    case_frame, magic, frames, context = framing
    name = rows[0]["case"]
    prefix = Prefix()
    fields = case_frame.unpack(stream.read(case_frame.size))
    require(fields[0] == name.encode().ljust(64, b"\0"), "Wrong native case")
    width = input_width(name, magic)
    require(fields[2] == width, "Wrong native input width")
    by_batch = {row["batches"]: (row, decision) for row, decision in zip(rows, old, strict=True)}
    history = []
    detected = False
    for batch in range(frames):
        values = BATCH.unpack(stream.read(BATCH.size))
        validate_context(values, batch, context["end"], context["counters"])
        context.update(end=values[3], counters=list(values[7::2]))
        payload = stream.read(BATCH_SIZE * (9 + width))
        require(len(payload) == BATCH_SIZE * (9 + width), "Truncated native payload")
        prefix.push(payload, batch)
        if batch in by_batch:
            row, original = by_batch[batch]
            evaluated = augment(row, original, prefix, detected)
            detected = evaluated["detected"]
            history.append(evaluated)
    require(len(history) == len(rows), "Missing candidate look")
    return history


def evaluate(execution: Path, source: Path):
    inputs = {
        name: identity(execution / name)
        for name in (
            "native.timing",
            "native.stdout",
            "observations.json",
            "decisions.json",
            "process.json",
        )
    }
    baseline = validate_baseline(execution, source)
    observations = load_json((execution / "observations.json").read_bytes())
    saved = load_json((execution / "decisions.json").read_bytes())
    bindings = {name: rows[0]["binding"] for name, rows in observations.items()}
    profile = next(iter(bindings.values()))["profile"]
    require(
        all(
            b["profile"] == profile
            and b["numerical_sha256"] == BASE_NUMERICAL
            and b["contract_sha256"] == BASE_CONTRACT
            for b in bindings.values()
        ),
        "Unreviewed original binding",
    )
    roles = contract_roles(
        load_json((Path(__file__).parent / "contracts/case-contract-candidate.json").read_bytes())
    )
    frames = CANDIDATE_PROFILES[profile][0][-1] + 1
    cases = []
    with (execution / "native.timing").open("rb") as stream:
        magic, case_frame = validate_header(
            stream.read(200), bindings, frames, inputs["native.timing"]["bytes"]
        )
        context = {"end": None, "counters": [0] * 6}
        for name, rows in observations.items():
            # The isolated original consumer already authenticated every saved decision.
            old = [r for r in saved if r["case"] == name]
            require(len(old) == len(rows), "Original decision inventory differs")
            history = case_replay(stream, (case_frame, magic, frames, context), rows, old)
            effective = [h["effective"] for h in history]
            cases.append(
                {
                    "case": name,
                    "binding": bindings[name],
                    "history": history,
                    "original_role": role_result(bindings[name], old, roles),
                    "experimental_role": role_result(bindings[name], effective, roles),
                }
            )
        require(stream.read(1) == b"", "Trailing timing evidence")
    require(
        inputs == {name: identity(execution / name) for name in inputs},
        "Evidence changed during replay",
    )
    return {
        "schema": POLICY["schema"],
        "policy": POLICY,
        "policy_sha256": POLICY_SHA256,
        "adopted": False,
        "gate_admission": "inactive",
        "fresh_native_timing": False,
        "execution": str(execution),
        "inputs": inputs,
        "baseline_validation": baseline,
        "analysis_sources": {
            p.name: identity(p) for p in sorted(Path(__file__).parent.glob("*.py"))
        },
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, required=True, help="Preserved tests/constant_time source directory"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(
        not args.output.resolve().is_relative_to(args.execution.resolve()),
        "Output must be separate from original evidence",
    )
    require(not args.output.exists(), "Refusing to overwrite a previous result")
    result = evaluate(args.execution, args.source)
    with args.output.open("x") as destination:
        destination.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(result["cases"]), "output": str(args.output), "adopted": False}))


if __name__ == "__main__":
    main()
