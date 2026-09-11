"""Exercise the installed Kani wrapper and reject broken library models."""

# Standalone Nix install-check CLI: no Python package, intentional progress output.
# ruff: noqa: INP001, T201

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command: list[str], case: Path, environment: dict[str, str]) -> tuple[int, bool]:
    timed_out = False
    with (case / "output.log").open("w") as log:
        process = subprocess.Popen(  # noqa: S603 - explicit tool argv, no shell
            command,
            cwd=case,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
    return code, timed_out


def classify(text: str, name: str, code: int, *, timed_out: bool) -> tuple[bool, list[str], int]:
    parsed = re.findall(r"^Check (\d+): (.+)\n[ \t]+- Status: (\w+)[ \t]*$", text, re.MULTILINE)
    checks = [(identifier, status) for _, identifier, status in parsed]
    failed = [identifier for identifier, status in checks if status == "FAILURE"]
    known_statuses = all(status in {"SUCCESS", "FAILURE", "UNREACHABLE"} for _, status in checks)
    # Complete counts harnesses, while SUMMARY counts their individual properties.
    # Callee safety/unwind checks are legitimate; missing or inconsistent checks are not.
    summaries = re.findall(
        r"^SUMMARY:\n[ \t]+\*\* (\d+) of (\d+) failed(?: \((\d+) unreachable\))?[ \t]*$",
        text,
        re.MULTILINE,
    )
    counts_match = (
        len(re.findall(r"^[ \t]*Check\b", text, re.MULTILINE)) == len(checks)
        and [int(number) for number, _, _ in parsed] == list(range(1, len(checks) + 1))
        and len({identifier for identifier, _ in checks}) == len(checks)
        and len(summaries) == 1
        and len(re.findall(r"^[ \t]*SUMMARY\b", text, re.MULTILINE)) == 1
        and tuple(int(count or "0") for count in summaries[0])
        == (len(failed), len(checks), sum(status == "UNREACHABLE" for _, status in checks))
    )
    verdicts = re.findall(r"^VERIFICATION:- (\S+)[ \t]*$", text, re.MULTILINE)
    completions = re.findall(
        r"^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.[ \t]*$",
        text,
        re.MULTILINE,
    )
    single_completion = (
        len(re.findall(r"^[ \t]*VERIFICATION:", text, re.MULTILINE)) == 1
        and len(re.findall(r"^[ \t]*Complete\b", text, re.MULTILINE)) == 1
    )
    if name == "wrong_size":
        expected = (
            code == 1
            and failed == ["wrong_size.assertion.1"]
            and verdicts == ["FAILED"]
            and completions == [("0", "1", "1")]
        )
    else:
        expected = (
            code == 0
            and not failed
            and (f"{name}.assertion.1", "SUCCESS") in checks
            and verdicts == ["SUCCESSFUL"]
            and completions == [("1", "0", "1")]
        )
    passed = (
        bool(checks)
        and known_statuses
        and counts_match
        and single_completion
        and expected
        and not timed_out
    )
    return passed, failed, len(checks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kani", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("KANI_", "RUST", "CARGO_"))
    }
    environment["KANI_HOME"] = str(output / "tool-state")
    records = []
    cases = (
        "arithmetic_control",
        "sized_control",
        "slice_size",
        "slice_alignment",
        "string_clone",
        "vec_clone",
        "wrong_size",
    )
    for name in cases:
        case = output / name
        case.mkdir()
        source = case / "probe.rs"
        source.write_bytes(args.source.read_bytes())
        command = [
            str(args.kani.resolve()),
            str(source),
            "--exact",
            "--harness",
            name,
            "--solver",
            "cadical",
            "--default-unwind",
            "2",
            "--keep-temps",
        ]
        code, timed_out = execute(command, case, environment)
        text = (case / "output.log").read_text()
        passed, failed, check_count = classify(text, name, code, timed_out=timed_out)
        records.append(
            {
                "case": name,
                "command": command,
                "exit_code": code,
                "timed_out": timed_out,
                "status": "PASS" if passed else "FAIL",
                "expected": "assertion rejection" if name == "wrong_size" else "verification",
                "failed_checks": failed,
                "check_count": check_count,
                "source_sha256": digest(source),
                "log_sha256": digest(case / "output.log"),
            }
        )
        print(f"Kani library {name}: {'PASS' if passed else 'FAIL'}", flush=True)
    accepted = all(record["status"] == "PASS" for record in records)
    (output / "RESULTS.json").write_text(
        json.dumps(
            {
                "scope": "verification-library regression; no application correspondence claim",
                "status": "PASS" if accepted else "FAIL",
                "wrapper_sha256": digest(args.kani),
                "checker_sha256": digest(Path(__file__)),
                "records": records,
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
