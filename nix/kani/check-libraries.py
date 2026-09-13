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

# Reviewed together with PROPERTY_INVENTORY. Do not derive this approval from
# --source: unchanged property identifiers do not identify assertion semantics.
CONTROL_SOURCE_SHA256 = "66ffb8e23fb003d05887a2aea0d0e392f80d4c29b4b30a999c55124bdc768ee8"

# Pinned Kani 0.66.0 / nightly-2025-11-05 / x86_64-linux controls, cadical,
# unwind 2. SHA256 of sorted property identifiers joined by a newline (no final
# newline). Deliberately independent of the report's SUMMARY: changing the tool
# or controls requires reviewing this inventory, not learning it from that run.
PROPERTY_INVENTORY = {
    "arithmetic_control": (2, "6f836bd3cad03cde0756de16d6916cc5d5c55d246c04f13f470b4e1452878ef5"),
    "sized_control": (4, "c36a613243ed4e6090deff0e334c046350b299cb312292f4341dade412cf94d1"),
    "slice_alignment": (4, "26bff07a48b175e86db882b71b5b51b552f68d43a12730e90fc524659ced3892"),
    "slice_size": (4, "bcd9cc8116169b2bd28f71ad1c0881f3a4932221d48f9dcdc960fdc14d0251e8"),
    "string_clone": (212, "0b05c3fc350b9b37b7e13a0e9d94a9c18aa7aa52c73c12c0ab0eb3340ac87a05"),
    "vec_clone": (384, "69dc278fd57caa21dbecf421202a6b2aef4065a935df8e40dfe4b212e5e27d64"),
    "wrong_size": (4, "da917938af8911092c56fd49ce28bb7a81f0f7ba28624f35fabf84d7ff1c09e8"),
}
PROPERTY = re.compile(
    r"^Check (\d+): ([^\n]+)\n"
    r"\t - Status: ([A-Z]+)\n"
    r'\t - Description: "[^\n]*(?:\n[ ]+[^\n]*)*"\n'
    r"(?:\t - Location: [^\n]+\n)?",
    re.MULTILINE,
)


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
    if text.count("\nRESULTS:\n") != 1:
        return False, [], 0
    report = text.split("\nRESULTS:\n", maxsplit=1)[1]
    body, separator, _ = report.partition("\nSUMMARY:\n")
    parsed = PROPERTY.findall(body)
    if not separator or not parsed or PROPERTY.sub("", body).strip():
        return False, [], len(parsed)
    checks = [(identifier, status) for _, identifier, status in parsed]
    inventory = (
        len(checks),
        hashlib.sha256(
            "\n".join(sorted(identifier for identifier, _ in checks)).encode()
        ).hexdigest(),
    )
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
        inventory == PROPERTY_INVENTORY.get(name)
        and len(re.findall(r"^[ \t]*Check\b", text, re.MULTILINE)) == len(checks)
        and len(re.findall(r"^[ \t]*- Status:", text, re.MULTILINE)) == len(checks)
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


def approved_control_source(source_path: Path, output: Path) -> bytes | None:
    # Read once: every harness receives the same approved snapshot, even if the
    # caller replaces the source path while the controls are running.
    try:
        control_source = source_path.read_bytes()
        source_sha256 = hashlib.sha256(control_source).hexdigest()
        source_error = None if source_sha256 == CONTROL_SOURCE_SHA256 else "source_digest_mismatch"
    except OSError:
        control_source = b""
        source_sha256 = None
        source_error = "source_unreadable"
    if source_error is not None:
        (output / "RESULTS.json").write_text(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": source_error,
                    "approved_source_sha256": CONTROL_SOURCE_SHA256,
                    "source_sha256": source_sha256,
                    "checker_sha256": digest(Path(__file__)),
                    "records": [],
                },
                indent=2,
            )
            + "\n"
        )
        print(f"Kani library controls: FAIL ({source_error})", flush=True)
        return None
    return control_source


def retained_control_source(source: Path) -> tuple[str | None, str | None]:
    try:
        source_sha256 = digest(source)
    except OSError:
        return None, "source_unreadable"
    error = None if source_sha256 == CONTROL_SOURCE_SHA256 else "source_digest_mismatch"
    return source_sha256, error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kani", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    control_source = approved_control_source(args.source, output)
    if control_source is None:
        return 1
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
        source.write_bytes(control_source)
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
        retained_source_sha256, source_error = retained_control_source(source)
        passed = passed and source_error is None
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
                "source_sha256": retained_source_sha256,
                "source_error": source_error,
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
                "approved_source_sha256": CONTROL_SOURCE_SHA256,
                "source_sha256": hashlib.sha256(control_source).hexdigest(),
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
