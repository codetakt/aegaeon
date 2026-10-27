# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Bounded full-provider sensitivity comparison, with a separate diagnostic role."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

from screen import evaluate, check_receipts


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n")


def labels(raw):
    result = []
    with raw.open("rb") as f:
        if f.read(8) != b"AEGTIM05":
            raise ValueError("Wrong timing version")
        f.seek(200)
        while header := f.read(112):
            name, stride, width, *_ = struct.unpack("<64s6Q", header)
            if name.rstrip(b"\0") != b"hmac_sha256":
                f.seek(17 * (144 + 65536 * (9 + width)), 1)
                continue
            if stride != 32 or width != 32:
                raise ValueError("Wrong HMAC input shape")
            for batch in range(17):
                context = struct.unpack("<18Q", f.read(144))
                if context[:2] != (batch, 65536):
                    raise ValueError("Wrong frame order")
                f.seek(8 * 65536, 1)
                result.append(f.read(65536))
                f.seek(width * 65536, 1)
            break
    return result


def validate(plan):
    for row in plan["inputs"]:
        p = Path(row["path"])
        if not p.is_file() or sha(p) != row["sha256"]:
            raise ValueError("Changed frozen input: " + str(p))
    if len(plan["arms"]) != 8 or plan["max_processes"] != 16 or plan["max_cases"] != 80:
        raise ValueError("Unexpected finite inventory")
    if sorted((a["compiler"], a["scope"]) for a in plan["arms"]) != sorted(
        (c, s) for c in ("gcc", "clang") for s in ("ordinary", "zero", "early", "late")
    ):
        raise ValueError("Unexpected arm inventory")


def main():  # noqa: C901, PLR0912, PLR0915 -- ordered evidence checks retain each rejection boundary
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--plan-sha256", required=True)
    args = ap.parse_args()
    if sha(args.plan) != args.plan_sha256:
        raise ValueError("Plan identity mismatch")
    plan = json.loads(args.plan.read_text())
    validate(plan)
    sys.path.insert(0, plan["analysis_path"])
    from run_analysis import SOURCE  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from analysis_contract import assess, identity  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from analysis_runtime import replay  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from dudect_contract import contract_roles  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from dudect_package import checked_package, expected_bindings  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from dudect_diagnostics import validate_diagnostics  # noqa: PLC0415 -- retain initialization order of the measured analysis
    import run_candidate  # noqa: PLC0415 -- retain initialization order of the measured analysis

    sys.path.insert(0, plan["environment_module_path"])
    import dudect_metal_environment as metal  # noqa: PLC0415 -- retain initialization order of the measured analysis

    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    roles = contract_roles(
        json.loads(
            (SOURCE / "tests/constant_time/contracts/case-contract-candidate.json").read_text()
        )
    )
    indexes = {
        c: checked_package(Path(p), run_candidate.current_sources(SOURCE), "nix")
        for c, p in plan["packages"].items()
    }
    results = []
    started = time.monotonic()

    def interrupted(signum, frame):
        raise TimeoutError("Fixed campaign limit or external stop")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.setitimer(signal.ITIMER_REAL, plan["campaign_seconds"])
    try:
        for arm in plan["arms"]:
            compiler, scope = arm["compiler"], arm["scope"]
            index = indexes[compiler]
            for executable in index["executables"]:
                if results:
                    time.sleep(plan["inter_process_seconds"])
                unit = arm["id"] + "-" + executable["name"]
                dest = output / unit
                dest.mkdir()
                host = metal.snapshot()
                save(dest / "environment-before.json", host)
                metal.check(host)
                analysis = identity("distributed", plan["id"], unit)
                if analysis != arm["analysis"][executable["name"]]:
                    raise ValueError("Analysis identity changed")  # noqa: TRY301 -- failure capture preserves partial evidence
                save(dest / "analysis.json", analysis)
                expected = expected_bindings(index, "pr")["bindings"]
                bindings = {n: expected[n] for n in executable["cases"]}
                binary = Path(plan["packages"][compiler]) / executable["relative_binary"]
                diagnostic = executable["name"] == "dudect_harness" and scope != "ordinary"
                if diagnostic:
                    artifact = json.loads(
                        Path(plan["diagnostics"][compiler]["artifact"]).read_text()
                    )
                    binary = Path(plan["diagnostics"][compiler]["binary"])
                    if sha(binary) != artifact["binary_sha256"]:
                        raise ValueError("Diagnostic ELF changed")  # noqa: TRY301 -- failure capture preserves partial evidence
                    for binding in bindings.values():
                        binding["build_sha256"] = artifact["binding"]["build_sha256"]
                os.environ["AEGAEON_HMAC_SIGNAL_SCOPE"] = "zero" if scope == "ordinary" else scope
                begin = time.monotonic()
                invocation = {
                    "analysis_path": plan["analysis_path"],
                    "analysis": analysis,
                    "binary": str(binary),
                    "binary_sha256": sha(binary),
                    "bindings": bindings,
                    "case_order": executable["cases"],
                    "output": str(dest),
                    "cpus": [0, 1],
                }
                invoke = dest / "collector-invocation.json"
                save(invoke, invocation)
                with (
                    (dest / "collector.stdout").open("wb") as stdout,
                    (dest / "collector.stderr").open("wb") as stderr,
                ):
                    child = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                        [
                            sys.executable,
                            "-B",
                            str(Path(__file__).with_name("collect_one.py")),
                            str(invoke),
                            sha(invoke),
                        ],
                        stdout=stdout,
                        stderr=stderr,
                        start_new_session=True,
                    )
                    try:
                        code = child.wait(
                            timeout=max(
                                0.001, plan["campaign_seconds"] - (time.monotonic() - started)
                            )
                        )
                    finally:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGTERM)
                            try:
                                child.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                os.killpg(child.pid, signal.SIGKILL)
                                child.wait()
                    if code != 0:
                        raise ValueError("Collector child failed; retain partial evidence")  # noqa: TRY301 -- failure capture preserves partial evidence
                rows = json.loads((dest / "observations.json").read_text())
                process = json.loads((dest / "process.json").read_text())
                if process["exit"] != 0 or not process["collection_complete"]:
                    raise ValueError("Incomplete process")  # noqa: TRY301 -- failure capture preserves partial evidence
                validate_diagnostics(dest, process, bindings, "pr")
                effective = replay(dest, bindings, rows, analysis)
                save(dest / "effective.json", effective)
                save(dest / "bindings.json", bindings)
                if diagnostic:
                    check_receipts(
                        (dest / "native.stderr").read_text(), scope, labels(dest / "native.timing")
                    )
                cases = []
                for name, binding in bindings.items():
                    cid = binding["case_id"]
                    history = [r for r in effective if r["case"] == name]
                    original_role = assess(cid, roles[cid], history)
                    entry = {"case_id": cid, "original_candidate_role": original_role}
                    if name == "hmac_sha256":
                        entry["sensitivity_screen"] = evaluate(history, scope, original_role)
                        entry["requirement_satisfied"] = entry["sensitivity_screen"]["passed"]
                    else:
                        entry["requirement_satisfied"] = original_role["requirement_satisfied"]
                    cases.append(entry)
                host = metal.snapshot()
                save(dest / "environment-after.json", host)
                metal.check(host)
                result = {
                    "unit": unit,
                    "compiler": compiler,
                    "scope": scope,
                    "seconds": time.monotonic() - begin,
                    "cases": cases,
                }
                results.append(result)
                save(
                    output / "results.json",
                    {
                        "plan_sha256": args.plan_sha256,
                        "complete": len(results) == 16,
                        "elapsed_seconds": time.monotonic() - started,
                        "results": results,
                        "adopted": False,
                    },
                )
                print(
                    json.dumps(
                        {
                            "unit": unit,
                            "cases": len(cases),
                            "satisfied": sum(c["requirement_satisfied"] for c in cases),
                            "seconds": result["seconds"],
                        }
                    ),
                    flush=True,
                )
        validate(plan)
    except BaseException as error:
        save(
            output / "failure.json",
            {
                "error": str(error),
                "type": type(error).__name__,
                "completed_processes": len(results),
            },
        )
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        os.environ.pop("AEGAEON_HMAC_SIGNAL_SCOPE", None)


if __name__ == "__main__":
    main()
