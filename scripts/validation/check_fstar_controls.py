"""Check recorded expected-rejection controls without admitting them as proofs.

Control identities must equal proof pass 1, whose tool pins are independently
checked by the normal assumption graph. Replay requires retained records only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from admit_fstar_modules import (
    AdmissionError,
    check_explicit_solver,
    check_tool_identity,
    digest_file,
    load_json,
    load_pass,
    parse_output,
    write_json_new,
)

CONTRACT = "fstar-expected-rejection-controls-v1"
CONTROLS = {
    "redis-flag": (
        "authcode/AuthCode.RedisFlag.fst",
        "../tests/fstar/property/TestAuthCodeRedisFlag.fst",
    ),
    "authorization-revision": (
        "authcode/Authorization.ProjectionRevision.fst",
        "../tests/fstar/property/TestAuthorizationProjectionRevision.fst",
    ),
}


def invocation(directory: Path, pass_id: str) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    inputs, result, raw, result_digest = load_pass(directory)
    if (
        result.get("pass_id") != pass_id
        or result.get("status") != "succeeded"
        or type(result.get("returncode")) is not int
        or result["returncode"] != 0
        or "error" in result
        or result.get("argv") != inputs["argv"]
        or result.get("cwd") != inputs["cwd"]
        or inputs.get("executed_argv") != [inputs["tool"]["path"], *inputs["argv"][1:]]
    ):
        raise AdmissionError(f"{pass_id}: unsuccessful or inconsistent invocation")
    if inputs.get("tool_identity_contract") != "entrypoint-before-after-v1":
        raise AdmissionError(f"{pass_id}: verifier endpoint contract is required")
    if not isinstance(inputs.get("solver"), dict) or "--smt" not in inputs["argv"]:
        raise AdmissionError(f"{pass_id}: an explicit solver pin is required")
    text = raw.decode(errors="replace")
    check_tool_identity(inputs, result)
    check_explicit_solver(inputs, result, text)
    return inputs, result, text, result_digest


def reconstruct(out_dir: Path, name: str) -> dict[str, Any]:
    reference, reference_result, _, reference_digest = invocation(out_dir / "invocations/1", "1")
    inputs, result, output, result_digest = invocation(
        out_dir / "controls/invocations" / name, name
    )
    for field in ("tool", "tool_resolved_path", "recorder", "solver", "cwd"):
        if inputs.get(field) != reference.get(field):
            raise AdmissionError(f"{name}: {field} differs from proof pass 1")
    if result["solver_effective"]["version"] != reference_result["solver_effective"]["version"]:
        raise AdmissionError(f"{name}: solver version differs from proof pass 1")
    sources = CONTROLS[name]
    solver = reference["argv"][reference["argv"].index("--smt") + 1]
    expected = ["fstar.exe", "--hint_info", "--smt", solver, "--include", "authcode", *sources]
    if inputs["argv"] != expected or inputs.get("include_paths") != ["authcode"]:
        raise AdmissionError(f"{name}: unexpected control command")
    manifest = out_dir / f"{name}-controls.sha256"
    modules = inputs["modules"]
    if [entry["path"] for entry in modules] != list(sources):
        raise AdmissionError(f"{name}: unexpected control source identities")
    if any(re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None for entry in modules):
        raise AdmissionError(f"{name}: malformed source digest")
    cached_names = {Path(source).name + ".checked" for source in sources}
    if any(Path(entry["path"]).name in cached_names for entry in inputs["local_context"]):
        raise AdmissionError(f"{name}: a control source has a pre-existing checked cache")
    expected_manifest = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in modules)
    if manifest.read_text() != expected_manifest:
        raise AdmissionError(f"{name}: source manifest differs from recorded inputs")
    if digest_file(out_dir / f"{name}-controls.log") != result["output_sha256"]:
        raise AdmissionError(f"{name}: retained control log differs from recorded output")
    parsed = parse_output(output)
    if parsed["errors"] or len(parsed["completion"]) != 1:
        raise AdmissionError(f"{name}: control errors or missing/duplicate completion marker")
    for source in sources:
        module = Path(source).stem
        lines = [line for observed, line in parsed["implementations"] if observed == module]
        if len(lines) != 1 or lines[0] >= parsed["completion"][0]:
            raise AdmissionError(f"{name}: missing/duplicate control module result for {module}")
    return {
        "contract": CONTRACT,
        "control": name,
        "status": "checked",
        "scope": "expected-rejection control only; not admitted proof evidence",
        "reference_pass": "1",
        "reference_result_sha256": reference_digest,
        "reference_inputs_sha256": reference_result["inputs_sha256"],
        "result_sha256": result_digest,
        "inputs_sha256": result["inputs_sha256"],
        "output_sha256": result["output_sha256"],
        "source_manifest_sha256": digest_file(manifest),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--control", choices=CONTROLS)
    mode.add_argument("--verify-records", action="store_true")
    args = parser.parse_args()
    try:
        for name in CONTROLS if args.verify_records else (args.control,):
            record = reconstruct(args.out_dir, name)
            path = args.out_dir / "controls" / f"{name}.json"
            if args.verify_records:
                if load_json(path) != record:
                    raise AdmissionError(f"{name}: control record differs from reconstruction")
            else:
                write_json_new(path, record)
            print("FSTAR-CONTROL " + json.dumps(record, sort_keys=True))
        return 0
    except (AdmissionError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"[FAIL] F* control records: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
