"""Bind compliance-matrix Kani citations to the Kani evidence registry.

Structural mode (default): every ``type: kani`` proof entry must bind to exactly one registry
entry by ``(file, short name)``; ``verified`` rows may bind only to required/evidence
harnesses. Evidential mode (``--gate``): the bound harness must be accepted in that gate's run.
A structural match is never reported as admitted. ``ci_check`` values are reported only.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import run_kani_evidence as kani  # noqa: E402 - sibling module


def matrix_citations(matrix: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "id" in node and isinstance(node.get("proof"), list):
                for proof in node["proof"]:
                    if isinstance(proof, dict) and proof.get("type") == "kani":
                        found.append(
                            {
                                "row": node["id"],
                                "status": node.get("status"),
                                "ci_check": node.get("ci_check"),
                                "file": proof.get("file"),
                                "harness": proof.get("harness"),
                            }
                        )
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(matrix)
    return found


def registry_index(registry: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for group in registry["groups"]:
        entries = group.get("harnesses") or group.get("sites") or []
        for entry in entries:
            key = (entry["file"], kani.short_name(entry["name"]))
            index.setdefault(key, []).append(
                {
                    "group": group["id"],
                    "class": group["class"],
                    "gating": group.get("gating"),
                    "name": entry["name"],
                }
            )
    ambiguous = {k: v for k, v in index.items() if len(v) > 1}
    if ambiguous:
        raise kani.AdmissionError(
            f"registry binds {len(ambiguous)} (file, short name) pairs more than once: "
            f"{sorted(ambiguous)[:3]}"
        )
    return {k: v[0] for k, v in index.items()}


def evaluate(
    citations: list[dict[str, Any]],
    index: dict[tuple[str, str], dict[str, Any]],
    results: dict[tuple[str, str], str] | None,
) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for citation in citations:
        entry = index.get((citation["file"], kani.short_name(str(citation["harness"]))))
        item = {**citation, "binding": None, "structural": "unbound", "evidence": "not-evaluated"}
        if entry is None:
            item["structural"] = "unbound"
        else:
            item["binding"] = entry
            if citation["status"] == "verified" and not (
                entry["class"] == "required" and entry["gating"] == "evidence"
            ):
                item["structural"] = "verified-row-cites-non-evidence"
            else:
                item["structural"] = "bound"
            if results is not None:
                if entry["class"] == "excluded":
                    item["evidence"] = "excluded-not-run"
                else:
                    status = results.get((entry["group"], entry["name"]))
                    if status is None:
                        item["evidence"] = "missing-from-run"
                    elif status == "accepted":
                        item["evidence"] = (
                            "accepted-evidence"
                            if entry["gating"] == "evidence"
                            else "accepted-regression"
                            if entry["class"] == "required"
                            else "accepted-diagnostic"
                        )
                    else:
                        item["evidence"] = (
                            "diagnostic-rejected"
                            if entry["class"] == "diagnostic"
                            else "required-rejected"
                        )
        report.append(item)
    return report


def failures(report: list[dict[str, Any]], evidential: bool) -> list[str]:
    problems: list[str] = []
    for item in report:
        if item["structural"] != "bound":
            problems.append(
                f"{item['row']}: {item['structural']} ({item['file']} {item['harness']})"
            )
        if evidential and item["status"] == "verified" and item["evidence"] != "accepted-evidence":
            problems.append(
                f"{item['row']}: verified row without accepted evidence ({item['evidence']})"
            )
        if evidential and item["evidence"] in ("missing-from-run", "required-rejected"):
            problems.append(f"{item['row']}: {item['evidence']} ({item['harness']})")
    return problems


def load_gate_results(
    gate_path: pathlib.Path,
    registry: dict[str, Any],
    registry_path: pathlib.Path,
    schema_path: pathlib.Path,
    root: pathlib.Path,
    matrix_path: pathlib.Path,
) -> dict[tuple[str, str], str]:
    """Reconstruct the gate run under the caller's trust inputs; only the reconstructed
    statuses feed the citation decision (never the stored summary alone)."""
    gate = kani.load_json(gate_path)
    run_dir = gate_path.parent / str(gate.get("run", ""))
    if not run_dir.is_dir():
        raise kani.AdmissionError("gate.json does not name a retained run")
    reconstruction = kani.reconstruct_run(run_dir, registry, registry_path, schema_path, root)
    kani.check_gate(run_dir, reconstruction)
    if not reconstruction["gate_ok"]:
        raise kani.AdmissionError(
            f"the run reconstructs to no admitted gate (status {reconstruction['status']})"
        )
    try:
        relative = matrix_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise kani.AdmissionError(
            "a matrix outside the repository cannot be bound to the run"
        ) from error
    if reconstruction["inputs"].get(relative) != kani.digest_file(matrix_path):
        raise kani.AdmissionError(f"matrix {relative} is not bound by the run's input snapshot")
    return dict(reconstruction["results"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--matrix", type=pathlib.Path, default=ROOT / "spec/compliance-matrix.yaml")
    parser.add_argument("--registry", type=pathlib.Path, default=ROOT / kani.REGISTRY)
    parser.add_argument("--schema", type=pathlib.Path, default=ROOT / kani.SCHEMA)
    parser.add_argument(
        "--gate",
        type=pathlib.Path,
        default=None,
        help="gate.json of a full-scope run (evidential mode)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()
    try:
        registry = kani.load_registry(
            args.root.resolve(), args.registry.resolve(), args.schema.resolve()
        )
        index = registry_index(registry)
        citations = matrix_citations(yaml.safe_load(args.matrix.read_text()))
        results = (
            load_gate_results(
                args.gate.resolve(),
                registry,
                args.registry.resolve(),
                args.schema.resolve(),
                args.root.resolve(),
                args.matrix.resolve(),
            )
            if args.gate
            else None
        )
        report = evaluate(citations, index, results)
        problems = failures(report, results is not None)
    except kani.AdmissionError as error:
        print(f"[FAIL] Kani citations: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(
            json.dumps(
                {
                    "mode": "evidential" if results is not None else "structural",
                    "citations": report,
                    "problems": problems,
                },
                indent=2,
            )
        )
    else:
        for item in report:
            print(
                f"{item['row']:<12} {item['status']:<9} {item['structural']:<34} "
                f"{item['evidence']:<22} {item['file']}::{item['harness']}  "
                f"ci_check={item['ci_check']}"
            )
        for problem in problems:
            print(f"[FAIL] {problem}")
        mode = "evidential" if results is not None else "structural"
        print(
            f"[{'FAIL' if problems else 'OK'}] {len(report)} Kani citations checked ({mode} mode)"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
