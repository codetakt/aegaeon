# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Verify every planned artifact before any native timing process is started."""

import json  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
import os
from pathlib import Path

from analysis_contract import SOURCE
from dudect_candidate import canonical, digest
from dudect_package import checked_package
from dudect_support import require
from live_runtime import identity
import run_candidate
import run_live


def verify_plan(plan, runtime_manifest):
    inventory = {row["path"] for row in runtime_manifest}
    require(len(inventory) == len(runtime_manifest), "Duplicate runtime path")
    checked = []
    for inv in plan["processes"]:
        require(
            inv["analysis"] == identity(inv["packet"], inv["unit"], inv["profile"]),
            "Wrong planned consumer identity",
        )
        if inv["kind"] == "diagnostic":
            root = Path(inv["artifact"])
            artifact, manifest = run_live.artifact_check(root)
            compare = manifest["schema"] == "legacy-compare-sensitivity-native/1"
            require(inv["suite"] == ("legacy" if compare else "nix"), "Diagnostic suite mismatch")
            require(artifact["kind"] == "physical_diagnostic", "Wrong diagnostic clock")
            require(
                inv["case_order"] == (["compare"] if compare else list(run_live.PROVIDER)),
                "Wrong diagnostic order",
            )
            binary = root / "native"
            libraries = artifact["dynamic_libraries"]
            require(
                set(libraries) <= inventory, "Declared diagnostic dependency absent from export"
            )
        else:
            require(
                inv["kind"] == "ordinary" and inv["profile"] == "ordinary",
                "Unknown planned process kind",
            )
            root = Path(inv["package"])
            require(inv["suite"] in ("nix", "legacy"), "Unknown native suite")
            package = checked_package(root, run_candidate.current_sources(SOURCE), inv["suite"])
            require(digest(canonical(package)) == inv["package_sha256"], "Wrong package identity")
            found = [e for e in package["executables"] if e["name"] == inv["executable"]]
            require(
                len(found) == 1 and found[0]["cases"] == inv["case_order"], "Wrong ordinary order"
            )
            binary = root / found[0]["relative_binary"]
            require(str(binary) in inventory, "Ordinary binary absent from export")
        require(binary.is_file() and os.access(binary, os.X_OK), "Native ELF is not executable")
        require(run_live.sha(binary) == inv["binary_sha256"], "Wrong planned ELF")
        checked.append(
            {
                "unit": inv["unit"],
                "binary_sha256": inv["binary_sha256"],
                "kind": inv["kind"],
                "case_order": inv["case_order"],
            }
        )
    require(bool(checked), "Empty physical plan")
    return {
        "all_planned_artifacts_checked": True,
        "processes": len(checked),
        "distinct_binaries": len({r["binary_sha256"] for r in checked}),
        "timing_executed": False,
        "checks": checked,
    }
