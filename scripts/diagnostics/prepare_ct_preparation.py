"""Freeze an AMD hosted input-preparation comparison before timing starts."""
# ruff: noqa: S603, S607 -- fixed Nix/git commands and digest-checked binaries

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from build_ct_preparation import PROVIDER, build as overlay
from ct_preparation_plan import ROOT, overlay_unit, package_unit, schedule

sys.path.insert(0, str(ROOT / "scripts/ci"))
import dudect_hosted_environment as hosted
from prepare_dudect_hosted import build
from verify_dudect_analysis_matrix import require, sha256, write_json


def selftests(binary: str, output: Path) -> None:
    for mode in ("baseline", "class0", "uniform", "unknown"):
        result = subprocess.run(
            [binary],
            env={**os.environ, "AEGAEON_DUDECT_PREPARATION": mode},
            capture_output=True,
            timeout=60,
            check=False,
        )
        (output / (mode + ".stdout")).write_bytes(result.stdout)
        (output / (mode + ".stderr")).write_bytes(result.stderr)
        if mode == "unknown":
            require(result.returncode != 0, "Unknown mode was accepted")
        else:
            require(result.returncode == 0, "Input compatibility self-test failed")
            require(
                json.loads(result.stdout)
                == {"cases": 7, "callbacks": 63, "timing_executed": False},
                "Incomplete input compatibility self-test",
            )


def prepare(output: Path, compiler: str) -> dict[str, Any]:  # noqa: PLR0915 -- freeze transaction
    config = hosted.freeze()
    write_json(output / "allocation.json", config)
    cpuinfo = Path("/proc/cpuinfo").read_text()
    (output / "cpuinfo").write_text(cpuinfo)
    require("AuthenticAMD" in cpuinfo, "Allocated CPU is outside this AMD experiment")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(head == config["runner"]["GITHUB_SHA"], "Wrong checkout")
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=ROOT, check=True)
    source = "git+" + ROOT.as_uri() + "?rev=" + head + "&shallow=1"
    baseline = json.loads((ROOT / "scripts/ci/dudect-hosted-reliability.json").read_text())[
        "packages"
    ]
    packages = {}
    for suite in ("nix", "legacy"):
        path = build(f"dudect-analysis-native-{compiler}-{suite}", output, source)
        expected = baseline["native_packages"][f"{compiler}-{suite}"]
        require(
            str(path) == expected["path"]
            and sha256(path / "package.json") == expected["index_sha256"],
            "Original native package changed",
        )
        packages[suite] = path
        shutil.copytree(path, output / "packages" / suite)
    analysis = build("dudect-analysis", output, source)
    require(str(analysis) == baseline["analysis_package"]["path"], "Analysis package changed")
    shutil.copytree(analysis, output / "packages/analysis")
    python = (
        Path(
            subprocess.check_output(
                ["nix", "eval", "--raw", f"{source}#dudect-analysis.python"], text=True
            ).strip()
        )
        / "bin/python"
    )
    builds = {
        variant: overlay(packages["nix"], output / "builds" / variant, variant)
        for variant in ("normal", "selftest", "signal")
    }
    selftests(builds["selftest"]["binary"], output / "builds/selftest")
    # Disassembly is retained for actual instruction and call-site review.
    for variant in ("normal", "signal"):
        with (output / "builds" / variant / "disassembly.txt").open("wb") as dest:
            subprocess.run(["objdump", "-d", builds[variant]["binary"]], stdout=dest, check=True)
    units = {
        "O": package_unit(packages["nix"], "dudect_harness"),
        "nix-controls": package_unit(packages["nix"], "dudect_controls"),
        "legacy-controls": package_unit(packages["legacy"], "dudect_controls"),
    }
    for arm, mode in (("S", "baseline"), ("P", "class0"), ("U", "uniform")):
        units[arm] = overlay_unit(builds["normal"], PROVIDER, mode)
    for dose in (0, 16):
        units[f"signal{dose}"] = overlay_unit(builds["signal"], PROVIDER[:3], "uniform", dose)
    sources = [
        *sorted((ROOT / "scripts/diagnostics").glob("*.*")),
        *[
            ROOT / "scripts/ci" / p
            for p in (
                "dudect_hosted_environment.py",
                "verify_dudect_analysis_matrix.py",
                "prepare_dudect_hosted.py",
                "retain_dudect_hosted.py",
                "dudect_analysis_environment.py",
            )
        ],
    ]
    plan = {
        "schema": "dudect-ct-preparation/1",
        "ci_admission": False,
        "compiler": compiler,
        "head": head,
        "hosted": config,
        "python": str(python),
        "python_sha256": sha256(python),
        "order": schedule(compiler),
        "units": units,
        "orchestration": {str(p.relative_to(ROOT)): sha256(p) for p in sources},
        "maximum_seconds": 9000,
        "gap_seconds": 10,
        "replacement_trials": 0,
    }
    require(hosted.freeze() == config, "Allocation changed during preparation")
    write_json(output / "plan.json", plan)
    (output / "plan.sha256").write_text(sha256(output / "plan.json") + "\n")
    (output / "closure.json").write_text(
        subprocess.check_output(
            [
                "nix",
                "path-info",
                "--recursive",
                "--json",
                str(analysis),
                *map(str, packages.values()),
            ],
            text=True,
        )
    )
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", choices=("gcc", "clang"), required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        prepare(output, args.compiler)
    except BaseException as error:
        write_json(
            output / "preparation-failure.json", {"error": str(error), "ci_admission": False}
        )
        raise


if __name__ == "__main__":
    main()
