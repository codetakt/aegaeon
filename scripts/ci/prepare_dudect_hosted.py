"""Build and freeze a single hosted opportunity before any timing acquisition."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import dudect_hosted_environment as hosted
from verify_dudect_analysis_matrix import (
    PLAN_SCHEMA,
    check_analysis,
    check_matrix,
    pinned_inputs,
    require,
    sha256,
    write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def build(attribute: str, output: Path, source: str) -> Path:
    with (output / f"{attribute}.log").open("xb") as log:
        result = subprocess.run(
            ["nix", "build", f"{source}#{attribute}", "--no-link", "--print-out-paths", "-L"],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
            check=True,
        )
    paths = result.stdout.splitlines()
    require(len(paths) == 1, "Expected a single package output")
    return Path(paths[0])


def identity(python: Path, analysis: Path, packet: str, unit: str) -> dict[str, Any]:
    program = (
        "import json,sys; sys.path.insert(0,sys.argv[1]); "
        "from analysis_contract import identity; "
        "print(json.dumps(identity('distributed',sys.argv[2],sys.argv[3])))"
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH"}
    }
    result = subprocess.check_output(
        [str(python), "-B", "-c", program, str(analysis / "libexec/dudect-analysis"), packet, unit],
        env=env,
        text=True,
        timeout=60,
    )
    return dict(json.loads(result))


def prepare(output: Path) -> dict[str, Any]:
    config = hosted.freeze()
    write_json(output / "allocation-before-build.json", config)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(head == config["runner"]["GITHUB_SHA"], "Checkout differs from workflow commit")
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL
    )
    source = "git+" + ROOT.as_uri() + "?rev=" + head
    analysis = build("dudect-analysis", output, source)
    natives = {
        f"{c}-{s}": build(f"dudect-analysis-native-{c}-{s}", output, source)
        for c, s in hosted.ORDER
    }
    python_root = subprocess.check_output(
        ["nix", "eval", "--raw", f"{source}#dudect-analysis.python"],
        text=True,
    ).strip()
    python = Path(python_root) / "bin/python"
    # Record exact interpreter and closure information before acquiring observations.
    closure = subprocess.check_output(
        ["nix", "path-info", "--recursive", "--json", str(analysis), *map(str, natives.values())],
        text=True,
    )
    (output / "closure.json").write_text(closure)
    for name, path in {"analysis": analysis, **natives}.items():
        shutil.copytree(path, output / "packages" / name)
    packet = f"hosted-{config['runner']['GITHUB_RUN_ID']}"
    contract = (
        analysis
        / "libexec/dudect-analysis/source/tests/constant_time/contracts"
        / "case-contract-candidate.json"
    )
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "adopted": False,
        "cycles": ["r1"],
        "packet": packet,
        "mode": "distributed",
        "source_revision": head,
        "execution": hosted.EXECUTION,
        "hosted": config,
        "analysis_package": {
            "path": str(analysis),
            "executable_sha256": sha256(analysis / "bin/dudect-analysis"),
        },
        "case_contract_sha256": sha256(contract),
        "native_packages": {
            key: {"path": str(path), "index_sha256": sha256(path / "package.json")}
            for key, path in natives.items()
        },
        "units": [],
        "orchestration": {name: sha256(ROOT / name) for name in hosted.SOURCES},
    }
    for compiler, suite in hosted.ORDER:
        unit = f"r1-{compiler}-{suite}"
        plan["units"].append(
            {
                "id": unit,
                "cycle": "r1",
                "compiler": compiler,
                "suite": suite,
                "analysis": identity(python, analysis, packet, unit),
            }
        )
    check_matrix(plan)
    check_analysis(plan)
    pinned_inputs(plan)
    require(hosted.freeze() == config, "Allocation changed while building")
    require(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == head,
        "Checkout revision changed while building",
    )
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL
    )
    write_json(output / "plan.json", plan)
    (output / "plan.sha256").write_text(sha256(output / "plan.json") + "\n")
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        prepare(args.output)
    except BaseException as error:
        write_json(
            args.output / "preparation-failure.json", {"error": str(error), "ci_admission": False}
        )
        raise


if __name__ == "__main__":
    main()
