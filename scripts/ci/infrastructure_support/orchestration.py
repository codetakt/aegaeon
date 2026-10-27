"""Validate repository OpenTofu modules without cloud credentials or deployment.

This checks static provider compatibility and explicit configuration contracts.
It does not read deployed state, plan changes, or establish deployment safety."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from infrastructure_support.commands import Commands, isolated_environment
from infrastructure_support.common import (
    RUNNER_PATH,
    VALIDATOR_SUPPORT_PATHS,
    digest,
    require,
    validator_sources,
)
from infrastructure_support.provider import initialize_providers, resource_contract, validate_schema
from infrastructure_support.rendering import check_support, check_templates
from infrastructure_support.runtime import runtime_contract_report
from infrastructure_support.selection import module_inputs, select_modules


def copy_module_inputs(module: Path, copy: Path) -> None:
    for source in module_inputs(module):
        target = copy / source.relative_to(module)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def validate_module(
    module: Path, root: Path, output: Path, tools: dict[str, str]
) -> dict[str, Any]:
    output.mkdir()
    inputs = {str(p.relative_to(root)): digest(p) for p in module_inputs(module)}
    report: dict[str, Any] = {
        "module": str(module.relative_to(root)),
        "inputs": inputs,
        "status": "failed",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="aegaeon-infra-") as temporary:
            work = Path(temporary)
            copy = work / module.name
            copy.mkdir()
            copy_module_inputs(module, copy)
            commands = Commands(output, isolated_environment(work))
            report["commands"] = commands.records
            report["tools"] = json.loads(commands.run([tools["tofu"], "version", "-json"], copy))
            commands.run([tools["tofu"], "fmt", "-check", "-diff"], copy)
            report.update(initialize_providers(copy, module, commands, tools["tofu"], work))
            report["validation"] = validate_schema(commands, tools["tofu"], copy)
            report["runtime_contract"] = runtime_contract_report(copy, root)
            resource_contract(copy, report["providers"])
            report["rendered_template_cases"] = check_templates(
                copy, commands, tools["tofu"], tools["bash"], work
            )
            report["support_scripts"] = check_support(module, root, commands, tools["bash"])
            require(
                digest(copy / ".terraform.lock.hcl") == digest(module / ".terraform.lock.hcl"),
                "OpenTofu rewrote readonly lock",
            )
            checked_sources = {
                **inputs,
                **report["runtime_contract"]["runtime_sources"],
                **report["support_scripts"],
            }
            require(
                all(digest(root / path) == value for path, value in checked_sources.items()),
                "Repository inputs changed during validation",
            )
            require(
                report["runtime_contract"]["status"] == "passed",
                "Runtime environment contract failed; see process/name/reason diagnostics",
            )
            report["status"] = "passed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def toolchain_provenance(root: Path, output: Path, tools: dict[str, str]) -> dict[str, Any]:
    inputs = [
        root / "flake.nix",
        root / "flake.lock",
        root / "pyproject.toml",
        root / ".github/workflows/infrastructure-validation.yml",
    ]
    inputs.extend(root / path for path in VALIDATOR_SUPPORT_PATHS)
    inputs.append(root / "scripts/ci/validate_infrastructure.py")
    for path in inputs:
        require(path.is_file() and not path.is_symlink(), f"Missing toolchain input: {path}")
    inputs.extend(sorted((root / "nix").rglob("*.nix")))
    inputs.extend(sorted((root / ".github/actions/setup-nix-ci").rglob("*")))
    source_hashes = {str(p.relative_to(root)): digest(p) for p in inputs if p.is_file()}
    source_hashes.update(validator_sources(root))
    executables = {**tools, "python": sys.executable}
    stores = set()
    for executable in executables.values():
        path = Path(executable).resolve()
        require(path.parts[1:3] == ("nix", "store"), f"Tool is not Nix-pinned: {path}")
        stores.add(str(Path(*path.parts[:4])))
    commands = Commands(output, dict(os.environ))
    closure = json.loads(
        commands.run([tools["nix"], "path-info", "--json", "--recursive", *sorted(stores)], root)
    )
    return {
        "toolchain_sources": source_hashes,
        "executable_paths": executables,
        "nix_closure": closure,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=RUNNER_PATH.resolve().parents[2])
    parser.add_argument(
        "--paths-json",
        type=Path,
        help="JSON array of changed infra/tofu paths; omitted means all modules",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/infrastructure-validation"))
    args = parser.parse_args()
    summary: dict[str, Any] = {
        "status": "failed",
        "scope": "Static infrastructure validation; no deployed state or live AWS assurance",
    }
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        paths = None if args.paths_json is None else json.loads(args.paths_json.read_text())
        require(
            paths is None or (isinstance(paths, list) and all(isinstance(p, str) for p in paths)),
            "Paths must be a JSON string array",
        )
        modules = select_modules(args.root.resolve(), paths)
        tools = {name: shutil.which(name) for name in ("tofu", "bash", "nix")}
        require(all(tools.values()), "Required tools unavailable: tofu, bash and nix")
        resolved = {name: str(path) for name, path in tools.items()}
        summary["tool_hashes"] = {
            name: digest(Path(path).resolve()) for name, path in resolved.items()
        }
        summary["runner_sha256"] = digest(RUNNER_PATH)
        summary["provenance"] = toolchain_provenance(args.root.resolve(), args.output, resolved)
        summary["modules"] = [
            validate_module(module, args.root.resolve(), args.output / module.name, resolved)
            for module in modules
        ]
        require(
            all(item["status"] == "passed" for item in summary["modules"]),
            "Infrastructure validation failed; see module diagnostics",
        )
        require(
            all(
                digest(args.root / path) == value
                for path, value in summary["provenance"]["toolchain_sources"].items()
            ),
            "Toolchain inputs changed during validation",
        )
        summary["status"] = "passed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        summary["error"] = str(error)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Infrastructure validation: {summary['status']}; evidence: {args.output}")
    return 0 if summary["status"] == "passed" else 1
