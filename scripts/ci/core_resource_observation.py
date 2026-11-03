"""One fixed resource observation; this does not replace any ordinary CI gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import sample_runner_resources

sys.dont_write_bytecode = True

STORE = "/nix/store/"
DRV = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")


def output(command: list[str]) -> str:
    return subprocess.check_output(command, text=True).strip()


def normalize(value: dict[str, Any]) -> dict[str, Any]:
    """Support the pinned host Nix and version 4 local derivation JSON."""
    if "derivations" in value:
        if value.get("version") != 4:
            raise ValueError("unsupported derivation schema")
        result = {}
        for name, row in value["derivations"].items():
            direct = {}
            for dep, selection in row["inputs"]["drvs"].items():
                if selection.get("dynamicOutputs"):
                    raise ValueError("dynamic derivation outside observation")
                direct[STORE + dep] = selection["outputs"]
            result[STORE + name] = {
                "inputDrvs": direct,
                "outputs": {k: {"path": STORE + v["path"]} for k, v in row["outputs"].items()},
            }
        return result
    return value


def select_dependencies(roots: list[str], graph: dict[str, Any]) -> list[str]:
    selected: dict[str, set[str]] = {}
    for root in roots:
        if not DRV.fullmatch(root) or root not in graph:
            raise ValueError("missing or invalid target derivation")
        for dep, names in graph[root]["inputDrvs"].items():
            if not DRV.fullmatch(dep) or dep in roots:
                raise ValueError("target outputs cannot be warmed as dependencies")
            if not names or any(not re.fullmatch(r"[a-zA-Z0-9_-]+", n) for n in names):
                raise ValueError("invalid output selection")
            selected.setdefault(dep, set()).update(names)
    return [drv + "^" + ",".join(sorted(names)) for drv, names in sorted(selected.items())]


def require_missing(roots: list[str], graph: dict[str, Any]) -> list[str]:
    outputs = [item["path"] for root in roots for item in graph[root]["outputs"].values()]
    for path in outputs:
        result = subprocess.run(
            ["nix-store", "--check-validity", path], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 or Path(path).exists():
            raise ValueError("ineligible warm target output: " + path)
        if result.returncode != 1 or "is not valid" not in result.stderr:
            raise ValueError("could not establish missing target output: " + path)
    return outputs


def configuration_report(
    manifest: dict[str, Any], roots: list[str], before: list[str], deps: list[str]
) -> dict[str, Any]:
    config = json.loads(output(["nix", "config", "show", "--json"]))
    return {
        "purpose": manifest["purpose"],
        "source": manifest["source"],
        "roots": roots,
        "target_outputs": before,
        "dependency_installables": deps,
        "cpu_count": os.cpu_count(),
        "nix": output(["nix", "--version"]),
        "builders": local_builders(config.get("builders", {}).get("value")),
        "nix_config": {
            k: config.get(k, {}).get("value")
            for k in ("max-jobs", "cores", "sandbox", "max-silent-time", "timeout")
        },
    }


def local_builders(value: object, machines: Path = Path("/etc/nix/machines")) -> dict[str, Any]:
    """Expand only Nix's default machines-file reference; never emit contents."""
    if value in ("", []):
        return {"local_only": True, "kind": "empty"}
    if value != "@/etc/nix/machines":
        return {"local_only": False, "kind": "unsupported_configuration"}
    try:
        with machines.open("rb") as stream:
            content = stream.read(65537)
    except FileNotFoundError:
        # Nix's expandBuilderLines explicitly skips ENOENT machines files.
        return {"local_only": True, "kind": "default_file_absent"}
    except OSError:
        return {"local_only": False, "kind": "default_file_unreadable"}
    if len(content) > 65536:
        return {"local_only": False, "kind": "default_file_oversized"}
    entries = [
        entry.strip()
        for line in content.decode().splitlines()
        for entry in line.split("#", 1)[0].split(";")
        if entry.strip()
    ]
    return {
        "local_only": not entries,
        "kind": "default_file",
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "entry_count": len(entries),
    }


def verify_candidate(manifest: dict[str, Any]) -> None:
    if output(["git", "rev-parse", "HEAD"]) != manifest["source"]:
        raise ValueError("candidate source changed")
    if output(["git", "rev-parse", "HEAD^{tree}"]) != manifest["source_tree"]:
        raise ValueError("candidate tree changed")
    if output(["git", "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("candidate checkout is dirty")
    spec = importlib.util.spec_from_file_location("core", "scripts/ci/run_core_pr_checks.py")
    if spec is None or spec.loader is None:
        raise ValueError("candidate check evaluator unavailable")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    actual = core.evaluate(
        ".#checks.x86_64-linux", "checks: builtins.mapAttrs (_: check: check.drvPath) checks"
    )
    if actual != manifest["checks"]:
        raise ValueError("check inventory changed")


def main() -> int:
    directory = Path(__file__).resolve().parent
    manifest = json.loads((directory / "core_resource_observation.json").read_text())
    evidence = Path(os.environ["DIAGNOSTIC_EVIDENCE"])
    evidence.mkdir(parents=True, exist_ok=True)
    observation = sample_runner_resources.sample(Path("/proc"))
    (evidence / "initial-resources.json").write_text(json.dumps(observation) + "\n")
    if not all("value" in observation[k] for k in ("meminfo_kib", "vmstat", "processes")):
        raise ValueError("required numeric resource observation unavailable")
    verify_candidate(manifest)
    roots = manifest["roots"]
    graph = normalize(json.loads(output(["nix", "derivation", "show", *roots])))
    deps = select_dependencies(roots, graph)
    before = require_missing(roots, graph)
    report = configuration_report(manifest, roots, before, deps)
    (evidence / "preflight.json").write_text(json.dumps(report, indent=2) + "\n")
    print("AEGAEON_PREFLIGHT " + json.dumps(report), flush=True)
    if not report["builders"]["local_only"]:
        raise ValueError("remote or unestablished builders outside the observation")
    # Only dependencies may be substituted. A cache miss refuses this diagnostic
    # instead of adding uncontrolled source builds to the observation.
    subprocess.run(
        [
            "timeout",
            "--kill-after=20s",
            "600s",
            "nix",
            "build",
            "--no-link",
            "--max-jobs",
            "0",
            *deps,
        ],
        check=True,
    )
    require_missing(roots, graph)
    print("AEGAEON_COLD_OUTPUTS_CONFIRMED", flush=True)
    # Recipes and ordinary concurrency are unchanged. The target output cache
    # alone is bypassed, after all selected inputs were realized successfully.
    command = [
        "timeout",
        "--signal=TERM",
        "--kill-after=20s",
        str(manifest["max_build_seconds"]) + "s",
        "nix",
        "build",
        "--no-link",
        "--print-build-logs",
        "--option",
        "substitute",
        "false",
    ]
    result = subprocess.run(command + [d + "^*" for d in roots], check=False)
    (evidence / "result.json").write_text(
        json.dumps(
            {"returncode": result.returncode, "scope": manifest["purpose"], "full_ci": False},
            indent=2,
        )
        + "\n"
    )
    return result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print("Diagnostic refused or failed: " + str(error), file=sys.stderr)
        sys.exit(1)
