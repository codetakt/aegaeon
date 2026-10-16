"""Fixed research schedule, artifact checks and process ownership helpers."""
# ruff: noqa: E402 -- repository helper import

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from verify_dudect_analysis_matrix import require, sha256

PROCESS_SECONDS = 2100
MAXIMUM_SECONDS = 9000
GAP_SECONDS = 10


def schedule(compiler: str) -> list[str]:
    require(compiler in {"gcc", "clang"}, "Unknown compiler")
    middle = ["O", "S", "P", "U"] if compiler == "gcc" else ["U", "P", "S", "O"]
    signals = ["signal0", "signal16"] if compiler == "gcc" else ["signal16", "signal0"]
    return ["nix-controls", *middle, "legacy-controls", *signals]


def package_unit(package: Path, executable: str) -> dict[str, Any]:
    index = json.loads((package / "package.json").read_text())
    entry = next(e for e in index["executables"] if e["name"] == executable)
    return {
        "source": str(package / "sources"),
        "sources": index["sources"],
        "binary": str(package / entry["relative_binary"]),
        "binary_sha256": entry["sha256"],
        "suite": index["suite"],
        "bindings": {
            name: {
                "case_id": f"{index['suite']}/{name}",
                "profile": "pr",
                "contract_sha256": index["contract_sha256"],
                "build_sha256": entry["build_sha256"],
                "numerical_sha256": index["numerical_sha256"],
            }
            for name in entry["cases"]
        },
        "environment": {},
        "signal": 0,
        "maximum_seconds": PROCESS_SECONDS,
    }


def overlay_unit(
    build: dict[str, Any], names: list[str], mode: str, dose: int = 0
) -> dict[str, Any]:
    require(mode in {"baseline", "class0", "uniform"} and dose in {0, 16}, "Unknown intervention")
    environment = {"AEGAEON_DUDECT_PREPARATION": mode}
    if build["variant"] == "signal":
        environment["AEGAEON_DUDECT_PREPARATION_SIGNAL"] = str(dose)
    return {
        "source": build["source"],
        "sources": build["sources"],
        "binary": build["binary"],
        "binary_sha256": build["binary_sha256"],
        "suite": "nix",
        "bindings": {
            name: {
                "case_id": f"nix/{name}",
                "profile": "pr",
                "contract_sha256": build["contract_sha256"],
                "build_sha256": build["build_sha256"],
                "numerical_sha256": build["numerical_sha256"],
            }
            for name in names
        },
        "environment": environment,
        "signal": dose,
        "maximum_seconds": PROCESS_SECONDS,
    }


def check_unit(unit: dict[str, Any]) -> None:
    require(sha256(Path(unit["binary"])) == unit["binary_sha256"], "Binary changed")
    source = Path(unit["source"])
    for name, digest in unit["sources"].items():
        require(sha256(source / name) == digest, "Source changed")
    require(unit["maximum_seconds"] == PROCESS_SECONDS, "Unreviewed process budget")


def wait_owned(child: subprocess.Popen[bytes], seconds: float) -> int:
    """Collector handles TERM and cleans its separate native process group."""
    try:
        return child.wait(timeout=seconds)
    except BaseException:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        raise
