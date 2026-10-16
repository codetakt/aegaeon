"""Hosted diagnostic placement; explicitly weaker than the isolated AMD profile."""

from __future__ import annotations

import datetime
import os
import platform
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/constant_time"))
from dudect_affinity import placement as placement  # noqa: PLC0414 -- explicit mypy re-export
from verify_dudect_analysis_matrix import require

PROFILE = "dudect-github-hosted-separated-cores/diagnostic-1"
RUNNER_FIELDS = (
    "GITHUB_ACTIONS",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "ImageOS",
    "ImageVersion",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_SHA",
)
EXECUTION = {
    "schema": "dudect-fresh-matrix/research-1",
    "environment": PROFILE,
    "maximum_seconds": 9000,
    "gap_seconds": 10,
    "replacement_trials": 0,
}
ORDER = [(c, s) for c in ("gcc", "clang") for s in ("legacy", "nix")]
SOURCES = [
    "scripts/ci/run_dudect_analysis_matrix.py",
    "scripts/ci/verify_dudect_analysis_matrix.py",
    "scripts/ci/dudect_analysis_environment.py",
    "scripts/ci/dudect_hosted_environment.py",
    "scripts/ci/prepare_dudect_hosted.py",
    "scripts/ci/retain_dudect_hosted.py",
    "scripts/ci/dudect_hosted_campaign.py",
    "scripts/ci/dudect-hosted-reliability.json",
    "tests/constant_time/dudect_affinity.py",
    "tests/constant_time/dudect_results.py",
    "tests/constant_time/dudect_support.py",
    ".github/workflows/dudect-hosted-screen.yml",
    ".github/workflows/dudect-hosted-reliability.yml",
    ".github/actions/setup-nix-ci/action.yml",
    ".github/actions/setup-nix-ci/prepare-disk.sh",
]


def observed(path: Path) -> str | dict[str, str]:
    try:
        return path.read_text().strip()
    except OSError as error:
        return {"unavailable": type(error).__name__}


def quota(root: Path = Path("/sys/fs/cgroup"), membership: str | None = None) -> dict[str, Any]:
    """Inspect every v2 ancestor, never treat an unreadable controller as unlimited."""
    membership = membership if membership is not None else Path("/proc/self/cgroup").read_text()
    groups = [line[3:] for line in membership.splitlines() if line.startswith("0::")]
    require(len(groups) == 1, "A readable unified CPU cgroup hierarchy is required")
    require(
        not any(
            "cpu" in line.split(":")[1].split(",")
            for line in membership.splitlines()
            if not line.startswith("0::")
        ),
        "CPU controller is outside the observed unified hierarchy",
    )
    group = groups[0]
    require(group.startswith("/") and ".." not in Path(group).parts, "Unknown cgroup namespace")
    directory = root / group.lstrip("/")
    values: dict[str, Any] = {}
    controllers = {}
    for ancestor in (directory, *directory.parents):
        if ancestor == root.parent:
            break
        file = ancestor / "cpu.max"
        parent_control = observed(ancestor.parent / "cgroup.subtree_control")
        controllers[str(ancestor)] = {
            "available": observed(ancestor / "cgroup.controllers"),
            "subtree": observed(ancestor / "cgroup.subtree_control"),
            "cpuset": observed(ancestor / "cpuset.cpus.effective"),
        }
        if not file.exists() and ancestor == root:
            values[str(file)] = "root_unlimited"
        elif (
            not file.exists()
            and isinstance(parent_control, str)
            and "cpu" not in parent_control.split()
        ):
            # Disabled child controllers have no interface; ancestor limits still apply.
            values[str(file)] = "controller_disabled_by_parent"
        else:
            values[str(file)] = observed(file)
    return {
        "membership": membership,
        "limits": values,
        "controllers": controllers,
        "stat": observed(directory / "cpu.stat"),
    }


def runner() -> dict[str, str]:
    # Never dump the process environment: it contains CI credentials.
    return {key: os.environ.get(key, "") for key in RUNNER_FIELDS}


def check_runner(value: dict[str, str]) -> None:
    require(value["GITHUB_ACTIONS"] == "true", "Not a GitHub Actions execution")
    require(value["RUNNER_ENVIRONMENT"] == "github-hosted", "Expected GitHub-hosted runner")
    require(value["RUNNER_OS"] == "Linux" and value["RUNNER_ARCH"] == "X64", "Wrong runner OS/arch")
    require(all(value[key] for key in RUNNER_FIELDS), "Incomplete runner/image identity")
    require(value["GITHUB_RUN_ATTEMPT"] == "1", "Replacement workflow attempts are not allowed")


def freeze() -> dict[str, Any]:
    identity = runner()
    check_runner(identity)
    selected = placement(os.sched_getaffinity(0))
    return {"runner": identity, "placement": selected}


def snapshot(config: dict[str, Any]) -> dict[str, Any]:
    selected = config["placement"]
    actual = placement(set(selected["original"]))
    value: dict[str, Any] = {
        "profile": PROFILE,
        "checked_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "runner": runner(),
        "placement": actual,
        "supervisor_affinity": sorted(os.sched_getaffinity(0)),
        "scheduler": os.sched_getscheduler(0),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpuinfo": Path("/proc/cpuinfo").read_text(),
        "cmdline": Path("/proc/cmdline").read_text().strip(),
        "cpu": {
            name: observed(Path("/sys/devices/system/cpu") / name)
            for name in ("online", "isolated", "nohz_full", "smt/active")
        },
        "cgroup": quota(),
        "events": {
            name: observed(Path("/proc") / name) for name in ("stat", "interrupts", "softirqs")
        },
        "irq_affinity": {
            str(p): observed(p) for p in Path("/proc/irq").glob("*/smp_affinity_list")
        },
        "competing_user_threads": [],
        "unreadable_processes": [],
        "competition_exclusion_established": False,
        "unobservable": [
            "physical core exclusivity",
            "hypervisor pauses",
            "firmware activity",
            "per-sample event association",
            "unobserved transient guest workloads",
        ],
        "interpretation": "Diagnostic only. Events do not filter samples or clear failures.",
    }
    siblings = set(actual["native_siblings"])
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            executable = str((process / "exe").readlink())
            for thread in (process / "task").iterdir():
                mask = sorted(os.sched_getaffinity(int(thread.name)))
                if siblings.intersection(mask):
                    value["competing_user_threads"].append(
                        {
                            "pid": int(process.name),
                            "tid": int(thread.name),
                            "exe": executable,
                            "affinity": mask,
                        }
                    )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            value["unreadable_processes"].append(int(process.name))
    return value


def check(value: dict[str, Any], config: dict[str, Any]) -> None:
    check_runner(value["runner"])
    require(value["runner"] == config["runner"], "Runner allocation/image changed")
    require(value["profile"] == PROFILE and value["machine"] == "x86_64", "Wrong hosted profile")
    require(value["placement"] == config["placement"], "Exposed CPU topology changed")
    require(value["supervisor_affinity"] == config["placement"]["collector"], "Supervisor moved")
    require(value["scheduler"] == os.SCHED_OTHER, "Unexpected scheduler policy")
    limits = value["cgroup"]["limits"]
    require(
        bool(limits)
        and all(
            isinstance(v, str)
            and (v in {"root_unlimited", "controller_disabled_by_parent"} or v.startswith("max "))
            for v in limits.values()
        ),
        "CPU quota active or unknown",
    )
    require(value["competition_exclusion_established"] is False, "Unproved environment claim")


def environment(path: Path, config: dict[str, Any]) -> None:
    from verify_dudect_analysis_matrix import write_json  # noqa: PLC0415

    value = snapshot(config)
    write_json(path, value)
    check(value, config)
