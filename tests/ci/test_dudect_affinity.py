# ruff: noqa: S603 - explicit Python/native fixture argv without a shell
"""CPU topology, restoration and actual child exec boundary regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_affinity import collector_placement, cpu_list, placement, validate_placement

ROOT = Path(__file__).resolve().parents[2]


def topology(root, groups):
    for cpu, siblings in groups.items():
        path = root / f"cpu{cpu}/topology/thread_siblings_list"
        path.parent.mkdir(parents=True)
        path.write_text(siblings)
    return root


def test_sparse_cpuset_excludes_all_native_siblings(tmp_path):
    plan = placement({2, 7, 19}, topology(tmp_path, {19: "7,19"}))
    assert plan["native"] == [19]
    assert plan["collector"] == [2]
    assert plan["native_siblings"] == [7, 19]
    assert plan["original"] == [2, 7, 19]


@pytest.mark.parametrize("value", ["", "4-2", "1-2-3", "0-4096", "-1", "a"])
def test_bad_topology_is_rejected(value):
    with pytest.raises(ValueError, match=r"CPU topology|invalid literal"):
        cpu_list(value)


def test_one_core_and_missing_topology_cannot_silently_use_shared_cpu(tmp_path):
    tree = topology(tmp_path, {2: "2,7", 7: "2,7"})
    with pytest.raises(ValueError, match="two allowed cores"):
        placement({2, 7}, tree)
    with pytest.raises(FileNotFoundError):
        placement({2, 8}, tree)


def test_collector_affinity_restored_after_failure():
    original = os.sched_getaffinity(0)
    plan = placement(original)
    with pytest.raises(RuntimeError, match="injected"), collector_placement() as selected:  # noqa: PT012 - inspect the failing scope
        assert selected == plan
        assert os.sched_getaffinity(0) == set(plan["collector"])
        raise RuntimeError("injected")  # noqa: EM101 - explicit failure fixture
    assert os.sched_getaffinity(0) == original


def test_denied_collector_placement_attempts_restoration():
    with (
        patch(
            "dudect_affinity.os.sched_setaffinity", side_effect=[PermissionError, None]
        ) as set_cpu,
        pytest.raises(PermissionError),
        collector_placement(),
    ):
        pytest.fail("placement should not yield")
    assert set_cpu.call_count == 2
    assert set_cpu.call_args.args == (0, os.sched_getaffinity(0))


def test_launcher_sets_native_cpu_before_exec_and_preserves_evidence_fd(tmp_path):
    original = os.sched_getaffinity(0)
    receipt = tmp_path / "affinity.json"
    with collector_placement() as plan, (tmp_path / "native.data").open("wb") as output:
        native = (
            "import os,json; "
            f"os.write({output.fileno()}, b'original evidence'); "
            "print(json.dumps({'pid':os.getpid(),'native':sorted(os.sched_getaffinity(0))}))"
        )
        command = [sys.executable, "-c", native]
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests/constant_time/dudect_affinity.py"),
                str(plan["native"][0]),
                str(receipt),
                *command,
            ],
            pass_fds=(output.fileno(),),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        actual = json.loads(result.stdout)
        assert actual["native"] == plan["native"]
        assert not set(actual["native"]) & os.sched_getaffinity(0)
        assert json.loads(receipt.read_text()) == {**actual, "argv": command}
    assert os.sched_getaffinity(0) == original
    assert (tmp_path / "native.data").read_bytes() == b"original evidence"


def test_replay_rejects_missing_or_overlapping_observed_placement(tmp_path):
    plan = placement({2, 7, 19}, topology(tmp_path, {19: "7,19"}))
    process = {"cpu_placement": plan, "argv": ["bound", "pr"]}
    receipt = {"native": [19], "argv": ["bound", "pr"]}
    rows = [{"phase": "observation", "native_affinity": [19], "collector_affinity": [2]}]
    validate_placement(process, receipt, rows)
    with pytest.raises(ValueError, match="Missing observed"):
        validate_placement(process, receipt, [])
    rows[0]["collector_affinity"] = [7]
    with pytest.raises(ValueError, match="collector affinity"):
        validate_placement(process, receipt, rows)
