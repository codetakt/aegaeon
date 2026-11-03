from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
spec = importlib.util.spec_from_file_location(
    "diagnostic", Path(__file__).resolve().parents[2] / "scripts/ci/core_resource_observation.py"
)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
A = "/nix/store/" + "a" * 32 + "-a.drv"
B = "/nix/store/" + "b" * 32 + "-b.drv"


class SelectionTests(unittest.TestCase):
    def test_dependencies_are_selected_without_building_target_outputs(self):
        graph = {A: {"inputDrvs": {B: ["out", "dev"]}}}
        assert subject.select_dependencies([A], graph) == [B + "^dev,out"]

    def test_targets_cannot_be_warmed_as_dependencies(self):
        graph = {A: {"inputDrvs": {B: ["out"]}}, B: {"inputDrvs": {}}}
        with pytest.raises(ValueError, match="target outputs"):
            subject.select_dependencies([A, B], graph)

    def test_missing_or_malformed_inventory_refuses(self):
        for graph in (
            {},
            {A: {"inputDrvs": {"bad": ["out"]}}},
            {A: {"inputDrvs": {B: ["bad^out"]}}},
        ):
            with pytest.raises(ValueError, match=r"missing|invalid|target outputs"):
                subject.select_dependencies([A], graph)

    def test_warm_outputs_refuse_the_challenge(self):
        graph = {A: {"outputs": {"out": {"path": "/nix/store/test"}}}}
        with (
            patch.object(
                subject.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
            ),
            pytest.raises(ValueError, match="warm target output"),
        ):
            subject.require_missing([A], graph)

    def test_store_errors_cannot_masquerade_as_cold_outputs(self):
        graph = {A: {"outputs": {"out": {"path": "/nix/store/absent"}}}}
        result = subprocess.CompletedProcess([], 1, "", "daemon unavailable")
        with (
            patch.object(subject.subprocess, "run", return_value=result),
            pytest.raises(ValueError, match="could not establish"),
        ):
            subject.require_missing([A], graph)
        result.stderr = "error: path '/nix/store/absent' is not valid"
        with patch.object(subject.subprocess, "run", return_value=result):
            assert subject.require_missing([A], graph) == ["/nix/store/absent"]

    def test_legacy_and_version_four_derivations_agree(self):
        expected = {
            A: {"inputDrvs": {B: ["out"]}, "outputs": {"out": {"path": "/nix/store/result"}}}
        }
        current = {
            "version": 4,
            "derivations": {
                Path(A).name: {
                    "inputs": {"drvs": {Path(B).name: {"outputs": ["out"], "dynamicOutputs": {}}}},
                    "outputs": {"out": {"path": "result"}},
                }
            },
        }
        assert subject.normalize(expected) == expected
        assert subject.normalize(current) == expected
        current["version"] = 5
        with pytest.raises(ValueError, match="unsupported derivation schema"):
            subject.normalize(current)


if __name__ == "__main__":
    unittest.main()
