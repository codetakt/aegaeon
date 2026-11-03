from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
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
    def test_default_absent_empty_and_comment_only_builders_are_local(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "machines"
            assert subject.local_builders("@/etc/nix/machines", path)["local_only"]
            for content in ("", "# comment only\n ; ;\n"):
                path.write_text(content)
                assert subject.local_builders("@/etc/nix/machines", path)["local_only"]

    def test_nonempty_or_unreadable_builders_refuse_without_leaking_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "machines"
            path.write_text("ssh://private-builder x86_64-linux /private/identity\n")
            result = subject.local_builders("@/etc/nix/machines", path)
            assert not result["local_only"]
            assert "private" not in str(result)
            with patch.object(Path, "open", side_effect=PermissionError()):
                assert not subject.local_builders("@/etc/nix/machines", path)["local_only"]

    def test_unknown_builder_configuration_does_not_open_arbitrary_paths(self):
        with patch.object(Path, "open", side_effect=AssertionError("must not read")):
            for value in (None, "ssh://remote", "@/private/file", "@/etc/nix/machines;remote"):
                assert not subject.local_builders(value)["local_only"]

    def test_oversized_default_file_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "machines"
            path.write_bytes(b" " * 65537)
            assert not subject.local_builders("@/etc/nix/machines", path)["local_only"]

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
