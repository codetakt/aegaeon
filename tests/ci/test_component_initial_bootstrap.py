"""Focused B predicates; modeled custody never attests hosted installation."""
# ruff: noqa: PT009, PT027

from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import bootstrap_component_controller as bootstrap

sys.path.pop(0)

REPOSITORY = Path(__file__).resolve().parents[2]
RECORD = json.loads((REPOSITORY / "ci/component-bootstrap-runtime.json").read_text())
MOUNT = "41 22 0:20 / /trusted/component-bootstrap ro,nosuid,nodev,noexec - ext4 /dev/root rw\n"


class InitialBootstrapTests(unittest.TestCase):
    def test_exact_closure_predicate_accepts_frozen_map(self) -> None:
        bootstrap.verify_nar_map(RECORD["nar_map"], copy.deepcopy(RECORD["nar_map"]))

    def test_extra_root_is_rejected(self) -> None:
        observed = copy.deepcopy(RECORD["nar_map"])
        observed["/nix/store/extra"] = next(iter(observed.values()))
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_nar_map(RECORD["nar_map"], observed)

    def test_missing_root_is_rejected(self) -> None:
        observed = copy.deepcopy(RECORD["nar_map"])
        observed.pop(next(iter(observed)))
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_nar_map(RECORD["nar_map"], observed)

    def test_hash_size_and_reference_mutations_are_rejected(self) -> None:
        for field, value in [("narHash", "sha256-bad"), ("narSize", 0), ("references", [])]:
            with self.subTest(field=field):
                observed = copy.deepcopy(RECORD["nar_map"])
                observed[next(iter(observed))][field] = value
                with self.assertRaises(bootstrap.BootstrapRejectedError):
                    bootstrap.verify_nar_map(RECORD["nar_map"], observed)

    def test_outside_reference_is_rejected_even_when_maps_agree(self) -> None:
        altered = copy.deepcopy(RECORD["nar_map"])
        altered[next(iter(altered))]["references"].append("/nix/store/outside")
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_nar_map(altered, altered)

    def test_readonly_mount_predicate_accepts_one_exact_mount(self) -> None:
        bootstrap.verify_readonly_mount(bootstrap.SOURCE_ROOT, MOUNT)

    def test_missing_writable_and_stacked_mounts_are_rejected(self) -> None:
        for text in ["", MOUNT.replace(" ro,", " rw,"), MOUNT + MOUNT]:
            with self.subTest(mountinfo=text), self.assertRaises(bootstrap.BootstrapRejectedError):
                bootstrap.verify_readonly_mount(bootstrap.SOURCE_ROOT, text)

    def test_malformed_mount_observation_is_rejected(self) -> None:
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_readonly_mount(bootstrap.SOURCE_ROOT, "invalid\n")

    def test_source_payload_mode_predicate(self) -> None:
        info = os.stat_result((stat.S_IFREG | 0o444, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        bootstrap.verify_owned_mode(info, readonly=True)
        for mode, owner in [(0o644, 0), (0o444, 1000), (0o464, 0)]:
            with self.subTest(mode=mode, owner=owner):
                info = os.stat_result((stat.S_IFREG | mode, 0, 0, 1, owner, 0, 0, 0, 0, 0))
                with self.assertRaises(bootstrap.BootstrapRejectedError):
                    bootstrap.verify_owned_mode(info, readonly=True)

    def test_candidate_source_path_is_rejected_before_io(self) -> None:
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_source_custody(Path("/workspace/candidate"), {}, MOUNT)

    def test_source_member_domain_is_rejected_before_io(self) -> None:
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.verify_source_custody(bootstrap.SOURCE_ROOT, {"extra": "a" * 64}, MOUNT)

    def test_duplicate_json_is_rejected(self) -> None:
        with self.assertRaises(bootstrap.BootstrapRejectedError):
            bootstrap.unique_object([("key", 1), ("key", 2)])

    def test_source_custody_positive_model_and_changed_bytes(self) -> None:
        # Actual private file reads; root/mount metadata is modeled, not native evidence.
        with tempfile.TemporaryDirectory(prefix="aegaeon-bootstrap-predicate-") as directory:
            root = Path(directory)
            hashes = {}
            for name in bootstrap.SOURCE_FILES:
                raw = name.encode()
                (root / name).write_bytes(raw)
                hashes[name] = bootstrap.hashlib.sha256(raw).hexdigest()
            original = Path.lstat

            def modeled_metadata(path: Path) -> os.stat_result:
                info = original(path)
                mode = stat.S_IFDIR | 0o555 if stat.S_ISDIR(info.st_mode) else stat.S_IFREG | 0o444
                return os.stat_result(
                    (mode, info.st_ino, info.st_dev, 1, 0, 0, info.st_size, 0, 0, 0)
                )

            with (
                patch.object(bootstrap, "SOURCE_ROOT", root),
                patch.object(Path, "lstat", modeled_metadata),
            ):
                mountinfo = MOUNT.replace("/trusted/component-bootstrap", str(root))
                bootstrap.verify_source_custody(root, hashes, mountinfo)
                (root / bootstrap.SOURCE_FILES[0]).write_bytes(b"changed")
                with self.assertRaises(bootstrap.BootstrapRejectedError):
                    bootstrap.verify_source_custody(root, hashes, mountinfo)

    def test_runtime_rejects_wrong_interpreter_before_filesystem_checks(self) -> None:
        with (
            patch.object(bootstrap.sys, "executable", "/candidate/python"),
            self.assertRaises(bootstrap.BootstrapRejectedError),
        ):
            bootstrap.verify_runtime(RECORD)

    def test_action_retains_uncertain_observations_and_only_cleans_owned_mount(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        self.assertNotIn('rm -rf "$work"', action)
        self.assertIn(
            'if (( status != 0 || cleanup_status != 0 )) && [[ "$mounted" == true ]]', action
        )
        self.assertIn("Private bootstrap observations retained at %s", action)
        self.assertIn('exit "$status"', action)
        for evidence in [
            "observed.json",
            "mountinfo.txt",
            "source-installed.sha256",
            "outcome.txt",
        ]:
            self.assertIn(evidence, action)

    def test_cleanup_failure_preserves_nonzero_status_and_private_observations(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        cleanup = action[
            action.index("        cleanup() {") : action.index("        trap cleanup EXIT")
        ]
        for setup_status, mount_failure, expected in [(7, True, 7), (7, False, 7), (0, False, 0)]:
            with (
                self.subTest(status=setup_status, mount_failure=mount_failure),
                tempfile.TemporaryDirectory(prefix="aegaeon-cleanup-predicate-") as directory,
            ):
                work = Path(directory) / "private"
                work.mkdir()
                (work / "observed.json").write_text("{}")
                # Mock only unmount; execute cleanup against owned temporary files.
                program = (
                    "work=$1; root=/unused; mounted=true; source_created=true; stage=fixture; "
                    f"function umount() {{ return {int(mount_failure)}; }}; "
                    + cleanup
                    + f"\ntrap cleanup EXIT; exit {setup_status}"
                )
                result = subprocess.run(  # noqa: S603 - fixed shell, sealed own cleanup text and private path
                    [
                        shutil.which("bash") or "/bin/bash",
                        "-c",
                        program,
                        "cleanup-predicate",
                        str(work),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, expected)
                self.assertTrue((work / "observed.json").is_file())
                outcome = dict(
                    line.split("=", 1) for line in (work / "outcome.txt").read_text().splitlines()
                )
                self.assertEqual(outcome["setup_status"], str(setup_status))
                self.assertEqual(outcome["cleanup_status"], str(int(mount_failure)))
                self.assertEqual(outcome["exit_status"], str(expected))
                self.assertEqual(
                    outcome["mount_retained"], str(setup_status == 0 or mount_failure).lower()
                )
                self.assertIn("Private bootstrap observations retained", result.stderr)
                if mount_failure:
                    self.assertIn("mount cleanup failed", result.stderr)
                work.chmod(0o700)

    def test_cleanup_records_final_sealing_failure_and_original_setup_status(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        cleanup = action[
            action.index("        cleanup() {") : action.index("        trap cleanup EXIT")
        ]
        for setup_status in [0, 7]:
            for failure in ["observation", "outcome", "directory"]:
                with (
                    self.subTest(setup_status=setup_status, failure=failure),
                    tempfile.TemporaryDirectory(prefix="aegaeon-sealing-failure-") as directory,
                ):
                    work = Path(directory) / "private"
                    work.mkdir()
                    (work / "observed.json").write_text("{}")
                    program = (
                        r"""
                    work=$1; failure=$2; root=/unused; mounted=true
                    source_created=true; stage=fixture
                    umount() { return 0; }
                    chmod() {
                      if [[ "$failure" == observation && "$2" == "$work/observed.json" ]] ||
                         [[ "$failure" == outcome && "$2" == "$work/outcome.txt" ]] ||
                         [[ "$failure" == directory && "$1" == 0500 ]]; then
                        return 1
                      fi
                      command chmod "$@"
                    }
                    """
                        + cleanup
                        + f"\ntrap cleanup EXIT; exit {setup_status}"
                    )
                    result = subprocess.run(  # noqa: S603 - fixed own cleanup and modeled chmod/unmount failures
                        [
                            shutil.which("bash") or "/bin/bash",
                            "-c",
                            program,
                            "sealing-failure",
                            str(work),
                            failure,
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, setup_status or 1)
                    outcome = dict(
                        line.split("=", 1)
                        for line in (work / "outcome.txt").read_text().splitlines()
                    )
                    self.assertEqual(outcome["setup_status"], str(setup_status))
                    self.assertEqual(outcome["cleanup_status"], "1")
                    self.assertEqual(outcome["exit_status"], str(result.returncode))
                    self.assertEqual(outcome["mount_retained"], "false")
                    self.assertEqual((work / "observed.json").read_text(), "{}")
                    work.chmod(0o700)

    def test_action_pins_actual_script_and_runtime_bytes(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        for key, relative in [
            ("script_hash", "scripts/ci/bootstrap_component_controller.py"),
            ("runtime_hash", "ci/component-bootstrap-runtime.json"),
        ]:
            digest = bootstrap.hashlib.sha256((REPOSITORY / relative).read_bytes()).hexdigest()
            self.assertIn(f"readonly {key}={digest}", action)

    def test_action_performs_real_pre_python_gate_and_direct_call(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        launch = action.index('"$python" -I -B')
        for operation in [
            "store verify --recursive",
            "path-info --recursive --json",
            "expected == projected",
            "mount -o remount,bind,ro",
        ]:
            self.assertLess(action.index(operation), launch)
        self.assertIn('"$root/bootstrap_component_controller.py"', action[launch:])
        self.assertNotIn("./.github/actions/", action)
        self.assertIn("91391f8e5c8f753359399cf37d7adaaa6cea4d1c", action)


if __name__ == "__main__":
    unittest.main()
