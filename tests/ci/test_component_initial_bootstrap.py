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
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import yaml

if TYPE_CHECKING:
    from typing import Any

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
        self.assertIn('[[ "$mounted" == true && "$mount_cleanup_attempted" == false ]]', action)
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

    def test_terminal_io_failure_releases_owned_mount_once(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        cleanup = action[
            action.index("        cleanup() {") : action.index("        trap cleanup EXIT")
        ]
        for failure in ["open", "write", "close", "locator"]:
            for setup_status in [0, 7]:
                for mount_failure in [False, True]:
                    with (
                        self.subTest(
                            failure=failure, setup_status=setup_status, mount_failure=mount_failure
                        ),
                        tempfile.TemporaryDirectory(prefix="aegaeon-terminal-io-") as directory,
                    ):
                        work = Path(directory) / "private"
                        work.mkdir()
                        (work / "observed.json").write_text("{}")
                        calls = Path(directory) / "unmount-calls"
                        program = (
                            r"""
                        work=$1; failure=$2; calls=$3; mount_failure=$4
                        root=/unused; mounted=true; source_created=true; stage=fixture; exec_calls=0
                        umount() {
                          command printf 'attempt\n' >> "$calls"
                          return "$mount_failure"
                        }
                        printf() {
                          if [[ "$failure" == write && "$1" == stage=* ]] ||
                             [[ "$failure" == locator && "$1" == 'Private bootstrap'* ]]; then
                            return 1
                          fi
                          command printf "$@"
                        }
                        exec() {
                          exec_calls=$((exec_calls + 1))
                          if [[ "$failure" == open && "$exec_calls" == 1 ]] ||
                             [[ "$failure" == close && "$exec_calls" == 2 ]]; then
                            return 1
                          fi
                          builtin exec "$@"
                        }
                        """
                            + cleanup
                            + f"\ntrap cleanup EXIT; exit {setup_status}"
                        )
                        result = subprocess.run(  # noqa: S603 - actual cleanup with modeled primitive failures
                            [
                                shutil.which("bash") or "/bin/bash",
                                "-c",
                                program,
                                "terminal-io",
                                str(work),
                                failure,
                                str(calls),
                                str(int(mount_failure)),
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=10,
                        )
                        self.assertEqual(result.returncode, setup_status or 1)
                        self.assertEqual(calls.read_text().splitlines(), ["attempt"])
                        self.assertEqual((work / "observed.json").read_text(), "{}")
                        if failure in {"write", "close"}:
                            self.assertIn("retained outcome is incomplete", result.stderr)
                        if mount_failure:
                            self.assertIn("mount cleanup failed", result.stderr)
                        work.chmod(0o700)

    def test_platform_output_failure_is_inside_owned_mount_cleanup(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        cleanup = action[
            action.index("        cleanup() {") : action.index("        trap cleanup EXIT")
        ]
        output = action[
            action.index("        stage=platform-outputs") : action.index("        BOOTSTRAP")
        ]
        for output_failure in [False, True]:
            with (
                self.subTest(output_failure=output_failure),
                tempfile.TemporaryDirectory(prefix="aegaeon-platform-output-") as directory,
            ):
                work = Path(directory) / "private"
                work.mkdir()
                (work / "observed.json").write_text("{}")
                platform_output = Path(directory) / "output"
                if output_failure:
                    platform_output.mkdir()
                else:
                    platform_output.touch()
                calls = Path(directory) / "unmount-calls"
                program = (
                    r"""
                set -euo pipefail
                work=$1; github_output=$2; calls=$3
                root=/unused; python=/fixed/python; mounted=true; source_created=true; stage=fixture
                umount() { command printf 'attempt\n' >> "$calls"; return 0; }
                """
                    + cleanup
                    + "\ntrap cleanup EXIT\n"
                    + output
                )
                result = subprocess.run(  # noqa: S603 - actual output/cleanup blocks and private paths
                    [
                        shutil.which("bash") or "/bin/bash",
                        "-c",
                        program,
                        "platform-output",
                        str(work),
                        str(platform_output),
                        str(calls),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, int(output_failure))
                self.assertEqual(calls.exists(), output_failure)
                outcome = dict(
                    line.split("=", 1) for line in (work / "outcome.txt").read_text().splitlines()
                )
                self.assertEqual(
                    outcome["stage"], "platform-outputs" if output_failure else "complete"
                )
                self.assertEqual(outcome["setup_status"], str(int(output_failure)))
                self.assertEqual(outcome["mount_retained"], str(not output_failure).lower())
                if output_failure:
                    self.assertEqual(calls.read_text().splitlines(), ["attempt"])
                else:
                    self.assertEqual(
                        platform_output.read_text(),
                        "interpreter=/fixed/python\nsource-root=/unused\n",
                    )
                work.chmod(0o700)

    def test_outcome_open_failure_never_releases_unowned_mount(self) -> None:
        action = (REPOSITORY / ".github/actions/setup-component-controller/action.yml").read_text()
        cleanup = action[
            action.index("        cleanup() {") : action.index("        trap cleanup EXIT")
        ]
        for owned_mount in [False, True]:
            with (
                self.subTest(owned_mount=owned_mount),
                tempfile.TemporaryDirectory(prefix="aegaeon-outcome-open-") as directory,
            ):
                work = Path(directory) / "private"
                work.mkdir()
                (work / "observed.json").write_text("{}")
                # A real failed redirection, independent of the exec function model.
                (work / "outcome.txt").mkdir()
                calls = Path(directory) / "unmount-calls"
                program = (
                    "set -euo pipefail; work=$1; mounted=$2; calls=$3; root=/unused; "
                    "source_created=true; stage=fixture; "
                    "umount() { command printf 'attempt\\n' >> \"$calls\"; return 0; }; "
                    + cleanup
                    + "\ntrap cleanup EXIT; exit 0"
                )
                result = subprocess.run(  # noqa: S603 - actual cleanup with real failed outcome redirection
                    [
                        shutil.which("bash") or "/bin/bash",
                        "-c",
                        program,
                        "outcome-open",
                        str(work),
                        str(owned_mount).lower(),
                        str(calls),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(calls.exists(), owned_mount)
                self.assertIn("outcome could not be opened", result.stderr)
                self.assertEqual((work / "observed.json").read_text(), "{}")
                if owned_mount:
                    self.assertEqual(calls.read_text().splitlines(), ["attempt"])
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

    def runtime_model_record(self) -> tuple[bootstrap.JsonObject, bytes]:
        # Deterministic model data; this does not attest installed CA bytes or custody.
        record = copy.deepcopy(RECORD)
        payload = b"modeled public CA bundle\n"
        record["ca_sha256"] = bootstrap.hashlib.sha256(payload).hexdigest()
        return record, payload

    def runtime_root_metadata(
        self, *, uid: int = 0, mode: int = 0o555, kind: int = stat.S_IFDIR
    ) -> os.stat_result:
        return os.stat_result((kind | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))

    def runtime_model(
        self,
        record: bootstrap.JsonObject,
        payload: bytes,
        *,
        paths: list[str] | None = None,
        flags: tuple[int, int] = (1, 1),
        roots: dict[str, os.stat_result] | None = None,
    ) -> ExitStack:
        runtime = SimpleNamespace(
            executable=record["interpreter"],
            flags=SimpleNamespace(isolated=flags[0], dont_write_bytecode=flags[1]),
            path=paths if paths is not None else [record["runtime_root"] + "/lib/python3.14"],
        )
        root_metadata = roots if roots is not None else {}
        default = self.runtime_root_metadata()

        def metadata(path: Path) -> os.stat_result:
            return root_metadata.get(str(path), default)

        stack = ExitStack()
        stack.enter_context(patch.object(bootstrap, "sys", runtime))
        stack.enter_context(
            patch.object(
                Path,
                "is_dir",
                autospec=True,
                side_effect=lambda p: (
                    stat.S_ISDIR(metadata(p).st_mode) or stat.S_ISLNK(metadata(p).st_mode)
                ),
            )
        )
        stack.enter_context(
            patch.object(
                Path,
                "is_symlink",
                autospec=True,
                side_effect=lambda p: stat.S_ISLNK(metadata(p).st_mode),
            )
        )
        stack.enter_context(patch.object(Path, "lstat", autospec=True, side_effect=metadata))
        stack.enter_context(patch.object(Path, "read_bytes", autospec=True, return_value=payload))
        return stack

    def test_runtime_accepts_valid_modeled_environment(self) -> None:
        record, payload = self.runtime_model_record()
        roots = list(record["nar_map"])
        with self.runtime_model(record, payload, paths=[roots[0], roots[-1] + "/lib"]):
            bootstrap.verify_runtime(record)

    def test_runtime_rejects_nonisolated_or_bytecode_enabled_execution(self) -> None:
        record, payload = self.runtime_model_record()
        for isolated, bytecode_disabled in [(0, 1), (1, 0)]:
            with (
                self.subTest(isolated=isolated, bytecode_disabled=bytecode_disabled),
                self.runtime_model(record, payload, flags=(isolated, bytecode_disabled)),
                self.assertRaisesRegex(
                    bootstrap.BootstrapRejectedError, "explicit isolated runtime differs"
                ),
            ):
                bootstrap.verify_runtime(record)

    def test_runtime_rejects_import_paths_outside_exact_closure(self) -> None:
        record, payload = self.runtime_model_record()
        for entry in [
            "",
            "/candidate/python",
            "/usr/lib/python",
            record["runtime_root"] + "-sibling/lib",
        ]:
            with (
                self.subTest(entry=entry),
                self.runtime_model(record, payload, paths=[record["runtime_root"], entry]),
                self.assertRaisesRegex(
                    bootstrap.BootstrapRejectedError, "runtime import path leaves"
                ),
            ):
                bootstrap.verify_runtime(record)

    def test_runtime_rejects_unowned_or_writable_closure_roots(self) -> None:
        record, payload = self.runtime_model_record()
        for root in [record["runtime_root"], record["ca_root"], list(record["nar_map"])[-1]]:
            for uid, mode in [(1000, 0o555), (0, 0o755), (0, 0o575), (0, 0o557)]:
                with (
                    self.subTest(root=root, uid=uid, mode=mode),
                    self.runtime_model(
                        record,
                        payload,
                        roots={root: self.runtime_root_metadata(uid=uid, mode=mode)},
                    ),
                    self.assertRaisesRegex(
                        bootstrap.BootstrapRejectedError,
                        "source custody is writable|source payload is writable",
                    ),
                ):
                    bootstrap.verify_runtime(record)

    def test_runtime_rejects_nondirectory_or_symlink_closure_roots(self) -> None:
        record, payload = self.runtime_model_record()
        root = list(record["nar_map"])[-1]
        for kind in [stat.S_IFREG, stat.S_IFLNK]:
            with (
                self.subTest(kind=kind),
                self.runtime_model(
                    record, payload, roots={root: self.runtime_root_metadata(kind=kind)}
                ),
                self.assertRaisesRegex(bootstrap.BootstrapRejectedError, "runtime root differs"),
            ):
                bootstrap.verify_runtime(record)

    def test_runtime_rejects_ca_outside_root_or_wrong_bundle_name(self) -> None:
        original, payload = self.runtime_model_record()
        for ca_file in [
            "/candidate/ca-bundle.crt",
            original["ca_root"] + "-sibling/ca-bundle.crt",
            str(Path(original["ca_file"]).with_name("other.crt")),
        ]:
            record = {**original, "ca_file": ca_file}
            with (
                self.subTest(ca_file=ca_file),
                self.runtime_model(record, payload),
                self.assertRaisesRegex(
                    bootstrap.BootstrapRejectedError, "literal public CA edge differs"
                ),
            ):
                bootstrap.verify_runtime(record)

    def test_runtime_rejects_changed_ca_bytes_or_expected_hash(self) -> None:
        record, payload = self.runtime_model_record()
        for observed, expected in [
            (payload + b"changed", record["ca_sha256"]),
            (payload, "0" * 64),
        ]:
            altered = {**record, "ca_sha256": expected}
            with (
                self.subTest(changed_bytes=observed != payload, expected=expected),
                self.runtime_model(altered, observed),
                self.assertRaisesRegex(bootstrap.BootstrapRejectedError, "public CA bytes differ"),
            ):
                bootstrap.verify_runtime(altered)


class InitialRuntimeCallerTests(unittest.TestCase):
    def plan_steps(self) -> list[dict[str, Any]]:
        workflow = yaml.safe_load((REPOSITORY / ".github/workflows/pr.yml").read_text())
        return cast("list[dict[str, Any]]", workflow["jobs"]["plan"]["steps"])

    def test_real_immutable_bootstrap_is_first_without_failure_bypass(self) -> None:
        steps = self.plan_steps()
        initial = steps[0]
        self.assertEqual(initial["id"], "component_bootstrap")
        self.assertEqual(
            initial["uses"],
            "codetakt/aegaeon/.github/actions/setup-component-controller@"
            "924f45ef248955acf4467ac2ce5d63e132d9462c",
        )
        self.assertEqual(
            set(initial), {"name", "id", "uses"}
        )  # No condition, override inputs or ignored failure.
        self.assertEqual(
            steps[1]["uses"], "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        )
        for step in steps[1:]:
            if "run" in step:
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)

    def test_every_plan_python_start_uses_verified_isolated_interpreter(self) -> None:
        runs = [str(step["run"]) for step in self.plan_steps() if "run" in step]
        self.assertEqual(len(runs), 2)
        self.assertEqual(sum(run.count('"$CONTROLLER_PYTHON" -I -B') for run in runs), 4)
        self.assertTrue(all("python3 -I" not in run for run in runs))
        self.assertIn('"$CONTROLLER_PYTHON" -I -B "$trusted"', runs[0])
        self.assertIn(
            '"$CONTROLLER_PYTHON" -I -B scripts/ci/validate_change.py --bootstrap', runs[0]
        )
        for step in self.plan_steps():
            if "run" in step:
                self.assertEqual(
                    step["env"]["CONTROLLER_PYTHON"],
                    "${{ steps.component_bootstrap.outputs.interpreter }}",
                )

    def test_wrong_or_missing_interpreter_stops_before_any_plan_execution(self) -> None:
        runs = [str(step["run"]) for step in self.plan_steps() if "run" in step]
        for run in runs:
            guard = run.splitlines()[0]
            self.assertEqual(
                guard, '[[ "$CONTROLLER_PYTHON" == ' + RECORD["interpreter"] + " ]] || exit 1"
            )
            for value in (None, "", "/usr/bin/python3", "/candidate/python", "$(false)"):
                with self.subTest(run=guard, output=value):
                    environment = dict(os.environ)
                    if value is None:
                        environment.pop("CONTROLLER_PYTHON", None)
                    else:
                        environment["CONTROLLER_PYTHON"] = value
                    result = subprocess.run(  # noqa: S603 - actual fixed guard only, no plan/native operations
                        [shutil.which("bash") or "/bin/bash", "-c", guard + "\nprintf reached"],
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")

    def test_exact_verified_interpreter_passes_guard_without_launching_it(self) -> None:
        for step in self.plan_steps():
            if "run" not in step:
                continue
            guard = str(step["run"]).splitlines()[0]
            result = subprocess.run(  # noqa: S603 - guard and harmless marker only
                [shutil.which("bash") or "/bin/bash", "-c", guard + "\nprintf reached"],
                env={**os.environ, "CONTROLLER_PYTHON": RECORD["interpreter"]},
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "reached")

    def test_caller_does_not_activate_private_package_or_carrier(self) -> None:
        workflow = (REPOSITORY / ".github/workflows/pr.yml").read_text()
        self.assertNotIn("Capture original protected invocation", workflow)
        self.assertNotIn("component-original-invocation", workflow)
        self.assertNotIn("/trusted/tools/python3", workflow)
        self.assertNotIn("component-validation.yml", workflow)
        policy = json.loads((REPOSITORY / "ci/pr-policy.json").read_text())
        self.assertEqual(policy["supplemental_lanes"]["components"], "pending")
        self.assertNotIn("component_release", policy)


if __name__ == "__main__":
    unittest.main()
