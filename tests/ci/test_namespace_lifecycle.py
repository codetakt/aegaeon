"""Local helper regressions; these are not actual AppArmor qualification results."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - stdlib unittest checks also run under Python -O.
import contextlib
import copy
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "organizations"))
import namespace_lifecycle as subject  # noqa: E402 - fixed repository helper.
import namespace_lifecycle_processes as processes  # noqa: E402 - fixed repository helper.

# A Nix Python environment can expose an executable wrapper through sys.executable.
# Use this interpreter's actual executable for both launch and independent binding.
FIXTURE_EXECUTABLE = str(Path("/proc/self/exe").readlink())


@contextlib.contextmanager
def child(directory: Path, **environment: str):
    process = subprocess.Popen(  # noqa: S603 - this interpreter, fixed code, no shell.
        [FIXTURE_EXECUTABLE, "-c", "import time; time.sleep(30)"],
        cwd=directory,
        env={**os.environ, **environment},
        start_new_session=True,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        if Path("/proc", str(process.pid)).exists():
            message = "owned fixture child was not reaped"
            raise AssertionError(message)


def setup_report() -> dict:
    return {
        "restriction_before": "1",
        "before": {"passed": False},
        "install_attempted": True,
        "profile_installed": True,
        "install": {"returncode": 0},
        "after": {"passed": True},
        "cancellation": "interrupted by signal 15",
    }


class NamespaceLifecycleHelpers(unittest.TestCase):
    def test_malformed_live_process_stat_is_uncertainty(self):
        for reader in (processes.process_fields, subject.identity):
            for raw in ("", f"{os.getpid()} (short) S 1"):
                with (
                    self.subTest(reader=reader.__name__, raw=raw),
                    mock.patch.object(Path, "read_text", return_value=raw),
                    self.assertRaisesRegex(ValueError, "incomplete process stat"),
                ):
                    reader(os.getpid())
            with (
                self.subTest(reader=reader.__name__, error="permission"),
                mock.patch.object(Path, "read_text", side_effect=PermissionError("stat denied")),
                self.assertRaisesRegex(PermissionError, "stat denied"),
            ):
                reader(os.getpid())
            with (
                self.subTest(reader=reader.__name__, error="absence check denied"),
                mock.patch.object(Path, "read_text", return_value=""),
                mock.patch.object(Path, "stat", side_effect=PermissionError("absence denied")),
                self.assertRaisesRegex(PermissionError, "absence denied"),
            ):
                reader(os.getpid())

    def test_incomplete_stat_requires_actual_process_absence(self):
        original_read = Path.read_text
        for reader in (processes.process_fields, subject.identity):
            with (
                self.subTest(reader=reader.__name__),
                tempfile.TemporaryDirectory() as temporary,
                child(Path(temporary)) as owned,
            ):
                target = Path("/proc", str(owned.pid), "stat")

                def read_after_exit(path, *args, target=target, **kwargs):
                    if path == target:
                        original_read(path, *args, **kwargs)
                        owned.terminate()
                        owned.wait(timeout=3)
                        return ""  # Injected short read plus independently reaped real child.
                    return original_read(path, *args, **kwargs)

                with mock.patch.object(
                    Path, "read_text", autospec=True, side_effect=read_after_exit
                ):
                    if reader is processes.process_fields:
                        with self.assertRaises(FileNotFoundError):
                            reader(owned.pid)
                    else:
                        self.assertIsNone(reader(owned.pid))
                self.assertFalse(Path("/proc", str(owned.pid)).exists())

    def test_cancel_records_real_exit_before_identity_or_signal(self):
        original_identity, original_kill = subject.identity, os.kill
        for boundary in ("identity", "signal"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case = subject.Case(root / "case", "cancel", time.monotonic() + 10)
                with child(root) as owned:
                    case.wrapper = owned
                    case.wrapper_identity = original_identity(owned.pid)

                    def identity_after_exit(pid, boundary=boundary):
                        if boundary == "identity" and owned.poll() is None:
                            original_kill(pid, signal.SIGTERM)
                            owned.wait(timeout=3)
                        return original_identity(pid)

                    def signal_after_exit(pid, signum):
                        self.assertEqual((pid, signum), (owned.pid, signal.SIGTERM))
                        original_kill(pid, signum)
                        owned.wait(timeout=3)
                        original_kill(pid, signum)  # Real ESRCH after confirmed child exit.

                    with (
                        mock.patch.object(subject, "identity", side_effect=identity_after_exit),
                        mock.patch.object(os, "kill", side_effect=signal_after_exit)
                        if boundary == "signal"
                        else contextlib.nullcontext(),
                    ):
                        case.cancel()
                    self.assertFalse(case.cancelled)
                    self.assertEqual(case.events[-1]["event"], "wrapper_exited_before_cancel")
                    self.assertFalse(Path("/proc", str(owned.pid)).exists())

    def test_cancel_uncertainty_does_not_authorize_a_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = subject.Case(root / "case", "cancel", time.monotonic() + 10)
            with child(root) as owned:
                case.wrapper = owned
                case.wrapper_identity = subject.identity(owned.pid)
                for value in (None, {**case.wrapper_identity, "starttime": "0"}):
                    with (
                        self.subTest(value=value),
                        mock.patch.object(subject, "identity", return_value=value),
                        mock.patch.object(os, "kill") as kill,
                        self.assertRaisesRegex(ValueError, "identity changed"),
                    ):
                        case.cancel()
                    kill.assert_not_called()
                with (
                    mock.patch.object(subject, "identity", side_effect=PermissionError("denied")),
                    mock.patch.object(os, "kill") as kill,
                    self.assertRaises(PermissionError),
                ):
                    case.cancel()
                kill.assert_not_called()
                self.assertFalse(case.cancelled)
                self.assertIsNone(owned.poll())

    def test_cancel_missing_signal_still_requires_confirmed_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = subject.Case(root / "case", "cancel", time.monotonic() + 10)
            with child(root) as owned:
                case.wrapper = owned
                case.wrapper_identity = subject.identity(owned.pid)
                with (
                    mock.patch.object(os, "kill", side_effect=ProcessLookupError("signal missing")),
                    self.assertRaisesRegex(ProcessLookupError, "signal missing"),
                ):
                    case.cancel()
                self.assertFalse(case.cancelled)
                self.assertEqual(case.events, [])
                self.assertIsNone(owned.poll())

    def test_final_worker_observation_error_preserves_failed_result(self):
        for fault in (PermissionError("worker denied"), ValueError("worker stat invalid")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case = subject.Case(root / "case", "cancel", time.monotonic() + 10)
                case.data["error"] = "original case failure"
                with child(root) as owned:
                    owned.terminate()
                    owned.wait(timeout=3)
                    case.worker = owned
                    case.worker_pid = owned.pid
                    case.children.append(owned)
                    with (
                        mock.patch.object(
                            subject, "recover", return_value=["work unconfirmed; retain policy"]
                        ),
                        mock.patch.object(
                            case, "census", return_value={"rows": [], "known_remaining": []}
                        ),
                        mock.patch.object(subject, "identity", side_effect=fault),
                    ):
                        subject.finish_case(case)
                    result = json.loads((case.path / "result.json").read_text())
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["census_ended"])
                    self.assertEqual(result["error"], "original case failure")
                    self.assertIn("work unconfirmed; retain policy", result["cleanup_errors"])
                    self.assertTrue(any(str(fault) in error for error in result["cleanup_errors"]))
                    self.assertEqual(result["remaining_controllers"], [])

    def test_run_publishes_failed_case_and_aggregate_on_final_observation_error(self):
        original_read = Path.read_text

        def capability(path, *args, **kwargs):
            if path == Path("/sys/module/apparmor/parameters/enabled"):
                return "Y"
            return original_read(path, *args, **kwargs)

        def exercise(case):
            case.worker_pid = os.getpid()
            message = "original exercise failure"
            raise RuntimeError(message)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "results"
            with (
                mock.patch.object(subject.Case, "check"),
                mock.patch.object(subject.Case, "exercise", autospec=True, side_effect=exercise),
                mock.patch.object(subject, "recover", return_value=["work unknown; retain policy"]),
                mock.patch.object(
                    subject, "identity", side_effect=PermissionError("worker denied")
                ),
                mock.patch.object(subject.namespace, "restriction", return_value="1"),
                mock.patch.object(Path, "is_file", return_value=True),
                mock.patch.object(Path, "read_text", autospec=True, side_effect=capability),
            ):
                self.assertEqual(subject.run(output), 1)
            case = json.loads((output / "cancel/result.json").read_text())
            aggregate = json.loads((output / "result.json").read_text())
            self.assertEqual(case["error"], "original exercise failure")
            self.assertFalse(case["passed"])
            self.assertFalse(case["census_ended"])
            self.assertTrue(any("worker denied" in error for error in case["cleanup_errors"]))
            self.assertFalse(aggregate["passed"])
            self.assertEqual(aggregate["cases"], [{"case": "cancel", "passed": False}])

    def test_actual_add_and_kernel_state_are_required(self):
        normal = {
            **setup_report(),
            "profile_removed": True,
            "profile_absent": True,
            "unconfirmed_groups": [],
            "restriction_after": "1",
        }
        subject.expected_report("cancel", normal, False)
        for change in (
            {"before": {"passed": True}},
            {"profile_installed": False},
            {"after": {"passed": False}},
            {"cancellation": ""},
            {"unconfirmed_groups": [123]},
            {"restriction_after": "0"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.expected_report("cancel", {**normal, **change}, False)
        with self.assertRaises(ValueError):
            subject.expected_report("cancel", normal, True)
        missing = {
            **setup_report(),
            "nested_cleanup_unconfirmed": "registered receipt missing",
            "policy_removal_deferred": "nested work unknown",
            "recovery": {"profile": "owned"},
        }
        subject.expected_report("missing-receipt", missing, True)
        for change in (
            {"nested_cleanup_unconfirmed": ""},
            {"remove": {"returncode": 0}},
            {"recovery": {}},
            {"profile_absent": True},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.expected_report("missing-receipt", {**missing, **change}, True)
        with self.assertRaises(ValueError):
            subject.expected_report("missing-receipt", missing, False)

    def test_only_required_dependency_outputs_must_be_realized(self):
        selected = "a" * 32 + "-probe.drv"
        dependency = "b" * 32 + "-tool.drv"
        output = "c" * 32 + "-tool"
        row = {"version": 4, "inputs": {"srcs": [], "drvs": {}}, "outputs": {}}
        top = copy.deepcopy(row)
        top["inputs"]["drvs"][dependency] = {"outputs": ["out"], "dynamicOutputs": {}}
        dep = copy.deepcopy(row)
        dep["outputs"] = {"out": {"path": output}, "unused": {"path": "d" * 32 + "-unused"}}
        # Historical inputs of an already-realized tool are deliberately absent.
        dep["inputs"] = {"srcs": ["f" * 32 + "-old-source"], "drvs": {"unavailable": {}}}
        document = {"version": 4, "derivations": {selected: top}}
        direct = {"version": 4, "derivations": {dependency: dep}}
        self.assertEqual(
            subject.dependency_paths(document, "/nix/store/" + selected),
            ["/nix/store/" + dependency],
        )
        with mock.patch.object(
            Path, "exists", autospec=True, side_effect=lambda path: path.name == output
        ):
            subject.check_dependencies(document, "/nix/store/" + selected, direct)
            top["inputs"]["drvs"][dependency]["outputs"].append("unused")
            with self.assertRaisesRegex(ValueError, "unrealized"):
                subject.check_dependencies(document, "/nix/store/" + selected, direct)
            top["inputs"]["drvs"][dependency]["outputs"].pop()
            top["inputs"]["srcs"] = ["e" * 32 + "-selected-source"]
            with self.assertRaisesRegex(ValueError, "unrealized"):
                subject.check_dependencies(document, "/nix/store/" + selected, direct)
            top["inputs"]["srcs"] = []
        with self.assertRaisesRegex(ValueError, "set differs"):
            subject.check_dependencies(
                document, "/nix/store/" + selected, {"version": 4, "derivations": {}}
            )
        top["inputs"]["drvs"][dependency] = {"outputs": ["out"], "dynamicOutputs": {"unknown": {}}}
        with self.assertRaisesRegex(ValueError, "dynamic"):
            subject.check_dependencies(document, "/nix/store/" + selected, direct)

    def make_census(self, root: Path) -> processes.Census:
        return processes.Census(
            {
                "scratch": str(root / "scratch"),
                "nonce": "a" * 32,
                "outputs": {"probe": "/nix/store/probe", "payload": "/nix/store/payload"},
                "caller_uid": os.getuid(),
                "owner_starttime": int(subject.identity(os.getpid())["starttime"]),
                "nix_executable": FIXTURE_EXECUTABLE,
            }
        )

    def test_real_child_needs_exact_output_nonce_and_private_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            census = self.make_census(root)
            try:
                with (
                    child(
                        census.scratch,
                        out="/nix/store/payload",
                        AEGAEON_NAMESPACE_LIFECYCLE_NONCE="a" * 32,
                    ) as owned,
                    child(
                        root, out="/nix/store/payload", AEGAEON_NAMESPACE_LIFECYCLE_NONCE="a" * 32
                    ) as outside,
                    child(
                        census.scratch,
                        out="/nix/store/payload",
                        AEGAEON_NAMESPACE_LIFECYCLE_NONCE="b" * 32,
                    ) as foreign,
                ):
                    row = census.inspect(owned.pid, census.directories())
                    self.assertEqual(row["kind"], "payload")
                    self.assertIsNone(census.inspect(outside.pid, census.directories()))
                    self.assertIsNone(census.inspect(foreign.pid, census.directories()))
                    with mock.patch.object(census, "snapshot", return_value={"rows": [row]}):
                        actions = census.stop(15)
                    owned.wait(timeout=3)
                    self.assertEqual(actions[0]["identity"]["pid"], owned.pid)
                    self.assertIsNone(outside.poll())
                    self.assertIsNone(foreign.poll())
            finally:
                census.close()

    def test_queued_build_directory_can_disappear_before_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            census = self.make_census(Path(temporary))
            vanished = census.scratch / "finished-build"
            surviving = census.scratch / "active-build"
            vanished.mkdir()
            surviving.mkdir()
            real_scan = os.scandir
            scanned = []

            def remove_before_scan(path):
                scanned.append(Path(path))
                if Path(path) == vanished:
                    vanished.rmdir()  # Already statted and queued by the real root scan.
                return real_scan(path)

            try:
                with mock.patch.object(processes.os, "scandir", side_effect=remove_before_scan):
                    directories = census.directories()
                self.assertIn(vanished, scanned)
                self.assertIn(surviving, scanned)
                self.assertFalse(vanished.exists())
                metadata = surviving.stat()
                self.assertEqual(directories[(metadata.st_dev, metadata.st_ino)], surviving)
                self.assertEqual(directories[census.identity], census.scratch)
            finally:
                census.close()

    def test_missing_or_replaced_scratch_is_not_an_exited_build(self):
        for condition in ("root-scan", "child-scan", "replacement"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                census = self.make_census(root)
                queued = census.scratch / "finished-build"
                queued.mkdir()
                real_scan = os.scandir

                def remove_scratch(path, census=census, condition=condition, real_scan=real_scan):
                    queued = census.scratch / "finished-build"
                    selected = census.scratch if condition == "root-scan" else queued
                    if Path(path) == selected:
                        queued.rmdir()
                        if condition == "replacement":
                            census.scratch.rename(census.scratch.parent / "original")
                            census.scratch.mkdir()
                        else:
                            census.scratch.rmdir()
                    return real_scan(path)

                expected = ValueError if condition == "replacement" else FileNotFoundError
                try:
                    with (
                        mock.patch.object(processes.os, "scandir", side_effect=remove_scratch),
                        self.assertRaises(expected),
                    ):
                        census.directories()
                finally:
                    census.close()

    def test_queued_directory_other_scan_errors_are_not_ignored(self):
        for failure in (PermissionError, NotADirectoryError, OSError):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                census = self.make_census(Path(temporary))
                queued = census.scratch / "active-build"
                queued.mkdir()
                real_scan = os.scandir

                def fail_child_scan(path, queued=queued, failure=failure, real_scan=real_scan):
                    if Path(path) == queued:
                        message = "injected child scan failure"
                        raise failure(message)
                    return real_scan(path)

                try:
                    with (
                        mock.patch.object(processes.os, "scandir", side_effect=fail_child_scan),
                        self.assertRaises(failure),
                    ):
                        census.directories()
                finally:
                    census.close()

    def test_replaced_private_directory_cannot_authorize_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            census = self.make_census(root)
            try:
                with child(
                    census.scratch,
                    out="/nix/store/payload",
                    AEGAEON_NAMESPACE_LIFECYCLE_NONCE="a" * 32,
                ) as owned:
                    row = census.inspect(owned.pid, census.directories())
                    census.scratch.rename(root / "original")
                    census.scratch.mkdir()
                    with (
                        mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                        self.assertRaisesRegex(ValueError, "identity"),
                    ):
                        census.stop(15)
                    self.assertIsNone(owned.poll())
            finally:
                census.close()

    def test_preexisting_process_is_excluded_before_environment_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            census = self.make_census(Path(temporary))
            try:
                fields = processes.process_fields(os.getpid())
                census.binding["owner_starttime"] = int(fields[19]) + 1
                with (
                    mock.patch.object(processes, "process_fields", return_value=fields),
                    mock.patch.object(
                        Path, "open", side_effect=AssertionError("must not read environment")
                    ),
                ):
                    self.assertIsNone(census.inspect(os.getpid(), census.directories()))
                census.binding["owner_starttime"] = int(fields[19])
                with (
                    mock.patch.object(processes, "process_fields", return_value=fields),
                    mock.patch.object(
                        Path, "open", side_effect=PermissionError("new process denied")
                    ),
                    self.assertRaises(PermissionError),
                ):
                    census.inspect(os.getpid(), census.directories())
            finally:
                census.close()

    def test_kernel_absence_precedes_fresh_process_observation(self):
        events = []
        state = {"live": True}

        def profile(_):
            events.append("profile")
            state["live"] = False  # Normal work stop and policy removal have now occurred.
            return False

        def snapshot():
            events.append("processes")
            return {"rows": [{"pid": 123}] if state["live"] else [], "known_remaining": []}

        census = mock.Mock(snapshot=snapshot)
        with mock.patch.object(processes, "profile_present", side_effect=profile):
            result = processes.observed_snapshot(census, "aegaeon-userns-" + "a" * 32)
        self.assertEqual(events, ["profile", "processes"])
        self.assertIs(result["profile_present"], False)
        self.assertEqual(result["rows"], [])

    def test_actual_registration_requires_independent_client_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            census = self.make_census(root)
            directory = root / "receipts"
            owner = "aegaeon-userns-" + "a" * 32
            try:
                with (
                    child(root, AEGAEON_NAMESPACE_LIFECYCLE_CASE="a" * 32) as native,
                    subject.nested.initialize(directory, owner),
                    mock.patch.dict(os.environ, {subject.nested.ENVIRONMENT: str(directory)}),
                ):
                    receipt = subject.nested.begin()
                    subject.nested.update(receipt, group=native.pid)
                    row = census.inspect(native.pid, census.directories())
                    self.assertIsNotNone(row)
                    self.assertEqual(row["kind"], "client")
                    with mock.patch.dict(
                        census.binding, {"nix_executable": str(root / "different-executable")}
                    ):
                        self.assertIsNone(census.inspect(native.pid, census.directories()))
                    result = subject.bind_registered_client(directory, [row], owner)
                    self.assertEqual(result["client"], row)
                    self.assertEqual(result["record"]["group"], native.pid)
                    for rows in (
                        [],
                        [row, row],
                        [{**row, "kind": "payload"}],
                        [{**row, "session": native.pid + 1}],
                        [{**row, "starttime": "0"}],
                    ):
                        with self.subTest(rows=rows), self.assertRaises(ValueError):
                            subject.bind_registered_client(directory, rows, owner)
                    self.assertIsNone(native.poll())
            finally:
                census.close()

    def test_missing_client_binding_blocks_independent_policy_recovery(self):
        case = mock.Mock()
        case.data = {}
        case.end = time.monotonic() + 20
        case.wrapper.poll.return_value = 1
        case.work_identity = {"group": os.getpid()}
        case.worker = object()
        case.profile = "aegaeon-userns-" + "a" * 32
        case.census.return_value = {"rows": [], "known_remaining": [], "profile_present": True}
        with (
            mock.patch.object(subject, "group_running", return_value=False),
            mock.patch.object(subject.namespace, "restriction", return_value="1"),
        ):
            errors = subject.recover(case)
        self.assertTrue(errors)
        self.assertIs(case.data["owned_work_stopped"], False)
        case.command.assert_not_called()

    def test_fault_removes_only_the_actual_registered_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "receipts"
            owner = "aegaeon-userns-" + "a" * 32
            with subject.nested.initialize(directory, owner) as pinned:
                with mock.patch.dict(os.environ, {subject.nested.ENVIRONMENT: str(directory)}):
                    receipt = subject.nested.begin()
                    subject.nested.update(receipt, group=os.getpid())
                ledger = (directory / subject.nested.LEDGER).read_bytes()
                result = subject.remove_registered_receipt(directory, root)
                self.assertEqual(result["identity"], pinned)
                self.assertEqual((directory / subject.nested.LEDGER).read_bytes(), ledger)
                self.assertFalse((directory / result["name"]).exists())
                self.assertTrue((root / "removed-receipt.json").is_file())
                with self.assertRaisesRegex(ValueError, "missing"):
                    subject.nested.confirm(directory, owner, pinned)

    def test_unconfirmed_work_never_calls_policy_removal(self):
        case = mock.Mock()
        case.end = time.monotonic()
        case.wrapper.poll.return_value = None
        case.worker = object()
        case.work_identity = None
        case.data = {}
        case.profile = "aegaeon-userns-" + "a" * 32
        case.census.return_value = {"rows": [], "known_remaining": [], "profile_present": True}
        with mock.patch.object(subject.namespace, "restriction", return_value="1"):
            errors = subject.recover(case)
        self.assertTrue(errors)
        self.assertIs(case.data["owned_work_stopped"], False)
        case.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
