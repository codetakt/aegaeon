"""Current-runtime ownership uses real child groups and simulated supplier cleanup."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest also runs without pytest and under Python -O.
import ast
import contextlib
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import database_execution as execution  # noqa: E402 - fixed repository module.


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentRuntimeCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory_owner = tempfile.TemporaryDirectory(prefix="aeg-current-cleanup-")
        self.addCleanup(self.directory_owner.cleanup)
        self.directory = Path(self.directory_owner.name)
        self.process = load_module("owned_current", ROOT / "tests/organizations/current_process.py")
        previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        self.addCleanup(lambda: [signal.signal(s, handler) for s, handler in previous.items()])
        self.process.install_cancellation()
        self.children = []
        self.addCleanup(self.reclaim_children)
        self.real_popen = subprocess.Popen

    def reclaim_children(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)

    def popen(self, *args, **kwargs):
        child = self.real_popen(*args, **kwargs)
        self.children.append(child)
        return child

    def run_child(self, *, code="import time; time.sleep(60)", **kwargs):
        with mock.patch.object(self.process.subprocess, "Popen", side_effect=self.popen):
            return self.process.run_owned(
                [sys.executable, "-c", code],
                root=self.directory,
                env=dict(os.environ),
                timeout=3,
                **kwargs,
            )

    def finalizer(self, run):
        # Load the actual function without invoking the top-level PG/native harness.
        path = ROOT / "tests/organizations/current_runtime.py"
        node = next(
            n
            for n in ast.parse(path.read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == "finish_runtime"
        )
        temporary = self.directory / "private-fixture"
        temporary.mkdir()
        (temporary / "credentials").write_text("private fixture stand-in")
        output = self.directory / "report"
        output.mkdir()
        report = {"passed": True}
        log = io.StringIO()
        values = {
            "cleanup_scope": self.process.cleanup_scope,
            "unconfirmed_groups": self.process.unconfirmed_groups,
            "supplier_start_groups": self.process.supplier_start_groups,
            "cancellation_recorded": self.process.cancellation_recorded,
            "check_cancellation": self.process.check_cancellation,
            "clusters": {"primary": {"data": temporary / "data"}},
            "pg": Path("/unused-postgres-bin"),
            "run": run,
            "setup_log": log,
            "report": report,
            "shutil": shutil,
            "temporary": temporary,
            "a": types.SimpleNamespace(output=output),
            "json": json,
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), values)  # noqa: S102
        return values["finish_runtime"], report, log, temporary, output / "result.json"

    def test_finally_entry_signal_stops_child_and_preserves_work_error(self):
        path = ROOT / "tests/organizations/current_process.py"
        line = next(
            i
            for i, text in enumerate(path.read_text().splitlines(), 1)
            if text.strip() == "if child is not None and not retained:"
        )
        seen = []

        def trace(frame, event, _arg):
            if (
                event == "line"
                and frame.f_code.co_filename == str(path)
                and frame.f_lineno == line
                and not seen
            ):
                seen.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGINT)
            return trace

        def fail(child):
            self.assertIn(child.pid, self.process.unconfirmed_groups())
            raise ValueError("original work failure")  # noqa: EM101, TRY003

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaisesRegex(ValueError, "original work failure"):
                self.run_child(before_wait=fail)
        finally:
            sys.settrace(previous)
        self.assertEqual(seen, [True])
        self.assertEqual(self.process.unconfirmed_groups(), [])
        self.assertFalse(execution.group_running(self.children[0].pid))
        with self.assertRaisesRegex(RuntimeError, "signal 15"):
            self.process.check_cancellation()

    def test_spawn_handoff_records_before_propagating_cancellation(self):
        def spawned(*args, **kwargs):
            child = self.popen(*args, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)
            return child

        with (
            mock.patch.object(self.process.subprocess, "Popen", side_effect=spawned),
            self.assertRaisesRegex(RuntimeError, "interrupted"),
        ):
            self.process.run_owned(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                root=self.directory,
                env=dict(os.environ),
                retain_supplier=True,
                timeout=3,
            )
        self.assertEqual(self.process.unconfirmed_groups(), [])
        self.assertEqual(self.process.supplier_start_groups(), [])
        self.assertFalse(execution.group_running(self.children[0].pid))

    def test_successful_supplier_handoff_precedes_pending_cancellation(self):
        # Isolate Linux subreaper ownership; do not orphan a grandchild to PID 1.
        controller = r"""
import ctypes, json, os, signal, subprocess, sys, time
from pathlib import Path
root, directory = map(Path, sys.argv[1:])
sys.path[:0] = [str(root/'scripts/validation'), str(root/'tests/organizations')]
import current_process as current
import database_execution as execution
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
current.install_cancellation()
children=[]
def registered(child):
    children.append(child)
    (directory/'supplier-group.json').write_text(json.dumps({'group':child.pid}))
    communicate=child.communicate
    def finished(*args, **kwargs):
        result=communicate(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGTERM)
        return result
    child.communicate=finished
record={}
code="import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])"
try:
    try:
        current.run_owned([sys.executable,'-c',code],root=directory,env=dict(os.environ),
                          before_wait=registered,retain_supplier=True,timeout=3)
    except RuntimeError as error:
        record['cancelled']='interrupted' in str(error)
    record.update(unconfirmed=current.unconfirmed_groups(),
                  supplier_groups=current.supplier_start_groups(),
                  live=execution.group_running(children[0].pid))
finally:
    for child in children:
        execution.stop_process_group(child,grace=.1)
    reaped=[];deadline=time.monotonic()+2
    while True:
        try: pid, status=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError: break
        if pid: reaped.append(pid)
        elif time.monotonic()>=deadline: raise TimeoutError('subreaper confirmation')
        else: time.sleep(.01)
    record.update(reaped_descendants=reaped,groups_stopped=all(
        not execution.group_running(c.pid) for c in children))
print(json.dumps(record))
"""
        with (self.directory / "supplier-controller.log").open("w+") as log:
            child = self.popen(
                [sys.executable, "-B", "-c", controller, str(ROOT), str(self.directory)],
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            try:
                status = child.wait(timeout=15)
            finally:
                execution.stop_process_group(child, grace=0.1)
                # Error paths retain and reclaim the exact independently owned group.
                marker = self.directory / "supplier-group.json"
                if marker.exists():
                    group = json.loads(marker.read_text())["group"]
                    if execution.group_running(group):
                        os.killpg(group, signal.SIGKILL)
            log.seek(0)
            text = log.read()
        self.assertEqual(status, 0, text)
        record = json.loads(text)
        self.assertTrue(record["cancelled"])
        self.assertTrue(record["live"])
        self.assertEqual(record["unconfirmed"], [])
        self.assertEqual(len(record["supplier_groups"]), 1)
        self.assertEqual(len(record["reaped_descendants"]), 1)
        self.assertTrue(record["groups_stopped"])

    def test_unconfirmed_work_retains_supplier_and_recovery_report(self):
        failure = ValueError("original work failure")

        def fail(_child):
            raise failure

        with (
            mock.patch.object(
                self.process, "stop_process_group", side_effect=TimeoutError("unconfirmed")
            ),
            self.assertRaises(ValueError) as caught,
        ):
            self.run_child(before_wait=fail)
        self.assertIs(caught.exception, failure)
        self.assertTrue(execution.group_running(self.children[0].pid))
        stop_supplier = mock.Mock()
        finish, report, log, temporary, result = self.finalizer(stop_supplier)
        finish(primary_error=failure)
        stop_supplier.assert_not_called()
        self.assertTrue(log.closed)
        self.assertTrue(temporary.is_dir())
        self.assertEqual(json.loads(result.read_text()), report)
        self.assertFalse(report["passed"])
        self.assertFalse(report["owned_suppliers_stopped"])
        self.assertFalse(report["owned_work_stopped"])
        self.assertEqual(report["unconfirmed_groups"], [self.children[0].pid])
        self.assertEqual(report["work_error"], "ValueError")
        self.assertEqual(report["cleanup_error"], "RuntimeError")
        self.assertIn("unconfirmed", failure.__notes__[0])

    def test_supplier_cleanup_error_closes_log_and_preserves_original_error(self):
        stop_supplier = mock.Mock(side_effect=TimeoutError("simulated supplier stop"))
        finish, report, log, temporary, result = self.finalizer(stop_supplier)
        failure = ValueError("work failure")
        finish(primary_error=failure)
        stop_supplier.assert_called_once()
        self.assertTrue(log.closed)
        self.assertTrue(temporary.is_dir())
        self.assertEqual(json.loads(result.read_text()), report)
        self.assertEqual(report["work_error"], "ValueError")
        self.assertEqual(report["cleanup_error"], "TimeoutError")
        self.assertFalse(report["owned_suppliers_stopped"])

    def test_runtime_finalizer_entry_signal_does_not_skip_supplier_cleanup(self):
        calls = []

        def stop_supplier(*args, **kwargs):
            self.process.check_cancellation()
            calls.append(args)
            return subprocess.CompletedProcess(args, 0)

        finish, report, log, temporary, result = self.finalizer(stop_supplier)
        target = finish.__code__.co_firstlineno + 1
        seen = []

        def trace(frame, event, _arg):
            if (
                frame.f_code is finish.__code__
                and event == "line"
                and frame.f_lineno == target
                and not seen
            ):
                seen.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                finish()
        finally:
            sys.settrace(previous)
        self.assertEqual(len(calls), 1)
        self.assertEqual(seen, [True])
        self.assertTrue(log.closed)
        self.assertTrue(temporary.is_dir())
        self.assertTrue(report["owned_suppliers_stopped"])
        self.assertTrue(report["cancellation_recorded"])
        self.assertFalse(json.loads(result.read_text())["passed"])

    def test_successful_cleanup_removes_private_fixture_after_confirmation(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, temporary, result = self.finalizer(stop_supplier)
        finish()
        self.assertTrue(log.closed)
        self.assertFalse(temporary.exists())
        self.assertTrue(report["passed"])
        self.assertTrue(report["owned_work_stopped"])
        self.assertTrue(json.loads(result.read_text())["owned_suppliers_stopped"])

    @contextlib.contextmanager
    def report_write_signal(self, result, *, after=False, repeat=False, rewrite_error=None):
        original = Path.write_text
        writes = []

        def write(path, text, *args, **kwargs):
            if path != result:
                return original(path, text, *args, **kwargs)
            writes.append(json.loads(text))
            self.assertLessEqual(len(writes), 2)
            if len(writes) == 2 and rewrite_error is not None:
                raise rewrite_error
            signal_now = len(writes) == 1 or repeat
            if signal_now and not after:
                os.kill(os.getpid(), signal.SIGTERM)
            value = original(path, text, *args, **kwargs)
            if signal_now and after:
                os.kill(os.getpid(), signal.SIGTERM)
            return value

        with mock.patch.object(Path, "write_text", write):
            yield writes

    def assert_report_cancelled(self, report, log, result, stop_supplier):
        stop_supplier.assert_called_once()
        self.assertTrue(log.closed)
        self.assertFalse(report["passed"])
        self.assertTrue(report["cancellation_recorded"])
        self.assertEqual(json.loads(result.read_text()), report)

    def test_report_write_cancellation_rewrites_once(self):
        for after in (False, True):
            with self.subTest(after_write=after), tempfile.TemporaryDirectory() as directory:
                self.process.install_cancellation()
                stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
                with mock.patch.object(self, "directory", Path(directory)):
                    finish, report, log, _, result = self.finalizer(stop_supplier)
                with (
                    self.report_write_signal(result, after=after, repeat=True) as writes,
                    self.assertRaisesRegex(RuntimeError, "signal 15"),
                ):
                    finish()
                self.assertEqual(len(writes), 2)
                self.assertTrue(writes[0]["passed"])
                self.assert_report_cancelled(report, log, result, stop_supplier)

    def test_report_cleanup_scope_exit_cancellation_rewrites_once(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, _, result = self.finalizer(stop_supplier)
        actual_scope = self.process.cleanup_scope

        @contextlib.contextmanager
        def interrupted_scope():
            with actual_scope():
                yield
            os.kill(os.getpid(), signal.SIGINT)

        finish.__globals__["cleanup_scope"] = interrupted_scope
        with self.assertRaisesRegex(RuntimeError, "signal 2"):
            finish()
        self.assert_report_cancelled(report, log, result, stop_supplier)

    def test_report_rewrite_error_fails_even_when_old_bytes_claim_success(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, _, result = self.finalizer(stop_supplier)
        failure = OSError("report rewrite failed")
        with (
            self.report_write_signal(result, rewrite_error=failure) as writes,
            self.assertRaises(OSError) as caught,
        ):
            finish()
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(writes), 2)
        stop_supplier.assert_called_once()
        self.assertTrue(log.closed)
        self.assertFalse(report["passed"])
        self.assertTrue(report["cancellation_recorded"])
        # An I/O failure may prevent correcting retained bytes; execution failed.
        self.assertTrue(json.loads(result.read_text())["passed"])

    def test_report_work_error_keeps_priority_over_cancelled_rewrite_error(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, temporary, result = self.finalizer(stop_supplier)
        failure = ValueError("original work failure")
        with self.report_write_signal(result, rewrite_error=OSError("rewrite")) as writes:
            finish(primary_error=failure)
        self.assertEqual(len(writes), 2)
        self.assertEqual(failure.__notes__, ["fixture cleanup failed: OSError"])
        self.assertEqual(report["work_error"], "ValueError")
        self.assertFalse(json.loads(result.read_text())["passed"])
        self.assertTrue(report["cancellation_recorded"])
        self.assertTrue(temporary.exists())
        self.assertTrue(log.closed)
        stop_supplier.assert_called_once()

    def test_report_cleanup_error_keeps_priority_over_cancelled_rewrite_error(self):
        failure = TimeoutError("original supplier stop failure")
        stop_supplier = mock.Mock(side_effect=failure)
        finish, report, log, _, result = self.finalizer(stop_supplier)
        with (
            self.report_write_signal(result, rewrite_error=OSError("rewrite")) as writes,
            self.assertRaises(TimeoutError) as caught,
        ):
            finish()
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(writes), 2)
        self.assertEqual(report["cleanup_error"], "TimeoutError")
        self.assertFalse(json.loads(result.read_text())["passed"])
        self.assertTrue(report["cancellation_recorded"])
        self.assertTrue(log.closed)
        stop_supplier.assert_called_once()

    def test_report_work_error_remains_primary_after_successful_cancelled_rewrite(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, _, result = self.finalizer(stop_supplier)
        failure = ValueError("original work failure")
        with self.report_write_signal(result) as writes:
            finish(primary_error=failure)
        self.assertEqual(len(writes), 2)
        self.assertEqual(report["work_error"], "ValueError")
        self.assertFalse(hasattr(failure, "__notes__"))
        self.assert_report_cancelled(report, log, result, stop_supplier)

    def test_report_cancellation_after_final_snapshot_is_outside_completion_boundary(self):
        stop_supplier = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        finish, report, log, _, result = self.finalizer(stop_supplier)
        path = ROOT / "tests/organizations/current_runtime.py"
        line = next(
            i
            for i, text in enumerate(path.read_text().splitlines(), 1)
            if text.strip() == 'if cancelled and not report["cancellation_recorded"]:'
        )
        seen = []

        def trace(frame, event, _arg):
            if frame.f_code is finish.__code__ and event == "line" and frame.f_lineno == line:
                seen.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            finish()
        finally:
            sys.settrace(previous)
        self.assertEqual(seen, [True])
        self.assertTrue(self.process.cancellation_recorded())
        self.assertTrue(report["passed"])
        self.assertFalse(report["cancellation_recorded"])
        self.assertTrue(log.closed)
        self.assertEqual(json.loads(result.read_text()), report)
        stop_supplier.assert_called_once()

    def test_polling_preserves_input_output_and_nonzero_status(self):
        data = "x" * 131072
        result = self.run_child(
            code=(
                "import sys,time; time.sleep(.15); data=sys.stdin.read(); "
                "print(len(data)); print('err',file=sys.stderr); sys.exit(37)"
            ),
            data=data,
        )
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (37, "131072\n", "err\n")
        )
        self.assertEqual(self.process.unconfirmed_groups(), [])

    def test_known_nonzero_status_survives_cancellation_during_confirmed_cleanup(self):
        stop_owned = self.process.stop_owned

        def stop_and_cancel(child, **kwargs):
            stop_owned(child, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)

        for status, retain_supplier in ((0, False), (37, False), (37, True)):
            with self.subTest(status=status, retain_supplier=retain_supplier):
                self.process.install_cancellation()
                code = (
                    f"import sys; print('out'); print('err', file=sys.stderr); sys.exit({status})"
                )
                with mock.patch.object(self.process, "stop_owned", side_effect=stop_and_cancel):
                    if status == 0:
                        with self.assertRaisesRegex(RuntimeError, "interrupted by signal 15"):
                            self.run_child(code=code, retain_supplier=retain_supplier)
                    else:
                        result = self.run_child(code=code, retain_supplier=retain_supplier)
                        self.assertEqual(
                            (result.returncode, result.stdout, result.stderr),
                            (status, "out\n", "err\n"),
                        )
                self.assertEqual(self.process.unconfirmed_groups(), [])
                self.assertEqual(self.process.supplier_start_groups(), [])
                self.assertFalse(execution.group_running(self.children[-1].pid))
                with self.assertRaisesRegex(RuntimeError, "interrupted by signal 15"):
                    self.process.check_cancellation()

    def test_outage_nonzero_drain_survives_cancellation_during_confirmed_cleanup(self):  # noqa: PLR0915 - keep the actual child and signal boundary together.
        with mock.patch.dict(
            sys.modules,
            {
                "current_process": self.process,
                "psycopg": types.ModuleType("psycopg"),
                "current_database": types.SimpleNamespace(connect=mock.Mock()),
                "current_http": types.SimpleNamespace(
                    ConnectionFailureError=OSError,
                    pause=mock.Mock(),
                    poll_all=mock.Mock(),
                    probes=mock.Mock(),
                    response=mock.Mock(),
                ),
            },
        ):
            outage = load_module("owned_outage", ROOT / "tests/organizations/current_outage.py")
        stop_owned = self.process.stop_owned

        def stop_and_cancel(child):
            stop_owned(child)
            os.kill(os.getpid(), signal.SIGTERM)

        for status in (0, 37):
            with self.subTest(status=status):
                self.process.install_cancellation()
                directory = self.directory / f"drain-{status}"
                directory.mkdir()
                fixture = object.__new__(outage.OutageFixture)
                fixture.directory, fixture.root = directory, self.directory
                fixture.environment = dict(os.environ)
                fixture.command = [
                    sys.executable,
                    "-c",
                    f"import sys; print('out'); print('err', file=sys.stderr); sys.exit({status})",
                ]
                fixture.running = True
                fixture.ready = mock.Mock(side_effect=lambda child: child.wait(timeout=3))
                fixture.outage = mock.Mock(return_value={})
                fixture.pg_control = mock.Mock(side_effect=AssertionError("unexpected PG call"))
                fixture.stale_generation = mock.Mock()
                expected = RuntimeError if status == 0 else AssertionError
                message = "interrupted by signal 15" if status == 0 else "did not drain cleanly"
                with (
                    mock.patch.object(outage.subprocess, "Popen", side_effect=self.popen),
                    mock.patch.object(outage, "stop_owned", side_effect=stop_and_cancel),
                    self.assertRaisesRegex(expected, message),
                ):
                    fixture.exercise()
                self.assertEqual(self.children[-1].returncode, status)
                self.assertEqual(self.process.unconfirmed_groups(), [])
                self.assertEqual(self.process.supplier_start_groups(), [])
                self.assertFalse(execution.group_running(self.children[-1].pid))
                self.assertCountEqual(
                    (directory / "outage-server.log").read_text().splitlines(), ["out", "err"]
                )
                fixture.pg_control.assert_not_called()
                fixture.stale_generation.assert_not_called()
                with self.assertRaisesRegex(RuntimeError, "interrupted by signal 15"):
                    self.process.check_cancellation()

    def test_outage_work_error_still_confirms_child_group_after_stop_error(self):
        with mock.patch.dict(
            sys.modules,
            {
                "current_process": self.process,
                "psycopg": types.ModuleType("psycopg"),
                "current_database": types.SimpleNamespace(connect=mock.Mock()),
                "current_http": types.SimpleNamespace(
                    ConnectionFailureError=OSError,
                    pause=mock.Mock(),
                    poll_all=mock.Mock(),
                    probes=mock.Mock(),
                    response=mock.Mock(),
                ),
            },
        ):
            outage = load_module("owned_outage", ROOT / "tests/organizations/current_outage.py")
        fixture = object.__new__(outage.OutageFixture)
        fixture.directory, fixture.root = self.directory, self.directory
        fixture.environment = dict(os.environ)
        fixture.command = [sys.executable, "-c", "import time; time.sleep(60)"]
        failure = ValueError("original outage failure")
        fixture.ready = mock.Mock(side_effect=failure)
        fixture.stop = mock.Mock(side_effect=RuntimeError("simulated supplier restart failure"))
        with (
            mock.patch.object(outage.subprocess, "Popen", side_effect=self.popen),
            self.assertRaises(ValueError) as caught,
        ):
            fixture.exercise()
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.process.unconfirmed_groups(), [])
        self.assertFalse(execution.group_running(self.children[0].pid))
        self.assertIn("outage cleanup failed", failure.__notes__[0])


if __name__ == "__main__":
    unittest.main()
