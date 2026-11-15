"""Actual descendant cleanup after command exit, cancellation and output limits."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Each fixture is a separate Linux subreaper so its orphaned children are reaped
# here even when exercising the preceding broken implementation.
CONTROLLER = r'''
import ctypes, json, os, signal, subprocess, sys, threading, time
from pathlib import Path
root, directory = Path(sys.argv[1]), Path(sys.argv[2])
runner, fault, delay = sys.argv[3:]
sys.path[:0] = [str(root/'scripts/ci'), str(root/'scripts/validation'),
               str(root/'tests/organizations')]
import database_execution as execution
import run_database_lanes as lanes
from build_observations import run_observed
import with_organization_userns as namespace
import current_process
lanes.CONTROLLER_GRACE = 4  # Includes the nested fixture's actual two-second cleanup.
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
pid_file = directory/'descendant.json'
spawner = directory/'spawner.py'
spawner.write_text("""
import json, os, signal, sys, time
from pathlib import Path
pid_file, fault = Path(sys.argv[1]), sys.argv[2]
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if not fault.startswith('pipe'):
        os.close(1)
        os.close(2)
    pending = pid_file.with_suffix('.tmp')
    pending.write_text(json.dumps({'pid': os.getpid(), 'group': os.getpgrp()}))
    pending.replace(pid_file)
    time.sleep(60)
    os._exit(0)
while not pid_file.exists(): time.sleep(.005)
if fault == 'log-limit':
    print('x'*4096, flush=True)
    time.sleep(60)
elif fault.startswith('cancel') or fault == 'deadline':
    time.sleep(60)
else:
    print('complete output', flush=True)
    os._exit(37 if fault in ('exit37', 'pipe37') else 0)
""")
command = [sys.executable, str(spawner), str(pid_file), fault]
if runner == 'namespace':
    observer = directory/'observer.py'
    observer.write_text("""
import sys
from pathlib import Path
root, directory = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(root/'scripts/ci'))
from build_observations import run_observed
run_observed(sys.argv[3:], directory/'observations.jsonl')
""")
    command = [sys.executable, str(observer), str(root), str(directory), *command]
if runner == 'nested':
    nested = directory/'nested.py'
    nested.write_text("""
import json, signal, sys
from pathlib import Path
root, directory = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(root/'scripts/validation'))
import database_execution as execution
def cancelled(signum, frame): raise SystemExit(128+signum)
signal.signal(signal.SIGTERM, cancelled)
command = sys.argv[3:]
plan = {'suites': {}, 'auxiliaries': ['probe'], 'package': str(directory),
        'context': {}, 'build_sha256': 'fixture'}
plan_path = directory/'nested-plan.json'
plan_path.write_text('{}')
execution.load_plan = lambda path: plan
execution.bind_package = lambda plan, path: None
execution.owned_command = lambda plan, name: command
execution.owned_cwd = lambda name: directory
execution.initialize_receipts(plan_path, directory/'nested-results')
execution.execute(plan_path, directory/'nested-results', 'probe', command)
""")
    wrapper = directory/'wrapper.py'
    wrapper.write_text('import subprocess,sys,time; subprocess.Popen(sys.argv[1:]); '
                       'time.sleep(60)')
    command = [sys.executable, str(wrapper), sys.executable, str(nested),
               str(root), str(directory), *command]
event = threading.Event()
record = {'runner': runner, 'fault': fault}
watchdog_done = threading.Event()
def alive(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1][0] not in ('Z', 'X')
    except FileNotFoundError: return False
def release_pipe_on_failure():
    # Receipt preparation can precede the child. Only time an actual pipe holder;
    # the outer subprocess timeout still bounds the entire fixture.
    while not pid_file.exists():
        if watchdog_done.wait(.01): return
    if watchdog_done.wait(15 if runner in ('observation', 'current') else 6): return
    child = json.loads(pid_file.read_text())['pid']
    # Receipt finalization can outlast cleanup. It cannot hold the output pipe
    # once the descendant has exited, and must not become a cleanup failure.
    if alive(child):
        record['watchdog_triggered'] = True
        try: os.kill(child, signal.SIGKILL)
        except ProcessLookupError: pass
watchdog = None
if fault.startswith('pipe'):
    watchdog = threading.Thread(target=release_pipe_on_failure, daemon=True)
    watchdog.start()
if fault == 'inspection':
    def unavailable_inspection(group): raise RuntimeError('process inspection unavailable')
    execution.group_running = unavailable_inspection
def trigger():
    deadline = time.monotonic()+5
    while not pid_file.exists() and time.monotonic()<deadline: time.sleep(.01)
    if runner in ('lane', 'nested', 'capture'): event.set()
    else: os.kill(os.getpid(), signal.SIGTERM)
    if fault == 'cancel-double':
        time.sleep(.05)
        os.kill(os.getpid(), signal.SIGINT)
def cancelled(signum, frame): raise SystemExit(128+signum)
signal.signal(signal.SIGTERM, cancelled)
timer = None
try:
    if fault.startswith('cancel'):
        timer = threading.Thread(target=trigger, daemon=True)
        timer.start()
    if runner == 'capture':
        lanes.CAPTURE_TIMEOUT = .5 if fault == 'deadline' else 8
        record['stdout'] = lanes.capture(command, dict(os.environ), cancelled=event)
        record['status'] = 0
    elif runner in ('lane', 'nested'):
        with (directory/'command.log').open('wb') as output:
            record['status'] = lanes.command(command, dict(os.environ), output, event,
                                            timeout=.5 if fault == 'deadline' else 8)
    elif runner == 'observation':
        run_observed(command, directory/'observations.jsonl')
        record['status'] = 0
    elif runner == 'namespace':
        namespace.prepare = lambda *args: None
        def remove_policy(*args):
            child = json.loads(pid_file.read_text())['pid']
            record['policy_removed_with_live_descendant'] = alive(child)
        namespace.cleanup = remove_policy
        sys.argv = ['with_organization_userns.py', '--report',
                    str(directory/'namespace.json'), '--', *command]
        record['status'] = namespace.main()
    elif runner in ('current', 'retained-failure'):
        current_process.install_cancellation()
        try:
            result = current_process.run_owned(command, root=directory, env=dict(os.environ),
                         timeout=.5 if fault == 'deadline' else 8,
                         retain_supplier=runner == 'retained-failure')
            record['status'] = result.returncode
            record['stdout'] = result.stdout
            record['stderr'] = result.stderr
        finally:
            current_process.ignore_cancellation()
    else:
        plan_path = directory/'plan.json'
        plan_path.write_text('{}')
        plan = {'suites': {}, 'auxiliaries': ['probe'], 'package': str(directory),
                'context': {}, 'build_sha256': 'fixture'}
        execution.load_plan = lambda path: plan
        execution.bind_package = lambda plan, path: None
        execution.owned_command = lambda plan, name: command
        execution.owned_cwd = lambda name: directory
        if fault == 'log-limit': execution.MAX_LOG_BYTES = 64
        if delay == 'preparation': time.sleep(7)
        if delay == 'receipt':
            original_finish = execution.finish_receipt
            def delayed_finish(*args):
                record['descendant_alive_before_receipt_delay'] = alive(
                    json.loads(pid_file.read_text())['pid'])
                time.sleep(7)
                return original_finish(*args)
            execution.finish_receipt = delayed_finish
        execution.initialize_receipts(plan_path, directory/'results')
        record['status'] = execution.execute(plan_path, directory/'results', 'probe', command)
except BaseException as error:
    record['error'] = type(error).__name__
    record['message'] = str(error)
    if runner == 'capture':
        record['error_command'] = getattr(error, 'cmd', None)
        record['error_timeout'] = getattr(error, 'timeout', None)
        record['error_output'] = getattr(error, 'output', None)
        record['error_output_is_bytes'] = isinstance(record['error_output'], bytes)
        if isinstance(record['error_output'], bytes):
            record['error_output'] = record['error_output'].decode()
        record['error_returncode'] = getattr(error, 'returncode', None)
        record['unconfirmed_group'] = getattr(error, 'group', None)
finally:
    record['signal_handler_restored'] = signal.getsignal(signal.SIGTERM) is cancelled
    watchdog_done.set()
    if watchdog: watchdog.join(timeout=1)
    if timer: timer.join(timeout=1)
    if pid_file.exists():
        child = json.loads(pid_file.read_text())['pid']
        if fault == 'inspection':
            # Failed inspection cannot certify cleanup, but must still send KILL.
            deadline = time.monotonic()+1
            while alive(child) and time.monotonic()<deadline: time.sleep(.01)
        record['descendant_alive_after_return'] = alive(child)
        group = json.loads(pid_file.read_text())['group']
        try:
            if group != os.getpgrp(): os.killpg(group, signal.SIGKILL)
            else: os.kill(child, signal.SIGKILL)
        except ProcessLookupError: pass
        while True:
            try:
                os.waitpid(-1, 0)
            except ChildProcessError: break
        record['fixture_reaped'] = True
    (directory/'result.json').write_text(json.dumps(record))
'''


class DatabaseProcessCleanupTests(unittest.TestCase):
    def assert_completed_result(self, runner, fault, observed):
        self.assertIn("status", observed, observed)
        self.assertEqual(observed["status"], 37 if fault in ("exit37", "pipe37") else 0)
        if runner == "current":
            self.assertEqual(observed["stdout"], "complete output\n")
            self.assertEqual(observed["stderr"], "")

    def assert_capture_result(self, fault, observed):
        expected = {
            "exit37": "CalledProcessError",
            "pipe37": "CalledProcessError",
            "cancel": "InterruptedError",
            "deadline": "TimeoutExpired",
            "inspection": "UnconfirmedCommandCleanupError",
        }
        if fault not in expected:
            self.assertEqual(observed["stdout"], "complete output")
            return
        self.assertEqual(observed["error"], expected[fault])
        if fault in ("exit37", "pipe37"):
            self.assertEqual(observed["error_returncode"], 37)
            self.assertEqual(observed["error_output"], "complete output\n")
        elif fault == "deadline":
            self.assertEqual(observed["error_timeout"], 0.5)
            self.assertEqual(observed["error_command"][-1], "deadline")
            self.assertTrue(observed["error_output_is_bytes"])
        elif fault == "inspection":
            self.assertIsInstance(observed["unconfirmed_group"], int)

    def assert_stopped_result(self, runner, observed):
        self.assertTrue(observed.get("fixture_reaped"), observed)
        if runner not in ("namespace", "current", "retained-failure"):
            self.assertTrue(observed["signal_handler_restored"], observed)
        self.assertFalse(observed.get("watchdog_triggered"), observed)
        self.assertFalse(observed["descendant_alive_after_return"], observed)

    def scenario(self, runner, fault, *, delay="none"):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = subprocess.run(  # noqa: S603 - fixed owned subprocess fixture
                [sys.executable, str(controller), str(ROOT), str(directory), runner, fault, delay],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads((directory / "result.json").read_text())
            self.assert_stopped_result(runner, observed)
            if runner == "namespace":
                self.assertEqual(observed["status"], 1)
                self.assertFalse(observed["policy_removed_with_live_descendant"], observed)
            elif runner in ("observation", "capture") and fault in ("exit37", "pipe37"):
                self.assertEqual(observed["error"], "CalledProcessError")
            elif fault in ("exit0", "exit37", "pipe0", "pipe37"):
                self.assert_completed_result(runner, fault, observed)
                if runner == "auxiliary":
                    self.assertEqual(
                        (directory / "results/probe.log").read_bytes(), b"complete output\n"
                    )
            else:
                self.assertIn("error", observed)
                if runner == "current" and fault.startswith("cancel"):
                    self.assertEqual(observed["error"], "RuntimeError", observed)
                    self.assertIn("interrupted by signal", observed["message"])
            if runner == "capture":
                self.assert_capture_result(fault, observed)
            if runner == "auxiliary":
                receipt = json.loads((directory / "results/probe.json").read_text())
                self.assertEqual(receipt["complete"], fault in ("exit0", "pipe0"))
            return observed

    def test_lane_stops_descendants_after_leader_exit(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario("lane", fault)

    def test_capture_stops_descendants_after_success_and_nonzero_exit(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario("capture", fault)

    def test_capture_does_not_wait_for_descendant_held_output(self):
        for fault in ("pipe0", "pipe37"):
            with self.subTest(fault=fault):
                self.scenario("capture", fault)

    def test_capture_stops_descendants_on_cancel_timeout_and_inspection_error(self):
        for fault in ("cancel", "deadline", "inspection"):
            with self.subTest(fault=fault):
                self.scenario("capture", fault)

    def test_lane_stops_descendants_on_cancel_and_deadline(self):
        for fault in ("cancel", "deadline"):
            with self.subTest(fault=fault):
                self.scenario("lane", fault)

    def test_auxiliary_stops_descendants_after_leader_exit(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario("auxiliary", fault)

    def test_auxiliary_stops_descendants_on_cancel_and_log_limit(self):
        for fault in ("cancel", "log-limit"):
            with self.subTest(fault=fault):
                self.scenario("auxiliary", fault)

    def test_outer_cancellation_waits_for_nested_group_cleanup(self):
        self.scenario("nested", "cancel")

    def test_inspection_failure_still_kills_group_and_rejects_receipt(self):
        self.scenario("auxiliary", "inspection")

    def test_auxiliary_stops_descendants_holding_output_pipes(self):
        for fault in ("pipe0", "pipe37"):
            with self.subTest(fault=fault):
                self.scenario("auxiliary", fault)

    def test_auxiliary_watchdog_excludes_receipt_preparation(self):
        self.scenario("auxiliary", "pipe0", delay="preparation")

    def test_auxiliary_watchdog_excludes_finalized_cleanup(self):
        observed = self.scenario("auxiliary", "pipe0", delay="receipt")
        self.assertFalse(observed["descendant_alive_before_receipt_delay"], observed)

    def test_observation_wrapper_cleans_up_without_held_pipe_or_signal_bypass(self):
        for fault in ("exit0", "exit37", "pipe0", "pipe37", "cancel"):
            with self.subTest(fault=fault):
                self.scenario("observation", fault)

    def test_namespace_wrapper_waits_for_observer_before_policy_removal(self):
        self.scenario("namespace", "cancel")

    def test_recovery_command_stops_nested_group_on_cancel_and_timeout(self):
        for fault in ("cancel-double", "deadline"):
            with self.subTest(fault=fault):
                self.scenario("current", fault)

    def test_recovery_command_stops_descendants_after_success_and_failure(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario("current", fault)

    def test_failed_supplier_start_cannot_retain_descendants(self):
        self.scenario("retained-failure", "exit37")

    def test_recovery_command_preserves_exit_status_with_inherited_output(self):
        for fault in ("pipe0", "pipe37"):
            with self.subTest(fault=fault):
                self.scenario("current", fault)

    def test_repeated_termination_does_not_interrupt_group_cleanup(self):
        self.scenario("auxiliary", "cancel-double")


if __name__ == "__main__":
    unittest.main()
