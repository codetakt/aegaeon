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
root, directory, runner, fault = Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:]
sys.path[:0] = [str(root/'scripts/ci'), str(root/'scripts/validation')]
import database_execution as execution
import run_database_lanes as lanes
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
    os.close(1)
    os.close(2)
    pid_file.write_text(json.dumps({'pid': os.getpid(), 'group': os.getpgrp()}))
    time.sleep(60)
    os._exit(0)
while not pid_file.exists(): time.sleep(.005)
if fault == 'log-limit':
    print('x'*4096, flush=True)
    time.sleep(60)
elif fault in ('cancel', 'deadline'):
    time.sleep(60)
else:
    os._exit(37 if fault == 'exit37' else 0)
""")
command = [sys.executable, str(spawner), str(pid_file), fault]
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
execution.execute(plan_path, directory/'nested-results', 'probe', command)
""")
    wrapper = directory/'wrapper.py'
    wrapper.write_text('import subprocess,sys,time; subprocess.Popen(sys.argv[1:]); '
                       'time.sleep(60)')
    command = [sys.executable, str(wrapper), sys.executable, str(nested),
               str(root), str(directory), *command]
event = threading.Event()
record = {'runner': runner, 'fault': fault}
if fault == 'inspection':
    def unavailable_inspection(group): raise RuntimeError('process inspection unavailable')
    execution.group_running = unavailable_inspection
def alive(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError: return False
def trigger():
    deadline = time.monotonic()+5
    while not pid_file.exists() and time.monotonic()<deadline: time.sleep(.01)
    if runner in ('lane', 'nested'): event.set()
    else: os.kill(os.getpid(), signal.SIGTERM)
def cancelled(signum, frame): raise SystemExit(128+signum)
signal.signal(signal.SIGTERM, cancelled)
timer = None
try:
    if fault == 'cancel':
        timer = threading.Thread(target=trigger, daemon=True)
        timer.start()
    if runner in ('lane', 'nested'):
        with (directory/'command.log').open('wb') as output:
            record['status'] = lanes.command(command, dict(os.environ), output, event,
                                            timeout=.5 if fault == 'deadline' else 8)
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
        record['status'] = execution.execute(plan_path, directory/'results', 'probe', command)
except BaseException as error:
    record['error'] = type(error).__name__
    record['message'] = str(error)
finally:
    if timer: timer.join(timeout=1)
    if pid_file.exists():
        child = json.loads(pid_file.read_text())['pid']
        if fault == 'inspection':
            # Failed inspection cannot certify cleanup, but must still send KILL.
            deadline = time.monotonic()+1
            while alive(child) and time.monotonic()<deadline: time.sleep(.01)
        record['descendant_alive_after_return'] = alive(child)
        try: os.kill(child, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(child, 0)
        while True:
            try:
                reaped, _ = os.waitpid(-1, os.WNOHANG)
                if not reaped: break
            except ChildProcessError: break
        record['fixture_reaped'] = True
    (directory/'result.json').write_text(json.dumps(record))
'''


class DatabaseProcessCleanupTests(unittest.TestCase):
    def scenario(self, runner, fault):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = subprocess.run(  # noqa: S603 - fixed owned subprocess fixture
                [sys.executable, str(controller), str(ROOT), str(directory), runner, fault],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads((directory / "result.json").read_text())
            self.assertTrue(observed.get("fixture_reaped"), observed)
            self.assertFalse(observed["descendant_alive_after_return"], observed)
            if fault in ("exit0", "exit37"):
                self.assertEqual(observed["status"], 37 if fault == "exit37" else 0)
            else:
                self.assertIn("error", observed)
            if runner == "auxiliary":
                receipt = json.loads((directory / "results/probe.json").read_text())
                self.assertEqual(receipt["complete"], fault == "exit0")

    def test_lane_stops_descendants_after_leader_exit(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario("lane", fault)

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


if __name__ == "__main__":
    unittest.main()
