"""Stop real descendants before returning to coverage supplier teardown."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CONTROLLER = r'''
import ctypes, json, os, signal, subprocess, sys, threading, time
from pathlib import Path
root, directory, fault = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root/'scripts/ci'))
import run_coverage as coverage
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
    def cleanup(signum, frame):
        time.sleep(.3)
        pid_file.with_name('cleaned').touch()
        os._exit(0)
    signal.signal(signal.SIGTERM, cleanup if fault == 'graceful-cancel' else signal.SIG_IGN)
    os.close(1)
    os.close(2)
    ready = pid_file.with_suffix('.tmp')
    ready.write_text(json.dumps({'pid': os.getpid(), 'group': os.getpgrp()}))
    ready.replace(pid_file)
    time.sleep(60)
    os._exit(0)
while not pid_file.exists(): time.sleep(.005)
if fault in ('cancel', 'graceful-cancel', 'deadline'): time.sleep(60)
else: os._exit(37 if fault == 'exit37' else 0)
""")
command = [sys.executable, str(spawner), str(pid_file), fault]
event = threading.Event()
record = {'fault': fault}
if fault == 'inspection':
    def unavailable(group): raise RuntimeError('process inspection unavailable')
    coverage.group_running = unavailable
def alive(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1][0] not in ('Z', 'X')
    except FileNotFoundError: return False
def trigger():
    deadline = time.monotonic()+5
    while not pid_file.exists() and time.monotonic()<deadline: time.sleep(.01)
    event.set()
timer = None
try:
    if fault in ('cancel', 'graceful-cancel'):
        timer = threading.Thread(target=trigger, daemon=True)
        timer.start()
    coverage.command(command, dict(os.environ), event, .5 if fault == 'deadline' else 8)
    record['status'] = 0
except subprocess.CalledProcessError as error:
    record['status'] = error.returncode
except BaseException as error:
    record['error'] = type(error).__name__
finally:
    if timer: timer.join(timeout=1)
    if pid_file.exists():
        child = json.loads(pid_file.read_text())['pid']
        record['descendant_alive_after_return'] = alive(child)
        record['cleanup_completed'] = pid_file.with_name('cleaned').exists()
        if fault == 'inspection':
            deadline = time.monotonic()+1
            while alive(child) and time.monotonic()<deadline: time.sleep(.01)
            record['descendant_alive_after_inspection_failure'] = alive(child)
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


class CoverageProcessCleanupTests(unittest.TestCase):
    def scenario(self, fault):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = subprocess.run(  # noqa: S603 - fixed owned subprocess fixture
                [sys.executable, str(controller), str(ROOT), str(directory), fault],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads((directory / "result.json").read_text())
            self.assertTrue(observed.get("fixture_reaped"), observed)
            if fault == "inspection":
                self.assertEqual(observed.get("error"), "RuntimeError", observed)
                self.assertFalse(observed["descendant_alive_after_inspection_failure"], observed)
            else:
                self.assertFalse(observed["descendant_alive_after_return"], observed)
            if fault == "graceful-cancel":
                self.assertTrue(observed["cleanup_completed"], observed)
            if fault in ("exit0", "exit37"):
                self.assertEqual(observed["status"], 37 if fault == "exit37" else 0)
            else:
                self.assertIn("error", observed)

    def test_no_live_descendant_after_leader_exit(self):
        for fault in ("exit0", "exit37"):
            with self.subTest(fault=fault):
                self.scenario(fault)

    def test_no_live_descendant_after_cancel_or_deadline(self):
        for fault in ("cancel", "deadline"):
            with self.subTest(fault=fault):
                self.scenario(fault)

    def test_cancellation_preserves_descendant_cleanup_grace(self):
        self.scenario("graceful-cancel")

    def test_inspection_failure_still_kills_and_rejects_cleanup(self):
        self.scenario("inspection")


if __name__ == "__main__":
    unittest.main()
