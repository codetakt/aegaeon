"""Deliver the first real signal exactly when an owned finalizer is entered."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions survive Python -O.
import json
import sys
import tempfile
import unittest
from pathlib import Path

from fixture_processes import run_fixture

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = r"""
import inspect, json, os, signal, subprocess, sys
from pathlib import Path
root, directory, kind = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path[:0] = [str(root/'scripts/validation'), str(root/'scripts/ci')]
import database_execution as execution
import build_observations as observations
pid_file = directory/'child.pid'
child_code = ('import os,sys,time; from pathlib import Path; '
              'Path(sys.argv[1]).write_text(str(os.getpid())); '
              'print("owned output",file=sys.stderr,flush=True); time.sleep(60)')
command = [sys.executable, '-c', child_code, str(pid_file)]
plan_path = directory/'plan.json'
plan_path.write_text('{}')
plan = {'suites': {}, 'auxiliaries': ['probe'], 'package': str(directory),
        'context': {}, 'build_sha256': 'fixture'}
execution.load_plan = lambda path: plan
execution.bind_package = lambda plan, path: None
execution.owned_command = lambda plan, name: command
execution.owned_cwd = lambda name: directory
execution.initialize_receipts(plan_path, directory/'results')
execution.MAX_LOG_BYTES = 1
target = (getattr(execution, 'execute_recorded', execution.execute)
          if kind == 'database' else observations.observe_process)
lines, start = inspect.getsourcelines(target)
entry = [start+i for i,line in enumerate(lines)
         if line.strip() == 'if process is not None and not cleaned:']
assert len(entry) == 1
record = {'kind':kind}
def trace(frame, event, arg):
    if (event == 'line' and frame.f_code is target.__code__
            and frame.f_lineno == entry[0] and not record.get('signal_sent')):
        record['signal_sent'] = True
        os.kill(os.getpid(), signal.SIGTERM)
    return trace
def fail_forward(chunk):
    raise ValueError('controlled output failure')
try:
    sys.settrace(trace)
    if kind == 'database':
        execution.execute(plan_path, directory/'results', 'probe', command)
    else:
        with execution.cancellation_scope():
            observations.observe_process(command, fail_forward)
except BaseException as error:
    record.update(error=type(error).__name__, message=str(error))
finally:
    sys.settrace(None)
    pid = int(pid_file.read_text())
    try:
        record['child_alive_after_return'] = (
            Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0] not in ('Z','X'))
    except FileNotFoundError:
        record['child_alive_after_return'] = False
    try: os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError: pass
    try: os.waitpid(pid,0)
    except ChildProcessError: pass
    record['fixture_reaped'] = True
    receipt = directory/'results/probe.json'
    if receipt.exists(): record['receipt'] = json.loads(receipt.read_text())
    (directory/'result.json').write_text(json.dumps(record))
"""


class FinalizerEntryTests(unittest.TestCase):
    def test_first_signal_at_finalizer_entry_preserves_stop_and_primary_error(self):
        for kind in ("database", "build"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                controller = directory / "controller.py"
                controller.write_text(CONTROLLER)
                result = run_fixture(
                    [sys.executable, str(controller), str(ROOT), str(directory), kind],
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads((directory / "result.json").read_text())
                self.assertTrue(record["signal_sent"] and record["fixture_reaped"], record)
                self.assertFalse(record["child_alive_after_return"], record)
                self.assertEqual(record["error"], "ValueError", record)
                if kind == "database":
                    self.assertFalse(record["receipt"]["complete"])
                    self.assertTrue(record["receipt"]["process_cleanup_confirmed"])


if __name__ == "__main__":
    unittest.main()
