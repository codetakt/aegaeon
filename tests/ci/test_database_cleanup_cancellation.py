"""Cancellation during cleanup must allow a nested supplier owner to finish."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions stay active under Python -O.
import json
import sys
import tempfile
import unittest
from pathlib import Path

from fixture_processes import run_fixture

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = r'''
import contextlib, ctypes, json, os, signal, subprocess, sys, threading, time
from pathlib import Path
root, directory, fault, handler = Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:]
sys.path[:0] = [str(root/'scripts/validation'),str(root/'scripts/ci'),
               str(root/'tests/organizations')]
import database_execution as execution
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
nested = directory/'nested.py'
nested.write_text("""
import json, os, signal, subprocess, sys, time
from pathlib import Path
d = Path(sys.argv[1])
if os.fork() != 0:
    while not (d/'ready.json').exists(): time.sleep(.005)
    os._exit(0)
supplier = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                            start_new_session=True)
def finish(signum, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    (d/'cleanup-started').write_text('started')
    time.sleep(.35)
    os.killpg(supplier.pid, signal.SIGTERM)
    supplier.wait(timeout=2)
    (d/'cleanup-complete').write_text('complete')
    os._exit(0)
signal.signal(signal.SIGTERM, finish)
pending = d/'ready.tmp'
pending.write_text(json.dumps({'controller':os.getpid(), 'supplier':supplier.pid}))
pending.replace(d/'ready.json')
while True: time.sleep(1)
""")
leader = subprocess.Popen([sys.executable, str(nested), str(directory)], start_new_session=True)
record = {'fault':fault, 'false_inspections':0}
def alive(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0] not in ('Z','X')
    except FileNotFoundError: return False
original_inspect = execution.group_running
def inspect(group):
    result = original_inspect(group)
    if not result:
        record['false_inspections'] += 1
        if fault == 'inspection-error': raise RuntimeError('controlled inspection failure')
        if fault == 'confirmation' and record['false_inspections'] == 2:
            (directory/'confirmation-started').write_text('started')
            time.sleep(.2)
        record['completed_false_inspections'] = record.get('completed_false_inspections',0)+1
    return result
execution.group_running = inspect
def trigger():
    marker = directory/('confirmation-started' if fault == 'confirmation' else 'cleanup-started')
    deadline = time.monotonic()+5
    while not marker.exists() and time.monotonic()<deadline: time.sleep(.005)
    if not marker.exists(): return
    record['signal_sent'] = True
    os.kill(os.getpid(), signal.SIGINT if fault in ('sigint','confirmation') else signal.SIGTERM)
    if fault == 'repeated':
        time.sleep(.05)
        os.kill(os.getpid(), signal.SIGINT)
sender = None
scope = execution.cancellation_scope
if handler == 'current':
    import current_process
    current_process.install_cancellation()
    scope = contextlib.nullcontext
elif handler == 'namespace':
    import with_organization_userns as namespace
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,namespace.interrupted)
    scope = contextlib.nullcontext
previous = {sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
try:
    leader.wait(timeout=5)
    record['leader_status'] = leader.returncode
    with scope():
        if fault == 'worker':
            def cleanup_worker():
                try: execution.stop_process_group(leader,grace=2)
                except BaseException as error:
                    record.update(error=type(error).__name__,message=str(error))
            worker = threading.Thread(target=cleanup_worker,daemon=True)
            worker.start()
            worker.join(timeout=5)
            record['worker_alive'] = worker.is_alive()
        else:
            sender = threading.Thread(target=trigger, daemon=True)
            sender.start()
            execution.stop_process_group(leader, grace=2)
            if handler == 'current': current_process.check_cancellation()
    record['returned'] = True
except BaseException as error:
    record.update(error=type(error).__name__, message=str(error))
finally:
    if handler == 'namespace':
        record['namespace_cancellation'] = str(namespace._cancellation)
    record['handlers_restored'] = all(
        signal.getsignal(sig)==handler for sig,handler in previous.items())
    # The broken negative may return before the repeated signal; fixture teardown
    # still owns and must reap every separate-session supplier.
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,signal.SIG_IGN)
    if sender: sender.join(timeout=1)
    identities = json.loads((directory/'ready.json').read_text())
    record.update(cleanup_complete=(directory/'cleanup-complete').exists(),
                  supplier_alive=alive(identities['supplier']),
                  controller_alive=alive(identities['controller']))
    for group in (leader.pid, identities['supplier']):
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass
    while True:
        try: os.waitpid(-1,0)
        except ChildProcessError: break
    record['fixture_reaped'] = True
    (directory/'result.json').write_text(json.dumps(record))
'''


class CleanupCancellationTests(unittest.TestCase):
    def scenario(self, fault, handler="execution"):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = run_fixture(
                [sys.executable, str(controller), str(ROOT), str(directory), fault, handler],
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((directory / "result.json").read_text())
            if fault != "worker":
                self.assertTrue(record.get("signal_sent"), record)
            self.assertEqual(record["leader_status"], 0, record)
            self.assertTrue(record["fixture_reaped"] and record["handlers_restored"], record)
            self.assertTrue(record["cleanup_complete"], record)
            self.assertFalse(record["supplier_alive"] or record["controller_alive"], record)
            return record

    def test_first_and_repeated_cancellation_wait_for_nested_cleanup(self):
        for fault in ("sigterm", "sigint", "repeated", "confirmation"):
            with self.subTest(fault=fault):
                record = self.scenario(fault)
                self.assertEqual(record["error"], "SystemExit", record)
                self.assertEqual(
                    record["message"], "130" if fault in ("sigint", "confirmation") else "143"
                )
                self.assertGreaterEqual(record.get("completed_false_inspections", 0), 2, record)

    def test_cleanup_error_is_preserved_over_pending_cancellation(self):
        record = self.scenario("inspection-error")
        self.assertEqual(record["error"], "RuntimeError", record)
        self.assertIn("controlled inspection failure", record["message"])

    def test_runtime_and_namespace_handlers_preserve_cleanup_and_its_error(self):
        for handler in ("current", "namespace"):
            for fault in ("sigterm", "inspection-error"):
                with self.subTest(handler=handler, fault=fault):
                    record = self.scenario(fault, handler)
                    if handler == "namespace" and fault == "sigterm":
                        self.assertNotIn("error", record)
                        self.assertIn("interrupted by signal", record["namespace_cancellation"])
                        continue
                    self.assertEqual(record["error"], "RuntimeError", record)
                    expected = (
                        "controlled inspection failure"
                        if fault == "inspection-error"
                        else "interrupted by signal"
                    )
                    self.assertIn(expected, record["message"])

    def test_worker_cleanup_preserves_main_thread_handlers(self):
        record = self.scenario("worker")
        self.assertNotIn("error", record)
        self.assertFalse(record["worker_alive"], record)
        self.assertTrue(record["returned"], record)


if __name__ == "__main__":
    unittest.main()
