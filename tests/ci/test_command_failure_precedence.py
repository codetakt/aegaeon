"""Keep observed command failures when real cancellation arrives during cleanup."""

from __future__ import annotations

# ruff: noqa: PT009, S603 - fixed owned subprocesses; assertions remain active under -O.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = r'''
import ctypes, json, os, signal, subprocess, sys, time
from pathlib import Path
root, directory, boundary = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
code = int(sys.argv[4])
sys.path[:0] = [str(root/'scripts/validation'), str(root/'scripts/ci')]
import database_execution as execution
import build_observations as observed
import with_organization_userns as namespace
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
ready, release = directory/'ready', directory/'release'
script = directory/'child.py'
script.write_text("""
import os, sys, time
from pathlib import Path
ready, release = Path(sys.argv[1]), Path(sys.argv[2])
boundary, code = sys.argv[3], int(sys.argv[4])
if boundary == 'build-poll':
    descendant = os.fork()
    if descendant == 0:
        ready.write_text(str(os.getpid()))
        time.sleep(10)
        os._exit(99)
    until = time.monotonic()+3
    while not ready.exists() and time.monotonic()<until: time.sleep(.005)
    if not ready.exists(): os._exit(98)
    print('original child output', file=sys.stderr, flush=True)
else:
    print('original child output', file=sys.stderr, flush=True)
    os.close(1); os.close(2)
    ready.write_text(str(os.getpid()))
    until = time.monotonic()+3
    while not release.exists() and time.monotonic()<until: time.sleep(.005)
    if not release.exists(): os._exit(98)
os._exit(code)
""")
command = [sys.executable, str(script), str(ready), str(release), boundary, str(code)]
record = {'boundary': boundary, 'expected_status': code, 'signals': 0}
children = []
real_popen, real_read, real_stop = subprocess.Popen, os.read, observed.stop_process_group
def signal_after_status(status):
    if not record['signals']:
        record['observed_before_signal'] = status
        record['signals'] += 1
        os.kill(os.getpid(), signal.SIGTERM)
def spawn(*args, **kwargs):
    child = real_popen(*args, **kwargs)
    children.append(child)
    if boundary == 'build-poll':
        if child.wait(timeout=4) != code: raise AssertionError('wrong actual child status')
    else:
        until = time.monotonic()+4
        while not ready.exists() and child.poll() is None and time.monotonic()<until:
            time.sleep(.005)
        if not ready.exists() or child.poll() is not None:
            raise AssertionError('child barrier failed')
        real_poll, real_wait = child.poll, child.wait
        def poll():
            status = real_poll()
            if boundary == 'build-wait' and record.get('eof_seen') and status is not None:
                signal_after_status(status)
            return status
        def wait(*args, **kwargs):
            if boundary.startswith('namespace-'): release.write_text('release')
            status = real_wait(*args, **kwargs)
            if boundary == 'namespace-wait': signal_after_status(status)
            return status
        child.poll, child.wait = poll, wait
    return child
def read(fd, size):
    data = real_read(fd, size)
    if boundary == 'build-wait' and not data and children:
        if fd == children[-1].stderr.fileno():
            record['eof_seen'] = True
            release.write_text('release')
    return data
def stop(child, *, grace):
    status = child.poll()
    real_stop(child, grace=grace)
    if boundary == 'build-poll': signal_after_status(status)
subprocess.Popen, os.read, observed.stop_process_group = spawn, read, stop
try:
    if boundary.startswith('namespace-'):
        namespace.restriction = lambda: 'fixture'
        namespace.prepare = lambda *args: None
        def cleanup(policy, name, report):
            record['cleanup_groups_live'] = any(execution.group_running(c.pid) for c in children)
            report['profile_absent'] = True
            if boundary == 'namespace-cleanup': signal_after_status(children[-1].returncode)
        namespace.cleanup = cleanup
        sys.argv = ['with_organization_userns.py', '--report', str(directory/'namespace.json'),
                    '--', *command]
        record['wrapper_status'] = namespace.main()
        record['namespace'] = json.loads((directory/'namespace.json').read_text())
    else:
        observed.run_observed(command, directory/'build.jsonl')
        record['wrapper_status'] = 0
except BaseException as error:
    record.update(error=type(error).__name__, message=str(error),
                  error_returncode=getattr(error, 'returncode', None),
                  cancelled_exit=getattr(error, 'code', None))
finally:
    subprocess.Popen, os.read, observed.stop_process_group = real_popen, real_read, real_stop
    record['child_pids'] = [child.pid for child in children]
    if ready.exists(): record['child_pids'].append(int(ready.read_text()))
    record['source_groups_live'] = any(execution.group_running(c.pid) for c in children)
    for child in children:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=3)
    until = time.monotonic()+3
    while time.monotonic()<until:
        try: pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError: break
        if not pid: time.sleep(.005)
    record['remaining_pids'] = [pid for pid in record['child_pids']
                              if Path('/proc', str(pid)).exists()]
    if (directory/'build.jsonl').exists():
        record['trace'] = [json.loads(line)
                           for line in (directory/'build.jsonl').read_text().splitlines()]
    (directory/'result.json').write_text(json.dumps(record))
'''


class CommandFailurePrecedenceTests(unittest.TestCase):
    def scenario(self, boundary, code):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            child = subprocess.run(
                [sys.executable, "-c", CONTROLLER, str(ROOT), str(directory), boundary, str(code)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(child.returncode, 0, child.stderr)
            record = json.loads((directory / "result.json").read_text())
            self.assertEqual(record["signals"], 1, record)
            self.assertEqual(record["observed_before_signal"], code, record)
            self.assertFalse(record["source_groups_live"], record)
            self.assertEqual(record["remaining_pids"], [], record)
            return record

    def assert_build_result(self, boundary, code):
        record = self.scenario(boundary, code)
        if code:
            self.assertEqual(record["error"], "CalledProcessError", record)
            self.assertEqual(record["error_returncode"], code, record)
            self.assertEqual(record["trace"][-1]["returncode"], code, record)
            self.assertEqual(
                "".join(row["text"] for row in record["trace"] if row["event"] == "output"),
                "original child output\n",
                record,
            )
        else:
            self.assertEqual(record["error"], "SystemExit", record)
            self.assertEqual(record["cancelled_exit"], 143, record)

    def test_build_failure_survives_cancellation_after_confirmed_group_stop(self):
        for code in (0, 37):
            with self.subTest(code=code):
                self.assert_build_result("build-poll", code)

    def test_build_failure_survives_cancellation_after_eof_and_observed_exit(self):
        for code in (0, 37):
            with self.subTest(code=code):
                self.assert_build_result("build-wait", code)

    def test_namespace_wait_preserves_observed_status_before_cancellation(self):
        for code in (0, 37):
            with self.subTest(code=code):
                self.assert_namespace_result("namespace-wait", code)

    def test_namespace_failure_survives_cancellation_during_confirmed_cleanup(self):
        for code in (0, 37):
            with self.subTest(code=code):
                self.assert_namespace_result("namespace-cleanup", code)

    def assert_namespace_result(self, boundary, code):
        record = self.scenario(boundary, code)
        self.assertEqual(record["wrapper_status"], code or 1, record)
        self.assertEqual(record["namespace"].get("command_returncode"), code, record)
        self.assertEqual(record["namespace"]["cancellation"], "interrupted by signal 15")
        self.assertEqual(record["namespace"]["unconfirmed_groups"], [], record)
        self.assertFalse(record["cleanup_groups_live"], record)


if __name__ == "__main__":
    unittest.main()
