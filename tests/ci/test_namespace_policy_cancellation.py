"""Real signals must not skip removal of a task-owned namespace policy."""

from __future__ import annotations

# ruff: noqa: PT009, S603 - owned subprocess fixtures; assertions survive Python -O.
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = r'''
import ctypes, hashlib, json, os, signal, subprocess, sys, time
from pathlib import Path
root, directory, phase, fault = Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:]
sys.path[:0] = [str(root/'scripts/ci'), str(root/'scripts/validation')]
import with_organization_userns as subject
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
stub = directory/'policy-control.py'
stub.write_text(r"""
import json, os, signal, sys, time
from pathlib import Path
d, action, phase, fault = Path(sys.argv[1]), *sys.argv[2:]
(d/f'pid-{os.getpid()}').write_text(str(os.getpgrp()))
if action == phase:
    (d/'ready').write_text(action)
    if fault == 'timeout':
        time.sleep(60)
    while not (d/'release').exists(): time.sleep(.005)
if action == 'remove':
    if fault == 'remove-error': sys.exit(23)
    (d/'loaded').unlink()
elif action in ('inspect', 'confirm'):
    if action == 'confirm' and fault == 'confirm-error': sys.exit(24)
    if (d/'loaded').exists(): print((d/'name').read_text()+' (unconfined)')
elif action == 'work':
    time.sleep(60)
elif action == 'inherited-output':
    child = os.fork()
    if child == 0:
        (d/f'pid-{os.getpid()}').write_text(str(os.getpgrp()))
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        os._exit(0)
    while not (d/f'pid-{child}').exists(): time.sleep(.005)
    print('completed with inherited output', flush=True)
    sys.exit(37)
""")
original_execute = subject.execute
def execute(command, **kwargs):
    if '--remove' in command: action = 'remove'
    elif command[:3] == ['sudo', '-n', 'cat']:
        action = 'inspect' if (directory/'loaded').exists() else 'confirm'
    else: raise AssertionError(command)
    argv = [sys.executable, str(stub), str(directory), action, phase, fault]
    return original_execute(argv, **kwargs)
subject.execute = execute
subject.restriction = lambda: '1'
record = {}
def prepare(policy, name, state):
    policy.write_text('owned policy fixture\n')
    policy.chmod(0o600)
    (directory/'name').write_text(name)
    (directory/'loaded').write_text('loaded')
    record['policy_path'] = str(policy)
    state.update(install_attempted=True, profile_installed=True, profile=name)
subject.prepare = prepare
original_cleanup = subject.cleanup
def cleanup(*args):
    if phase == 'entry':
        (directory/'ready').write_text('entry')
        while not (directory/'release').exists(): time.sleep(.005)
    return original_cleanup(*args)
subject.cleanup = cleanup
if fault == 'group-error':
    original_stop = subject.stop_process_group
    def stop(process, **kwargs):
        original_stop(process, **kwargs)
        if 'inspect' in process.args:
            raise RuntimeError('controlled cleanup confirmation failure')
    subject.stop_process_group = stop
if phase == 'capture':
    def capture(command, **kwargs):
        argv = [sys.executable, str(stub), str(directory),
                'inherited-output', 'none', 'none']
        record['capture'] = original_execute(argv, timeout=2)
        return record['capture']['returncode']
    subject.run_command = capture
def alive(pid):
    try: return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1][0] not in ('Z', 'X')
    except FileNotFoundError: return False
command = [sys.executable, '-c', 'pass']
if phase == 'work': command = [sys.executable, str(stub), str(directory), 'work', phase, fault]
try:
    sys.argv = ['with_organization_userns.py', '--report',
                str(directory/'report.json'), '--', *command]
    record['status'] = subject.main()
except BaseException as error:
    record.update(error=type(error).__name__, message=str(error))
finally:
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, signal.SIG_IGN)
    record['loaded'] = (directory/'loaded').exists()
    record['policy_exists'] = Path(record['policy_path']).exists()
    if record['policy_exists']:
        policy = Path(record['policy_path'])
        record['policy_sha256'] = hashlib.sha256(policy.read_bytes()).hexdigest()
        record['policy_mode'] = policy.stat().st_mode & 0o777
        recovery = policy.parent/'recovery.json'
        if recovery.exists(): record['recovery'] = json.loads(recovery.read_text())
    record['live_children'] = [int(p.name[4:]) for p in directory.glob('pid-*')
                               if alive(int(p.name[4:]))]
    for p in directory.glob('pid-*'):
        try: os.kill(int(p.name[4:]), signal.SIGKILL)
        except ProcessLookupError: pass
    while True:
        try: os.waitpid(-1, 0)
        except ChildProcessError: break
    record['fixture_reaped'] = True
    (directory/'result.json').write_text(json.dumps(record))
'''


class PolicyCancellationTests(unittest.TestCase):
    def run_fixture(self, directory, case):
        phase, fault, _, _ = case
        controller = directory / "controller.py"
        controller.write_text(CONTROLLER)
        with (directory / "controller.log").open("wb") as output:
            child = subprocess.Popen(
                [sys.executable, str(controller), str(ROOT), str(directory), phase, fault],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                if phase != "capture":
                    self.signal_fixture(child, directory, case)
                self.assertEqual(child.wait(timeout=15), 0)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)
                self.stop_fixture_children(directory)

    def stop_fixture_children(self, directory):
        # A controller crash must not strand a separately-sessioned stand-in.
        for path in directory.glob("pid-*"):
            pid = int(path.name[4:])
            try:
                command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                if not command or command == [b""]:
                    continue
                self.assertIn(os.fsencode(directory), command)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except FileNotFoundError:
                continue
            deadline = time.monotonic() + 2
            while Path(f"/proc/{pid}/stat").exists():
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0]
                except FileNotFoundError:
                    break
                if state in ("Z", "X"):
                    break
                self.assertLess(time.monotonic(), deadline, "fixture child did not stop")
                time.sleep(0.005)

    def signal_fixture(self, child, directory, case):
        _, fault, delivery, signum = case
        deadline = time.monotonic() + 5
        while not (directory / "ready").exists() and child.poll() is None:
            if time.monotonic() >= deadline:
                self.fail("policy-control handshake timed out")
            time.sleep(0.005)
        self.assertTrue((directory / "ready").exists())
        send = os.killpg if delivery == "group" else os.kill
        send(child.pid, signum)
        if fault == "repeated":
            time.sleep(0.03)
            send(child.pid, signal.SIGINT)
        (directory / "release").write_text("release")

    @staticmethod
    def remove_retained(policy):
        if policy.exists():
            policy.unlink()
            (policy.parent / "recovery.json").unlink(missing_ok=True)
            shutil.rmtree(policy.parent / "process-cleanup")
            policy.parent.rmdir()

    def assert_result(self, record, report, fault):
        self.assertTrue(record["fixture_reaped"], record)
        self.assertFalse(record["live_children"], record)
        self.assertEqual(record["status"], 1, (record, report))
        if fault in ("timeout", "remove-error", "confirm-error", "group-error"):
            self.assertTrue(record["policy_exists"], (record, report))
            self.assertIn("recovery", report)
            self.assertEqual(report["recovery"], record["recovery"])
            self.assertEqual(report["recovery"]["policy_sha256"], record["policy_sha256"])
            self.assertEqual(record["policy_mode"], 0o600)
            self.assertNotIn("interrupted by signal", report["error"])
            if fault != "confirm-error":
                self.assertTrue(record["loaded"], (record, report))
        else:
            self.assertFalse(record["loaded"], (record, report))
            self.assertFalse(record["policy_exists"], (record, report))
            self.assertTrue(report.get("profile_removed"), report)
            self.assertEqual(report["restriction_after"], "1", report)
            self.assertIn("interrupted by signal", report["error"])
        self.assertEqual(bool(report["unconfirmed_groups"]), fault == "group-error")

    def scenario(self, phase, fault="cancel", delivery="parent", signum=signal.SIGTERM):
        case = (phase, fault, delivery, signum)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.run_fixture(directory, case)
            record = json.loads((directory / "result.json").read_text())
            report = json.loads((directory / "report.json").read_text())
            self.addCleanup(self.remove_retained, Path(record["policy_path"]))
            evidence = os.environ.get("AEGAEON_NAMESPACE_TEST_RESULTS")
            if evidence:
                destination = Path(evidence) / f"{phase}-{fault}-{delivery}-{signum}.json"
                with destination.open("x") as stream:
                    json.dump(
                        {
                            "record": record,
                            "report": report,
                            "controller_log": (directory / "controller.log").read_text(),
                        },
                        stream,
                        indent=2,
                    )
            if phase == "capture":
                self.assertEqual(record["status"], 37, record)
                self.assertFalse(record["live_children"] or record["loaded"], record)
                self.assertEqual(record["capture"]["stdout"], "completed with inherited output\n")
            else:
                self.assert_result(record, report, fault)

    def test_parent_signal_during_policy_cleanup(self):
        for phase in ("inspect", "remove", "confirm", "entry"):
            with self.subTest(phase=phase):
                self.scenario(phase)

    def test_group_signal_does_not_kill_policy_controller(self):
        for phase in ("inspect", "remove"):
            with self.subTest(phase=phase):
                self.scenario(phase, delivery="group")

    def test_sigint_and_repeated_signals_finish_policy_cleanup(self):
        self.scenario("remove", signum=signal.SIGINT)
        self.scenario("inspect", fault="repeated", delivery="group")

    def test_work_cancellation_reaps_child_before_policy_cleanup(self):
        self.scenario("work")
        self.scenario("work", delivery="group")

    def test_cleanup_failure_precedes_cancellation_and_retains_policy(self):
        self.scenario("remove", fault="remove-error")
        self.scenario("confirm", fault="confirm-error")

    def test_policy_timeout_reaps_child_and_preserves_recovery(self):
        self.scenario("inspect", fault="timeout")

    def test_unconfirmed_group_cannot_remove_recovery_evidence(self):
        self.scenario("inspect", fault="group-error")

    def test_capture_reaps_inherited_output_and_preserves_status(self):
        self.scenario("capture")


if __name__ == "__main__":
    unittest.main()
