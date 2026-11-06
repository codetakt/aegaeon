"""Exercise cancellation through the imported compiled-package entrypoint."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The supervisor remains alive to reap even the preceding implementation's
# escaped children. Only the actual package runner receives cancellation.
CONTROLLER = r'''
import ctypes, json, os, signal, subprocess, sys, time
from pathlib import Path
root, directory = map(Path, sys.argv[1:])
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
pid_file = directory/'descendant.json'
package = directory/'package'
(package/'libexec').mkdir(parents=True)
binary = package/'libexec/aegaeon_server'
binary.write_text(f'#!{sys.executable}\n' + """
import json, os, signal, time
from pathlib import Path
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.close(1)
    os.close(2)
    Path(PID_FILE).write_text(json.dumps({'pid': os.getpid(), 'group': os.getpgrp()}))
    time.sleep(60)
    os._exit(0)
time.sleep(60)
""".replace('PID_FILE', repr(str(pid_file))))
binary.chmod(0o755)
crate = directory/'crates/server'
crate.mkdir(parents=True)
(crate/'Cargo.toml').touch()
runner = directory/'package-runner.py'
runner.write_text("""
import json, os, sys
from pathlib import Path
root, directory = map(Path, sys.argv[1:])
sys.path.insert(0, str(root/'scripts/validation'))
import database_test_package as package
import database_execution as execution
plan_path = directory/'plan.json'
plan_path.write_text('{}')
plan = {'suites': {'probe': {'target': 'aegaeon_server',
        'args': ['--ignored', '--test-threads=1'], 'tests': ['probe']}},
        'auxiliaries': [], 'package': str(directory/'package'),
        'context': {}, 'build_sha256': 'fixture'}
execution.load_plan = lambda path: plan
execution.bind_package = lambda plan, path: None
package.validate = lambda path: None
execution.owned_cwd = lambda name: directory/'crates/server'
os.environ['AEGAEON_DATABASE_EXECUTION_PLAN'] = str(plan_path)
os.environ['AEGAEON_DATABASE_EXECUTION_RESULTS'] = str(directory/'results')
package.run(directory/'package', ['-p', 'aegaeon-server', '--lib', '--',
                                 '--ignored', '--test-threads=1'])
""")
record = {}
process = subprocess.Popen([sys.executable, str(runner), str(root), str(directory)],
                           cwd=directory, start_new_session=True)
try:
    deadline = time.monotonic()+5
    while not pid_file.exists():
        if time.monotonic() >= deadline: raise TimeoutError('fixture did not start')
        time.sleep(.01)
    process.send_signal(signal.SIGTERM)
    record['returncode'] = process.wait(timeout=8)
    child = json.loads(pid_file.read_text())['pid']
    try:
        record['descendant_alive_after_return'] = (
            Path(f'/proc/{child}/stat').read_text().split(') ', 1)[1][0] != 'Z')
    except FileNotFoundError:
        record['descendant_alive_after_return'] = False
finally:
    for group in ([json.loads(pid_file.read_text())['group']] if pid_file.exists() else []):
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait(timeout=2)
    while True:
        try: os.waitpid(-1, 0)
        except ChildProcessError: break
    record['fixture_reaped'] = True
    (directory/'result.json').write_text(json.dumps(record))
'''


class DatabasePackageCancellationTests(unittest.TestCase):
    def test_imported_package_runner_cleans_up_on_sigterm(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = subprocess.run(  # noqa: S603 - fixed owned subprocess fixture
                [sys.executable, str(controller), str(ROOT), str(directory)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads((directory / "result.json").read_text())
            self.assertTrue(observed["fixture_reaped"], observed)
            self.assertFalse(observed["descendant_alive_after_return"], observed)
            self.assertEqual(observed["returncode"], 143, observed)
            receipt = json.loads((directory / "results/probe.json").read_text())
            self.assertFalse(receipt["complete"])
            self.assertIn("finished_unix", receipt)


if __name__ == "__main__":
    unittest.main()
