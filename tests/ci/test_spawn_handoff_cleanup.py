"""Owned process handoffs and uncertain work cleanup must retain their safeguards."""

from __future__ import annotations

# ruff: noqa: PT009, S603 - owned subprocess fixtures; assertions survive Python -O.
import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = r"""
import json, os, signal, subprocess, sys, time
from pathlib import Path
source, directory = Path(sys.argv[1]), Path(sys.argv[2])
kind, signum = sys.argv[3], int(sys.argv[4])
for relative in ('scripts/validation','scripts/ci','tests/organizations'):
    sys.path.insert(0,str(source/relative))
import database_execution as database
import build_observations as observations
import current_process as current
import with_organization_userns as namespace
record = {'kind':kind,'signal':signum}
children = []
original_popen = subprocess.Popen
command = [sys.executable,'-c','import time; time.sleep(60)']
def live(process):
    try: return Path(f'/proc/{process.pid}/stat').read_text().rsplit(') ',1)[1][0] not in ('Z','X')
    except FileNotFoundError: return False
def created(*args,**kwargs):
    child = original_popen(*args,**kwargs)
    children.append(child)
    (directory/'owned-pids.json').write_text(json.dumps([c.pid for c in children]))
    if kind != 'policy':
        record['signal_sent'] = True
        os.kill(os.getpid(),signum)
    return child
subprocess.Popen = created
try:
    if kind == 'execution':
        plan = directory/'plan.json'; plan.write_text('{}')
        database.load_plan = lambda _: {'auxiliaries':['models'],'suites':{},'context':{},
                                        'build_sha256':'fixture','package':'/unbuilt'}
        database.bind_package = lambda *args: None
        database.owned_cwd = lambda _: directory
        database.owned_command = lambda *args: command
        database.initialize_receipts(plan,directory/'results')
        record['returncode'] = database.execute(plan,directory/'results','models',command)
    elif kind == 'observation':
        observations.run_observed(command,directory/'build.jsonl')
    elif kind == 'current':
        current.install_cancellation()
        current.run_owned(command,root=directory,env=dict(os.environ))
    elif kind == 'policy':
        loaded = directory/'loaded'; loaded.write_text('loaded')
        record['remove_calls'] = 0
        namespace.restriction = lambda: '1'
        def prepare(policy,name,result):
            policy.write_text('fixture-policy\n'); policy.chmod(0o600)
            record['policy_path'] = str(policy)
            result.update(install_attempted=True,profile_installed=True)
        namespace.prepare = prepare
        namespace.present = lambda *args,**kwargs: loaded.exists()
        def remove(*args,**kwargs):
            record['remove_calls'] += 1
            loaded.unlink()
            return {'returncode':0}
        namespace.execute = remove
        stop = namespace.stop_process_group
        def unconfirmed(process,**kwargs):
            stop(process,**kwargs)
            raise RuntimeError('controlled work-group confirmation failure')
        namespace.stop_process_group = unconfirmed
        report = directory/'report.json'
        record['returncode'] = namespace.run([sys.executable,'-c','pass'],report)
        record['report'] = json.loads(report.read_text())
        record['policy_loaded'] = loaded.exists()
        policy = Path(record['policy_path'])
        record['policy_retained'] = policy.is_file()
        record['policy_contents'] = policy.read_text() if policy.is_file() else None
        recovery = policy.parent/'recovery.json'
        record['recovery'] = json.loads(recovery.read_text()) if recovery.is_file() else None
    else:
        raise ValueError(kind)
except BaseException as error:
    record.update(error_type=type(error).__name__,error=str(error))
finally:
    # Preserve the product result before the independent fixture always reaps it.
    record['live_before_fixture_cleanup'] = [c.pid for c in children if live(c)]
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,signal.SIG_IGN)
    subprocess.Popen = original_popen
    for child in children:
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=2)
    record['fixture_reaped'] = not any(live(c) for c in children)
    (directory/'result.json').write_text(json.dumps(record))
"""


class SpawnHandoffCleanupTests(unittest.TestCase):
    @staticmethod
    def run_fixture(source: Path, directory: Path, kind: str, signum: int) -> int:
        with (directory / "controller.log").open("wb") as output:
            child = subprocess.Popen(
                [sys.executable, "-c", FIXTURE, str(source), str(directory), kind, str(signum)],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={**os.environ, "TMPDIR": str(directory)},
            )
            try:
                child.wait(timeout=15)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)
                # Only failed fixture controllers need this emergency ownership cleanup.
                pids = directory / "owned-pids.json"
                if child.returncode != 0 and pids.exists():
                    for pid in json.loads(pids.read_text()):
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(pid, signal.SIGKILL)
        return child.returncode

    def check_result(self, result: dict, kind: str, signum: int) -> None:
        self.assertTrue(result["fixture_reaped"], result)
        self.assertFalse(result["live_before_fixture_cleanup"], result)
        if kind == "policy":
            self.assertEqual(result["returncode"], 1, result)
            self.assertEqual(result["remove_calls"], 0, result)
            self.assertTrue(result["policy_loaded"] and result["policy_retained"], result)
            self.assertEqual(
                result["report"]["error"], "controlled work-group confirmation failure"
            )
            self.assertEqual(result["report"]["recovery"], result["recovery"])
            self.assertTrue(result["report"]["unconfirmed_groups"], result)
            self.assertEqual(
                result["recovery"]["unconfirmed_groups"], result["report"]["unconfirmed_groups"]
            )
            self.assertIn(
                "Confirm all listed owned groups and every nested group recorded in "
                "nested_cleanup_directory have terminated.",
                result["recovery"]["confirmation_required"],
            )
            self.assertIn(
                "Resolve missing or incomplete nested evidence before running remove_command.",
                result["recovery"]["confirmation_required"],
            )
        else:
            self.assertTrue(result["signal_sent"], result)
            expected = "RuntimeError" if kind == "current" else "SystemExit"
            self.assertEqual(result["error_type"], expected, result)
            if kind == "current":
                self.assertIn(f"signal {signum}", result["error"])
            else:
                self.assertEqual(result["error"], str(128 + signum))

    def scenario(self, kind: str, signum: int = signal.SIGTERM) -> None:
        source = Path(os.environ.get("AEGAEON_HANDOFF_SOURCE", str(ROOT)))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            returncode = self.run_fixture(source, directory, kind, signum)
            log = (directory / "controller.log").read_text()
            self.assertEqual(returncode, 0, log)
            result = json.loads((directory / "result.json").read_text())
            evidence = os.environ.get("AEGAEON_HANDOFF_RESULTS")
            if evidence:
                with (Path(evidence) / f"{kind}-{signum}.json").open("x") as stream:
                    json.dump({"result": result, "log": log}, stream)
            self.check_result(result, kind, signum)

    def test_work_group_confirmation_failure_preserves_loaded_policy(self):
        self.scenario("policy")

    def test_execution_spawn_handoff_cancellation(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.scenario("execution", signum)

    def test_observation_spawn_handoff_cancellation(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.scenario("observation", signum)

    def test_current_runtime_spawn_handoff_cancellation(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.scenario("current", signum)


if __name__ == "__main__":
    unittest.main()
