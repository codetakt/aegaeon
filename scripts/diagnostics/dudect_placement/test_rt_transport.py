"""Local binding, lifecycle and authenticated-recovery fixtures; no Hosted/RT."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import hosted_rt_preflight as host
import recover_rt_preflight as recovery
import rt_runtime as runtime

REAL_ROOT = host.ROOT


class RuntimeTests(unittest.TestCase):
    def test_actual_systemctl_loader_objects_have_fixed_file_binding(self):
        executable = shutil.which('systemctl')
        snapshot = runtime.dependency_snapshot(executable)
        result = runtime.run([executable, '--version'], env={**runtime.ENV, 'LD_DEBUG': 'files'})
        self.assertEqual(result['returncode'], 0)
        trace = runtime.verify_loader_trace(result['stderr'], snapshot)
        self.assertTrue(trace['link_map_files'])
        self.assertEqual(snapshot, runtime.dependency_snapshot(executable))
        host.check_files(snapshot)

    def test_missing_or_unbound_loader_objects_rejected(self):
        executable = shutil.which('systemctl')
        snapshot = runtime.dependency_snapshot(executable)
        for raw in (b'', b'file=unknown.so [0]; generating link map\ntransferring control:',
                    b'calling init: /proc/self/exe\ntransferring control:'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                runtime.verify_loader_trace(raw, snapshot)

    def test_runtime_digest_detects_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lib.so'
            path.write_bytes(b'before')
            snapshot = {'files': [runtime.digest(path)]}
            path.write_bytes(b'after!')
            with self.assertRaises(ValueError):
                host.check_files(snapshot)

    def test_bad_elf_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'exe'
            path.write_bytes(b'not ELF')
            with self.assertRaises(ValueError):
                runtime.interpreter(path)
            with self.assertRaises(ValueError):
                runtime.digest(path, 2)

    def test_group_timeout_kills_only_owned_unreaped_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / 'pid'
            source = 'import os,time,pathlib; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid()));time.sleep(20)'
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                runtime.run([sys.executable, '-I', '-B', '-c', source], 0.5, new_group=True)
            self.assertLess(time.monotonic() - started, 3)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_completed_group_not_signalled_after_reaping(self):
        with patch.object(runtime.os, 'killpg') as kill:
            result = runtime.run([sys.executable, '-I', '-B', '-c', 'pass'], new_group=True)
            self.assertEqual(result['returncode'], 0)
            kill.assert_not_called()

    def test_both_output_streams_are_bounded(self):
        for fd in (1, 2):
            with self.subTest(fd=fd), self.assertRaises(ValueError):
                runtime.run([sys.executable, '-I', '-B', '-c',
                             f'import os;os.write({fd},b"x"*(2*1024*1024))'])


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.class_root = Path(cls.temp.name)
        cls.key = cls.class_root / 'test-private.pem'
        cls.cert = cls.class_root / 'test-public.pem'
        cls.openssl = shutil.which('openssl')
        result = runtime.run([cls.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                              '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '1',
                              '-subj', '/CN=Local-RT-transport-fixture', '-batch'], 15)
        if result['returncode']:
            raise RuntimeError('fixture key generation failed')
        cls.key.chmod(0o600)
        cls.openssl_snapshot = runtime.dependency_snapshot(cls.openssl)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            here = root / host.PREFIX
            here.mkdir(parents=True)
            for relative in host.FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if relative.endswith(host.CERT):
                    shutil.copyfile(self.cert, destination)
                else:
                    shutil.copyfile(REAL_ROOT / relative, destination)
            plan = {'schema': 'aegaeon.dudect.rt-readonly-plan.v1', 'branch': host.BRANCH,
                    'workflow': host.WORKFLOW, 'unit': 'hosted-compute-agent.service',
                    'limits': dict(host.LIMITS), 'plan_id': 'rt-readonly-local-fixture',
                    'generation': 1, 'stage': 'read_only_acquisition', 'execution_admitted': False,
                    'source_sha256': {r: runtime.digest(root / r)['sha256'] for r in sorted(host.FILES)}}
            host.write(here / host.PLAN, plan)
            head = 'a' * 40
            event = {'created': True, 'deleted': False, 'before': '0' * 40, 'after': head,
                     'ref': 'refs/heads/' + host.BRANCH, 'repository': {'full_name': host.REPO}}
            host.write(root / 'event.json', event)
            env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': event['ref'],
                   'GITHUB_REPOSITORY': host.REPO, 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '1',
                   'GITHUB_WORKFLOW_REF': host.REPO + '/' + host.WORKFLOW + '@' + event['ref'],
                   'GITHUB_SHA': head, 'GITHUB_WORKFLOW_SHA': head, 'GITHUB_RUN_ID': '1234',
                   'GITHUB_EVENT_PATH': str(root / 'event.json')}
            tools = {**host.TOOLS, 'openssl': self.openssl}
            opportunity = {'head': head, 'plan_sha256': runtime.digest(here / host.PLAN)['sha256'],
                           'plan_id': plan['plan_id'], 'generation': 1, 'run_id': '1234'}
            with patch.object(host, 'ROOT', root), patch.object(host, 'HERE', here), \
                    patch.object(host, 'TOOLS', tools), patch.dict(os.environ, env):
                yield root, here, plan, opportunity

    def collect(self, private, deadline):
        plan = host.load_plan()
        host.write(private / 'inspection.json', {
            'classification': 'UNKNOWN_NO_EXECUTION', 'censuses': [{'partial': True}],
            'native_invocations': 0, 'configuration_mutations': 0, 'execution_admitted': False,
            'job_pid': os.getpid(), 'unit': plan['unit'],
            'source_sha256': plan['source_sha256'][host.PREFIX + 'rt_preflight.py'],
            'private_marker': 'PRIVATE_FIXTURE_DO_NOT_UPLOAD'})
        return {'returncode': 0, 'stdout': b'private-stdout', 'stderr': b'private-stderr'}

    @contextlib.contextmanager
    def mock_acquisition(self, collector=None):
        binding = {'source': 'fixture', 'executables': {'openssl': self.openssl_snapshot}}
        with patch.object(host, 'binding', return_value=binding), \
                patch.object(host, 'invoke_collector', side_effect=collector or self.collect):
            yield binding

    def recovered(self, root, opportunity):
        upload = root / 'artifacts/rt-preflight-upload'
        summary = json.loads((upload / 'summary.json').read_text())
        out = root / 'recovered'
        return recovery.recover(upload / 'evidence.cms', self.key, summary, out,
                                opportunity['head'], opportunity['plan_sha256'], self.openssl), out

    def test_plan_source_and_inventory_enforced(self):
        with self.fixture() as (root, here, plan, _):
            self.assertEqual(host.load_plan(), plan)
            (here / 'rt_preflight.py').write_text('changed')
            with self.assertRaises(ValueError):
                host.load_plan()
            del plan['source_sha256'][host.PREFIX + 'rt_preflight.py']
            with self.assertRaises(ValueError):
                host.source_binding(plan)

    def test_limits_and_generation_cannot_be_relaxed(self):
        with self.fixture() as (_, here, plan, _):
            for key, value in (('generation', 2), ('execution_admitted', True),
                               ('limits', {**plan['limits'], 'allocations': 2})):
                changed = {**plan, key: value}
                (here / host.PLAN).write_bytes(host.encoded(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    host.load_plan()

    def test_event_branch_attempt_run_and_commit_guard(self):
        with self.fixture() as (_, _, plan, opportunity):
            git = {'returncode': 0, 'stdout': opportunity['head'].encode() + b'\n', 'stderr': b''}
            with patch.object(runtime, 'run', return_value=git):
                self.assertEqual(host.admit(plan)['head'], opportunity['head'])
            for key, value in (('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_RUN_NUMBER', '2'),
                               ('GITHUB_REF', 'refs/heads/test/dudect-hosted-service-inspection'),
                               ('GITHUB_WORKFLOW_SHA', 'b' * 40), ('GITHUB_EVENT_NAME', 'workflow_dispatch')):
                with self.subTest(key=key), patch.dict(os.environ, {key: value}), \
                        patch.object(runtime, 'run') as run, self.assertRaises(ValueError):
                    host.admit(plan)
                run.assert_not_called()

    def test_non_creation_event_and_checkout_mismatch(self):
        with self.fixture() as (root, _, plan, _):
            path = root / 'event.json'
            event = json.loads(path.read_text())
            for key, value in (('created', False), ('deleted', True), ('before', 'b' * 40)):
                path.write_bytes(host.encoded({**event, key: value}))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    host.admit(plan)
            path.write_bytes(host.encoded(event))
            with patch.object(runtime, 'run', return_value={'returncode': 0, 'stdout': b'b' * 40}), \
                    self.assertRaises(ValueError):
                host.admit(plan)

    def test_unknown_report_authenticated_roundtrip_no_plaintext_upload(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition():
            self.assertEqual(host.execute(plan, opportunity, root / 'artifacts'), 0)
            result, out = self.recovered(root, opportunity)
            self.assertTrue(result['authenticated'])
            self.assertEqual(result['classification'], 'UNKNOWN_NO_EXECUTION')
            self.assertFalse(result['execution_admitted'])
            self.assertIn('PRIVATE_FIXTURE_DO_NOT_UPLOAD', (out / 'inspection.json').read_text())
            upload = root / 'artifacts/rt-preflight-upload'
            self.assertEqual({f.name for f in upload.iterdir()}, {'evidence.cms', 'summary.json'})
            self.assertNotIn('PRIVATE_FIXTURE', (upload / 'summary.json').read_text())
            self.assertEqual((root / 'artifacts/rt-preflight-private').stat().st_mode & 0o777, 0o700)

    def test_collector_failure_keeps_encrypted_failure(self):
        def fail(private, deadline):
            return {'returncode': 1, 'stdout': b'', 'stderr': b'private failure'}
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition(fail):
            self.assertEqual(host.execute(plan, opportunity, root / 'artifacts'), 1)
            result, out = self.recovered(root, opportunity)
            self.assertFalse(result['operation_complete'])
            self.assertEqual((out / 'collector.stderr').read_bytes(), b'private failure')

    def test_collector_timeout_keeps_encrypted_partial(self):
        def timeout(private, deadline):
            (private / 'inspection.json').write_text('{partial')
            raise TimeoutError('fixed fixture timeout')
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition(timeout):
            self.assertEqual(host.execute(plan, opportunity, root / 'artifacts'), 1)
            result, out = self.recovered(root, opportunity)
            self.assertFalse(result['operation_complete'])
            self.assertEqual((out / 'inspection.json').read_text(), '{partial')

    def test_runtime_change_is_not_completed_collection(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition() as before:
            with patch.object(host, 'binding', side_effect=[before, {**before, 'changed': True}]):
                self.assertEqual(host.execute(plan, opportunity, root / 'artifacts'), 1)
            result, _ = self.recovered(root, opportunity)
            self.assertFalse(result['operation_complete'])

    def test_report_requesting_execution_is_rejected(self):
        def bad(private, deadline):
            result = self.collect(private, deadline)
            path = private / 'inspection.json'
            row = json.loads(path.read_text());row['execution_admitted'] = True
            path.write_bytes(host.encoded(row))
            return result
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition(bad):
            self.assertEqual(host.execute(plan, opportunity, root / 'artifacts'), 1)
            result, _ = self.recovered(root, opportunity)
            self.assertFalse(result['operation_complete'])

    def test_encryption_failure_never_publishes_plaintext(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition(), \
                patch.object(host, 'encrypt', side_effect=RuntimeError('fixture encryption failure')):
            with self.assertRaises(RuntimeError):
                host.execute(plan, opportunity, root / 'artifacts')
            self.assertEqual(list((root / 'artifacts/rt-preflight-upload').iterdir()), [])

    def test_gcm_tampering_rejected_before_destination(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition():
            host.execute(plan, opportunity, root / 'artifacts')
            upload = root / 'artifacts/rt-preflight-upload'
            cipher = upload / 'evidence.cms'; raw = bytearray(cipher.read_bytes());raw[-1] ^= 1
            cipher.write_bytes(raw)
            summary = json.loads((upload / 'summary.json').read_text())
            summary['ciphertext_sha256'] = host.sha_bytes(raw)
            out = root / 'bad-recovery'
            with self.assertRaisesRegex(ValueError, 'authentication'):
                recovery.recover(cipher, self.key, summary, out, opportunity['head'],
                                 opportunity['plan_sha256'], self.openssl)
            self.assertFalse(out.exists())

    def test_digest_head_plan_and_existing_output_rejected(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition():
            host.execute(plan, opportunity, root / 'artifacts')
            upload = root / 'artifacts/rt-preflight-upload';cipher = upload / 'evidence.cms'
            summary = json.loads((upload / 'summary.json').read_text())
            out = root / 'no-output'
            for key in ('head', 'plan_sha256', 'ciphertext_sha256'):
                changed = {**summary, key: '0' * len(summary[key])}
                with self.subTest(key=key), self.assertRaises(ValueError):
                    recovery.recover(cipher, self.key, changed, out, opportunity['head'],
                                     opportunity['plan_sha256'], self.openssl)
                self.assertFalse(out.exists())
            out.mkdir()
            with self.assertRaises(FileExistsError):
                recovery.recover(cipher, self.key, summary, out, opportunity['head'],
                                 opportunity['plan_sha256'], self.openssl)

    def test_authenticated_manifest_tampering_and_tar_path_rejected(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition() as before:
            host.execute(plan, opportunity, root / 'artifacts')
            private = root / 'artifacts/rt-preflight-private'
            archive = root / 'tampered.tar'
            for mode in ('hash', 'path'):
                with tarfile.open(archive, 'w') as out:
                    for file in sorted(private.iterdir()):
                        raw = file.read_bytes()
                        if mode == 'hash' and file.name == 'inspection.json':
                            raw += b'changed'
                        member = tarfile.TarInfo('../escape' if mode == 'path' else file.name)
                        member.size = len(raw);out.addfile(member, io.BytesIO(raw))
                upload = root / ('tamper-upload-' + mode);upload.mkdir()
                transport = host.encrypt(archive, private, upload, plan, before, time.monotonic() + 30)
                summary = json.loads((root / 'artifacts/rt-preflight-upload/summary.json').read_text())
                summary.update(transport)
                destination = root / ('invalid-' + mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    recovery.recover(upload / 'evidence.cms', self.key, summary, destination,
                                     opportunity['head'], opportunity['plan_sha256'], self.openssl)
                self.assertFalse(destination.exists())

    def test_preexisting_opportunity_is_not_overwritten(self):
        with self.fixture() as (root, _, plan, opportunity), self.mock_acquisition():
            host.execute(plan, opportunity, root / 'artifacts')
            with self.assertRaises(FileExistsError):
                host.execute(plan, opportunity, root / 'artifacts')


if __name__ == '__main__':
    unittest.main()
