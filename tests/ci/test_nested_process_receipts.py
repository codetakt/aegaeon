"""Keep a dependency policy until separate nested command groups confirm stop."""

from __future__ import annotations

# ruff: noqa: PT009, S603 - owned subprocess fixtures; active assertions under -O.
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import process_cleanup_receipts as receipts  # noqa: E402

CONTROLLER = r'''
import ctypes, json, os, signal, subprocess, sys
from pathlib import Path
root, directory, fault = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path[:0] = [str(root/'scripts/validation'),str(root/'scripts/ci')]
import with_organization_userns as namespace
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0) != 0:
    raise OSError(ctypes.get_errno(), 'subreaper setup failed')
stub = directory/'child.py'
stub.write_text("""
import json,os,sys,time
from pathlib import Path
path=Path(sys.argv[1])
child=os.fork()
if child == 0:
    os.close(1);os.close(2)
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'pid':os.getpid(),'group':os.getpgrp()}))
    temporary.replace(path)
    time.sleep(60)
    os._exit(0)
while not path.exists():time.sleep(.005)
print('owned command completed',file=sys.stderr,flush=True)
""")
observer=directory/'observer.py'
observer.write_text("""
import sys
from pathlib import Path
root,directory,fault=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
sys.path.insert(0,str(root/'scripts/ci'))
import build_observations as observed
if fault in ('stop-failure', 'missing-receipt'):
    def unconfirmed(*args,**kwargs):raise RuntimeError('controlled nested stop failure')
    observed.stop_process_group=unconfirmed
try:
    observed.run_observed([sys.executable,str(directory/'child.py'),str(directory/'child.json')],
                          directory/'trace.jsonl')
finally:
    if fault == 'missing-receipt':
        import os
        selected=Path(os.environ['AEGAEON_PROCESS_CLEANUP_RECEIPTS'])
        for receipt in selected.glob('*.json'):
            if receipt.name != 'owner.json':receipt.unlink()
""")
state={}
namespace.restriction=lambda:'1'
def prepare(policy,name,record):
    policy.write_text('owned mock policy')
    (directory/'loaded').write_text(name)
    state['policy']=str(policy)
    record.update(install_attempted=True,profile_installed=True,profile=name)
def cleanup(policy,name,record):
    (directory/'loaded').unlink()
    record.update(profile_absent=True,restriction_after='1')
namespace.prepare=prepare;namespace.cleanup=cleanup
try:
    state['status']=namespace.run([sys.executable,str(observer),str(root),str(directory),fault],
                                  directory/'report.json')
    state['report']=json.loads((directory/'report.json').read_text())
    state['policy_loaded']=(directory/'loaded').exists()
    state['policy_retained']=Path(state['policy']).exists()
finally:
    child=json.loads((directory/'child.json').read_text())
    try:
        status=Path(f"/proc/{child['pid']}/stat").read_text().rsplit(') ',1)[1][0]
        state['nested_alive']=status not in ('Z','X')
    except FileNotFoundError:state['nested_alive']=False
    try:os.killpg(child['group'],signal.SIGKILL)
    except ProcessLookupError:pass
    while True:
        try:os.waitpid(-1,0)
        except ChildProcessError:break
    state['fixture_reaped']=True
    # Remove only this fixture's simulated policy and recovery directory.
    import shutil
    shutil.rmtree(Path(state['policy']).parent,ignore_errors=True)
    (directory/'result.json').write_text(json.dumps(state))
'''


class NestedProcessReceiptTests(unittest.TestCase):
    def scenario(self, fault):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            controller = directory / "controller.py"
            controller.write_text(CONTROLLER)
            result = subprocess.run(
                [sys.executable, str(controller), str(ROOT), str(directory), fault],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((directory / "result.json").read_text())
            self.assertTrue(record["fixture_reaped"], record)
            return record

    def test_confirmed_nested_stop_allows_policy_removal(self):
        record = self.scenario("normal")
        self.assertEqual(record["status"], 0, record)
        self.assertFalse(record["policy_loaded"] or record["nested_alive"], record)
        self.assertFalse(record["policy_retained"], record)
        self.assertEqual(len(record["report"]["nested_cleanup_receipts"]), 1)

    def test_unconfirmed_nested_stop_preserves_policy_and_recovery(self):
        record = self.scenario("stop-failure")
        self.assertNotEqual(record["status"], 0, record)
        self.assertTrue(record["nested_alive"], record)
        self.assertTrue(record["policy_loaded"] and record["policy_retained"], record)
        self.assertIn("nested_cleanup_unconfirmed", record["report"])
        self.assertIn("nested_cleanup_directory", record["report"]["recovery"])

    def test_deleted_nested_receipt_preserves_live_group_policy(self):
        record = self.scenario("missing-receipt")
        self.assertNotEqual(record["status"], 0, record)
        self.assertTrue(record["nested_alive"], record)
        self.assertTrue(record["policy_loaded"] and record["policy_retained"], record)
        self.assertIn("missing", record["report"]["nested_cleanup_unconfirmed"])
        self.assertIn("nested_cleanup_directory", record["report"]["recovery"])


class ReceiptProtocolTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.directory = self.root / "receipts"
        self.owner = "aegaeon-userns-" + "a" * 32
        self.identity = self.enterContext(receipts.initialize(self.directory, self.owner))
        self.enterContext(mock.patch.dict(os.environ, {receipts.ENVIRONMENT: str(self.directory)}))

    def test_no_started_group_and_confirmed_group_are_distinct(self):
        self.assertEqual(receipts.confirm(self.directory, self.owner, self.identity), [])
        receipt = receipts.begin()
        self.assertIsNotNone(receipt)
        with pytest.raises(ValueError, match="unconfirmed"):
            receipts.confirm(self.directory, self.owner, self.identity)
        receipts.update(receipt, group=123, confirmed=True)
        self.assertEqual(receipts.confirm(self.directory, self.owner, self.identity), [receipt[1]])

    def test_missing_parent_and_foreign_owner_refuse_confirmation(self):
        with pytest.raises(ValueError, match="owner changed"):
            receipts.confirm(self.directory, "aegaeon-userns-" + "b" * 32, self.identity)
        self.directory.rename(self.root / "retained")
        with pytest.raises(FileNotFoundError):
            receipts.confirm(self.directory, self.owner, self.identity)
        self.directory.symlink_to(self.root / "retained")
        with pytest.raises(NotADirectoryError):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_incomplete_foreign_or_malformed_receipts_refuse_confirmation(self):
        receipt = receipts.begin()
        receipts.update(receipt, group=123, confirmed=True)
        path, original = receipt
        for field, value in (
            ("confirmed", False),
            ("confirmed", 1),
            ("group", None),
            ("group", True),
            ("owner", "other"),
            ("invocation", "b" * 32),
        ):
            with self.subTest(field=field, value=value):
                path.write_text(json.dumps({**original, field: value}))
                with pytest.raises(ValueError, match="unconfirmed"):
                    receipts.confirm(self.directory, self.owner, self.identity)
        for content in ("{", "[]", '{"confirmed":false,"confirmed":true}', " " * (1024 * 1024 + 1)):
            with self.subTest(content=content[:80]):
                path.write_text(content)
                with pytest.raises(ValueError, match=r"cleanup receipt|Expecting"):
                    receipts.confirm(self.directory, self.owner, self.identity)

    def test_replaced_empty_directory_with_same_owner_is_lost_evidence(self):
        receipts.begin()
        old = self.root / "original"
        self.directory.rename(old)
        with receipts.initialize(self.directory, self.owner):
            pass
        self.assertEqual(
            (old / "owner.json").read_bytes(), (self.directory / "owner.json").read_bytes()
        )
        with pytest.raises(ValueError, match="directory identity changed"):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_special_files_and_incomplete_atomic_update_refuse_confirmation(self):
        receipt = receipts.begin()
        path, _ = receipt
        path.unlink()
        os.mkfifo(path)
        with pytest.raises(ValueError, match="regular file"):
            receipts.confirm(self.directory, self.owner, self.identity)
        path.unlink()
        path.symlink_to(self.directory / "owner.json")
        with pytest.raises(OSError, match="Too many levels"):
            receipts.confirm(self.directory, self.owner, self.identity)
        path.unlink()
        path.with_suffix(".tmp").write_text("interrupted write")
        with pytest.raises(ValueError, match="unfinished"):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_deleted_registered_receipt_is_not_an_empty_invocation(self):
        receipt = receipts.begin()
        receipt[0].unlink()
        with pytest.raises(ValueError, match="missing"):
            receipts.confirm(self.directory, self.owner, self.identity)
        with pytest.raises(ValueError, match="missing"):
            receipts.begin()
        with pytest.raises(ValueError, match="missing"):
            receipts.update(receipt, group=123, confirmed=True)

    def test_ledger_missing_replacement_and_truncation_refuse_confirmation(self):
        ledger = self.directory / receipts.LEDGER
        original = ledger.read_bytes()
        ledger.unlink()
        with pytest.raises(FileNotFoundError):
            receipts.confirm(self.directory, self.owner, self.identity)
        # The parent still holds the unlinked ledger inode: a copy is not its identity.
        ledger.write_bytes(original)
        self.assertNotEqual(ledger.stat().st_ino, self.identity["ledger_inode"])
        with pytest.raises(ValueError, match="ledger replaced"):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_short_ledger_reads_cannot_hide_a_missing_later_receipt(self):
        first, second = receipts.begin(), receipts.begin()
        for receipt in (first, second):
            receipts.update(receipt, group=123, confirmed=True)
        second[0].unlink()
        real_read = os.read
        prefix = len(
            (
                "aegaeon-process-cleanup-v1\n" + self.owner + "\n" + first[1]["invocation"] + "\n"
            ).encode()
        )
        calls = []

        def short_read(descriptor, count):
            calls.append(count)
            return real_read(descriptor, min(count, prefix) if len(calls) == 1 else count)

        with (
            mock.patch.object(receipts.os, "read", side_effect=short_read),
            pytest.raises(ValueError, match="missing"),
        ):
            receipts.confirm(self.directory, self.owner, self.identity)
        self.assertGreaterEqual(len(calls), 3)  # Short prefix, remaining bytes, actual EOF.

    def test_zero_partial_and_complete_prefix_truncation_are_rejected(self):
        first, second = receipts.begin(), receipts.begin()
        for receipt in (first, second):
            receipts.update(receipt, group=123, confirmed=True)
        ledger = self.directory / receipts.LEDGER
        original = ledger.read_bytes()
        for damaged in (
            b"",
            original[:-1],
            original[: original.rfind(second[1]["invocation"].encode())],
        ):
            with self.subTest(damaged=damaged):
                ledger.write_bytes(damaged)
                with pytest.raises(ValueError, match=r"cleanup receipt|cleanup registrations"):
                    receipts.confirm(self.directory, self.owner, self.identity)
        ledger.write_bytes(original)
        self.assertEqual(len(receipts.confirm(self.directory, self.owner, self.identity)), 2)

    def test_registration_partial_write_and_missing_initial_receipt_fail_closed(self):
        ledger = self.directory / receipts.LEDGER
        initial = ledger.read_bytes()
        real_write = os.write

        def partial(descriptor, data):
            return real_write(descriptor, data[:5])

        with (
            mock.patch.object(receipts.os, "write", side_effect=partial),
            pytest.raises(OSError, match="partial"),
        ):
            receipts.begin()
        with pytest.raises(ValueError, match="partial"):
            receipts.confirm(self.directory, self.owner, self.identity)
        ledger.write_bytes(initial)
        with (
            mock.patch.object(
                receipts, "write_json", side_effect=OSError("controlled write failure")
            ),
            pytest.raises(OSError, match="controlled"),
        ):
            receipts.begin()
        self.assertGreater(ledger.stat().st_size, len(initial))
        with pytest.raises(ValueError, match="missing"):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_owner_header_and_duplicate_registration_are_rejected(self):
        receipt = receipts.begin()
        receipts.update(receipt, group=123, confirmed=True)
        ledger = self.directory / receipts.LEDGER
        original = ledger.read_bytes()
        for damaged in (
            original.replace(self.owner.encode(), ("aegaeon-userns-" + "b" * 32).encode()),
            original + (receipt[1]["invocation"] + "\n").encode(),
            original + b"not-an-invocation\n",
        ):
            with self.subTest(damaged=damaged):
                ledger.write_bytes(damaged)
                with pytest.raises(ValueError, match=r"cleanup receipt|cleanup registrations"):
                    receipts.confirm(self.directory, self.owner, self.identity)
        ledger.write_bytes(original)
        with (
            mock.patch.object(
                receipts.uuid, "uuid4", return_value=mock.Mock(hex=receipt[1]["invocation"])
            ),
            pytest.raises(ValueError, match="duplicate"),
        ):
            receipts.begin()
        self.assertEqual(ledger.read_bytes(), original)

    def test_unregistered_extra_receipt_and_over_limit_registration_refuse(self):
        extra = self.directory / ("b" * 32 + ".json")
        extra.write_text("{}")
        with pytest.raises(ValueError, match="unknown"):
            receipts.confirm(self.directory, self.owner, self.identity)
        extra.unlink()
        registered = [receipts.begin() for _ in range(64)]
        with pytest.raises(ValueError, match="too many"):
            receipts.begin()
        for receipt in registered:
            receipts.update(receipt, group=123, confirmed=True)
        self.assertEqual(len(receipts.confirm(self.directory, self.owner, self.identity)), 64)
        with (self.directory / receipts.LEDGER).open("a") as stream:
            stream.write("c" * 32 + "\n")
        with pytest.raises(ValueError, match="too many"):
            receipts.confirm(self.directory, self.owner, self.identity)

    def test_concurrent_registration_keeps_every_invocation(self):
        def operation(index):
            receipt = receipts.begin()
            receipts.update(receipt, group=100 + index, confirmed=True)
            return receipt[1]["invocation"]

        with ThreadPoolExecutor(max_workers=8) as workers:
            identifiers = list(workers.map(operation, range(16)))
        rows = receipts.confirm(self.directory, self.owner, self.identity)
        self.assertEqual(len(set(identifiers)), 16)
        self.assertEqual({row["invocation"] for row in rows}, set(identifiers))

    def test_lock_is_bounded_and_replacement_does_not_switch_lock_identity(self):
        ledger = self.directory / receipts.LEDGER
        descriptor = os.open(ledger, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (
                mock.patch.object(receipts, "LOCK_SECONDS", 0),
                pytest.raises(TimeoutError, match="lock deadline"),
            ):
                receipts.begin()
        finally:
            os.close(descriptor)
        real_lock = fcntl.flock

        def replace_after_lock(descriptor, flags):
            real_lock(descriptor, flags)
            content = ledger.read_bytes()
            ledger.rename(self.root / "retained-ledger")
            ledger.write_bytes(content)

        with (
            mock.patch.object(receipts.fcntl, "flock", side_effect=replace_after_lock),
            pytest.raises(ValueError, match="identity changed"),
        ):
            receipts.begin()

    def test_ledger_special_file_or_oversized_content_does_not_block(self):
        ledger = self.directory / receipts.LEDGER
        ledger.write_bytes(b"x" * (16 * 1024 + 1))
        with pytest.raises(ValueError, match="registration ledger"):
            receipts.begin()
        ledger.unlink()
        os.mkfifo(ledger)
        with pytest.raises(ValueError, match="regular file"):
            receipts.begin()
        ledger.unlink()
        ledger.symlink_to(self.directory / "owner.json")
        with pytest.raises(OSError, match="Too many levels"):
            receipts.begin()


if __name__ == "__main__":
    unittest.main()
