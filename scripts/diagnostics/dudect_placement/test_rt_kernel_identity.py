"""Kernel identity/collector fixtures, never scheduling or Hosted execution."""
import ast
import base64
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import rt_kernel_identity as k
import rt_preflight as r
from test_rt_preflight import facts

REF = json.loads(k.REFERENCE.read_bytes())
UNAME = SimpleNamespace(release=REF['identity']['release'], version=REF['identity']['version'],
                        machine=REF['identity']['architecture'])


def note(desc=None, name=b'GNU\0', kind=3):
    desc = bytes.fromhex(REF['identity']['build_id']) if desc is None else desc
    return (struct.pack('<III', len(name), len(desc), kind) + name + bytes(-len(name) % 4)
            + desc + bytes(-len(desc) % 4))


def source():
    return {'source': '/boot/config-' + UNAME.release,
            'expanded_sha256': REF['identity']['config_sha256'],
            'expanded_bytes': REF['archive_chain']['config_bytes'],
            'values': {'CONFIG_CGROUP_SCHED': 'y', 'CONFIG_RT_GROUP_SCHED': 'n',
                       'CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED': None,
                       'CONFIG_POSIX_TIMERS': 'y', 'CONFIG_HZ': '1000', 'CONFIG_SMP': 'y'}}


def captured(raw=None):
    raw = note() if raw is None else raw
    return {'raw_base64': base64.b64encode(raw).decode(), 'sha256': k.sha(raw),
            'bytes': len(raw), 'provenance': {'fixture': True}}


class NotesTests(unittest.TestCase):
    def test_unique_id_and_unknown_note_preserved(self):
        raw = note(b'xyz', b'Linux\0', 1) + note()
        self.assertEqual(k.parse_notes(raw)['build_id'], REF['identity']['build_id'])
        self.assertEqual(k.parse_notes(raw)['note_count'], 2)

    def test_malformed_and_duplicate_notes_rejected(self):
        variants = [b'', note()[:-1], note() + b'x', note() * 2,
                    note(name=b'GNU'), note(kind=2), note(bytes(15)), note(bytes(65)),
                    struct.pack('<III', 0xffffffff, 20, 3),
                    struct.pack('<III', 0, 0, 0),
                    note(b'x', b'Linux\0', 1)[:-1] + b'x' + note()]
        for raw in variants:
            with self.subTest(raw=raw[:16]), self.assertRaises(ValueError):
                k.parse_notes(raw)

    def test_byte_and_record_limits(self):
        with self.assertRaises(ValueError):
            k.parse_notes(bytes(k.MAX_NOTES + 1))
        extra = note(b'', b'Linux\0', 1)
        self.assertEqual(k.parse_notes(extra * 1023 + note())['note_count'], 1024)
        with self.assertRaises(ValueError):
            k.parse_notes(extra * 1024 + note())

    def test_deadline_interrupts_parser(self):
        def expired():
            raise r.Deadline('parser deadline fixture')
        with self.assertRaises(r.Deadline):
            k.parse_notes(note(), expired)

    def test_reference_exact_bytes_required(self):
        self.assertEqual(k.reference(lambda *args: k.REFERENCE.read_bytes()), REF)
        for raw in (k.REFERENCE.read_bytes() + b' ', b'{}'):
            with self.subTest(raw=raw[:12]), self.assertRaises(ValueError):
                k.reference(lambda *args: raw)

    def test_sysfs_mount_and_actual_fd_match(self):
        raw = b'41 63 0:23 / /sys rw - sysfs sysfs rw\n'
        self.assertEqual(k.sysfs_binding(raw, b'mnt_id:\t41\n', os.makedev(0, 23))['mount_id'], 41)
        for changed in (raw * 2, raw.replace(b' / /sys', b' /kernel /sys'),
                        raw.replace(b'- sysfs', b'- tmpfs'), raw.replace(b'0:23', b'0:24'),
                        raw + b'42 41 0:23 /kernel /sys/kernel ro - sysfs sysfs ro\n',
                        raw + b'42 41 0:23 /kernel/notes /sys/kernel/notes ro - sysfs sysfs ro\n'):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                k.sysfs_binding(changed, b'mnt_id:\t41\n', os.makedev(0, 23))
        with self.assertRaises(ValueError):
            k.sysfs_binding(raw, b'mnt_id:\t42\n', os.makedev(0, 23))

    def test_read_only_api_surface(self):
        forbidden = {'sched_setscheduler', 'sched_setaffinity', 'setrlimit', 'execve',
                     'Popen', 'system', 'socket', 'urlopen'}
        for node in ast.walk(ast.parse(Path(k.__file__).read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'kernel').mkdir()
        (self.root / 'kernel/notes').write_bytes(note())
        self.open = os.open
        self.collector = r.Collector('example.service', os.getpid())

    def redirected_open(self, path, flags, *args, **kwargs):
        notes_path = path in ('/sys', 'kernel', 'notes')
        if path == '/sys':
            path = self.root
        self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if notes_path:
            self.assertTrue(flags & os.O_NOFOLLOW)
        return self.open(path, flags, *args, **kwargs)

    def capture(self, binding=None):
        with patch.object(k.os, 'open', side_effect=self.redirected_open), \
                patch.object(k, 'sysfs_binding', side_effect=binding or (lambda *args: {'fixture': True})):
            return k.capture(self.collector.read, self.collector.check)

    def test_full_bytes_capture_and_closed_descriptors(self):
        before = set(os.listdir('/proc/self/fd'))
        result = self.capture()
        self.assertEqual(base64.b64decode(result['raw_base64']), note())
        self.assertEqual(result['sha256'], k.sha(note()))
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_missing_permissions_and_symlink_rejected(self):
        path = self.root / 'kernel/notes'
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.capture()
        path.symlink_to('/proc/self/stat')
        with self.assertRaises(OSError):
            self.capture()
        with patch.object(k.os, 'open', side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                k.capture(self.collector.read, self.collector.check)

    def test_symlink_directory_and_fifo_rejected(self):
        (self.root / 'kernel/notes').unlink()
        os.mkfifo(self.root / 'kernel/notes')
        with self.assertRaises(ValueError):
            self.capture()
        (self.root / 'kernel/notes').unlink()
        (self.root / 'kernel').rmdir()
        (self.root / 'kernel').symlink_to('/sys/kernel')
        with self.assertRaises(OSError):
            self.capture()

    def test_oversize_and_deadline_close_fds(self):
        (self.root / 'kernel/notes').write_bytes(bytes(k.MAX_NOTES + 1))
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):
            self.capture()
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        self.collector.deadline = time.monotonic() - 1
        with self.assertRaises(r.Deadline):
            self.capture()
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_mount_change_and_mid_read_deadline(self):
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):
            self.capture([{'mount_id': 1}, {'mount_id': 2}])
        calls = []
        def check():
            calls.append(1)
            if len(calls) == 4:
                raise r.Deadline('read deadline fixture')
        with patch.object(self.collector, 'check', side_effect=check), self.assertRaises(r.Deadline):
            self.capture()
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)


class CorrespondenceTests(unittest.TestCase):
    def evaluate(self, uname=UNAME, sources=None, notes=None, version=None, errors=()):
        return k.correspondence(REF, uname, sources if sources is not None else [source()],
                                notes if notes is not None else {'parsed': k.parse_notes(note())},
                                version or {'status': 'absent'}, errors)

    def test_match_is_not_execution_or_attestation(self):
        result = self.evaluate()
        self.assertEqual(result['status'], k.MATCH)
        self.assertFalse(result['execution_admitted'])
        self.assertFalse(result['runtime_patch_absence_proven'])

    def test_unknown_build_and_full_config_mismatch(self):
        for change in ('release', 'version', 'machine'):
            uname = copy.copy(UNAME);setattr(uname, change, 'different')
            with self.subTest(change=change):
                self.assertEqual(self.evaluate(uname=uname)['status'], k.UNKNOWN)
        for field in ('expanded_sha256', 'expanded_bytes'):
            row = source();row[field] = 'bad'
            self.assertEqual(self.evaluate(sources=[row])['status'], k.UNKNOWN)
        self.assertEqual(self.evaluate(sources=[])['status'], k.UNKNOWN)
        self.assertEqual(self.evaluate(notes={})['status'], k.UNKNOWN)
        self.assertEqual(self.evaluate(notes={'parsed': k.parse_notes(note(bytes(20)))})['status'], k.UNKNOWN)

    def test_supporting_signature_and_errors(self):
        self.assertEqual(self.evaluate(version={'status': 'present', 'value': REF['version_signature']})['status'], k.MATCH)
        self.assertEqual(self.evaluate(version={'status': 'present', 'value': 'changed'})['status'], k.UNKNOWN)
        self.assertEqual(self.evaluate(errors=['permission denied'])['status'], k.UNKNOWN)

    def kernel(self, *, capture_value=None, capture_error=None, reference_raw=None,
               config_error=None, signature_error=None, notes_parser=None):
        c = r.Collector('example.service', os.getpid())
        def read(path, *args):
            if Path(path) == k.REFERENCE:
                return reference_raw if reference_raw is not None else k.REFERENCE.read_bytes()
            if str(path).startswith('/boot/config-'):
                if config_error:
                    raise config_error
                return b'functional config fixture'
            if str(path) == '/proc/cmdline':
                return b''
            if str(path) == '/proc/version_signature' and signature_error:
                raise signature_error
            raise FileNotFoundError(str(path))
        with patch.object(r.os, 'uname', return_value=UNAME), \
                patch.object(c, 'read', side_effect=read), \
                patch.object(r, 'parse_config', return_value=source()), \
                patch.object(k, 'capture', side_effect=capture_error,
                             return_value=capture_value if capture_value is not None else captured()):
            if notes_parser:
                with patch.object(k, 'parse_notes', side_effect=notes_parser):
                    return c.kernel()
            return c.kernel()

    def test_collector_matching_archive_fixture(self):
        row = self.kernel()
        self.assertTrue(row['config_correspondence'])
        self.assertEqual(row['correspondence_receipt']['status'], k.MATCH)
        self.assertFalse(row['errors'])
        self.assertEqual(base64.b64decode(row['notes']['raw_base64']), note())

    def test_collector_failure_never_uses_release_name_fallback(self):
        for kw in ({'capture_error': FileNotFoundError()}, {'capture_error': PermissionError()},
                   {'capture_value': captured(note()[:-1])}, {'capture_value': captured(note() * 2)},
                   {'capture_value': captured(note(bytes(20)))}, {'reference_raw': b'{}'},
                   {'config_error': PermissionError()}, {'signature_error': PermissionError()}):
            with self.subTest(kw=kw):
                row = self.kernel(**kw)
                self.assertFalse(row['config_correspondence'])
                self.assertEqual(row['correspondence_receipt']['status'], k.UNKNOWN)

    def test_malformed_raw_retained_and_deadline_propagates(self):
        raw = note()[:-1]
        result = self.kernel(capture_value=captured(raw))
        self.assertEqual(base64.b64decode(result['notes']['raw_base64']), raw)
        for kw in ({'capture_error': r.Deadline('capture')}, {'notes_parser': r.Deadline('parse')}):
            with self.subTest(kw=kw), self.assertRaises(r.Deadline):
                self.kernel(**kw)

    def test_each_identity_change_between_censuses_is_unknown(self):
        row = {'facts': facts(), 'errors': []}
        row['facts']['kernel'] = self.kernel()
        row['facts']['boot_id'] = 'original'
        self.assertEqual(r.classify([row, copy.deepcopy(row)])[0], r.COMPATIBLE)
        for field in ('notes', 'release', 'version', 'config_sources', 'correspondence_receipt'):
            changed = copy.deepcopy(row)
            changed['facts']['kernel'][field] = 'changed'
            self.assertEqual(r.classify([row, changed])[0], r.UNKNOWN)
        changed = copy.deepcopy(row);changed['facts']['boot_id'] = 'new boot'
        self.assertEqual(r.classify([row, changed])[0], r.UNKNOWN)


if __name__ == '__main__':
    unittest.main()
