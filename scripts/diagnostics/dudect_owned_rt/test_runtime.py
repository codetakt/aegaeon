import copy
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import time
import unittest
from unittest import mock

import runtime as r
import run_functional as f


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.d = dict(uid=1001, gid=100, cpu=31, rtprio=[1, 1], rttime=[50000, 150000], unit='aeg-ort-test-native.service')
        self.c = dict(uid=1001, gid=100, affinity=[31], rtprio=[1, 1], rttime=[50000, 150000],
                      pid=42, policy=r.RESET, priority=0, threads=['42'],
                      caps=dict(CapEff='0', CapPrm='0', CapAmb='0'),
                      cgroup='0::/system.slice/aeg-ort-test-native.service\n')

    def test_accept_other(self):
        r.validate_context(self.d, self.c)

    def test_reject_each_unsafe_constraint(self):
        for key, value in dict(uid=0, gid=0, affinity=[30], rtprio=[0, 0], rttime=[-1, -1],
                               policy=r.RESET | os.SCHED_FIFO, priority=1, threads=['42','43'],
                               cgroup='0::/system.slice/background.service\n').items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.validate_context(self.d, self.c | {key: value})

    def test_capabilities_rejected(self):
        for cap in self.c['caps']:
            c = copy.deepcopy(self.c); c['caps'][cap] = '800000'
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                r.validate_context(self.d, c)

    def test_unit_bootstrap_is_never_fifo(self):
        d = dict(cpu=31, housekeeping=[0,16], fault='none', rtprio=[1,1], rttime=[50000,150000])
        account = mock.Mock(pw_name='fixture', pw_gid=100)
        for role in ('launcher', 'primary', 'rescue', 'controller', 'deadline'):
            text = f.render('owned', role, d, account, '/runtime.py', '/owned')
            self.assertIn('CPUSchedulingPolicy=other\n', text)
            self.assertIn('CPUSchedulingResetOnFork=yes\n', text)
            self.assertIn('KillMode=control-group\n', text)
            self.assertIn('Restart=no\n', text)
            self.assertNotIn('CPUSchedulingPolicy=fifo', text)
        text = f.render('owned', 'launcher', d, account, '/runtime.py', '/owned')
        self.assertIn('LimitRTTIME=50000:150000\n', text)
        self.assertIn('CapabilityBoundingSet=\n', text)


class Leases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.d = dict(dir=self.path, generation='one', start_by=time.monotonic()+10,
                      heartbeat_limit=.75, unit='aeg-ort-one-native.service', systemctl='/systemctl')

    def test_revocation_is_monotonic(self):
        r.current_start(self.d); r.close(self.d)
        with self.assertRaises(ValueError): r.current_start(self.d)
        with self.assertRaises(FileExistsError): r.close(self.d)

    def test_expired_start(self):
        with self.assertRaises(ValueError):
            r.current_start(self.d | {'start_by': time.monotonic()-1})

    def test_pid_reuse_is_not_live(self):
        ident = r.identity(os.getpid())
        r.pulse(self.d, 'primary', ident)
        self.assertTrue(r.live(self.d, 'primary'))
        with mock.patch.object(r, 'identity', return_value=ident | {'start': ident['start']+1}):
            self.assertFalse(r.live(self.d, 'primary'))

    def test_stale_generation(self):
        r.pulse(self.d, 'primary', r.identity(os.getpid()))
        self.assertFalse(r.live(self.d | {'generation': 'two'}, 'primary'))

    def test_stale_and_future_heartbeat(self):
        for at in (time.monotonic()-1, time.monotonic()+10):
            r.write(self.path/'primary.heartbeat.json', dict(generation='one',at=at,identity=r.identity(os.getpid())))
            self.assertFalse(r.live(self.d, 'primary'))

    def test_ack_absence_corruption_expiration(self):
        self.assertFalse(r.lease_ok(self.d))
        (self.path/'ack.json').write_text('bad')
        self.assertFalse(r.lease_ok(self.d))
        for gen, at in [('two',time.monotonic()), ('one',time.monotonic()-1), ('one',time.monotonic()+10)]:
            r.write(self.path/'ack.json', dict(generation=gen,at=at))
            self.assertFalse(r.lease_ok(self.d))

    def test_stop_before_journal_or_rpc(self):
        order=[]
        with mock.patch.object(signal,'pidfd_send_signal', side_effect=lambda *a:order.append('kill')), \
             mock.patch.object(r,'close', side_effect=lambda *a:order.append('revoke')), \
             mock.patch.object(r,'event'), \
             mock.patch.object(r.subprocess,'run', side_effect=lambda *a,**k: (order.append('rpc') or mock.Mock(returncode=0,stderr=''))):
            r.stop(self.d,'rescue','fault',123)
        self.assertEqual(order,['kill','rpc','revoke'])

    def test_rpc_timeout_remains_unconfirmed(self):
        with mock.patch.object(r.subprocess,'run',side_effect=r.subprocess.TimeoutExpired('ctl',1)), \
             mock.patch.object(r,'event') as ev:
            r.stop(self.d,'rescue','fault')
        self.assertEqual(ev.call_args.args[2], 'stop-rpc-unconfirmed')
        self.assertTrue(r.closed(self.d))

    def test_descriptor_rejects_outside_protected_root(self):
        with self.assertRaises(ValueError): r.descriptor(self.path/'descriptor.json')

    def test_plan_is_not_timing(self):
        self.assertEqual(len(f.CASES),26)
        self.assertEqual(len(f.CASES),len(set(f.CASES)))

    def test_archive_socket_metadata(self):
        source = self.path / 'source'; source.mkdir()
        (source/'regular').write_text('evidence')
        sock=socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(source/'guard.sock'))
        f.archive(source,self.path/'archive')
        self.assertEqual((self.path/'archive/regular').read_text(),'evidence')
        self.assertEqual(r.read(self.path/'archive/nonregular-entries.json'),[{'path':'guard.sock','type':'unix_socket'}])


if __name__ == '__main__': unittest.main()
