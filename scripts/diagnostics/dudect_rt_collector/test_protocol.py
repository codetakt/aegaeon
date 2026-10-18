import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import protocol as p
import runtime as r
import run_unit


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        now=time.monotonic()
        self.d=dict(dir=Path(self.tmp.name),generation='one',epoch=now,start_by=now+20,
                    end_at=now+2700,collector={'cases':['first','second','third']})
        self.p=p.Progress(self.d)

    def test_native_deadline_is_not_heartbeat(self):
        self.p.started();before=self.p.deadline
        for look in range(1,8):
            self.p.validation();self.p.acknowledged(0,look,'row','proof')
            self.assertEqual(self.p.deadline,before)

    def test_only_complete_case_renews(self):
        self.p.started();before=self.p.deadline
        for look in range(1,9):
            self.p.validation();self.p.acknowledged(0,look,'row','proof')
        self.assertEqual(self.p.case,1)
        self.assertGreater(self.p.deadline,before)
        self.assertLessEqual(self.p.deadline,self.d['end_at'])

    def test_look_order_and_phase(self):
        with self.assertRaises(ValueError):self.p.validation()
        self.p.started();self.p.validation()
        for case,look in [(1,1),(0,2),(0,0)]:
            with self.assertRaises(ValueError):self.p.acknowledged(case,look,'row','proof')

    def test_expired_validation_cannot_ack_or_extend(self):
        self.p.started();deadline=self.p.validation()
        with patch.object(time,'monotonic',return_value=deadline+.001):
            self.assertFalse(p.progress_valid(self.d))
            with self.assertRaises(TimeoutError):self.p.acknowledged(0,1,'row','proof')

    def test_actual_ack_receipt(self):
        self.p.started();self.p.validation();self.p.acknowledged(0,1,'a'*64,'b'*64)
        row=r.read(self.d['dir']/'progress.json')
        self.assertTrue(row['ack_sent']);self.assertEqual(row['look'],1)
        self.assertEqual(row['row_sha256'],'a'*64)

    def test_missing_corrupt_wrong_generation_future(self):
        good=r.read(self.d['dir']/'progress.json')
        for change in ({'generation':'old'},{'phase':'fake'}, {'at':self.d['end_at']+1},
                       {'until':self.d['end_at']+1},{'case_deadline':0}):
            r.write(self.d['dir']/'progress.json',good|change)
            self.assertFalse(p.progress_valid(self.d))
        (self.d['dir']/'progress.json').write_text('bad')
        self.assertFalse(p.progress_valid(self.d))

    def test_final_completion_is_bounded(self):
        self.p.started()
        for case in range(3):
            for look in range(1,9):
                self.p.validation();self.p.acknowledged(case,look,'row','proof')
        self.assertEqual(self.p.state,'completion')
        row=r.read(self.d['dir']/'progress.json')
        self.assertLessEqual(row['until']-row['at'],10)
        with self.assertRaises(ValueError):self.p.validation()

    def test_common_arm_unit_monitor(self):
        d=dict(cpu=2,housekeeping=[0,1],epoch=1,end_at=151,uid=1001,gid=100,
               rttime=[60000000,90000000],dir=Path('/run/example'))
        for role in ('controller','primary','rescue','deadline','launcher'):
            a=run_unit.render(role,d|{'arm':'A'},'/runtime.py','/python')
            b=run_unit.render(role,d|{'arm':'B'},'/runtime.py','/python')
            self.assertEqual(a,b)
            self.assertIn('CPUSchedulingPolicy=other',a)
            self.assertNotIn('CPUSchedulingPolicy=fifo',a)
        self.assertIn('LimitRTTIME=60000000:90000000',a)

    def test_supervisor_placement_rejects_shared_core(self):
        with patch.object(Path,'read_text',return_value='2-3\n'):
            with self.assertRaises(ValueError):run_unit.place_supervisor({'native':2,'housekeeping':[0,3]})

    def test_supervisor_placement_readback_required(self):
        with patch.object(Path,'read_text',return_value='2-3\n'),patch.object(os,'sched_setaffinity') as setcpu, \
                patch.object(os,'sched_getaffinity',return_value={0,1,2}):
            with self.assertRaises(ValueError):run_unit.place_supervisor({'native':2,'housekeeping':[0,1]})
            setcpu.assert_called_once_with(0,{0,1})


if __name__=='__main__':unittest.main()
