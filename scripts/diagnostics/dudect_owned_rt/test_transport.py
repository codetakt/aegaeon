import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import hosted as h
import recover as r


class Transport(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)
        self.plan={'limits':h.LIMITS,'cases':h.functional.CASES,'branch':h.BRANCH}
        self.env={'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/'+h.BRANCH,'GITHUB_REPOSITORY':'codetakt/aegaeon',
                  'GITHUB_RUN_NUMBER':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,
                  'GITHUB_RUN_ID':'123','GITHUB_WORKFLOW_REF':'codetakt/aegaeon/'+h.WORKFLOW+'@refs/heads/'+h.BRANCH}
        self.event={'created':True,'deleted':False,'before':'0'*40,'after':'a'*40,'ref':self.env['GITHUB_REF'],
                    'repository':{'full_name':'codetakt/aegaeon'}}

    def test_admit_first_creation(self):
        with mock.patch.object(h.rt,'digest',return_value='b'*64):
            self.assertEqual(h.admit(self.env,self.event,self.plan)['head'],'a'*40)

    def test_reject_repeats_and_wrong_bindings(self):
        for key,val in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_NUMBER','2'),('GITHUB_SHA','bad'),
                        ('GITHUB_REF','refs/heads/main'),('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_EVENT_NAME','workflow_dispatch')]:
            with self.subTest(key=key),self.assertRaises(ValueError):h.admit(self.env|{key:val},self.event,self.plan)
        for key,val in [('created',False),('deleted',True),('before','c'*40),('after','c'*40)]:
            with self.subTest(key=key),self.assertRaises(ValueError):h.admit(self.env,self.event|{key:val},self.plan)

    def test_reject_changed_budget(self):
        plan=copy.deepcopy(self.plan);plan['limits']['fixtures']=27
        with self.assertRaises(ValueError):h.admit(self.env,self.event,plan)

    def test_roundtrip_and_tamper(self):
        private=self.p/'private';private.mkdir()
        receipt={'opportunity':{'head':'a'*40,'plan_sha256':'b'*64,'run_id':'123'},'completed':False,'timing':False,'dudect_cases':0}
        (private/'receipt.json').write_text(json.dumps(receipt));(private/'nested').mkdir();(private/'nested/data').write_bytes(b'raw\x00bytes')
        archive=self.p/'data.tar';h.pack(private,archive)
        key,cert=self.p/'key.pem',self.p/'cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
                        '-subj','/CN=functional-test','-days','1'],capture_output=True,check=True,timeout=10)
        cipher=self.p/'cipher.cms'
        subprocess.run(['openssl','cms','-encrypt','-aes-256-gcm','-binary','-outform','DER','-in',str(archive),
                        '-out',str(cipher),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],capture_output=True,check=True,timeout=10)
        summary=dict(schema='owned-rt-functional-summary/1',head='a'*40,plan_sha256='b'*64,run_id='123',
                     timing=False,dudect_cases=0,completed=False,ciphertext_sha256=hashlib.sha256(cipher.read_bytes()).hexdigest())
        got=r.recover(cipher,key,summary,self.p/'recovered','a'*40,'b'*64)
        self.assertTrue(got['authenticated']);self.assertEqual((self.p/'recovered/nested/data').read_bytes(),b'raw\x00bytes')
        raw=bytearray(cipher.read_bytes());raw[-1]^=1;cipher.write_bytes(raw)
        summary['ciphertext_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError):r.recover(cipher,key,summary,self.p/'bad','a'*40,'b'*64)
        self.assertFalse((self.p/'bad').exists())

    def test_archive_traversal(self):
        for name in ('../escape','/absolute','dir/../escape','./relative','dir//bad'):
            archive=self.p/'unsafe.tar'
            with tarfile.open(archive,'w') as t:
                m=tarfile.TarInfo(name);m.size=1;t.addfile(m,io.BytesIO(b'x'))
            with self.subTest(name=name),self.assertRaises(ValueError):r.unpack(archive)

    def test_archive_duplicate(self):
        archive=self.p/'duplicate.tar'
        with tarfile.open(archive,'w') as t:
            for _ in range(2):
                m=tarfile.TarInfo('same');m.size=1;t.addfile(m,io.BytesIO(b'x'))
        with self.assertRaises(ValueError):r.unpack(archive)

    def test_pack_rejects_symlink(self):
        private=self.p/'private';private.mkdir();(private/'link').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):h.pack(private,self.p/'data.tar')


if __name__=='__main__':unittest.main()
