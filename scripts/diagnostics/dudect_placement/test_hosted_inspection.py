import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hosted_inspection as host


class HostedTransportTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            here = root / 'collector'
            here.mkdir()
            plan = {'branch':'test/dudect-hosted-service-inspection','source_sha256':{}}
            (here/'inspection-plan.json').write_text(json.dumps(plan))
            # Only this generated fixture private key is used; not the publication key.
            key = root/'key.pem'
            result = subprocess.run([shutil.which('openssl'),'req','-x509','-newkey','rsa:2048','-noenc',
                                     '-keyout',str(key),'-out',str(here/'receipt-recipient.pem'),
                                     '-days','1','-subj','/CN=Transport-test','-batch'],
                                    capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0)
            env = {'GITHUB_RUN_ATTEMPT':'1','GITHUB_REF':'refs/heads/'+plan['branch'],
                   'GITHUB_REPOSITORY':'codetakt/aegaeon','GITHUB_SHA':'fixture-head'}
            original = host.command
            def command(argv, seconds=5):
                if argv[0]=='git':
                    return 'fixture-head'
                if argv[0]=='/usr/bin/openssl':
                    argv = [shutil.which('openssl'),*argv[1:]]
                return original(argv,seconds)
            with patch.dict(os.environ,env),patch.object(host,'ROOT',root), \
                 patch.object(host,'HERE',here),patch.object(host,'command',side_effect=command):
                yield root,here,key

    def collect(self,argv,**kwargs):
        output=Path(argv[-2]);runtime=Path(argv[-1])
        output.write_text(json.dumps({'timing_admission':False,'native_invocations':0,
                                     'configuration_mutations':0,'classification':'INHERITED_UNSET'}))
        runtime.write_text('{}')
        return subprocess.CompletedProcess(argv,0,'','')

    def decrypt(self,root,key):
        output=root/'recovered.tar'
        subprocess.run([shutil.which('openssl'),'cms','-decrypt','-binary','-inform','DER',
                        '-in',str(root/'artifacts/service-inspection-upload/evidence.cms'),
                        '-inkey',str(key),'-out',str(output)],check=True,capture_output=True,timeout=10)
        return output.read_bytes()

    def test_complete_receipt_roundtrip_is_encrypted_only(self):
        with self.fixture() as (root,_,key):
            original_run = subprocess.run
            def run(argv,**kwargs):
                return self.collect(argv,**kwargs) if argv[:2]==['/usr/bin/python3','-I'] else original_run(argv,**kwargs)
            with patch.object(host,'binding',return_value={'fixed':True}),patch.object(subprocess,'run',side_effect=run):
                self.assertEqual(host.main(),0)
            self.assertIn(b'INHERITED_UNSET',self.decrypt(root,key))
            upload=root/'artifacts/service-inspection-upload'
            self.assertEqual([x.name for x in upload.iterdir()],['evidence.cms'])
            self.assertEqual((root/'artifacts').stat().st_mode & 0o777,0o755)
            self.assertEqual((root/'artifacts/service-inspection-private').stat().st_mode & 0o777,0o700)

    def test_failed_collection_still_encrypts_failure(self):
        with self.fixture() as (root,_,key):
            original_run = subprocess.run
            def run(argv,**kwargs):
                if argv[:2]==['/usr/bin/python3','-I']:
                    return subprocess.CompletedProcess(argv,1,'','model read failure')
                return original_run(argv,**kwargs)
            with patch.object(host,'binding',return_value={'fixed':True}),patch.object(subprocess,'run',side_effect=run):
                self.assertEqual(host.main(),1)
            self.assertIn(b'model read failure',self.decrypt(root,key))

    def test_binding_change_is_not_complete(self):
        with self.fixture() as (root,_,key):
            original_run = subprocess.run
            def run(argv,**kwargs):
                return self.collect(argv,**kwargs) if argv[:2]==['/usr/bin/python3','-I'] else original_run(argv,**kwargs)
            with patch.object(host,'binding',side_effect=[{'hash':'before'},{'hash':'after'}]), \
                 patch.object(subprocess,'run',side_effect=run):
                self.assertEqual(host.main(),1)
            receipt=json.loads((root/'artifacts/service-inspection-private/opportunity.json').read_text())
            self.assertFalse(receipt['operation_complete'])

    def test_replacement_attempt_is_refused_before_collection(self):
        with self.fixture() as (root,_,key):
            with patch.dict(os.environ,{'GITHUB_RUN_ATTEMPT':'2'}),patch.object(host,'binding') as bind:
                with self.assertRaises(RuntimeError):
                    host.main()
                bind.assert_not_called()
            self.assertFalse((root/'artifacts').exists())


if __name__=='__main__':
    unittest.main()
