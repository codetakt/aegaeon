import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from recover import unpack


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)

    def archive(self,entries):
        file=self.path/'input.tar.gz'
        with tarfile.open(file,'w:gz') as tar:
            for name,data,kind in entries:
                m=tarfile.TarInfo(name);m.size=len(data);m.type=kind
                tar.addfile(m,io.BytesIO(data))
        return file

    def test_stream_manifest(self):
        raw=b'evidence';row=dict(path='sub/raw',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        file=self.archive([('sub/raw',raw,tarfile.REGTYPE),
                           ('manifest.json',json.dumps({'files':[row]}).encode(),tarfile.REGTYPE)])
        self.assertEqual(unpack(file,self.path/'output'),1)
        self.assertEqual((self.path/'output/sub/raw').read_bytes(),raw)

    def test_path_rejections(self):
        for name in ('../escape','/absolute','a/../b','a//b','./a'):
            with self.subTest(name=name):
                file=self.archive([(name,b'',tarfile.REGTYPE)])
                with self.assertRaises(ValueError):unpack(file,self.path/'output')

    def test_links_rejected(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE):
            file=self.archive([('link',b'',kind)])
            with self.assertRaises(ValueError):unpack(file,self.path/'output')

    def test_duplicate_rejected(self):
        file=self.archive([('x',b'a',tarfile.REGTYPE),('x',b'a',tarfile.REGTYPE)])
        with self.assertRaises(ValueError):unpack(file,self.path/'output')

    def test_mismatch_rejected(self):
        row=dict(path='x',bytes=1,sha256='0'*64)
        file=self.archive([('x',b'a',tarfile.REGTYPE),('manifest.json',json.dumps({'files':[row]}).encode(),tarfile.REGTYPE)])
        with self.assertRaises(ValueError):unpack(file,self.path/'output')

    def test_missing_manifest_entry(self):
        file=self.archive([('x',b'a',tarfile.REGTYPE),('manifest.json',b'{"files":[]}',tarfile.REGTYPE)])
        with self.assertRaises(ValueError):unpack(file,self.path/'output')


if __name__=='__main__':unittest.main()
