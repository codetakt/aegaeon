"""Authenticate bounded nested functional evidence before releasing plaintext."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


def unpack(path):
    values={};total=0
    with tarfile.open(path,'r:') as archive:
        for m in archive:
            p=PurePosixPath(m.name)
            if (not m.isfile() or p.is_absolute() or str(p)!=m.name or
                any(x in ('.','..') for x in m.name.split('/')) or m.name in values or len(values)>=4097):
                raise ValueError('unsafe archive inventory')
            total+=m.size
            if m.size<0 or total>65*1024*1024:
                raise ValueError('archive exceeds bound')
            raw=archive.extractfile(m).read(m.size+1)
            if len(raw)!=m.size:raise ValueError('truncated archive')
            values[m.name]=raw
    manifest=json.loads(values['manifest.json'])
    entries=manifest['files']
    if set(values)-{'manifest.json'}!={x['path'] for x in entries} or len(entries)!=len(values)-1:
        raise ValueError('manifest inventory')
    for e in entries:
        raw=values[e['path']]
        if len(raw)!=e['bytes'] or hashlib.sha256(raw).hexdigest()!=e['sha256']:
            raise ValueError('manifest digest')
    return values


def recover(cipher,key,summary,output,head,plan,openssl='openssl'):
    if output.exists():raise FileExistsError('recovery exists')
    if (summary['schema']!='owned-rt-functional-summary/1' or summary['head']!=head or
        summary['plan_sha256']!=plan or summary['timing'] is not False or summary['dudect_cases']!=0):
        raise ValueError('summary binding')
    if cipher.stat().st_size>80*1024*1024 or hashlib.sha256(cipher.read_bytes()).hexdigest()!=summary['ciphertext_sha256']:
        raise ValueError('cipher binding')
    with tempfile.TemporaryDirectory(dir=output.parent,prefix='.owned-rt-decrypt-') as temp:
        archive=Path(temp)/'unverified.tar'
        r=subprocess.run([openssl,'cms','-decrypt','-binary','-inform','DER','-in',str(cipher),
                          '-inkey',str(key),'-out',str(archive)],capture_output=True,timeout=30)
        if r.returncode:raise ValueError('authentication failed')
        if archive.stat().st_size>80*1024*1024:raise ValueError('archive size')
        values=unpack(archive)
        receipt=json.loads(values['receipt.json']);op=receipt['opportunity']
        if (op['head']!=head or op['plan_sha256']!=plan or op['run_id']!=summary['run_id'] or
            receipt['completed']!=summary['completed'] or receipt['timing'] is not False or receipt['dudect_cases']!=0):
            raise ValueError('private binding')
        verified=Path(temp)/'verified';verified.mkdir(mode=0o700)
        for name,raw in values.items():
            p=verified/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(raw);p.chmod(0o400)
        verified.rename(output)
    return {'authenticated':True,'files':len(values)-1,'completed':receipt['completed']}


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('cipher','key','summary','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--head',required=True);p.add_argument('--plan',required=True)
    a=p.parse_args()
    print(json.dumps(recover(a.cipher,a.key,json.loads(a.summary.read_text()),a.output,a.head,a.plan)))
