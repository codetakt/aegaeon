"""Stream authenticated private evidence into a temporary directory, then verify."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def unpack(archive, dest):
    seen=set();total=0
    with tarfile.open(archive,'r|gz') as tar:
        for m in tar:
            path=PurePosixPath(m.name)
            if (not m.isfile() or path.is_absolute() or str(path)!=m.name or
                any(x in ('.','..') for x in m.name.split('/')) or m.name in seen or len(seen)>=12001):
                raise ValueError('unsafe archive member')
            total+=m.size
            if m.size<0 or m.size>512*1024**2 or total>6*1024**3:raise ValueError('archive bound')
            seen.add(m.name);out=dest/m.name;out.parent.mkdir(parents=True,exist_ok=True)
            source=tar.extractfile(m)
            with out.open('xb') as f:
                remaining=m.size
                while remaining:
                    data=source.read(min(1024**2,remaining))
                    if not data:raise ValueError('short member')
                    f.write(data);remaining-=len(data)
            out.chmod(0o400)
    manifest=json.loads((dest/'manifest.json').read_text())['files']
    if seen-{'manifest.json'}!={r['path'] for r in manifest} or len(manifest)!=len(seen)-1:
        raise ValueError('manifest inventory')
    for row in manifest:
        p=dest/row['path']
        if p.stat().st_size!=row['bytes'] or sha(p)!=row['sha256']:raise ValueError('manifest digest')
    return len(manifest)


def recover(cipher,key,summary,output,head,plan,slot):
    if output.exists():raise FileExistsError(output)
    if (summary['schema']!='owned-scheduler-comparison/1' or summary['head']!=head or
        summary['plan_sha256']!=plan or summary['slot']!=slot or summary['timing'] is not True or
        cipher.stat().st_size>8*1024**3 or sha(cipher)!=summary['ciphertext_sha256']):
        raise ValueError('outer binding')
    with tempfile.TemporaryDirectory(dir=output.parent,prefix='.authenticated-owned-') as temp:
        temp=Path(temp);archive=temp/'verified.gz'
        r=subprocess.run(['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(cipher),
                          '-inkey',str(key),'-out',str(archive)],capture_output=True,timeout=180)
        if r.returncode:raise ValueError('authenticated decryption failed')
        dest=temp/'evidence';dest.mkdir(mode=0o700)
        files=unpack(archive,dest)
        receipt=json.loads((dest/'receipt.json').read_text());op=receipt['opportunity']
        if (op['head']!=head or op['plan_sha256']!=plan or op['slot']!=slot or
            op['run_id']!=summary['run_id'] or receipt['completed']!=summary['completed'] or
            receipt['dudect_cases']!=summary['dudect_cases']):raise ValueError('inner binding')
        dest.rename(output)
    return dict(authenticated=True,files=files,completed=receipt['completed'])


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for key in ('cipher','key','summary','output'):p.add_argument('--'+key,type=Path,required=True)
    for key in ('head','plan'):p.add_argument('--'+key,required=True)
    p.add_argument('--slot',type=int,required=True)
    a=p.parse_args()
    print(json.dumps(recover(a.cipher,a.key,json.loads(a.summary.read_text()),a.output,a.head,a.plan,a.slot)))
