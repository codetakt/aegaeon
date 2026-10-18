"""One bounded Hosted functional allocation; never invokes Dudect timing."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'dudect_placement'))
import runtime as rt
import run_functional as functional
import rt_runtime as bounded

BRANCH = 'test/dudect-owned-rt-functional-20261018'
WORKFLOW = '.github/workflows/dudect-owned-rt-functional.yml'
PLAN = HERE / 'hosted-plan.json'
LIMITS = {'allocations': 1, 'attempts': 1, 'fixtures': 26, 'dudect_cases': 0,
          'timing': False, 'replacements': 0, 'stage_seconds': 240, 'wrapper_seconds': 480,
          'job_seconds': 600}
FILES = {str(Path('scripts/diagnostics/dudect_owned_rt') / n) for n in
         ('runtime.py','run_functional.py','helper.c','observe.h','observe.c','hosted.py',
          'recover.py','test_runtime.py','test_transport.py','recipient.pem','README.md')}
FILES |= {str(Path('scripts/diagnostics/dudect_placement') / n) for n in
          ('rt_preflight.py','rt_runtime.py','rt_kernel_identity.py','rt-kernel-reference.json')}
FILES.add(WORKFLOW)


def binding(plan):
    if set(plan['inputs']) != FILES:
        raise ValueError('source inventory')
    actual = {p: rt.digest(ROOT / p) for p in sorted(FILES)}
    if actual != plan['inputs']:
        raise ValueError('source digest')
    return actual


def admit(env, event, plan):
    want = {'GITHUB_EVENT_NAME':'push', 'GITHUB_REF':'refs/heads/'+BRANCH,
            'GITHUB_REPOSITORY':'codetakt/aegaeon', 'GITHUB_RUN_NUMBER':'1', 'GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_WORKFLOW_REF':'codetakt/aegaeon/'+WORKFLOW+'@refs/heads/'+BRANCH}
    head = env.get('GITHUB_SHA','')
    if any(env.get(k) != v for k,v in want.items()) or not re.fullmatch('[0-9a-f]{40}',head) or env.get('GITHUB_WORKFLOW_SHA') != head:
        raise ValueError('event identity')
    if (event.get('created') is not True or event.get('deleted') is not False or
            event.get('before') != '0'*40 or event.get('after') != head or
            event.get('ref') != want['GITHUB_REF'] or event.get('repository',{}).get('full_name') != 'codetakt/aegaeon'):
        raise ValueError('not first branch creation')
    if plan['limits'] != LIMITS or plan['cases'] != functional.CASES or plan['branch'] != BRANCH:
        raise ValueError('plan limits')
    return {'head':head,'run_id':env['GITHUB_RUN_ID'],'plan_sha256':rt.digest(PLAN),
            'image':{k:env.get(k) for k in ('ImageOS','ImageVersion')}}


def pack(directory, destination):
    files = []
    total = 0
    for p in sorted(directory.rglob('*')):
        if p.is_dir():
            continue
        if p.is_symlink() or not p.is_file():
            raise ValueError('nonregular evidence')
        total += p.stat().st_size
        if total > 64*1024*1024 or len(files) >= 4096:
            raise ValueError('evidence bound')
        files.append({'path':str(p.relative_to(directory)), 'bytes':p.stat().st_size,'sha256':rt.digest(p)})
    rt.write(directory/'manifest.json',{'files':files})
    with tarfile.open(destination,'x') as archive:
        for p in [directory/f['path'] for f in files]+[directory/'manifest.json']:
            archive.add(p,arcname=str(p.relative_to(directory)),recursive=False)


def call(argv, timeout, path):
    r = bounded.run(argv,timeout,new_group=True)
    rt.write(path, {'argv':argv,'returncode':r['returncode'],
                   'stdout':r['stdout'].decode(errors='replace'),'stderr':r['stderr'].decode(errors='replace')})
    if r['returncode']:
        raise RuntimeError('bounded subprocess failed: '+str(path.name))
    return r


def execute(plan, opportunity):
    base = ROOT/'artifacts/owned-rt'
    base.mkdir(parents=True,mode=0o700)
    private,upload=base/'private',base/'upload'
    private.mkdir(mode=0o700);upload.mkdir(mode=0o755)
    started=time.monotonic()
    receipt={'opportunity':opportunity,'completed':False,'timing':False,'dudect_cases':0,
             'started':started,'stage':'preflight','owned_units_started':False}
    status=1
    try:
        receipt['source_before']=binding(plan)
        receipt['runtime_before']={n:bounded.dependency_snapshot(n,5) for n in
             ('/usr/bin/python3','/usr/bin/systemctl','/usr/bin/openssl','/usr/bin/cc')}
        code = ('import sys,runpy;sys.path.insert(0,sys.argv[1]);p=sys.argv.pop(1);'
                'sys.argv[0]=p+"/rt_preflight.py";runpy.run_path(sys.argv[0],run_name="__main__")')
        call(['/usr/bin/python3','-I','-B','-c',code,str(HERE.parent/'dudect_placement'),
              '--unit','hosted-compute-agent.service','--job-pid',str(os.getpid()),
              '--output',str(private/'inspection.json')],65,private/'collector-command.json')
        inspection=rt.read(private/'inspection.json')
        receipt['preflight_classification']=inspection['classification']
        if inspection['classification'] != 'READ_ONLY_PRECONDITIONS_COMPATIBLE_AUTHORIZATION_UNPROVEN':
            raise ValueError('preflight is not compatible; no execution')
        facts=inspection['censuses'][0]['facts']
        if (facts['kernel']['config']['CONFIG_RT_GROUP_SCHED'] != 'n' or
            facts['rt_budget'] != {'runtime_us':950000,'period_us':1000000}):
            raise ValueError('outside fixed RT functional environment')
        selection=facts['core_selection']
        if selection['M'] != [2,3] or selection['H'] != [0,1] or selection['native_cpu'] != 2:
            raise ValueError('outside fixed topology')
        account=pwd.getpwnam('runner')
        if account.pw_uid == 0:
            raise ValueError('native must be unprivileged')
        os.sched_setaffinity(0,selection['H'])  # owned wrapper only
        build=private/'build';build.mkdir(mode=0o755)
        for output,args in [('helper',['helper.c','-pthread']),('observe.so',['observe.c','-shared','-fPIC'])]:
            call(['/usr/bin/cc','-O2','-Wall','-Wextra','-Werror',*[str(HERE/x) if x.endswith('.c') else x for x in args],
                  '-o',str(build/output)],15,private/('build-'+output+'.json'))
        fp={'schema':'owned-rt-local-functional/1','cases':functional.CASES,'binaries':[],
            'timing':False,'replacements':0,'user':'runner','native':2,'housekeeping':[0,1],
            'stage_seconds':240,'helper':str(build/'helper'),'observer':str(build/'observe.so'),
            'inputs':{str(HERE/n):rt.digest(HERE/n) for n in
                      ('runtime.py','run_functional.py','helper.c','observe.c','observe.h')}}
        fp['inputs'].update({str(p):rt.digest(p) for p in build.iterdir()})
        rt.write(private/'functional-plan.json',fp)
        receipt['stage']='functional';receipt['owned_units_started']=True
        call(['/usr/bin/python3','-B',str(HERE/'run_functional.py'),str(private/'functional-plan.json'),
              str(private/'functional')],255,private/'functional-command.json')
        summary=rt.read(private/'functional/summary.json')
        if not summary['all_expected_completed'] or summary['completed'] != 26 or not all(r['success'] for r in summary['results']):
            raise ValueError('functional result incomplete')
        receipt['completed_fixtures']=26
        receipt['runtime_after']={n:bounded.dependency_snapshot(n,5) for n in receipt['runtime_before']}
        receipt['source_after']=binding(plan)
        if receipt['source_before']!=receipt['source_after'] or receipt['runtime_before']!=receipt['runtime_after']:
            raise ValueError('source/runtime changed')
        receipt['completed']=True;status=0
    except Exception as exc:
        receipt['error']=repr(exc)
    finally:
        receipt['ended']=time.monotonic()
        # Even wrapper/collection failure cannot extend generation deadlines.
        receipt['remaining_units']=bounded.run(['/usr/bin/systemctl','list-units','aeg-ort-*','--all','--no-legend','--no-pager'],5)['stdout'].decode()
        rt.write(private/'receipt.json',receipt)
        archive=base/'private.tar';pack(private,archive)
        call(['/usr/bin/openssl','cms','-encrypt','-aes-256-gcm','-binary','-outform','DER',
              '-in',str(archive),'-out',str(upload/'evidence.cms'),'-recip',str(HERE/'recipient.pem'),
              '-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],30,base/'encrypt-command.json')
        rt.write(upload/'summary.json',dict(schema='owned-rt-functional-summary/1',**opportunity,
                 completed=receipt['completed'],timing=False,dudect_cases=0,
                 ciphertext_sha256=rt.digest(upload/'evidence.cms')))
        for p in (ROOT/'artifacts',base,upload):p.chmod(0o755)
        for p in upload.iterdir():p.chmod(0o644)
    return status


def main():
    os.umask(0o022)
    signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('wrapper deadline')))
    signal.alarm(480)
    try:
        plan=rt.read(PLAN);binding(plan)
        opportunity=admit(os.environ,rt.read(os.environ['GITHUB_EVENT_PATH']),plan)
        checked=bounded.run(['/usr/bin/git','-c','safe.directory='+str(ROOT),'-C',str(ROOT),'rev-parse','HEAD'],5)
        if checked['returncode'] or checked['stdout'].decode().strip()!=opportunity['head']:
            raise ValueError('checkout mismatch')
        result=execute(plan,opportunity)
    except Exception:
        print('Owned functional opportunity failed; no plaintext fallback or retry.')
        return 1
    finally:
        signal.alarm(0)
    print('Owned functional opportunity ended; encrypted evidence retained; no timing or CI admission.')
    return result


if __name__=='__main__':raise SystemExit(main())
