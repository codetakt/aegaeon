"""Two fixed diagnostic opportunities; no ordinary CI admission or replacement."""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent/'dudect_placement'))
import runtime as rt
import rt_runtime as bounded
from run_unit import run

BRANCH='test/dudect-owned-scheduler-comparison-20261018'
WORKFLOW='.github/workflows/dudect-owned-scheduler-comparison.yml'


def binding():
    spec=rt.read(HERE/'hosted-plan.json')
    for name,sha in spec['inputs'].items():
        if rt.digest(ROOT/name)!=sha:raise ValueError('published source changed')
    return spec


def admit(slot):
    env=os.environ;head=env['GITHUB_SHA'];event=rt.read(env['GITHUB_EVENT_PATH'])
    expected={'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/'+BRANCH,
        'GITHUB_REPOSITORY':'codetakt/aegaeon','GITHUB_RUN_NUMBER':'1','GITHUB_RUN_ATTEMPT':'1',
        'GITHUB_WORKFLOW_REF':'codetakt/aegaeon/'+WORKFLOW+'@refs/heads/'+BRANCH,
        'GITHUB_WORKFLOW_SHA':head}
    if (slot not in (1,2) or any(env.get(k)!=v for k,v in expected.items()) or
        event.get('created') is not True or event.get('deleted') is not False or
        event.get('before')!='0'*40 or event.get('after')!=head or event.get('ref')!=expected['GITHUB_REF']):
        raise ValueError('not a frozen first opportunity')
    return dict(head=head,slot=slot,run_id=env['GITHUB_RUN_ID'],plan_sha256=rt.digest(HERE/'hosted-plan.json'),
                image={k:env.get(k) for k in ('ImageOS','ImageVersion')})


def pack(directory,destination):
    files=[];total=0
    for p in sorted(directory.rglob('*')):
        if p.is_symlink():raise ValueError('symlink evidence')
        if p.is_dir():continue
        if not p.is_file():raise ValueError('nonregular evidence')
        total+=p.stat().st_size
        if total>6*1024**3 or len(files)>=12000:raise ValueError('bounded evidence size')
        files.append(dict(path=str(p.relative_to(directory)),bytes=p.stat().st_size,sha256=rt.digest(p)))
    rt.write(directory/'manifest.json',{'files':files})
    with tarfile.open(destination,'x:gz',compresslevel=1) as archive:
        for p in [directory/f['path'] for f in files]+[directory/'manifest.json']:
            archive.add(p,arcname=str(p.relative_to(directory)),recursive=False)


def execute(slot):
    spec=binding();op=admit(slot)
    base=ROOT/'artifacts/owned-scheduler'
    base.mkdir(parents=True,exist_ok=True)
    private=base/'private';private.mkdir(mode=0o700)
    upload=base/'upload';upload.mkdir()
    receipt=dict(opportunity=op,completed=False,timing=True,dudect_cases=0,results=[],stage='preflight')
    status=1
    try:
        prep=base/'preparation'
        cfg=rt.read(prep/'plan.json')
        if rt.digest(prep/'plan.json')!=(prep/'plan.sha256').read_text().strip():raise ValueError('preparation digest')
        if cfg['slot']!=slot or len(cfg['units'])!=16 or cfg['maximum_seconds']!=1200 or cfg['gap_seconds']!=10:
            raise ValueError('schedule changed')
        if cfg['plan']['rttime']!=[60000000,90000000] or cfg['plan']['replacement_trials']!=0:
            raise ValueError('execution limits changed')
        keys=[c+'-'+s for c in ('gcc','clang') for s in ('nix','legacy','signal0','signal16')]
        if slot==2:keys.reverse()
        expected=[a+'-'+k for a in (('A','B') if slot==1 else ('B','A')) for k in keys]
        if [u['id'] for u in cfg['units']]!=expected:raise ValueError('order changed')
        for u in cfg['units']:
            cases=['ct_eq_32','ct_eq_64','ct_eq_128'] if 'signal' in u['id'] else [
                'control_independent','control_mean_shift','control_variance_shift']
            if (u['cases']!=cases or u['maximum_seconds']!=150 or u['timing'] is not True or
                u['arm']!=u['id'][0] or u['signal']!=(16 if u['id'].endswith('signal16') else 0) or
                u.get('fault') or u.get('collector_fault')):raise ValueError('unit policy changed')
        receipt['prepared_plan_sha256']=rt.digest(prep/'plan.json')
        receipt['source_before']=spec['inputs']
        receipt['runtime_before']={x:bounded.dependency_snapshot(x,5) for x in ('/usr/bin/python3','/usr/bin/systemctl','/usr/bin/openssl')}
        code=('import sys,runpy;sys.path.insert(0,sys.argv[1]);p=sys.argv.pop(1);'
              'sys.argv[0]=p+"/rt_preflight.py";runpy.run_path(sys.argv[0],run_name="__main__")')
        r=bounded.run(['/usr/bin/python3','-I','-B','-c',code,str(HERE.parent/'dudect_placement'),
            '--unit','hosted-compute-agent.service','--job-pid',str(os.getpid()),
            '--output',str(private/'inspection.json')],65,new_group=True)
        if r['returncode']:raise ValueError('preflight execution failed')
        inspection=rt.read(private/'inspection.json')
        if inspection['classification']!='READ_ONLY_PRECONDITIONS_COMPATIBLE_AUTHORIZATION_UNPROVEN':
            raise ValueError('preflight not compatible')
        facts=inspection['censuses'][0]['facts']
        if (facts['kernel']['config']['CONFIG_RT_GROUP_SCHED']!='n' or
            facts['rt_budget']!={'runtime_us':950000,'period_us':1000000} or
            facts['core_selection']['M']!=[2,3] or facts['core_selection']['H']!=[0,1]):
            raise ValueError('outside frozen scheduler environment')
        os.sched_setaffinity(0,{0,1})
        measurement=private/'measurement';measurement.mkdir()
        started=time.monotonic();end=started+1200
        receipt['stage']='measurement';receipt['started']=started
        for unit in cfg['units']:
            if time.monotonic()+unit['maximum_seconds']+20>=end:raise TimeoutError('fixed campaign deadline')
            result=run(cfg['plan'],unit,measurement/unit['id'])
            receipt['results'].append(result);receipt['dudect_cases']+=len(unit['cases'])
            rt.write(private/'partial.json',receipt)
            if len(receipt['results'])<16:time.sleep(10)
        receipt['elapsed']=time.monotonic()-started
        receipt['source_after']=binding()['inputs']
        receipt['runtime_after']={x:bounded.dependency_snapshot(x,5) for x in receipt['runtime_before']}
        if receipt['runtime_after']!=receipt['runtime_before']:raise ValueError('runtime changed')
        receipt['rt_budget_after']={name:int(Path('/proc/sys/kernel/sched_rt_'+name).read_text())
                                   for name in ('runtime_us','period_us')}
        if receipt['rt_budget_after']!=facts['rt_budget']:raise ValueError('global RT budget changed')
        receipt['completed']=True;status=0
    except BaseException as exc:
        receipt['error']=repr(exc)
    finally:
        # Deadline timers remain independent if orchestration is interrupted.
        receipt['remaining_units']=bounded.run(['/usr/bin/systemctl','list-units','aeg-ort-*','--all','--no-legend','--no-pager'],5)['stdout'].decode()
        if receipt['remaining_units']:
            receipt['cleanup_unconfirmed']=True;status=1;receipt['completed']=False
        rt.write(private/'receipt.json',receipt)
        # Freeze preparation with the private observations; no raw public fallback.
        if (base/'preparation').exists():(base/'preparation').rename(private/'preparation')
        archive=base/'private.tar.gz';pack(private,archive)
        result=subprocess.run(['/usr/bin/openssl','cms','-encrypt','-aes-256-gcm','-binary','-outform','DER',
            '-in',str(archive),'-out',str(upload/'evidence.cms'),'-recip',str(HERE/'recipient.pem'),
            '-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],capture_output=True,timeout=180)
        if result.returncode:raise ValueError('authenticated evidence encryption failed')
        rt.write(upload/'summary.json',dict(schema='owned-scheduler-comparison/1',**op,
            completed=receipt['completed'],dudect_cases=receipt['dudect_cases'],timing=True,
            ciphertext_sha256=rt.digest(upload/'evidence.cms'),ci_admission=False))
        for p in (base,upload):p.chmod(0o755)
        for p in upload.iterdir():p.chmod(0o644)
    return status


if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('wrapper deadline')))
    signal.alarm(1650)
    try:raise SystemExit(execute(int(sys.argv[1])))
    finally:signal.alarm(0)
