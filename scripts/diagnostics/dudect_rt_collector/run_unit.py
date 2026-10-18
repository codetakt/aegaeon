"""Single-use owned units; collect stop receipts before removing their definitions."""
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import time
import uuid
import importlib.util

import runtime as rt

HERE = Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_functional_helpers',HERE.parent/'dudect_owned_rt/run_functional.py')
f=importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def render(role, d, script, python):
    cpu = [d['cpu']] if role == 'launcher' else d['housekeeping']
    text = ('[Unit]\nDescription=Bounded Dudect owned scheduler comparison\n[Service]\n'
            'Type=exec\nRestart=no\nKillMode=control-group\nSendSIGKILL=yes\n'
            'FinalKillSignal=SIGKILL\nTimeoutStopSec=300ms\nTimeoutStartSec=20s\n'
            'CPUSchedulingPolicy=other\nCPUSchedulingPriority=0\nCPUSchedulingResetOnFork=yes\n'
            'RuntimeRandomizedExtraSec=0\nNotifyAccess=none\n')
    text += f'RuntimeMaxSec={d["end_at"]-d["epoch"]+5}s\n'
    text += 'CPUAffinity=' + ' '.join(map(str, cpu)) + '\n'
    if role in ('launcher', 'controller'):
        text += 'RemainAfterExit=yes\n'
    if role == 'launcher':
        text += f'User={d["uid"]}\nGroup={d["gid"]}\n'
        text += f'LimitRTPRIO=1:1\nLimitRTTIME={d["rttime"][0]}:{d["rttime"][1]}\n'
        text += 'CapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\n'
    text += f'ExecStart={python} -B {script} {role} {d["dir"]}/descriptor.json\n'
    text += f'StandardOutput=append:{d["dir"]}/{role}.stdout\nStandardError=append:{d["dir"]}/{role}.stderr\n'
    return text


def finished(name):
    p = f.show(name)
    done = f.terminal(p) or (p['ActiveState'] == 'active' and p['SubState'] == 'exited' and p['MainPID'] == '0')
    return p if done and f.taskless(name) else None


def place_supervisor(plan):
    cpus=set(plan['housekeeping'])
    if not cpus or plan['native'] in cpus:
        raise ValueError('invalid owned placement')
    siblings=set()
    path=Path(f'/sys/devices/system/cpu/cpu{plan["native"]}/topology/thread_siblings_list')
    for item in path.read_text().strip().split(','):
        pair=item.split('-')
        siblings.update(range(int(pair[0]),int(pair[-1])+1))
    if siblings & cpus:raise ValueError('owned supervisor shares native physical core')
    os.sched_setaffinity(0,cpus)
    if os.sched_getaffinity(0)!=cpus or os.sched_getscheduler(0) not in (0,rt.RESET):
        raise ValueError('owned supervisor placement/policy differs')
    return dict(identity=rt.identity(os.getpid()),affinity=sorted(cpus),policy=os.sched_getscheduler(0))


def run(plan, unit, out):
    if os.geteuid() != 0:
        raise ValueError('owned unit setup requires existing authorized sudo')
    if unit['arm'] not in ('A', 'B') or plan['replacement_trials'] != 0:
        raise ValueError('unreviewed execution')
    supervisor=place_supervisor(plan)
    for name, sha in plan['implementation'].items():
        if rt.digest(HERE / name) != sha:
            raise ValueError('implementation changed')
    for name, sha in unit['sources'].items():
        if rt.digest(Path(unit['source']) / name) != sha:
            raise ValueError('native source changed')
    if rt.digest(unit['binary']) != unit['binary_sha256']:
        raise ValueError('native ELF changed')
    root = rt.ROOT / uuid.uuid4().hex[:12]
    root.mkdir(parents=True, mode=0o755)
    out.mkdir()
    for name in ('runtime.py', 'protocol.py', 'collector.py'):
        shutil.copyfile(HERE / name, root / name)
        (root / name).chmod(0o444)
    account = pwd.getpwnam(plan['user'])
    (root / 'native').mkdir()
    os.chown(root / 'native', account.pw_uid, account.pw_gid)
    epoch = time.monotonic()
    d = dict(generation=root.name, boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             epoch=epoch, start_by=epoch+20, end_at=epoch+unit['maximum_seconds'],
             stop_by=epoch+unit['maximum_seconds']+5, cleanup_by=epoch+unit['maximum_seconds']+20,
             heartbeat_limit=1.5, cpu=plan['native'], housekeeping=plan['housekeeping'],
             uid=account.pw_uid, gid=account.pw_gid, rtprio=[1,1], rttime=plan['rttime'],
             fault='none', arm=unit['arm'], target=unit['binary'], target_sha256=unit['binary_sha256'],
             argv=unit.get('argv',['pr']), path=plan['path'], systemctl=f.CTL,
             unit=f'aeg-ort-{root.name}-native.service', native_environment=unit['environment'],
             collector={k:unit[k] for k in ('source','cases','bindings','signal','id','packet','analysis',
                                          'analysis_identity','timing')})
    allowed = {'AEGAEON_DUDECT_PREPARATION','AEGAEON_DUDECT_PREPARATION_SIGNAL'}
    if set(d['native_environment']) - allowed:
        raise ValueError('unbound native environment')
    if unit.get('collector_fault'):
        if unit['timing'] or unit['collector_fault'] != 'validation-stall':
            raise ValueError('fault forbidden in timing')
        d['collector']['functional_fault']=unit['collector_fault']
    rt.write(root / 'descriptor.json', d)
    (root / 'descriptor.json').chmod(0o444)
    (root / 'descriptor.sha256').write_text(rt.digest(root / 'descriptor.json'))
    (root / 'descriptor.sha256').chmod(0o444)
    d['dir'] = root
    roles = {r:f'aeg-ort-{root.name}-{r}.service' for r in ('controller','primary','rescue','deadline')}
    roles['launcher'] = d['unit']
    timer = f'aeg-ort-{root.name}-deadline.timer'
    files=[]
    result={'id':unit['id'],'arm':unit['arm'],'complete':False,'timing':unit['timing'], 'ci_admission':False}
    rt.write(root/'unit-plan.json',unit)
    rt.write(root/'supervisor.json',supervisor)
    rt.write(root/'background-before.json',f.background())
    try:
        for role,name in roles.items():
            p=Path('/run/systemd/system')/name
            with p.open('x') as file:
                file.write(render(role,d,root/'runtime.py',plan['python']))
            files.append(p)
        p=Path('/run/systemd/system')/timer
        with p.open('x') as file:
            file.write('[Unit]\nDescription=Owned absolute deadline\n[Timer]\n'
                f'OnBootSec={d["end_at"]}s\nAccuracySec=10ms\nRandomizedDelaySec=0\nUnit={roles["deadline"]}\n')
        files.append(p)
        f.command(f.CTL,'daemon-reload',timeout=5)
        f.command(f.CTL,'start',timer)
        armed=f.show(timer); rt.write(root/'armed-timer.json',armed)
        if armed['ActiveState']!='active':raise ValueError('timer not armed')
        f.command(f.CTL,'start',roles['controller'],roles['primary'],roles['rescue'])
        f.wait(lambda:(root/'collector-ready.json').exists() and all(rt.live(d,r) for r in
               ('controller','primary','rescue')),d['start_by'])
        f.command(f.CTL,'start',roles['launcher'])
        fault=unit.get('fault')
        if fault:
            f.wait(lambda:(root/'native/promoted.json').exists() and
                   rt.read(root/'progress.json')['sequence']>=4,d['start_by'])
            if fault in ('collector-stop','collector-kill'):
                victim=int(f.show(roles['controller'])['MainPID'])
                fd=os.pidfd_open(victim)
                signal.pidfd_send_signal(fd,signal.SIGSTOP if fault.endswith('stop') else signal.SIGKILL)
                os.close(fd)
            elif fault=='both-guards-stop':
                for role in ('primary','rescue'):
                    fd=os.pidfd_open(int(f.show(roles[role])['MainPID']))
                    signal.pidfd_send_signal(fd,signal.SIGSTOP);os.close(fd)
            else:raise ValueError('unreviewed fault')
            result['fault_at']=time.monotonic()
        result['native_final']=f.wait(lambda:finished(roles['launcher']),d['stop_by'])
        result['native_stop_at']=time.monotonic()
        if fault:
            result['complete']=True
        else:
            result['collector_final']=f.wait(lambda:finished(roles['controller']),d['stop_by'])
            for name in ('native_final','collector_final'):
                if result[name]['Result']!='success' or result[name]['ExecMainStatus']!='0':
                    raise ValueError('owned process failed: '+name)
            report=rt.read(root/'observations/result.json')
            if not report['complete']:raise ValueError('collector incomplete')
            result.update(complete=True, assessment=report['assessment'],
                          requirements_satisfied=report['requirements_satisfied'])
    except BaseException as exc:
        result['error']=repr(exc)
        raise
    finally:
        # Revoke before any late start; independent timer was already armed.
        (root/'closed').touch(exist_ok=True)
        for name in [roles['launcher'],roles['controller'],roles['primary'],roles['rescue'],timer,roles['deadline']]:
            f.command(f.CTL,'stop','--no-block',name,check=False)
        stopped={}
        for name in roles.values():
            try:stopped[name]=f.wait(lambda:f.terminal(f.show(name)) and f.taskless(name),d['cleanup_by'])
            except Exception as exc:stopped[name]=repr(exc)
        result['cleanup_confirmed']=all(v is True for v in stopped.values())
        result['stopped']=stopped
        if result['cleanup_confirmed']:
            for p in files:shutil.copyfile(p,root/p.name);p.unlink()
            f.command(f.CTL,'daemon-reload',timeout=5)
            f.command(f.CTL,'reset-failed',*roles.values(),check=False)
        rt.write(root/'background-after.json',f.background())
        result['supervisor_placement_preserved']=(rt.identity(os.getpid())==supervisor['identity'] and
            sorted(os.sched_getaffinity(0))==supervisor['affinity'] and os.sched_getscheduler(0)==supervisor['policy'])
        if not result['supervisor_placement_preserved']:result['complete']=False
        result['elapsed']=time.monotonic()-epoch
        rt.write(root/'result.json',result)
        f.archive(root,out/'evidence')
        if result['cleanup_confirmed']:shutil.rmtree(root)
        rt.write(out/'result.json',result)
    if not result['cleanup_confirmed']:raise RuntimeError('cleanup unconfirmed')
    if not result['complete']:raise RuntimeError('owned execution or supervisor placement incomplete')
    return result


if __name__=='__main__':
    plan=rt.read(sys.argv[1]);unit=rt.read(sys.argv[2])
    run(plan,unit,Path(sys.argv[3]))
