"""Fixed, local owned-unit functionality campaign. Not a timing campaign."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

import runtime as rt

CASES = ['normal-other', 'normal-fifo', 'deny-rt', 'wrong-limit', 'wrong-affinity',
         'missing-guard', 'expired-lease', 'cancelled-start', 'late-start',
         'bootstrap-stop', 'stale-generation', 'wrong-target',
         'controller-kill', 'controller-stop', 'primary-kill', 'primary-stop',
         'rescue-kill', 'rescue-stop', 'ack-stall', 'busy-soft-hard',
         'blocking-wall', 'fork-reset', 'unexpected-thread', 'native-stop',
         'both-guards-stop', 'closed-late-start']
HERE = Path(__file__).resolve().parent
PYTHON = str(Path(sys.executable).resolve())
CTL = shutil.which('systemctl')


def command(*args, timeout=2, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def show(name):
    r = command(CTL, 'show', name, '--property=Id,LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID,Result,ExecMainCode,ExecMainStatus')
    return dict(x.split('=', 1) for x in r.stdout.splitlines())


def wait(fn, deadline):
    while time.monotonic() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(.02)
    raise TimeoutError('functional wait deadline')


def background():
    """Snapshot surviving identities, not a claim that all tasks are stationary."""
    rows = {}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            cg = (p / 'cgroup').read_text()
            if 'aeg-ort-' in cg:
                continue
            for t in (p / 'task').iterdir():
                tid = int(t.name)
                ident = rt.identity(tid)
                rows[f'{tid}:{ident["start"]}'] = dict(identity=ident,
                    affinity=sorted(os.sched_getaffinity(tid)), policy=os.sched_getscheduler(tid),
                    priority=os.sched_getparam(tid).sched_priority)
        except (OSError, ProcessLookupError):
            pass
    return rows


def render(name, role, d, account, script, directory):
    base = '[Unit]\nDescription=Owned bounded RT functional fixture\n[Service]\nType=exec\n'
    base += 'Restart=no\nKillMode=control-group\nSendSIGKILL=yes\nFinalKillSignal=SIGKILL\nTimeoutStopSec=300ms\n'
    base += 'TimeoutStartSec=4s\nRuntimeMaxSec=12s\nRuntimeRandomizedExtraSec=0\nNotifyAccess=none\n'
    base += 'CPUSchedulingPolicy=other\nCPUSchedulingPriority=0\nCPUSchedulingResetOnFork=yes\n'
    cpus = [d['cpu']] if role == 'launcher' else d['housekeeping']
    if role == 'launcher' and d['fault'] == 'wrong-affinity':
        cpus = [d['housekeeping'][0]]
    base += 'CPUAffinity=' + ' '.join(map(str, cpus)) + '\n'
    if role == 'launcher':
        base += 'RemainAfterExit=yes\n'
        base += f'User={account.pw_name}\nGroup={account.pw_gid}\n'
        pr = d['rtprio'][0]
        soft, hard = d['rttime']
        if d['fault'] == 'wrong-limit':
            hard += 1000
        base += f'LimitRTPRIO={pr}:{pr}\nLimitRTTIME={soft}:{hard}\n'
        base += 'CapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\n'
    base += f'ExecStart={PYTHON} -B {script} {role} {directory}/descriptor.json\n'
    base += f'StandardOutput=append:{directory}/{role}.stdout\nStandardError=append:{directory}/{role}.stderr\n'
    return base


def terminal(props):
    return props['ActiveState'] in ('inactive', 'failed') and props['MainPID'] == '0'


def taskless(unit):
    path = Path('/sys/fs/cgroup/system.slice') / unit
    return not path.exists() or 'populated 1' not in (path / 'cgroup.events').read_text()


def archive(source, destination):
    # UNIX sockets have no restorable file contents. Record metadata separately.
    omitted = []
    def ignore(directory, names):
        skipped = []
        for name in names:
            p = Path(directory) / name
            if stat.S_ISSOCK(p.lstat().st_mode):
                skipped.append(name)
                omitted.append({'path': str(p.relative_to(source)), 'type': 'unix_socket'})
        return skipped
    shutil.copytree(source, destination, ignore=ignore)
    rt.write(destination / 'nonregular-entries.json', omitted)


def execute(case, plan, output, target=None, arm=None):
    generation = uuid.uuid4().hex[:12]
    root = rt.ROOT / generation
    root.mkdir(mode=0o755)
    native = root / 'native'
    native.mkdir(mode=0o755)
    account = pwd.getpwnam(plan['user'])
    os.chown(native, account.pw_uid, account.pw_gid)
    script = root / 'runtime.py'
    shutil.copyfile(HERE / 'runtime.py', script)
    script.chmod(0o444)
    if rt.digest(script) != plan['inputs'][str(HERE / 'runtime.py')]:
        raise ValueError('runtime changed before unit creation')
    helper = root / 'helper'
    shutil.copyfile(plan['helper'], helper)
    helper.chmod(0o555)
    pre = root / 'observe.so'
    shutil.copyfile(plan['observer'], pre)
    pre.chmod(0o555)
    out = output / case
    out.mkdir()
    epoch = time.monotonic()
    d = {'generation': generation, 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'plan_sha256': rt.digest(output / 'fixed-plan.json'), 'unit': f'aeg-ort-{generation}-native.service',
         'epoch': epoch, 'start_by': epoch + 4, 'end_at': epoch + 7,
         'stop_by': epoch + 10, 'cleanup_by': epoch + 15, 'heartbeat_limit': .75,
         'cpu': plan['native'], 'housekeeping': plan['housekeeping'], 'uid': account.pw_uid,
         'gid': account.pw_gid, 'rtprio': [0, 0] if case == 'deny-rt' else [1, 1],
         'rttime': [50000, 150000] if case == 'busy-soft-hard' else [2000000, 3000000],
         'fault': case, 'arm': arm or ('A' if case == 'normal-other' else 'B'),
         'target': target or str(helper), 'target_sha256': rt.digest(target or helper),
         'argv': ['--self-test'] if target else ['exit' if case.startswith('normal-') else
                  'busy' if case == 'busy-soft-hard' else 'fork' if case == 'fork-reset' else
                  'thread' if case == 'unexpected-thread' else 'blocking'],
         'path': os.environ['PATH'], 'systemctl': CTL}
    if target:
        d.update(preload=str(pre), preload_sha256=rt.digest(pre))
    if case == 'wrong-target':
        d['target_sha256'] = '0' * 64
    if case == 'expired-lease':
        d['epoch'] = epoch - 2
        d['start_by'] = epoch - 1
    rt.write(root / 'descriptor.json', d)
    (root / 'descriptor.json').chmod(0o444)
    (root / 'descriptor.sha256').write_text(rt.digest(root / 'descriptor.json'))
    (root / 'descriptor.sha256').chmod(0o444)
    roles = {'launcher': d['unit']}
    roles.update({r: f'aeg-ort-{generation}-{r}.service' for r in ('controller', 'primary', 'rescue', 'deadline')})
    files = []
    result = {'case': case, 'generation': generation, 'success': False, 'timing': False}
    before = background()
    rt.write(root / 'background-before.json', before)
    try:
        for role, name in roles.items():
            f = Path('/run/systemd/system') / name
            if f.exists():
                raise RuntimeError('unit collision')
            f.write_text(render(name, role, d, account, script, root))
            files.append(f)
        timername = f'aeg-ort-{generation}-deadline.timer'
        f = Path('/run/systemd/system') / timername
        f.write_text('[Unit]\nDescription=Owned independent absolute stop\n[Timer]\n'
                     f'OnBootSec={d["end_at"]}s\nAccuracySec=10ms\nRandomizedDelaySec=0\nUnit={roles["deadline"]}\n')
        files.append(f)
        command(CTL, 'daemon-reload', timeout=4)
        command(CTL, 'start', timername)
        rt.write(root / 'armed-timer.json', show(timername))
        if show(timername)['ActiveState'] != 'active':
            raise ValueError('independent deadline not armed')
        command(CTL, 'start', roles['controller'], roles['primary'], *([] if case == 'missing-guard' else [roles['rescue']]))
        if case != 'expired-lease':
            wait(lambda: rt.live(d | {'dir': root}, 'primary'), d['start_by'])
        if case in ('cancelled-start', 'closed-late-start'):
            (root / 'closed').touch(mode=0o444)
        if case in ('late-start', 'closed-late-start'):
            wait(lambda: time.monotonic() >= d['start_by'], d['start_by'] + .2)
        start_reply = command(CTL, 'start', roles['launcher'], check=False)
        result['start_reply'] = {'returncode': start_reply.returncode, 'stderr': start_reply.stderr}
        if case.endswith(('-kill', '-stop')) and case not in ('bootstrap-stop', 'native-stop', 'both-guards-stop'):
            wait(lambda: (native / 'target.json').exists(), d['start_by'])
            role, sig = case.split('-')
            victim = int(show(roles[role])['MainPID'])
            if not victim:
                raise ValueError('fault window lost')
            signal.pidfd_send_signal(fd := os.pidfd_open(victim), signal.SIGKILL if sig == 'kill' else signal.SIGSTOP)
            os.close(fd)
            result['fault_at'] = time.monotonic()
        if case in ('ack-stall', 'native-stop', 'both-guards-stop'):
            wait(lambda: (native / 'target.json').exists(), d['start_by'])
            if case == 'ack-stall':
                (root / 'stall-ack').touch()
            else:
                victims = ['primary', 'rescue'] if case == 'both-guards-stop' else ['launcher']
                for role in victims:
                    fd = os.pidfd_open(int(show(roles[role])['MainPID']))
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                    os.close(fd)
            result['fault_at'] = time.monotonic()
        def finished():
            p = show(d['unit'])
            ended = terminal(p) or (p['ActiveState'] == 'active' and p['SubState'] == 'exited' and p['MainPID'] == '0')
            return p if ended and taskless(d['unit']) else None
        final = wait(finished, d['stop_by'])
        result.update(unit_final=final, stop_confirmed_at=time.monotonic(), stop_confirmed=True)
        observed = native / 'target.json'
        result['native_started'] = observed.exists()
        if observed.exists():
            c = rt.read(observed)
            bootstrap = rt.read(native / 'bootstrap.json')
            promoted = rt.read(native / 'promoted.json')
            assert c['ok'] and c['pid'] == c['tid'] == bootstrap['pid'] == promoted['pid']
            assert c['policy'] == promoted['policy']
            for role in ('primary', 'rescue'):
                assert rt.read(root / (role + '.registered.json'))['at'] <= promoted['before']
            result['same_pid_context_verified'] = True
        no_start = {'deny-rt', 'wrong-limit', 'wrong-affinity', 'missing-guard', 'expired-lease',
                    'cancelled-start', 'late-start', 'bootstrap-stop', 'stale-generation', 'wrong-target', 'closed-late-start'}
        assert result['native_started'] == (case not in no_start)
        if case.startswith('normal-') or target:
            assert final['Result'] == 'success' and final['ExecMainStatus'] == '0'
        if case == 'deny-rt':
            assert 'PermissionError' in rt.read(native / 'refused.json')['error']
        if case == 'busy-soft-hard':
            assert 'SIGXCPU' in (native / 'soft-signal.txt').read_text()
            assert final['ExecMainStatus'] == str(signal.SIGKILL)
        if case == 'fork-reset':
            assert rt.read(native / 'child.json')['policy'] == 0
        result['success'] = True
    except Exception as exc:
        result['error'] = repr(exc)
        raise
    finally:
        # Revoke first; a delayed OTHER startup cannot consume this generation.
        (root / 'closed').touch(exist_ok=True)
        for name in [*roles.values(), f'aeg-ort-{generation}-deadline.timer']:
            command(CTL, 'stop', '--no-block', name, check=False)
        stopped = {}
        for name in roles.values():
            try:
                stopped[name] = wait(lambda: terminal(show(name)) and taskless(name), d['cleanup_by'])
            except Exception as exc:
                stopped[name] = repr(exc)
        result['owned_stopped'] = stopped
        result['cleanup_confirmed'] = all(v is True for v in stopped.values())
        if result['cleanup_confirmed']:
            for f in files:
                shutil.copyfile(f, root / f.name)
                f.unlink()
            command(CTL, 'daemon-reload', timeout=4)
            command(CTL, 'reset-failed', *roles.values(), check=False)
        after = background()
        rt.write(root / 'background-after.json', after)
        changed = {k: {'before': v, 'after': after[k]} for k, v in before.items() if k in after and v != after[k]}
        result['background_surviving_checked'] = len(before.keys() & after.keys())
        result['background_changed'] = changed
        result['success'] &= result['cleanup_confirmed'] and not changed
        result['elapsed'] = time.monotonic() - epoch
        if not result.get('stop_confirmed'):
            result['terminal'] = 'STOP_UNCONFIRMED'
        elif not result['cleanup_confirmed']:
            result['terminal'] = 'CLEANUP_UNCONFIRMED'
        elif not result.get('native_started'):
            result['terminal'] = 'NO_NATIVE_STARTED'
        else:
            result['terminal'] = ('NORMAL_EXIT' if case.startswith('normal-') or target else 'FAULT') + '_STOP_CONFIRMED_CLEANUP_CONFIRMED'
        rt.write(root / 'result.json', result)
        archive(root, out / 'evidence')
        if result['cleanup_confirmed']:
            shutil.rmtree(root)
        rt.write(out / 'result.json', result)
    if not result['success']:
        raise RuntimeError('functional case failed; no automatic replacement')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('owned unit API requires existing authorized sudo')
    plan = rt.read(args.plan)
    if plan['cases'] != CASES or plan['timing'] or plan['replacements'] != 0:
        raise ValueError('fixed functional plan differs')
    for file, sha in plan['inputs'].items():
        if rt.digest(file) != sha:
            raise ValueError('plan input changed: ' + file)
    args.output.mkdir()
    shutil.copyfile(args.plan, args.output / 'fixed-plan.json')
    rt.ROOT.mkdir(mode=0o755, exist_ok=True)
    results = []
    end = time.monotonic() + plan['stage_seconds']
    try:
        for case in CASES:
            if time.monotonic() >= end:
                raise TimeoutError('stage deadline')
            print('start', case, flush=True)
            results.append(execute(case, plan, args.output))
            print('pass', case, flush=True)
        for arm in ('A', 'B'):
            for i, binary in enumerate(plan['binaries']):
                if time.monotonic() >= end:
                    raise TimeoutError('stage deadline')
                case = f'non-timing-{arm}-{i:02}'
                print('start', case, flush=True)
                results.append(execute(case, plan, args.output, binary, arm))
                print('pass', case, flush=True)
    finally:
        rt.write(args.output / 'summary.json', {'completed': len(results), 'results': results,
                 'all_expected_completed': len(results) == len(CASES) + 2 * len(plan['binaries']),
                 'timing': False})


if __name__ == '__main__':
    main()
