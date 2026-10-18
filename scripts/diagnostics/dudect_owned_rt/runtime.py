"""Experimental owned-unit launcher. No Dudect timing entry point.

PID1 starts every role as OTHER. Only launcher changes its own policy, after
two reuse-safe guard registrations. Guards never change background tasks.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import struct
import subprocess
import sys
import time

RESET = 0x40000000
ROOT = Path('/run/aegaeon-owned-rt')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.' + str(os.getpid()) + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read(path):
    return json.loads(Path(path).read_text())


def identity(pid):
    p = Path('/proc') / str(pid)
    # comm may contain spaces or parentheses.
    start = int((p / 'stat').read_text().rsplit(')', 1)[1].split()[19])
    return {'pid': pid, 'start': start, 'cgroup': (p / 'cgroup').read_text()}


def context():
    caps = {k: v.strip() for k, v in (x.split(':', 1) for x in
            Path('/proc/self/status').read_text().splitlines()) if k.startswith('Cap')}
    return dict(identity(os.getpid()), uid=os.getuid(), gid=os.getgid(),
                affinity=sorted(os.sched_getaffinity(0)), policy=os.sched_getscheduler(0),
                priority=os.sched_getparam(0).sched_priority,
                rtprio=list(resource.getrlimit(resource.RLIMIT_RTPRIO)),
                rttime=list(resource.getrlimit(resource.RLIMIT_RTTIME)), caps=caps,
                threads=sorted(p.name for p in Path('/proc/self/task').iterdir()))


def descriptor(path):
    path = Path(path)
    if path.parent.parent != ROOT or path.name != 'descriptor.json':
        raise ValueError('descriptor outside owned root')
    for p in (ROOT, path.parent, path, path.with_suffix('.sha256')):
        s = p.lstat()
        if p.is_symlink() or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unprotected descriptor')
    if digest(path) != path.with_suffix('.sha256').read_text().strip():
        raise ValueError('descriptor digest')
    d = read(path)
    if d['generation'] != path.parent.name or d['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('generation/boot mismatch')
    if not d['unit'].startswith('aeg-ort-' + d['generation'] + '-'):
        raise ValueError('foreign unit')
    if not (d['epoch'] < d['start_by'] <= d['end_at'] < d['stop_by'] < d['cleanup_by']):
        raise ValueError('invalid absolute deadlines')
    d['dir'] = path.parent
    return d


def event(d, role, name, **kwargs):
    print(json.dumps(dict(role=role, event=name, at=time.monotonic(), **kwargs)), flush=True)


def closed(d):
    return (d['dir'] / 'closed').exists()


def close(d):
    # Single-use, append-only revocation. No journal or lock is required to stop.
    fd = os.open(d['dir'] / 'closed', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    os.close(fd)


def live(d, role):
    try:
        r = read(d['dir'] / (role + '.heartbeat.json'))
        return (r['generation'] == d['generation'] and
                0 <= time.monotonic() - r['at'] < d['heartbeat_limit'] and
                identity(r['identity']['pid']) == r['identity'])
    except (OSError, ValueError, KeyError):
        return False


def pulse(d, role, ident):
    write(d['dir'] / (role + '.heartbeat.json'), dict(generation=d['generation'], at=time.monotonic(), identity=ident))


def lease_ok(d):
    try:
        a = read(d['dir'] / 'ack.json')
        return a['generation'] == d['generation'] and 0 <= time.monotonic() - a['at'] < d['heartbeat_limit']
    except (OSError, ValueError, KeyError):
        return False


def validate_context(d, c):
    if (c['uid'] != d['uid'] or c['gid'] != d['gid'] or c['affinity'] != [d['cpu']] or
            c['rtprio'] != d['rtprio'] or c['rttime'] != d['rttime'] or
            c['policy'] != RESET or c['priority'] != 0 or c['threads'] != [str(c['pid'])]):
        raise ValueError('actual bootstrap constraints differ')
    if any(int(c['caps'][x], 16) for x in ('CapEff', 'CapPrm', 'CapAmb')):
        raise ValueError('native has capabilities')
    if c['cgroup'].strip() != '0::/system.slice/' + d['unit']:
        raise ValueError('native unit differs')


def current_start(d):
    if closed(d) or time.monotonic() >= d['start_by']:
        raise ValueError('generation closed or start expired')


def launcher(d):
    c = context()
    write(d['dir'] / 'native' / 'bootstrap.json', c)
    validate_context(d, c)
    current_start(d)
    if d['fault'] == 'bootstrap-stop':
        os.kill(os.getpid(), signal.SIGSTOP)
    fd = os.open(d['target'], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(os.dup(fd), 'rb') as f:
        if hashlib.file_digest(f, 'sha256').hexdigest() != d['target_sha256']:
            raise ValueError('target digest mismatch')
    sockets = []
    for role in ('primary', 'rescue'):
        current_start(d)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.settimeout(max(.01, d['start_by'] - time.monotonic()))
        s.connect(str(d['dir'] / (role + '.sock')))
        gen = 'stale' if d['fault'] == 'stale-generation' else d['generation']
        s.send(json.dumps({'generation': gen, 'identity': c | {}}).encode())
        ack = json.loads(s.recv(4096))
        if ack != {'generation': d['generation'], 'identity': identity(os.getpid()), 'registered': True}:
            raise ValueError('guard registration refused')
        sockets.append(s)
    current_start(d)
    if not all(live(d, r) for r in ('primary', 'rescue', 'controller')) or not lease_ok(d):
        raise ValueError('guard/controller lease not ready')
    validate_context(d, context())
    before = time.monotonic()
    os.sched_setscheduler(0, RESET | (os.SCHED_FIFO if d['arm'] == 'B' else os.SCHED_OTHER),
                          os.sched_param(1 if d['arm'] == 'B' else 0))
    promoted = context()
    if promoted['policy'] != (RESET | (os.SCHED_FIFO if d['arm'] == 'B' else 0)) or promoted['priority'] != (d['arm'] == 'B'):
        raise ValueError('self promotion readback')
    write(d['dir'] / 'native' / 'promoted.json', dict(promoted, before=before, after=time.monotonic()))
    current_start(d)
    env = {'PATH': d['path'], 'LC_ALL': 'C', 'LANG': 'C',
           'ORT_DIR': str(d['dir'] / 'native'), 'ORT_CPU': str(d['cpu']),
           'ORT_POLICY': str(promoted['policy']), 'ORT_PID': str(os.getpid()),
           'ORT_RTSOFT': str(d['rttime'][0]), 'ORT_RTHARD': str(d['rttime'][1]),
           'ORT_RTPRIO': str(d['rtprio'][0])}
    if d.get('preload'):
        if digest(d['preload']) != d['preload_sha256']:
            raise ValueError('functional observer digest mismatch')
        env['LD_PRELOAD'] = d['preload']
    # CLOEXEC on the socket fds is intentional; pidfds, not EOF, track target life.
    # exec by opened descriptor keeps identity even if the path is replaced.
    os.execve(fd, [d['target']] + d['argv'], env)


def stop(d, role, reason, pidfd=None):
    # Stop delivery must precede any potentially blocking storage or PID1 RPC.
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
    reply = None
    try:
        r = subprocess.run([d['systemctl'], 'stop', '--no-block', d['unit']],
                           capture_output=True, text=True, timeout=1)
        reply = dict(returncode=r.returncode, stderr=r.stderr)
    except subprocess.TimeoutExpired:
        pass
    # A blocked filesystem must not delay either direct or manager stop delivery.
    try:
        close(d)
    except FileExistsError:
        pass
    event(d, role, 'stop-attempt', reason=reason)
    if reply is None:
        event(d, role, 'stop-rpc-unconfirmed')
    else:
        event(d, role, 'stop-rpc', **reply)


def controller(d):
    ident = identity(os.getpid())
    while time.monotonic() < d['end_at'] and not closed(d):
        pulse(d, 'controller', ident)
        if not (d['dir'] / 'stall-ack').exists():
            write(d['dir'] / 'ack.json', dict(generation=d['generation'], at=time.monotonic()))
        time.sleep(.05)


def guard(d, role):
    ident = identity(os.getpid())
    other = 'rescue' if role == 'primary' else 'primary'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(d['dir'] / (role + '.sock')))
    os.chmod(d['dir'] / (role + '.sock'), 0o666)
    server.listen(1)
    pidfd, native = None, None
    admitted = False
    started = time.monotonic()
    try:
        while time.monotonic() < d['stop_by']:
            pulse(d, role, ident)
            if pidfd is not None and select.select([pidfd], [], [], 0)[0]:
                event(d, role, 'identity-exited', identity=native)
                cg = Path('/sys/fs/cgroup/system.slice') / d['unit']
                if cg.exists() and 'populated 1' in (cg / 'cgroup.events').read_text():
                    stop(d, role, 'surviving-descendant')
                else:
                    # RemainAfterExit retains PID1's exit receipt until collection.
                    try:
                        close(d)
                    except FileExistsError:
                        pass
                return
            reason = None
            if closed(d):
                reason = 'generation-closed'
            elif time.monotonic() >= d['end_at']:
                reason = 'absolute-deadline'
            elif not admitted and time.monotonic() >= d['start_by']:
                reason = 'start-deadline'
            elif time.monotonic() - started > d['heartbeat_limit'] and not all(live(d, r) for r in (other, 'controller')):
                reason = 'monitor-lost'
            elif admitted and not lease_ok(d):
                reason = 'ack-expired'
            elif native:
                try:
                    tasks = list((Path('/proc') / str(native['pid']) / 'task').iterdir())
                    if len(tasks) != 1:
                        reason = 'unexpected-thread'
                    cg = Path('/sys/fs/cgroup/system.slice') / d['unit']
                    pids = set((cg / 'cgroup.procs').read_text().split())
                    if pids != {str(native['pid'])}:
                        reason = 'unexpected-child'
                except FileNotFoundError:
                    pass  # pidfd determines exit; missing cgroup is never success evidence.
            if reason:
                stop(d, role, reason, pidfd)
                return
            if not admitted and select.select([server], [], [], .02)[0]:
                conn, _ = server.accept()
                conn.settimeout(.1)
                with conn:
                    pid, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    reg = json.loads(conn.recv(8192))
                    current_start(d)
                    if uid != d['uid'] or reg['generation'] != d['generation']:
                        raise ValueError('peer/generation mismatch')
                    pidfd = os.pidfd_open(pid)
                    native = identity(pid)
                    if select.select([pidfd], [], [], 0)[0] or native['cgroup'].strip() != '0::/system.slice/' + d['unit']:
                        raise ValueError('peer identity/unit mismatch')
                    if any(native[k] != reg['identity'][k] for k in native):
                        raise ValueError('peer identity changed')
                    signal.pidfd_send_signal(pidfd, 0)
                    write(d['dir'] / (role + '.registered.json'), dict(identity=native, at=time.monotonic(), generation=d['generation']))
                    conn.send(json.dumps(dict(generation=d['generation'], identity=native, registered=True)).encode())
                    admitted = True
            else:
                time.sleep(.02)
    except Exception as exc:
        stop(d, role, 'guard-error:' + repr(exc), pidfd)
        raise
    finally:
        if pidfd is not None:
            os.close(pidfd)
        server.close()


def main():
    role, path = sys.argv[1:]
    d = descriptor(path)
    if role != 'launcher':
        c = context()
        if c['policy'] != RESET or c['priority'] != 0 or c['affinity'] != d['housekeeping'] or c['uid'] != 0:
            raise ValueError('monitor context differs')
        write(d['dir'] / (role + '.context.json'), c)
    if role == 'launcher':
        try:
            launcher(d)
        except Exception as exc:
            write(d['dir'] / 'native' / 'refused.json', {'error': repr(exc), 'at': time.monotonic()})
            raise
    elif role == 'controller':
        controller(d)
    elif role in ('primary', 'rescue'):
        guard(d, role)
    elif role == 'deadline':
        stop(d, role, 'independent-timer')
    else:
        raise ValueError('role')


if __name__ == '__main__':
    main()
