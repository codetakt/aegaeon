"""Finite read-only service inspection. Never starts native or mutates systemd."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time

from state import mask

CG = Path('/sys/fs/cgroup')
PROPERTIES = ('Id LoadState ActiveState SubState InvocationID MainPID ControlGroup Slice '
              'AllowedCPUs StartupAllowedCPUs EffectiveCPUs Delegate DelegateControllers '
              'DelegateSubgroup FragmentPath DropInPaths CPUWeight CPUQuotaPerSecUSec '
              'MemoryMax CPUSchedulingPolicy CPUSchedulingPriority User Group').split()
CGFILES = ('cpuset.cpus cpuset.cpus.effective cpuset.mems cpuset.mems.effective '
           'cgroup.events cgroup.procs cgroup.threads cgroup.type cgroup.controllers cgroup.subtree_control').split()
CPU_KEYS = set('AllowedCPUs StartupAllowedCPUs CPUAffinity CPUWeight StartupCPUWeight '
               'CPUQuota CPUQuotaPeriodSec CPUSchedulingPolicy CPUSchedulingPriority'.split())
ROOT_ABSENT = {'cpuset.cpus': 'root_requested_mask_absent',
               'cpuset.mems': 'root_requested_mask_absent',
               'cgroup.events': 'root_nonroot_interface_absent',
               'cgroup.type': 'root_nonroot_interface_absent'}


def read(path, limit=1048576):
    with path.open('rb') as file:
        raw = file.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError('read resource limit: ' + str(path))
    return raw


def digest(path):
    return hashlib.sha256(read(path, 64 * 1024 * 1024)).hexdigest()


def command(*argv):
    # Only these two read APIs are available, with no caller-supplied subcommand.
    if argv != ('systemctl', '--version') and not (
        len(argv) == 4 and argv[:2] == ('systemctl', 'show') and argv[3].startswith('--property=')):
        raise RuntimeError('command not allowlisted')
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=5).stdout


def props(unit):
    raw = command('systemctl', 'show', unit, '--property=' + ','.join(PROPERTIES))
    values = dict(line.split('=', 1) for line in raw.splitlines())
    return {key: values.get(key) for key in PROPERTIES}


def root_binding(path):
    if path != CG or path.resolve() != CG:
        raise RuntimeError('not the expected cgroup root')
    mounts = []
    for line in read(Path('/proc/self/mountinfo')).decode().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        if fields[4] == str(CG) and right.split()[0] == 'cgroup2' and fields[3] == '/':
            mounts.append(line)
    if len(mounts) != 1:
        raise RuntimeError('cgroup2 root mount is not uniquely identified')
    return {'mountinfo': mounts[0], 'namespaces': {
        name: os.readlink('/proc/self/ns/' + name) for name in ('mnt', 'cgroup')}}


def cg_record(path):
    binding = root_binding(path) if path == CG else None
    row = {'root_binding': binding} if binding else {}
    for name in CGFILES:
        try:
            row[name] = {'value': read(path / name).decode().strip()}
        except FileNotFoundError:
            if binding and name in ROOT_ABSENT:
                row[name] = {'not_applicable': ROOT_ABSENT[name]}
            else:
                raise
    return row


def proc(pid):
    base = Path('/proc') / str(pid)
    def start(path):
        return int(read(path / 'stat').decode().rsplit(')', 1)[1].split()[19])
    before = start(base)
    status = dict(line.split(':', 1) for line in read(base / 'status').decode().splitlines())
    exe = base / 'exe'
    st = exe.stat()
    result = {'pid': pid, 'start': before, 'uid': status['Uid'].split(),
              'executable': str(exe.resolve()), 'device': st.st_dev, 'inode': st.st_ino,
              'executable_sha256': digest(exe), 'cmdline_sha256': digest(base / 'cmdline'),
              'cgroup': read(base / 'cgroup').decode().strip(), 'threads': {}}
    for task in sorted((base / 'task').iterdir()):
        tid = int(task.name)
        birth = start(task)
        cpus = sorted(os.sched_getaffinity(tid))
        if start(task) != birth:
            raise RuntimeError('thread identity changed')
        result['threads'][task.name] = {'start': birth, 'cpus': cpus}
    after = exe.stat()
    if (start(base) != before or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
            (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) or digest(base / 'cmdline') != result['cmdline_sha256']):
        raise RuntimeError('process identity changed during census')
    return result


def census(unit, partial=None):
    partial = {} if partial is None else partial
    start = time.monotonic()
    p = props(unit)
    partial.update(phase='properties', properties=p, start=start)
    if p['Id'] != unit or p['LoadState'] != 'loaded' or p['ActiveState'] != 'active' or not p['InvocationID']:
        raise RuntimeError('unit not active and identifiable')
    if not p['ControlGroup'] or '..' in Path(p['ControlGroup']).parts:
        raise RuntimeError('invalid cgroup path')
    path = CG / p['ControlGroup'].lstrip('/')
    if path == CG or not path.resolve().is_relative_to(CG):
        raise RuntimeError('invalid cgroup boundary')
    partial.update(path=str(path), phase='cgroups')
    descendants = [path, *sorted(x for x in path.rglob('*') if x.is_dir())]
    cgroups = partial['cgroups'] = {}
    for x in descendants:
        cgroups[str(x)] = cg_record(x)
    members = sorted({int(pid) for row in cgroups.values() for pid in row['cgroup.procs']['value'].split()})
    partial.update(phase='members', member_pids=members)
    processes = partial['members'] = {}
    for pid in members:
        processes[str(pid)] = proc(pid)
    # Never retry a census that lost a task or acquired a new task.
    ending = sorted({int(pid) for x in descendants for pid in read(x / 'cgroup.procs').split()})
    if members != ending:
        raise RuntimeError('membership changed within census')
    ancestor_paths = [x for x in path.parents if x.is_relative_to(CG)]
    partial.update(phase='ancestors')
    ancestors = partial['ancestors'] = {}
    for x in ancestor_paths:
        ancestors[str(x)] = cg_record(x)
    partial.update(phase='files')
    files = partial['files'] = {}
    for name in [p['FragmentPath'], *shlex.split(p['DropInPaths'] or '')]:
        if not name:
            raise RuntimeError('unit file unavailable')
        raw = read(Path(name))
        cpu_lines = []
        for line in raw.decode().splitlines():
            stripped = line.strip()
            if stripped.split('=', 1)[0] in CPU_KEYS:
                if stripped.endswith('\\'):
                    raise RuntimeError('CPU config continuation requires review')
                cpu_lines.append(stripped)
        files[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'cpu_directives': cpu_lines}
    if props(unit) != p:
        raise RuntimeError('unit properties changed within census')
    return {'start': start, 'end': time.monotonic(), 'properties': p, 'path': str(path),
            'cgroups': cgroups, 'ancestors': ancestors, 'members': processes, 'files': files}


def stable(row):
    return {k: v for k, v in row.items() if k not in ('start', 'end')}


def classify(rows, online):
    unknown = 'MISMATCH_UNKNOWN_UNREADABLE'
    if len(rows) != 2 or stable(rows[0]) != stable(rows[1]):
        return unknown, 'two census results differ or are incomplete'
    row = rows[1]
    prop = row['properties']
    cg = row['cgroups'][row['path']]
    if prop['AllowedCPUs'] is None:
        return unknown, 'requested CPU property unavailable'
    requested = mask(prop['AllowedCPUs'])
    kernel = mask(cg['cpuset.cpus']['value'])
    effective = set(mask(cg['cpuset.cpus.effective']['value']))
    if not effective or not effective <= set(online) or not row['members']:
        return unknown, 'empty/unavailable effective CPUs or no known members'
    if bool(requested) != bool(kernel) or requested != kernel:
        return unknown, 'manager and kernel requested masks differ'
    for ancestor in row['ancestors'].values():
        if not effective <= set(mask(ancestor['cpuset.cpus.effective']['value'])):
            return unknown, 'effective CPUs exceed ancestor'
    for member in row['members'].values():
        if not member['threads']:
            return unknown, 'no observed threads'
        for task in member['threads'].values():
            if not task['cpus'] or not set(task['cpus']) <= effective:
                return unknown, 'member affinity exceeds service effective CPUs'
    if not requested:
        return 'INHERITED_UNSET', 'current direct-change method rejected; no mutation'
    if effective != set(requested):
        return unknown, 'requested and effective masks differ'
    return 'EXPLICIT_CONSISTENT', 'read compatibility only; no timing admission'


def environment():
    cpuroot = Path('/sys/devices/system/cpu')
    status = dict(x.split(':', 1) for x in read(Path('/proc/self/status')).decode().splitlines())
    online = mask(read(cpuroot / 'online').decode())
    return {'kernel': list(os.uname()), 'systemd': command('systemctl', '--version'),
            'os_release': read(Path('/etc/os-release')).decode(),
            'image': {key: os.environ.get(key) for key in ('ImageOS', 'ImageVersion')},
            'boot': read(Path('/proc/sys/kernel/random/boot_id')).decode().strip(),
            'namespaces': {key: os.readlink('/proc/self/ns/' + key) for key in ('mnt', 'cgroup')},
            'mountinfo_cgroup': [x for x in read(Path('/proc/self/mountinfo')).decode().splitlines()
                                 if ' - cgroup2 ' in x],
            'uid': os.getuid(), 'gid': os.getgid(), 'capabilities': status.get('CapEff', '').strip(),
            'cpu_masks': {key: read(cpuroot / key).decode().strip() for key in ('possible', 'present', 'online')},
            'topology': {str(cpu): {key: read(cpuroot / f'cpu{cpu}/topology' / key).decode().strip()
                                   for key in ('core_id', 'physical_package_id', 'thread_siblings_list')}
                         for cpu in online}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', args.unit):
        parser.error('explicit service name required')
    if args.output.exists():
        parser.error('output already exists')
    result = {'schema': 'dudect.service-inspection/1', 'unit': args.unit, 'census': [],
              'native_invocations': 0, 'configuration_mutations': 0, 'replacements': 0,
              'limits': {'collector_seconds': 60, 'command_seconds': 5, 'census_passes': 2},
              'timing_admission': False}
    def timeout(*_):
        raise TimeoutError('60 second collector deadline')
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(60)
    result['started'] = time.monotonic()
    try:
        result['environment'] = environment()
        for _ in range(2):
            result['partial_census'] = {}
            result['census'].append(census(args.unit, result['partial_census']))
            del result['partial_census']
        after = read(Path('/sys/devices/system/cpu/online')).decode().strip()
        if after != result['environment']['cpu_masks']['online']:
            raise RuntimeError('online CPUs changed')
        result['classification'], result['reason'] = classify(
            result['census'], mask(after))
    except Exception as exc:
        result['classification'] = 'MISMATCH_UNKNOWN_UNREADABLE'
        result['reason'] = repr(exc)
    finally:
        signal.alarm(0)
    result['ended'] = time.monotonic()
    # Only the private output is written. No unit, cgroup or task is changed.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        json.dump(result, file, indent=2)
        file.write('\n')


if __name__ == '__main__':
    main()
