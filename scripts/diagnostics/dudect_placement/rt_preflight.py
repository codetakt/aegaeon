"""Read-only RT preflight. No unit creation, scheduler mutation, or native launch.

Classification uses the reviewed upstream Linux 6.17 admission model, not a
proof that an Ubuntu-patched kernel or a future syscall behaves identically.
All results prohibit execution; a compatible result is review material only.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time

import rt_runtime

CG = Path('/sys/fs/cgroup')
MAX_FILE = 1024 * 1024
MAX_CONFIG = 4 * MAX_FILE
MAX_CGROUPS = 128
MAX_PROCESSES = 128
MAX_THREADS = 1024
MAX_CPUS = 4096
MAX_BINDING_FILE = 64 * MAX_FILE
MAX_BINDING_TOTAL = 384 * MAX_FILE
CONFIG_KEYS = ('CONFIG_CGROUP_SCHED', 'CONFIG_RT_GROUP_SCHED',
               'CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED', 'CONFIG_POSIX_TIMERS',
               'CONFIG_HZ', 'CONFIG_SMP')
PROC_KEYS = ('Uid', 'Gid', 'CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp')
UNIT_KEYS = ('Id', 'LoadState', 'ActiveState', 'InvocationID', 'ControlGroup',
             'MainPID', 'AllowedCPUs', 'StartupAllowedCPUs', 'Delegate',
             'RestrictRealtime', 'CPUSchedulingPolicy', 'CPUSchedulingPriority')
MANAGER_KEYS = ('DefaultLimitRTPRIO', 'DefaultLimitRTPRIOSoft',
                'DefaultLimitRTTIME', 'DefaultLimitRTTIMESoft')
CG_KEYS = ('cgroup.controllers', 'cgroup.subtree_control', 'cgroup.type',
           'cpuset.cpus.effective', 'cpuset.cpus', 'cpu.max')
ROOT_NA = {'cgroup.type', 'cpuset.cpus', 'cpu.max'}
UNKNOWN = 'UNKNOWN_NO_EXECUTION'
INCOMPATIBLE = 'NO_GO_INCOMPATIBLE_CURRENT_CONFIGURATION'
STOP_NO_GO = 'NO_GO_UNDER_PROPOSED_STOP_PROTOCOL'
COMPATIBLE = 'READ_ONLY_PRECONDITIONS_COMPATIBLE_AUTHORIZATION_UNPROVEN'


class Deadline(Exception):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cpu_list(value):
    if not value.strip():
        return []
    out = set()
    for part in value.strip().split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?', part):
            raise ValueError('invalid CPU list')
        a, _, b = part.partition('-')
        a, b = int(a), int(b or a)
        if a > b or b >= MAX_CPUS:
            raise ValueError('CPU range outside collector bound')
        out.update(range(a, b + 1))
    return sorted(out)


def parse_config(raw, compressed=False):
    if compressed:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(MAX_CONFIG + 1)
    if len(raw) > MAX_CONFIG:
        raise ValueError('expanded config exceeds bound')
    values = {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        match = re.fullmatch(r'(CONFIG_\w+)=(\S+)', line)
        disabled = re.fullmatch(r'# (CONFIG_\w+) is not set', line)
        if match:
            key, value = match.groups()
        elif disabled:
            key, value = disabled.group(1), 'n'
        else:
            continue
        if key in CONFIG_KEYS:
            if key in values:
                raise ValueError('duplicate config key')
            values[key] = value
    return {'values': {k: values.get(k) for k in CONFIG_KEYS},
            'expanded_sha256': sha(raw), 'expanded_bytes': len(raw)}


def cmdline_projection(raw):
    # Neither the entire command line nor unrelated tokens leave this function.
    tokens = [t for t in raw.decode('utf-8', errors='strict').split()
              if t == 'rt_group_sched' or t.startswith('rt_group_sched=')]
    return {'sha256': sha(raw), 'rt_group_sched_tokens': tokens}


def rt_group_state(config, tokens):
    if config.get('CONFIG_CGROUP_SCHED') not in ('y', 'n'):
        return None, 'missing CONFIG_CGROUP_SCHED'
    built = config.get('CONFIG_RT_GROUP_SCHED')
    if built not in ('y', 'n'):
        return None, 'missing CONFIG_RT_GROUP_SCHED'
    if config['CONFIG_CGROUP_SCHED'] == 'n' and built == 'y':
        return None, 'inconsistent RT group dependency'
    # A duplicated/invalid boot argument is deliberately not interpreted.
    if len(tokens) > 1 or any(t not in ('rt_group_sched=0', 'rt_group_sched=1')
                              for t in tokens):
        return None, 'ambiguous rt_group_sched command line'
    if built == 'n':
        return False, 'RT group scheduler not built'
    default = config.get('CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED')
    if default not in ('y', 'n'):
        return None, 'unknown RT group default'
    return (tokens[0].endswith('=1') if tokens else default == 'n'), 'upstream 6.17 model'


def choose_cores(topology):
    online = topology['online']
    groups = {}
    for cpu in online:
        row = topology['cpus'][str(cpu)]
        key = (row['package'], row['core'])
        siblings = set(row['siblings']) & set(online)
        if cpu not in siblings:
            raise ValueError('self missing from sibling set')
        group = groups.setdefault(key, set())
        group.add(cpu)
    for group in groups.values():
        for cpu in group:
            if set(topology['cpus'][str(cpu)]['siblings']) & set(online) != group:
                raise ValueError('inconsistent core/sibling topology')
    if len(groups) < 2:
        return None
    cores = sorted((sorted(v) for v in groups.values()), key=lambda v: v[0])
    measure = cores[-1]
    return {'M': measure, 'H': sorted(set(online) - set(measure)),
            'native_cpu': measure[0], 'rule': 'last complete online physical core'}


def classify(censuses):
    try:
        return _classify(censuses)
    except (KeyError, TypeError, ValueError, IndexError):
        return UNKNOWN, ['incomplete or invalid mandatory classification input']


def _classify(censuses):
    if len(censuses) != 2:
        return UNKNOWN, ['two complete censuses not available']
    a, b = censuses
    errors = [e for c in censuses for e in c['errors']]
    # Exclude timestamps and optional debug data, never identity or mandatory facts.
    if a['facts'] != b['facts']:
        errors.append('mandatory facts/identity changed between censuses')
    if errors:
        return UNKNOWN, errors
    f = a['facts']
    if not f['kernel']['model_version_supported']:
        return UNKNOWN, ['kernel outside reviewed 6.17 admission model']
    if not f['kernel']['config_correspondence']:
        return UNKNOWN, ['running kernel/config correspondence unavailable']
    config = f['kernel']['config']
    if config.get('CONFIG_POSIX_TIMERS') not in ('y', 'n'):
        return UNKNOWN, ['CONFIG_POSIX_TIMERS unknown']
    if (config.get('CONFIG_SMP') not in ('y', 'n') or
            not str(config.get('CONFIG_HZ')).isdigit() or int(config['CONFIG_HZ']) <= 0):
        return UNKNOWN, ['SMP/HZ config unknown']
    enabled, reason = rt_group_state(config, f['kernel']['cmdline']['rt_group_sched_tokens'])
    if enabled is None:
        return UNKNOWN, [reason]
    period, runtime = f['rt_budget']['period_us'], f['rt_budget']['runtime_us']
    if period <= 0 or runtime < -1 or runtime > period:
        return UNKNOWN, ['invalid RT period/runtime']
    if config['CONFIG_POSIX_TIMERS'] == 'n':
        return STOP_NO_GO, ['required RTTIME enforcement not built']
    if not f['core_selection']:
        return STOP_NO_GO, ['two disjoint physical core sets unavailable']
    selected = set(f['core_selection']['M'] + f['core_selection']['H'])
    if any(not selected <= set(cpu_list(f['cgroups'][p]['cpuset.cpus.effective']['value']))
           for p in ('/', '/system.slice')):
        return STOP_NO_GO, ['proposed core sets exceed ancestor effective CPUs']
    if enabled and runtime >= 0:
        # A new service under system.slice gets a non-root CPU task group if
        # the cpu controller is enabled along both ancestor edges. No group
        # runtime is created or allocated by this proposed protocol.
        ancestors = f['cgroups']
        both = all('cpu' in ancestors[p]['cgroup.subtree_control'].get('value', '').split()
                   for p in ('/', '/system.slice'))
        if both:
            return INCOMPATIBLE, ['upstream model: new non-root CPU group has zero RT bandwidth']
        return UNKNOWN, ['effective non-root RT bandwidth cannot be established read-only']
    if runtime == 0:
        return STOP_NO_GO, ['zero global RT runtime does not meet the proposed execution protocol']
    return COMPATIBLE, ['no model rejection found; kernel patch equivalence, actual authorization, '
                        'RT admission and bounded stopping remain unproven']


def stat_start(raw):
    tail = raw.decode().rsplit(')', 1)[1].split()
    return int(tail[19])  # field 22; tail starts at field 3


class Collector:
    def __init__(self, unit, job_pid, duration=60):
        if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit) or unit.startswith('-'):
            raise ValueError('invalid fixed service name')
        if not isinstance(job_pid, int) or job_pid <= 0:
            raise ValueError('invalid job PID')
        self.unit, self.job_pid = unit, job_pid
        self.deadline = time.monotonic() + duration
        self.systemctl = shutil.which('systemctl')
        self.records = []
        self.thread_count = 0
        self.child_runtime = None
        self.child_traces = []

    def check(self):
        if time.monotonic() >= self.deadline:
            raise Deadline('collector deadline')

    def read(self, path, limit=MAX_FILE):
        self.check()
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode):
                raise ValueError('not a regular proc/sys/config file')
            chunks, size = [], 0
            while True:
                self.check()
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError('file exceeds read bound')
                chunks.append(chunk)
            raw = b''.join(chunks)
        finally:
            os.close(fd)
        self.records.append({'path': str(path), 'sha256': sha(raw), 'bytes': len(raw)})
        return raw

    def text(self, path):
        return self.read(path).decode('utf-8', errors='strict').strip()

    def command(self, kind):
        self.check()
        if not self.systemctl:
            raise FileNotFoundError('systemctl unavailable')
        base = [self.systemctl, '--no-pager', '--no-ask-password']
        if kind == 'version':
            argv = base + ['--version']
        elif kind == 'unit':
            argv = base + ['show', self.unit, '--property=' + ','.join(UNIT_KEYS)]
        elif kind == 'manager':
            argv = base + ['show', '--property=' + ','.join(MANAGER_KEYS)]
        else:
            raise ValueError('command not allowlisted')
        env = dict(rt_runtime.ENV)
        if self.child_runtime is not None:
            env['LD_DEBUG'] = 'files'
        result = rt_runtime.run(argv, min(5, self.deadline - time.monotonic()), env)
        self.records.append({'argv': argv, 'sha256': sha(result['stdout']),
                             'bytes': len(result['stdout']), 'returncode': result['returncode'],
                             'stderr_sha256': sha(result['stderr'])})
        if self.child_runtime is not None:
            self.child_traces.append({'kind': kind,
                **rt_runtime.verify_loader_trace(result['stderr'], self.child_runtime)})
        if result['returncode']:
            raise RuntimeError('read-only command failed: ' + str(result['returncode']))
        return result['stdout'].decode('utf-8', errors='strict')

    def properties(self, kind):
        raw = self.command(kind)
        values = {}
        for line in raw.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                if key in values:
                    raise ValueError('duplicate systemd property')
                values[key] = value
        keys = UNIT_KEYS if kind == 'unit' else MANAGER_KEYS
        if any(k not in values for k in keys):
            raise ValueError('required systemd property absent')
        if kind == 'unit' and (values['Id'] != self.unit or values['LoadState'] != 'loaded'):
            raise ValueError('target service not loaded or mismatched')
        return {k: values[k] for k in keys}

    def kernel(self):
        uname = os.uname()
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+', uname.release):
            raise ValueError('unexpected kernel release')
        sources, missing, errors = [], [], []
        for path, compressed in [(Path('/boot') / ('config-' + uname.release), False),
                                 (Path('/proc/config.gz'), True)]:
            try:
                raw = self.read(path)
                parsed = parse_config(raw, compressed)
            except FileNotFoundError:
                missing.append({'path': str(path), 'status': 'absent'})
                continue
            except (OSError, ValueError, EOFError) as exc:
                errors.append(f'{path}: {type(exc).__name__}')
                continue
            parsed['source'] = str(path)
            parsed['correspondence'] = 'running_kernel_interface' if compressed else 'release_named_file_only'
            sources.append(parsed)
        if not sources:
            errors.append('kernel config unavailable')
        if any(s['expanded_sha256'] != sources[0]['expanded_sha256'] for s in sources):
            errors.append('kernel config sources disagree')
        try:
            cmdline = cmdline_projection(self.read('/proc/cmdline'))
        except (OSError, ValueError) as exc:
            cmdline = None
            errors.append('cmdline: ' + type(exc).__name__)
        return {'release': uname.release, 'version': uname.version, 'machine': uname.machine,
                'config': sources[0]['values'] if sources else None,
                'config_sources': sources, 'missing_sources': missing, 'errors': errors,
                # A filename alone is not a build binding. A later reviewed
                # package/image binding may supply that evidence; we do not invent it.
                'config_correspondence': any(s['correspondence'] == 'running_kernel_interface' for s in sources),
                'model_version_supported': bool(re.match(r'^6\.17(?:\.|-)', uname.release)),
                'cmdline': cmdline}

    def mount(self):
        rows = self.text('/proc/self/mountinfo').splitlines()
        matches = []
        for row in rows:
            left, sep, right = row.partition(' - ')
            fields = left.split()
            if sep and len(fields) >= 6 and fields[4] == str(CG):
                if fields[3] != '/' or right.split()[0] != 'cgroup2':
                    raise ValueError('non-root or non-cgroup2 mount')
                matches.append(row)
        if len(matches) != 1 or CG.resolve() != CG:
            raise ValueError('ambiguous cgroup root binding')
        return matches[0]

    def cg(self, relative):
        if not relative.startswith('/') or '..' in Path(relative).parts:
            raise ValueError('invalid cgroup path')
        path = CG / relative.lstrip('/')
        if path.resolve() != path:
            raise ValueError('cgroup path indirection')
        values = {}
        for name in CG_KEYS:
            try:
                values[name] = {'value': self.text(path / name)}
            except FileNotFoundError:
                if relative == '/' and name in ROOT_NA:
                    values[name] = {'not_applicable': 'documented_root_interface_absence'}
                else:
                    raise
        if not cpu_list(values['cpuset.cpus.effective']['value']):
            raise ValueError('empty effective CPUs')
        return values

    def topology(self):
        base = Path('/sys/devices/system/cpu')
        masks = {k: cpu_list(self.text(base / k)) for k in ('online', 'possible', 'present')}
        if not set(masks['online']) <= set(masks['present']) <= set(masks['possible']):
            raise ValueError('CPU mask mismatch')
        rows = {}
        for cpu in masks['online']:
            p = base / f'cpu{cpu}' / 'topology'
            rows[str(cpu)] = {'package': int(self.text(p / 'physical_package_id')),
                              'core': int(self.text(p / 'core_id')),
                              'siblings': cpu_list(self.text(p / 'thread_siblings_list'))}
            if rows[str(cpu)]['package'] < 0 or rows[str(cpu)]['core'] < 0:
                raise ValueError('unknown physical CPU identity')
        return {**masks, 'cpus': rows}

    def process(self, pid):
        base = Path('/proc') / str(pid)
        start = stat_start(self.read(base / 'stat'))
        membership = self.text(base / 'cgroup')
        exe = os.stat(base / 'exe')
        rows = dict(line.split(':', 1) for line in self.text(base / 'status').splitlines() if ':' in line)
        values = {k: rows[k].strip() for k in PROC_KEYS}
        limits = {k: list(resource.prlimit(pid, value)) for k, value in
                  [('RTPRIO', resource.RLIMIT_RTPRIO), ('RTTIME', resource.RLIMIT_RTTIME),
                   ('CPU', resource.RLIMIT_CPU)]}
        namespaces = {k: os.readlink(base / 'ns' / k) for k in ('user', 'pid', 'mnt', 'cgroup')}
        with os.scandir(base / 'task') as directory:
            tids = []
            for entry in directory:
                self.check()
                if entry.name.isdecimal():
                    self.thread_count += 1
                    if self.thread_count > MAX_THREADS:
                        raise ValueError('thread census bound exceeded')
                    tids.append(int(entry.name))
        threads = {}
        for tid in sorted(tids):
            p = base / 'task' / str(tid)
            before = stat_start(self.read(p / 'stat'))
            row = {'start': before, 'affinity': sorted(os.sched_getaffinity(tid)),
                   'scheduler': os.sched_getscheduler(tid),
                   'priority': os.sched_getparam(tid).sched_priority,
                   'cgroup': self.text(p / 'cgroup')}
            if stat_start(self.read(p / 'stat')) != before:
                raise ValueError('thread identity changed')
            threads[str(tid)] = row
        after = os.stat(base / 'exe')
        if (stat_start(self.read(base / 'stat')) != start or self.text(base / 'cgroup') != membership
                or (exe.st_dev, exe.st_ino) != (after.st_dev, after.st_ino)):
            raise ValueError('process identity/exec/membership changed')
        with os.scandir(base / 'task') as directory:
            remaining = set()
            for entry in directory:
                self.check()
                if entry.name.isdecimal():
                    remaining.add(int(entry.name))
                    if len(remaining) > MAX_THREADS:
                        raise ValueError('thread census bound exceeded')
        if remaining != set(tids):
            raise ValueError('thread set changed during process read')
        return {'pid': pid, 'start': start, 'cgroup': membership, 'status': values,
                'namespaces': namespaces, 'limits': limits,
                'exe_inode': [exe.st_dev, exe.st_ino], 'threads': threads}

    def members(self, relative):
        # Descendants are read-only; bounded before materializing large trees.
        todo, groups, members = [relative], {}, set()
        while todo:
            self.check()
            rel = todo.pop()
            if len(groups) >= MAX_CGROUPS:
                raise ValueError('cgroup census bound exceeded')
            groups[rel] = self.cg(rel)
            path = CG / rel.lstrip('/')
            ids = self.text(path / 'cgroup.procs').split()
            for pid in ids:
                if not pid.isdecimal() or int(pid) <= 0:
                    raise ValueError('invalid cgroup PID')
                members.add(int(pid))
                if len(members) > MAX_PROCESSES:
                    raise ValueError('process census bound exceeded')
            with os.scandir(path) as directory:
                for entry in directory:
                    if entry.is_dir(follow_symlinks=False):
                        todo.append(rel.rstrip('/') + '/' + entry.name)
                        if len(todo) + len(groups) > MAX_CGROUPS:
                            raise ValueError('cgroup census bound exceeded')
        return groups, members

    def census(self, result):
        result.update(start=time.monotonic(), facts={}, errors=[], optional={})
        f = result['facts']
        self.thread_count = 0
        def capture(key, operation):
            try:
                f[key] = operation()
            except Deadline:
                raise
            except (OSError, ValueError, RuntimeError, KeyError, EOFError, IndexError) as exc:
                result['errors'].append(f'{key}: {type(exc).__name__}: {exc}')
        capture('boot_id', lambda: self.text('/proc/sys/kernel/random/boot_id'))
        capture('kernel', self.kernel)
        if 'kernel' in f:
            result['errors'].extend('kernel: ' + e for e in f['kernel']['errors'])
        capture('rt_budget', lambda: {'period_us': int(self.text('/proc/sys/kernel/sched_rt_period_us')),
                                     'runtime_us': int(self.text('/proc/sys/kernel/sched_rt_runtime_us'))})
        capture('systemd_version', lambda: self.command('version').strip())
        capture('manager_limits', lambda: self.properties('manager'))
        capture('background', lambda: self.properties('unit'))
        capture('mount_binding', self.mount)
        if 'mount_binding' in f:
            capture('cgroups', lambda: {p: self.cg(p) for p in ('/', '/system.slice')})
        capture('topology', self.topology)
        if 'topology' in f:
            capture('core_selection', lambda: choose_cores(f['topology']))
        f['processes'] = {}
        pids = {1, os.getpid(), self.job_pid}
        if 'background' in f and 'mount_binding' in f:
            try:
                relative = f['background']['ControlGroup']
                groups, extra = self.members(relative)
                f['background_cgroups'] = groups
                pids |= extra
                if len(pids) > MAX_PROCESSES:
                    raise ValueError('combined process census bound exceeded')
                f['background_members'] = sorted(extra)
            except (OSError, ValueError) as exc:
                result['errors'].append('background census: ' + repr(exc))
        if len(pids) > MAX_PROCESSES:
            result['errors'].append('combined process census bound exceeded')
            pids = set()
        for pid in sorted(pids):
            try:
                f['processes'][str(pid)] = self.process(pid)
            except (OSError, ValueError, KeyError, IndexError) as exc:
                result['errors'].append(f'process {pid}: {type(exc).__name__}')
        # Optional debug/tracing is deliberately not enabled. Omissions are data.
        result['optional'] = {'scheduler_debug': 'not_collected', 'kernel_RT_log': 'not_collected',
                              'RT_throttling_during_execution': 'not_observed_no_execution'}
        result['end'] = time.monotonic()

    def runtime_binding(self):
        # Bind the parent and the actual systemctl commands separately.
        child = rt_runtime.dependency_snapshot(self.systemctl,
                    min(5, self.deadline - time.monotonic()))
        if self.child_runtime is None:
            self.child_runtime = child
        elif self.child_runtime != child:
            raise ValueError('systemctl dependency binding changed')
        paths = {str(Path(__file__).resolve()), str(Path(sys.executable).resolve())}
        if self.systemctl:
            paths.add(str(Path(self.systemctl).resolve()))
        for module in list(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).is_file():
                paths.add(str(Path(path).resolve()))
        for line in self.text('/proc/self/maps').splitlines():
            columns = line.split(None, 5)
            if len(columns) == 6 and columns[5].startswith('/'):
                paths.add(columns[5])
        if len(paths) > 256:
            raise ValueError('runtime file count exceeds bound')
        total, files = 0, []
        for name in sorted(paths):
            raw = self.read(name, min(MAX_BINDING_FILE, MAX_BINDING_TOTAL - total))
            total += len(raw)
            files.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
        return {'python': sys.version, 'executable': str(Path(sys.executable).resolve()),
                'files': files, 'bytes': total,
                'systemctl_dependencies': child,
                'workflow_checkout_event_binding': 'external_runner_responsibility'}

    def collect(self):
        result = {'schema': 'aegaeon.dudect.rt-readonly-preflight.v1', 'censuses': [],
                  'classification': UNKNOWN, 'execution_admitted': False,
                  'hosted_execution_ready': False,
                  'native_invocations': 0, 'configuration_mutations': 0,
                  'unit': self.unit, 'job_pid': self.job_pid,
                  'source_sha256': sha(Path(__file__).read_bytes()),
                  'limits': {'seconds': 60, 'command_seconds': 5, 'file_bytes': MAX_FILE,
                             'expanded_config_bytes': MAX_CONFIG, 'cgroups': MAX_CGROUPS,
                             'processes': MAX_PROCESSES, 'threads_per_census': MAX_THREADS,
                             'CPU_ID_bound': MAX_CPUS, 'censuses': 2},
                  'model': 'upstream-linux-v6.17-source-reviewed; distribution patches unproven'}
        try:
            result['runtime_before'] = self.runtime_binding()
            for _ in range(2):
                row = {}
                result['censuses'].append(row)
                self.census(row)
            result['runtime_after'] = self.runtime_binding()
            before = {v['path']: v['sha256'] for v in result['runtime_before']['files']}
            after = {v['path']: v['sha256'] for v in result['runtime_after']['files']}
            if any(after.get(k) != v for k, v in before.items()):
                raise ValueError('runtime input changed during collection')
            result['classification'], result['reasons'] = classify(result['censuses'])
        except Exception as exc:
            result['reasons'] = [type(exc).__name__ + ': ' + str(exc)]
        result['read_receipts'] = self.records
        result['systemctl_loader_traces'] = self.child_traces
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--job-pid', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    collector = Collector(args.unit, args.job_pid)
    # Reserve output before collecting. Never overwrite old evidence.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    def expired(*_):
        raise Deadline('60 second collector alarm')
    old_handler = signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    with os.fdopen(fd, 'w') as output:
        try:
            result = collector.collect()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps({'classification': result['classification'], 'execution_admitted': False}))


if __name__ == '__main__':
    main()
