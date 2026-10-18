"""Functional fixtures only: no service creation or scheduling changes."""
import copy
import ast
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import rt_preflight as r


CONFIG = {
    'CONFIG_CGROUP_SCHED': 'y', 'CONFIG_RT_GROUP_SCHED': 'y',
    'CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED': 'y',
    'CONFIG_POSIX_TIMERS': 'y', 'CONFIG_HZ': '250', 'CONFIG_SMP': 'y',
}


def config_bytes(values=None):
    return ''.join(f'{k}={v}\n' for k, v in (values or CONFIG).items()).encode()


def topology():
    return {'online': [0, 1, 2, 3], 'cpus': {
        str(i): {'package': 0, 'core': i // 2,
                 'siblings': [i // 2 * 2, i // 2 * 2 + 1]} for i in range(4)}}


def facts():
    return {
        'kernel': {'model_version_supported': True, 'config_correspondence': True,
                   'config': dict(CONFIG), 'cmdline': {'rt_group_sched_tokens': []}},
        'rt_budget': {'period_us': 1000000, 'runtime_us': 950000},
        'core_selection': r.choose_cores(topology()),
        'cgroups': {p: {'cgroup.subtree_control': {'value': 'cpu cpuset'},
                       'cpuset.cpus.effective': {'value': '0-3'}}
                    for p in ('/', '/system.slice')},
    }


def classify(f):
    row = {'facts': f, 'errors': []}
    return r.classify([row, copy.deepcopy(row)])[0]


class DecisionTests(unittest.TestCase):
    def test_compatible_is_not_execution_permission(self):
        self.assertEqual(classify(facts()), r.COMPATIBLE)

    def test_explicit_group_enable_rejects_default_child(self):
        f = facts()
        f['kernel']['cmdline']['rt_group_sched_tokens'] = ['rt_group_sched=1']
        self.assertEqual(classify(f), r.INCOMPATIBLE)

    def test_enabled_default_and_explicit_disable(self):
        f = facts()
        f['kernel']['config']['CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED'] = 'n'
        self.assertEqual(classify(f), r.INCOMPATIBLE)
        f['kernel']['cmdline']['rt_group_sched_tokens'] = ['rt_group_sched=0']
        self.assertEqual(classify(f), r.COMPATIBLE)

    def test_unbuilt_group_scheduler(self):
        f = facts()
        f['kernel']['config']['CONFIG_RT_GROUP_SCHED'] = 'n'
        f['kernel']['config']['CONFIG_RT_GROUP_SCHED_DEFAULT_DISABLED'] = None
        self.assertEqual(classify(f), r.COMPATIBLE)

    def test_unlimited_global_budget_is_not_auth_proof(self):
        f = facts()
        f['kernel']['cmdline']['rt_group_sched_tokens'] = ['rt_group_sched=1']
        f['rt_budget']['runtime_us'] = -1
        self.assertEqual(classify(f), r.COMPATIBLE)

    def test_unknown_controller_edge(self):
        f = facts()
        f['kernel']['cmdline']['rt_group_sched_tokens'] = ['rt_group_sched=1']
        f['cgroups']['/system.slice']['cgroup.subtree_control']['value'] = 'cpuset'
        self.assertEqual(classify(f), r.UNKNOWN)

    def test_missing_config_or_model_never_passes(self):
        for key in ('model_version_supported', 'config_correspondence'):
            with self.subTest(key=key):
                f = facts()
                f['kernel'][key] = False
                self.assertEqual(classify(f), r.UNKNOWN)
        self.assertEqual(classify({}), r.UNKNOWN)

    def test_unknown_config_defaults_and_dependency(self):
        for key in CONFIG:
            with self.subTest(key=key):
                f = facts()
                del f['kernel']['config'][key]
                self.assertEqual(classify(f), r.UNKNOWN)
        f = facts()
        f['kernel']['config']['CONFIG_CGROUP_SCHED'] = 'n'
        self.assertEqual(classify(f), r.UNKNOWN)

    def test_duplicate_or_malformed_boot_options(self):
        for tokens in (['rt_group_sched'], ['rt_group_sched=x'],
                       ['rt_group_sched=0', 'rt_group_sched=1'],
                       ['rt_group_sched=0', 'rt_group_sched=0']):
            with self.subTest(tokens=tokens):
                f = facts()
                f['kernel']['cmdline']['rt_group_sched_tokens'] = tokens
                self.assertEqual(classify(f), r.UNKNOWN)

    def test_stop_protocol_requires_timers_and_core_sets(self):
        f = facts()
        f['kernel']['config']['CONFIG_POSIX_TIMERS'] = 'n'
        self.assertEqual(classify(f), r.STOP_NO_GO)
        f = facts()
        f['core_selection'] = None
        self.assertEqual(classify(f), r.STOP_NO_GO)
        f = facts()
        f['cgroups']['/system.slice']['cpuset.cpus.effective']['value'] = '0-1'
        self.assertEqual(classify(f), r.STOP_NO_GO)

    def test_invalid_budget(self):
        for period, runtime in ((0, 0), (-1, 1), (100, 101), (100, -2)):
            with self.subTest(period=period, runtime=runtime):
                f = facts()
                f['rt_budget'] = {'period_us': period, 'runtime_us': runtime}
                self.assertEqual(classify(f), r.UNKNOWN)

    def test_zero_budget_rejects_proposed_protocol(self):
        f = facts()
        f['rt_budget']['runtime_us'] = 0
        self.assertEqual(classify(f), r.STOP_NO_GO)

    def test_partial_error_and_drift(self):
        row = {'facts': facts(), 'errors': []}
        self.assertEqual(r.classify([row])[0], r.UNKNOWN)
        second = copy.deepcopy(row)
        second['errors'] = ['permission denied']
        self.assertEqual(r.classify([row, second])[0], r.UNKNOWN)
        second = copy.deepcopy(row)
        second['facts']['boot_id'] = 'changed'
        self.assertEqual(r.classify([row, second])[0], r.UNKNOWN)


class InputTests(unittest.TestCase):
    def test_cpu_ranges_and_limit(self):
        self.assertEqual(r.cpu_list('0-3,2,7'), [0, 1, 2, 3, 7])
        for value in ('3-2', '-1', '0--3', '0-99999999', '0,x', '1,'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.cpu_list(value)

    def test_core_selection_checks_siblings(self):
        top = topology()
        self.assertEqual(r.choose_cores(top)['M'], [2, 3])
        top['cpus']['2']['siblings'] = [2]
        with self.assertRaises(ValueError):
            r.choose_cores(top)
        top = topology()
        top['online'] = [0, 1]
        self.assertIsNone(r.choose_cores(top))

    def test_config_exact_plain_and_gzip(self):
        raw = config_bytes()
        self.assertEqual(r.parse_config(raw), r.parse_config(gzip.compress(raw), True))
        self.assertEqual(r.parse_config(b'# CONFIG_SMP is not set\n')['values']['CONFIG_SMP'], 'n')

    def test_config_duplicates_and_expansion_limit(self):
        with self.assertRaises(ValueError):
            r.parse_config(config_bytes() + b'CONFIG_SMP=n\n')
        with self.assertRaises(ValueError):
            r.parse_config(gzip.compress(b'x' * (r.MAX_CONFIG + 1)), True)
        with self.assertRaises((OSError, EOFError)):
            r.parse_config(b'bad gzip', True)

    def test_cmdline_redacts_unrelated_tokens(self):
        raw = b'root=secret password=TOPSECRET rt_group_sched=0 quiet'
        result = r.cmdline_projection(raw)
        self.assertNotIn('TOPSECRET', json.dumps(result))
        self.assertEqual(result['rt_group_sched_tokens'], ['rt_group_sched=0'])
        self.assertEqual(result['sha256'], r.sha(raw))

    def test_stat_name_with_closing_parenthesis(self):
        raw = b'42 (name ) with spaces) S ' + b'0 ' * 18 + b'12345 0'
        self.assertEqual(r.stat_start(raw), 12345)

    def kernel_with(self, mapping):
        collector = r.Collector('example.service', 1)
        def read(path, *args):
            key = str(path)
            value = mapping.get('/boot/config' if key.startswith('/boot/config-') else key,
                                FileNotFoundError(key))
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(collector, 'read', side_effect=read):
            return collector.kernel()

    def test_running_kernel_config_binding(self):
        result = self.kernel_with({'/proc/config.gz': gzip.compress(config_bytes()), '/proc/cmdline': b''})
        self.assertTrue(result['config_correspondence'])
        self.assertFalse(result['errors'])

    def test_boot_filename_is_not_kernel_build_binding(self):
        result = self.kernel_with({'/boot/config': config_bytes(), '/proc/cmdline': b''})
        self.assertFalse(result['config_correspondence'])
        self.assertFalse(result['errors'])

    def test_config_unavailable_preserves_identity_and_boot_projection(self):
        result = self.kernel_with({'/proc/cmdline': b'rt_group_sched=1'})
        self.assertEqual(result['release'], os.uname().release)
        self.assertIn('kernel config unavailable', result['errors'])
        self.assertEqual(result['cmdline']['rt_group_sched_tokens'], ['rt_group_sched=1'])

    def test_permission_is_not_optional_absence(self):
        result = self.kernel_with({'/boot/config': PermissionError(),
                                  '/proc/config.gz': gzip.compress(config_bytes()), '/proc/cmdline': b''})
        self.assertTrue(result['errors'])

    def test_disagreeing_config_sources(self):
        result = self.kernel_with({'/boot/config': config_bytes(),
                                  '/proc/config.gz': gzip.compress(config_bytes() + b'#extra\n'),
                                  '/proc/cmdline': b''})
        self.assertIn('kernel config sources disagree', result['errors'])


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.collector = r.Collector('example.service', os.getpid())

    def cgroup(self, relative='/', omit=()):
        p = self.root / relative.lstrip('/')
        p.mkdir(parents=True, exist_ok=True)
        for name in r.CG_KEYS:
            if name not in omit:
                (p / name).write_text('0-3' if name == 'cpuset.cpus.effective' else '')
        (p / 'cgroup.procs').write_text('')
        return p

    def test_root_only_absence(self):
        self.cgroup(omit=r.ROOT_NA)
        with patch.object(r, 'CG', self.root):
            record = self.collector.cg('/')
            self.assertEqual(set(k for k, v in record.items() if 'not_applicable' in v), r.ROOT_NA)
            self.cgroup('/child', omit=['cgroup.type'])
            with self.assertRaises(FileNotFoundError):
                self.collector.cg('/child')

    def test_root_effective_missing_empty_or_permission_fails(self):
        p = self.cgroup(omit=['cpuset.cpus.effective'])
        with patch.object(r, 'CG', self.root):
            with self.assertRaises(FileNotFoundError):
                self.collector.cg('/')
            (p / 'cpuset.cpus.effective').write_text('')
            with self.assertRaises(ValueError):
                self.collector.cg('/')
            with patch.object(self.collector, 'text', side_effect=PermissionError()):
                with self.assertRaises(PermissionError):
                    self.collector.cg('/')

    def test_symlink_and_parent_paths_rejected(self):
        self.cgroup()
        (self.root / 'link').symlink_to(self.root, target_is_directory=True)
        with patch.object(r, 'CG', self.root):
            for path in ('/link', '/../other', ''):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.collector.cg(path)

    def test_bounded_regular_file_and_nonblocking_fifo(self):
        p = self.root / 'data'
        p.write_bytes(b'abcd')
        self.assertEqual(self.collector.read(p, 4), b'abcd')
        with self.assertRaises(ValueError):
            self.collector.read(p, 3)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.collector.read(fifo)

    def test_deadline_checked_before_read(self):
        self.collector.deadline = time.monotonic() - 1
        with self.assertRaises(r.Deadline):
            self.collector.read('/proc/self/stat')

    def test_member_and_cgroup_bounds(self):
        p = self.cgroup()
        (p / 'cgroup.procs').write_text('1 2 3')
        with patch.object(r, 'CG', self.root), patch.object(r, 'MAX_PROCESSES', 2):
            with self.assertRaises(ValueError):
                self.collector.members('/')
        (p / 'cgroup.procs').write_text('')
        self.cgroup('/child')
        with patch.object(r, 'CG', self.root), patch.object(r, 'MAX_CGROUPS', 1):
            with self.assertRaises(ValueError):
                self.collector.members('/')

    def test_invalid_service_and_command_not_executed(self):
        for unit in ('-example.service', 'example;id.service', '../example.service'):
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                r.Collector(unit, 1)
        with patch.object(r.subprocess, 'Popen') as popen:
            with self.assertRaises(ValueError):
                self.collector.command('start')
            popen.assert_not_called()

    def test_systemd_property_missing_duplicate_or_unloaded(self):
        valid = {k: '' for k in r.UNIT_KEYS}
        valid.update(Id='example.service', LoadState='loaded')
        for modify in ('missing', 'duplicate', 'unloaded'):
            values = dict(valid)
            if modify == 'missing':
                del values['RestrictRealtime']
            if modify == 'unloaded':
                values['LoadState'] = 'not-found'
            raw = ''.join(f'{k}={v}\n' for k, v in values.items())
            if modify == 'duplicate':
                raw += 'Id=example.service\n'
            with self.subTest(modify=modify), patch.object(self.collector, 'command', return_value=raw):
                with self.assertRaises(ValueError):
                    self.collector.properties('unit')

    def helper(self, body):
        p = self.root / 'read-helper'
        p.write_text('#!' + sys.executable + '\n' + body)
        p.chmod(0o700)
        self.collector.systemctl = str(p)

    def test_read_command_output_bound(self):
        self.helper("import os\nos.write(1, b'x' * (2 * 1024 * 1024))\n")
        with self.assertRaises(ValueError):
            self.collector.command('version')

    def test_stalled_read_command_stops_owned_child(self):
        pidfile = self.root / 'pid'
        self.helper('import os,time\nfrom pathlib import Path\n'
                    f'Path({str(pidfile)!r}).write_text(str(os.getpid()))\ntime.sleep(30)\n')
        self.collector.deadline = time.monotonic() + 0.5
        with self.assertRaises(TimeoutError):
            self.collector.command('version')
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_partial_deadline_is_retained_and_never_admitted(self):
        runtime = {'files': []}
        def fail(row):
            row.update(facts={'partial': True}, errors=[])
            raise r.Deadline('injected')
        with patch.object(self.collector, 'runtime_binding', return_value=runtime), \
                patch.object(self.collector, 'census', side_effect=fail):
            result = self.collector.collect()
        self.assertEqual(result['classification'], r.UNKNOWN)
        self.assertEqual(len(result['censuses']), 1)
        self.assertTrue(result['censuses'][0]['facts']['partial'])
        self.assertFalse(result['execution_admitted'])

    def test_runtime_change_rejects_otherwise_compatible(self):
        def census(row):
            row.update(facts=facts(), errors=[])
        with patch.object(self.collector, 'census', side_effect=census), \
                patch.object(self.collector, 'runtime_binding', side_effect=[
                    {'files': [{'path': 'x', 'sha256': 'before'}]},
                    {'files': [{'path': 'x', 'sha256': 'after'}]}]):
            result = self.collector.collect()
        self.assertEqual(result['classification'], r.UNKNOWN)
        self.assertIn('runtime input changed', result['reasons'][0])

    def test_self_process_read_preserves_policy_affinity_and_limits(self):
        before = (os.sched_getscheduler(0), os.sched_getparam(0), os.sched_getaffinity(0),
                  r.resource.getrlimit(r.resource.RLIMIT_RTPRIO),
                  r.resource.getrlimit(r.resource.RLIMIT_RTTIME))
        row = self.collector.process(os.getpid())
        after = (os.sched_getscheduler(0), os.sched_getparam(0), os.sched_getaffinity(0),
                 r.resource.getrlimit(r.resource.RLIMIT_RTPRIO),
                 r.resource.getrlimit(r.resource.RLIMIT_RTTIME))
        self.assertEqual(before, after)
        self.assertIn(str(os.getpid()), row['threads'])

    def test_thread_bound_and_pid_identity_change(self):
        with patch.object(r, 'MAX_THREADS', 0):
            with self.assertRaises(ValueError):
                self.collector.process(os.getpid())
        self.collector.thread_count = 0
        with patch.object(r, 'stat_start', side_effect=[1, 2, 3]):
            with self.assertRaisesRegex(ValueError, 'thread identity changed'):
                self.collector.process(os.getpid())

    def test_cli_does_not_overwrite_evidence(self):
        p = self.root / 'existing.json'
        p.write_text('immutable')
        command = [sys.executable, '-B', str(Path(r.__file__)), '--unit', 'example.service',
                   '--job-pid', str(os.getpid()), '--output', str(p)]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(p.read_text(), 'immutable')

    def test_mutating_scheduler_and_limit_apis_absent(self):
        tree = ast.parse(Path(r.__file__).read_text())
        forbidden = {'sched_setscheduler', 'sched_setparam', 'sched_setaffinity',
                     'setrlimit', 'execve', 'execv', 'system', 'setpriority', 'nice'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
                if node.func.attr == 'prlimit':
                    self.assertEqual(len(node.args), 2)
                    self.assertFalse(node.keywords)

    def test_all_systemd_commands_are_read_only_and_environment_filtered(self):
        self.helper('import os,sys,json\nprint(json.dumps({"argv":sys.argv[1:],'
                    '"keys":sorted(os.environ)}))\n')
        with patch.dict(os.environ, {'PRIVATE_CREDENTIAL_TEST': 'secret'}):
            for kind in ('version', 'unit', 'manager'):
                with self.subTest(kind=kind):
                    result = json.loads(self.collector.command(kind))
                    self.assertNotIn('PRIVATE_CREDENTIAL_TEST', result['keys'])
                    self.assertEqual(result['argv'][:2], ['--no-pager', '--no-ask-password'])
                    self.assertEqual(result['argv'][2], '--version' if kind == 'version' else 'show')

    def test_collector_does_not_replenish_mismatched_censuses(self):
        calls = []
        def census(row):
            calls.append(len(calls))
            f = facts()
            f['process_identity'] = len(calls)
            row.update(facts=f, errors=[])
        with patch.object(self.collector, 'census', side_effect=census), \
                patch.object(self.collector, 'runtime_binding', return_value={'files': []}):
            result = self.collector.collect()
        self.assertEqual(calls, [0, 1])
        self.assertEqual(result['classification'], r.UNKNOWN)
        self.assertFalse(result['execution_admitted'])
        self.assertFalse(result['hosted_execution_ready'])


if __name__ == '__main__':
    unittest.main()
