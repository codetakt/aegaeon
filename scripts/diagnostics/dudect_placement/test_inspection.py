import copy
import contextlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import inspect_environment as inspect


def row():
    return {'start': 1, 'end': 2, 'properties': {'AllowedCPUs': '0-1'}, 'path': '/x',
            'cgroups': {'/x': {'cpuset.cpus': {'value': '0-1'}, 'cpuset.cpus.effective': {'value': '0-1'}}},
            'ancestors': {'/': {'cpuset.cpus.effective': {'value': '0-3'}}},
            'members': {'4': {'start': 10, 'threads': {'4': {'start': 10, 'cpus': [0, 1]}}}}}


class InspectionTests(unittest.TestCase):
    def test_explicit_is_read_compatibility_only(self):
        a, b = row(), row()
        b.update(start=3, end=4)
        self.assertEqual(inspect.classify([a, b], [0, 1, 2, 3])[0], 'EXPLICIT_CONSISTENT')

    def test_unset_retained(self):
        a = row()
        a['properties']['AllowedCPUs'] = ''
        a['cgroups']['/x']['cpuset.cpus']['value'] = ''
        self.assertEqual(inspect.classify([a, a], [0, 1])[0], 'INHERITED_UNSET')

    def test_missing_not_unset(self):
        a = row()
        a['properties']['AllowedCPUs'] = None
        a['cgroups']['/x']['cpuset.cpus']['value'] = ''
        self.assertEqual(inspect.classify([a, a], [0, 1])[0], 'MISMATCH_UNKNOWN_UNREADABLE')

    def test_requested_kernel_mismatch(self):
        a = row()
        a['cgroups']['/x']['cpuset.cpus']['value'] = ''
        self.assertEqual(inspect.classify([a, a], [0, 1])[0], 'MISMATCH_UNKNOWN_UNREADABLE')

    def test_changed_membership_or_identity(self):
        a, b = row(), row()
        b['members']['4']['start'] += 1
        self.assertEqual(inspect.classify([a, b], [0, 1])[0], 'MISMATCH_UNKNOWN_UNREADABLE')

    def test_ancestor_and_affinity_checks(self):
        for field in ('ancestor', 'thread'):
            a = row()
            if field == 'ancestor':
                a['ancestors']['/']['cpuset.cpus.effective']['value'] = '0'
            else:
                a['members']['4']['threads']['4']['cpus'] = [0, 3]
            self.assertEqual(inspect.classify([a, a], [0, 1, 2, 3])[0], 'MISMATCH_UNKNOWN_UNREADABLE')

    def test_mutating_subcommand_cannot_execute(self):
        with patch.object(inspect.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                inspect.command('systemctl', 'set-property', 'anything.service', 'AllowedCPUs=0')
            run.assert_not_called()


@contextlib.contextmanager
def tree(root_absent=True):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        child = root / 'unit.service'
        child.mkdir()
        values = {'cpuset.cpus': '0-1', 'cpuset.cpus.effective': '0-1',
                  'cpuset.mems': '0', 'cpuset.mems.effective': '0',
                  'cgroup.events': 'populated 1', 'cgroup.type': 'domain',
                  'cgroup.procs': '4', 'cgroup.threads': '4',
                  'cgroup.controllers': 'cpu cpuset', 'cgroup.subtree_control': 'cpu cpuset'}
        for directory in (root, child):
            for name, value in values.items():
                if directory == root and root_absent and name in inspect.ROOT_ABSENT:
                    continue
                (directory / name).write_text(value)
        original = inspect.read
        mount = f'1 0 0:1 / {root} rw - cgroup2 cgroup rw\n'.encode()
        def source(path, *args):
            if path == Path('/proc/self/mountinfo'):
                return mount
            return original(path, *args)
        with patch.object(inspect, 'CG', root), patch.object(inspect, 'read', side_effect=source):
            yield root, child


class RootCensusTests(unittest.TestCase):
    def test_C01_root_absent_interfaces_are_reasoned_na(self):
        with tree() as (root, _):
            record = inspect.cg_record(root)
            for name, reason in inspect.ROOT_ABSENT.items():
                self.assertEqual(record[name], {'not_applicable': reason})
            self.assertEqual(record['cpuset.cpus.effective'], {'value': '0-1'})
            self.assertIn('mountinfo', record['root_binding'])
            with patch.object(inspect, 'root_binding', side_effect=RuntimeError('bad mount')):
                with self.assertRaises(RuntimeError):
                    inspect.cg_record(root)

    def test_C02_root_actual_values_are_preserved(self):
        with tree(root_absent=False) as (root, _):
            record = inspect.cg_record(root)
            self.assertEqual(record['cgroup.events'], {'value': 'populated 1'})
            self.assertEqual(record['cgroup.type'], {'value': 'domain'})
            self.assertEqual(record['cpuset.cpus'], {'value': '0-1'})
            self.assertEqual(record['cpuset.mems'], {'value': '0'})

    def test_C03_nonroot_missing_events_fails(self):
        with tree() as (_, child):
            (child / 'cgroup.events').unlink()
            with self.assertRaises(FileNotFoundError):
                inspect.cg_record(child)

    def test_C04_nonroot_missing_type_fails(self):
        with tree() as (_, child):
            (child / 'cgroup.type').unlink()
            with self.assertRaises(FileNotFoundError):
                inspect.cg_record(child)

    def test_C05_root_permission_error_is_not_na(self):
        for name in ('cgroup.events', 'cgroup.type'):
            with self.subTest(name=name), tree() as (root, _):
                previous = inspect.read
                def denied(path, *args):
                    if path == root / name:
                        raise PermissionError('denied')
                    return previous(path, *args)
                with patch.object(inspect, 'read', side_effect=denied):
                    with self.assertRaises(PermissionError):
                        inspect.cg_record(root)

    def test_C06_root_missing_effective_cpus_fails(self):
        with tree() as (root, _):
            (root / 'cpuset.cpus.effective').unlink()
            with self.assertRaises(FileNotFoundError):
                inspect.cg_record(root)

    def test_C07_root_missing_effective_mems_fails(self):
        with tree() as (root, _):
            (root / 'cpuset.mems.effective').unlink()
            with self.assertRaises(FileNotFoundError):
                inspect.cg_record(root)

    def test_C08_census_through_root_reaches_classification(self):
        with tree() as (root, child):
            unit = 'unit.service'
            config = root / 'source.conf'
            config.write_text('[Service]\nAllowedCPUs=0-1\n')
            properties = {key: '' for key in inspect.PROPERTIES}
            properties.update(Id=unit, LoadState='loaded', ActiveState='active', InvocationID='fixed',
                              ControlGroup='/unit.service', AllowedCPUs='0-1', FragmentPath=str(config))
            with patch.object(inspect, 'props', return_value=properties), \
                 patch.object(inspect, 'proc', return_value=row()['members']['4']):
                records = [inspect.census(unit), inspect.census(unit)]
            partial = {}
            with patch.object(inspect, 'props', return_value=properties), \
                 patch.object(inspect, 'proc', side_effect=ProcessLookupError('vanished')):
                with self.assertRaises(ProcessLookupError):
                    inspect.census(unit, partial)
            self.assertEqual(partial['properties'], properties)
            self.assertEqual(partial['phase'], 'members')
            self.assertEqual(inspect.classify(records, [0, 1])[0], 'EXPLICIT_CONSISTENT')
            self.assertEqual(records[0]['ancestors'][str(root)]['cgroup.events'],
                             {'not_applicable': 'root_nonroot_interface_absent'})


if __name__ == '__main__':
    unittest.main()
