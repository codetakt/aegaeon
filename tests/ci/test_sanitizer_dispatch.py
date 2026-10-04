# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise sanitizer status preservation through the real security dispatcher."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_security_fuzz as fuzz_fixture

NIX = r"""
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
args = sys.argv[1:]
expected = ['develop', '.#asan', '--command', 'bash', 'scripts/sanitizers/run_sanitizers.sh']
sanitizer = args == expected
code = int(os.environ.get('SANITIZER_CHILD_EXIT' if sanitizer else 'SBOM_EXIT', '0'))
with (root / 'dispatch-calls.jsonl').open('a') as out:
    out.write(json.dumps({'kind': 'sanitizer' if sanitizer else 'nix-other',
                         'args': args, 'exit_code': code}) + '\n')
if sanitizer:
    directory = pathlib.Path(os.environ['SANITIZER_ARTIFACT_DIR'])
    (directory / 'child-receipt.json').write_text(json.dumps({'exit_code': code}))
    (directory / 'run-summary.json').write_text(json.dumps({
        'status': 'completed' if code == 0 else 'failed', 'exit_code': code,
        'commands': [{'phase': 'run', 'exit_code': code}],
        'units': [{'package': 'ffi', 'targets': [{'name': 'ffi', 'status':
                   'completed' if code == 0 else 'failed'}]}]}))
    if not os.environ.get('SANITIZER_UNSAFE_TARGET_TEST'):
        scratch = (root / (os.environ.get('SANITIZER_TARGET_DIR') or 'target/sanitizers')).resolve()
        scratch.mkdir(parents=True, exist_ok=True)
        (scratch / 'child-output').write_text('transient sanitizer output')
        swap = os.environ.get('SANITIZER_SWAP', '')
        external = pathlib.Path(os.environ.get('SANITIZER_EXTERNAL', root / 'unused-external'))
        if swap in ('target-symlink', 'target-directory'):
            scratch.rename(scratch.with_name(scratch.name + '.held'))
            if swap == 'target-symlink':
                scratch.symlink_to(external, target_is_directory=True)
            else:
                scratch.mkdir()
                (scratch / 'replacement-sentinel').write_text('preserve replacement')
        elif swap == 'ancestor-symlink':
            scratch.parent.rename(scratch.parent.with_name(scratch.parent.name + '.held'))
            scratch.parent.symlink_to(external, target_is_directory=True)
        elif swap == 'nested-symlink':
            (scratch / 'nested-link').symlink_to(external, target_is_directory=True)
        elif swap == 'evidence-symlink':
            directory.rename(directory.with_name(directory.name + '.held'))
            directory.symlink_to(external, target_is_directory=True)
        elif swap == 'evidence-ancestor':
            directory.parent.rename(directory.parent.with_name(directory.parent.name + '.held'))
            directory.parent.symlink_to(external, target_is_directory=True)
    print('sanitizer child diagnostic: SUCCESS! exit=' + str(code))
else:
    print('optional SBOM fixture exit=' + str(code))
raise SystemExit(code)
"""

PYTHON = r"""
import json, os, pathlib, sys
arguments = sys.argv[1:]
if arguments[:1] == ['-I']:
    arguments = arguments[1:]
if len(arguments) > 1 and arguments[1] == 'open-exec-bound':
    mode = os.environ.get('SANITIZER_OPENER_RECOVERY_UNAVAILABLE', '')
    if mode:
        bash = pathlib.Path(os.environ['FIXTURE_ROOT']).parent / 'bin/bash'
        bash.unlink()
        if mode == 'exec-failure':
            bash.write_text('#!/nonexistent-security-recovery-interpreter\n')
            bash.chmod(0o755)
if arguments[:2] == ['-', 'cleanup']:
    root = pathlib.Path(os.environ['FIXTURE_ROOT'])
    target = json.loads(arguments[2])['target']
    code = int(os.environ.get('SANITIZER_CLEANUP_EXIT', '0'))
    with (root / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'cleanup', 'args': ['fd-relative', '--', target],
                             'exit_code': code}) + '\n')
    if code:
        print('sanitizer cleanup failed with exit=' + str(code), file=sys.stderr)
        raise SystemExit(code)
os.execv(sys.executable, [sys.executable] + sys.argv[1:])
"""

HANDOFF_BASH = r"""
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
if (sys.argv[1:2] == [str(root / 'scripts/security/run_security_suite.sh')]
        and 'SANITIZER_SECURITY_LOG_FD' in os.environ):
    evidence = pathlib.Path(os.environ['SANITIZER_ARTIFACT_DIR'])
    target = pathlib.Path(os.environ['SANITIZER_VALIDATED_TARGET'])
    original = (evidence / 'run-summary.json').read_text()
    with (root / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'handoff', 'evidence': str(evidence),
            'evidence_binding': os.environ['SANITIZER_EVIDENCE_BINDING'],
            'target': str(target), 'cleanup_binding': os.environ['SANITIZER_CLEANUP_BINDING'],
            'summary': original}) + '\n')
    receipt = os.environ.get('SANITIZER_HANDOFF_RECEIPT', '')
    summary = evidence / 'run-summary.json'
    if receipt == 'detailed':
        summary.write_text(json.dumps({'status': os.environ['SANITIZER_HANDOFF_RECEIPT_STATUS'],
            'commands': [{'phase': 'run', 'exit_code': 71}],
            'units': [{'package': 'ffi', 'targets': [{'name': 'ffi', 'status': 'failed'}]}]}))
    elif receipt:
        summary.rename(summary.with_name(summary.name + '.held'))
        if receipt == 'replacement-initial':
            summary.write_text(original)
        elif receipt == 'summary-symlink':
            summary.symlink_to(pathlib.Path(os.environ['SANITIZER_EXTERNAL']) / 'run-summary.json')
        else:
            summary.mkdir()
            (summary / 'replacement-sentinel').write_bytes(b'preserve replacement\n')
    swap = os.environ.get('SANITIZER_HANDOFF_SWAP', '')
    if swap:
        external = pathlib.Path(os.environ['SANITIZER_EXTERNAL'])
        route = (evidence.parent if swap.startswith('artifact-') else
                 evidence.parent / 'summary' if swap.startswith('log-') else evidence)
        route.rename(route.with_name(route.name + '.held'))
        if swap.endswith('symlink'):
            route.symlink_to(external, target_is_directory=True)
        elif swap.endswith('file'):
            route.write_bytes(b'preserve replacement\n')
        else:
            route.mkdir()
            (route / 'replacement-sentinel').write_bytes(b'preserve replacement\n')
    swap = os.environ.get('SANITIZER_HANDOFF_TARGET_SWAP', '')
    if swap:
        route = target.parent if swap == 'ancestor-symlink' else target
        route.rename(route.with_name(route.name + '.held'))
        if swap.endswith('symlink'):
            route.symlink_to(os.environ['SANITIZER_EXTERNAL'], target_is_directory=True)
        else:
            route.mkdir()
            (route / 'replacement-sentinel').write_bytes(b'preserve replacement\n')
    for setting, destination in (
            ('SANITIZER_HANDOFF_FLAGS', 'SANITIZER_CARGO_FLAGS'),
            ('SANITIZER_HANDOFF_MARKER', 'SANITIZER_EVIDENCE_ROUTE_CHANGED')):
        if setting in os.environ:
            os.environ[destination] = os.environ[setting]
os.execv(ACTUAL_BASH, [ACTUAL_BASH] + sys.argv[1:])
"""

RM = r"""
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
workspace = root.resolve()
artifacts = (root / os.environ['SECURITY_ARTIFACT_DIR']).resolve()
recursive = any(arg == '--recursive' or
                (arg.startswith('-') and not arg.startswith('--') and 'r' in arg[1:])
                for arg in args)
for arg in args:
    if arg.startswith('-'):
        continue
    resolved = (root / arg).resolve()
    if resolved == workspace or resolved in workspace.parents:
        with (root / 'dispatch-calls.jsonl').open('a') as out:
            out.write(json.dumps({'kind': 'unsafe-cleanup', 'args': args,
                                 'exit_code': 83}) + '\n')
        print('intercepted dangerous cleanup; no deletion delegated', file=sys.stderr)
        raise SystemExit(83)
    overlaps = (resolved == artifacts or resolved in artifacts.parents
                or artifacts in resolved.parents)
    if recursive and overlaps:
        with (root / 'dispatch-calls.jsonl').open('a') as out:
            out.write(json.dumps({'kind': 'artifact-overlap-cleanup', 'args': args,
                                 'exit_code': 84}) + '\n')
        print('intercepted artifact overlap; no deletion delegated', file=sys.stderr)
        raise SystemExit(84)
target = str((root / (os.environ.get('SANITIZER_TARGET_DIR') or 'target/sanitizers')).resolve())
if target in args:
    root = pathlib.Path(os.environ['FIXTURE_ROOT'])
    code = int(os.environ.get('SANITIZER_CLEANUP_EXIT', '0'))
    with (root / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'cleanup', 'args': args, 'exit_code': code}) + '\n')
    if code:
        print('sanitizer cleanup failed with exit=' + str(code), file=sys.stderr)
        raise SystemExit(code)
os.execv(ACTUAL_RM, [ACTUAL_RM] + args)
"""

TEE = r"""
import os, pathlib, subprocess, sys
text = sys.stdin.read()
marker = os.environ.get('SANITIZER_LOG_FAILURE', '')
if marker and marker in text:
    print('controlled sanitizer log write failure', file=sys.stderr)
    raise SystemExit(74)
fds = tuple(int(arg.rsplit('/', 1)[1]) for arg in sys.argv[1:] if arg.startswith('/proc/self/fd/'))
code = subprocess.run(
    [ACTUAL_TEE] + sys.argv[1:], input=text, text=True, pass_fds=fds).returncode
swap = os.environ.get('SANITIZER_INITIAL_EVIDENCE_SWAP', '')
if code == 0 and swap and 'starting security suite' in text:
    evidence = pathlib.Path(os.environ['SECURITY_ARTIFACT_DIR']) / 'sanitizers'
    external = pathlib.Path(os.environ['SANITIZER_EXTERNAL'])
    if swap == 'ancestor-symlink':
        evidence.parent.rename(evidence.parent.with_name(evidence.parent.name + '.held'))
        evidence.parent.symlink_to(external, target_is_directory=True)
    else:
        evidence.rename(evidence.with_name(evidence.name + '.held'))
        if swap == 'leaf-symlink':
            evidence.symlink_to(external, target_is_directory=True)
        else:
            evidence.mkdir()
            (evidence / 'replacement-sentinel').write_bytes(b'preserve replacement\n')
raise SystemExit(code)
"""

MKDIR = r"""
import os, pathlib, subprocess, sys
if (os.environ.get('SANITIZER_RESUMED_HOME_FAILURE')
        and os.environ.get('SANITIZER_SECURITY_LOG_FD')
        and os.environ['CARGO_HOME'] in sys.argv[1:]):
    print('controlled resumed Cargo home directory failure', file=sys.stderr)
    raise SystemExit(76)
summary = str(pathlib.Path(os.environ['SECURITY_ARTIFACT_DIR']) / 'summary')
if os.environ.get('SANITIZER_MKDIR_FAILURE') and summary in sys.argv[1:]:
    print('controlled shared log directory failure', file=sys.stderr)
    raise SystemExit(76)
external = os.environ.get('SANITIZER_OPENER_LOG_SYMLINK', '')
if external and summary in sys.argv[1:]:
    code = subprocess.run([ACTUAL_MKDIR] + sys.argv[1:]).returncode
    if code == 0:
        (pathlib.Path(summary) / 'security.log').symlink_to(external)
    raise SystemExit(code)
os.execv(ACTUAL_MKDIR, [ACTUAL_MKDIR] + sys.argv[1:])
"""

VET = r"""
import json, os, pathlib, sys
if sys.argv[1:2] == ['vet']:
    code = int(os.environ.get('VET_EXIT', '0'))
    with (pathlib.Path(os.environ['FIXTURE_ROOT']) / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'vet', 'exit_code': code}) + '\n')
    print('optional cargo vet fixture exit=' + str(code))
    raise SystemExit(code)
"""

PRE_SANITIZER_CARGO = r"""
import json, os, pathlib, sys
args = sys.argv[1:]
stage = os.environ.get('SANITIZER_PRE_STAGE', '')
selected = (
    (stage == 'supply-chain' and args[:2] == ['deny', 'check']) or
    (stage == 'runtime-tests' and args[:4] == ['test', '-p', 'aegaeon-server', 'transport']) or
    (stage == 'jose-boundaries' and
     args[:5] == ['test', '-p', 'aegaeon-jose', '--test', 'tlv_parity'])
)
if selected:
    root = pathlib.Path(os.environ['FIXTURE_ROOT'])
    evidence = pathlib.Path(os.environ['SANITIZER_ARTIFACT_DIR'])
    target = pathlib.Path(os.environ['SANITIZER_VALIDATED_TARGET'])
    code = int(os.environ['SANITIZER_PRE_STAGE_EXIT'])
    with (root / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'pre-sanitizer-stage', 'stage': stage,
            'args': args, 'exit_code': code,
            'initial_summary': (evidence / 'run-summary.json').read_text()}) + '\n')
    swap = os.environ.get('SANITIZER_PRE_STAGE_SWAP', '')
    if swap:
        route = target if swap.startswith('target-') else evidence
        route.rename(route.with_name(route.name + '.held'))
        if swap.endswith('symlink'):
            route.symlink_to(os.environ['SANITIZER_EXTERNAL'], target_is_directory=True)
        else:
            route.mkdir()
            (route / 'replacement-sentinel').write_bytes(b'preserve replacement\n')
    print('controlled blocking stage exit=' + str(code))
    raise SystemExit(code)
"""


class SanitizerDispatchTests(unittest.TestCase):
    def fixture(self, *, full_fuzz=False, intercept_tee=True):
        fixture = fuzz_fixture.SecurityFuzzTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        # Individual sanitizer controls retain aggregate dispatch with one local
        # fuzz target; dedicated composition controls require all seven.
        fixture.env["FUZZ_TARGETS"] = " ".join(
            fuzz_fixture.TARGETS if full_fuzz else fuzz_fixture.TARGETS[:1]
        )
        # Aggregate dispatch runs fuzz preflight with controlled fixture tools.
        # Remove inherited native target overrides, retaining the fixture's
        # explicit CC/CXX/AR and owned CARGO_TARGET_DIR from SecurityFuzzFixture.
        for name in tuple(fixture.env):
            if name != "CARGO_TARGET_DIR" and name.startswith(
                (
                    "CC_",
                    "CXX_",
                    "AR_",
                    "CARGO_TARGET_",
                    "TARGET_CC",
                    "TARGET_CXX",
                    "TARGET_AR",
                    "HOST_CC",
                    "HOST_CXX",
                    "HOST_AR",
                )
            ):
                fixture.env.pop(name)
        fixture.env.pop("SANITIZER_TARGET_DIR", None)
        fixture.env.pop("SANITIZER_UNSAFE_TARGET_TEST", None)
        fixture.install("nix", NIX)
        fixture.install("python3", PYTHON)
        fixture.install("rm", "ACTUAL_RM = " + repr(shutil.which("rm")) + "\n" + RM)
        if intercept_tee:
            fixture.install("tee", "ACTUAL_TEE = " + repr(shutil.which("tee")) + "\n" + TEE)
        fixture.install("mkdir", "ACTUAL_MKDIR = " + repr(shutil.which("mkdir")) + "\n" + MKDIR)
        fixture.install("cargo", VET + fuzz_fixture.CARGO)
        return fixture

    def run_suite(self, fixture, *, aggregate=False, case="ok", stages=None, **environment):
        args = [] if aggregate else ["--stage", "sanitizers"]
        if stages is not None:
            args = [value for stage in stages for value in ("--stage", stage)]
        result = subprocess.run(  # noqa: S603 - real wrapper with controlled fixture tools
            [
                str(fixture.bin / "bash"),
                str(fixture.root / "scripts/security/run_security_suite.sh"),
                *args,
            ],
            cwd=fixture.root,
            env={**fixture.env, "CASE": case, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if aggregate:
            evidence = fixture.artifacts
            if evidence.is_symlink():
                evidence = evidence.with_name(evidence.name + ".held")
            summary = evidence / "fuzz/run_summary.json"
            selected = fixture.env["FUZZ_TARGETS"].split()
            if result.returncode == 0 or selected == list(fuzz_fixture.TARGETS):
                self.assertTrue(summary.is_file(), result.stdout + result.stderr)
            if summary.is_file():
                execution = json.loads(summary.read_text())["execution"]
                self.assertEqual(execution["required_targets"], list(fuzz_fixture.TARGETS))
                self.assertEqual(execution["selected_targets"], selected)
                self.assertEqual(
                    execution["coverage"],
                    "full" if selected == list(fuzz_fixture.TARGETS) else "local-subset",
                )
        return result

    def calls(self, fixture, kind):
        path = fixture.root / "dispatch-calls.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [row for row in rows if row["kind"] == kind]

    def install_handoff_wrapper(self, fixture):
        fixture.install("bash", "ACTUAL_BASH = " + repr(shutil.which("bash")) + "\n" + HANDOFF_BASH)

    def receipt(self, fixture):
        return json.loads((fixture.artifacts / "sanitizers/child-receipt.json").read_text())

    def target_directory(self, fixture, setting):
        if setting == "absolute":
            return str(Path(fixture.temporary) / "custom sanitizer outputs")
        if setting == "symlink":
            directory = Path(fixture.temporary) / "resolved sanitizer outputs"
            directory.mkdir()
            (fixture.root / "sanitizer-link").symlink_to(directory, target_is_directory=True)
            return "sanitizer-link"
        return setting

    def unsafe_target_directory(self, fixture, setting):
        if setting in ("workspace-absolute", "parent-absolute"):
            directory = fixture.root if setting == "workspace-absolute" else fixture.root.parent
            return str(directory)
        if setting in ("workspace-symlink", "parent-symlink"):
            destination = fixture.root if setting == "workspace-symlink" else fixture.root.parent
            link = fixture.root / setting
            link.symlink_to(destination, target_is_directory=True)
            return setting
        return setting

    def artifact_target_directory(self, fixture, setting):
        artifact_name = "retained artifacts/security evidence\n"
        fixture.artifacts = fixture.root / artifact_name
        # Resolve the same relative/absolute artifact semantics as ARTIFACT_BASE.
        fixture.env["SECURITY_ARTIFACT_DIR"] = artifact_name
        fixture.artifacts.mkdir(parents=True)
        destinations = {
            "root": fixture.artifacts,
            "descendant": fixture.artifacts / "sanitizers",
            "ancestor": fixture.artifacts.parent,
            "absolute-artifacts": fixture.artifacts / "sanitizers",
        }
        aliases = {
            "root-symlink": fixture.artifacts,
            "ancestor-symlink": fixture.artifacts.parent,
            "descendant-symlink": fixture.artifacts / "sanitizers",
        }
        if setting in destinations:
            target = str(destinations[setting])
            if setting == "absolute-artifacts":
                fixture.env["SECURITY_ARTIFACT_DIR"] = str(fixture.artifacts)
        elif setting == "normalized":
            target = artifact_name + "/missing-parent/.."
        elif setting in aliases:
            destination = aliases[setting]
            destination.mkdir(parents=True, exist_ok=True)
            (fixture.root / setting).symlink_to(destination, target_is_directory=True)
            target = setting
        elif setting == "artifact-symlink":
            (fixture.root / "artifact-alias").symlink_to(
                fixture.artifacts, target_is_directory=True
            )
            fixture.env["SECURITY_ARTIFACT_DIR"] = "artifact-alias"
            target = str(fixture.artifacts)
        else:
            raise ValueError(setting)
        return target

    def seed_retained_evidence(self, fixture):
        files = {
            "sanitizers/run-summary.json": '{"status": "retained"}',
            "sanitizers/raw.stderr.log": "retained sanitizer raw diagnostic",
            "prior-stage/raw.log": "retained earlier-stage evidence",
        }
        for path, text in files.items():
            destination = fixture.artifacts / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
        return files

    def pre_sanitizer_failure_fixture(self):
        fixture = self.fixture()
        fixture.install("cargo", PRE_SANITIZER_CARGO + fuzz_fixture.CARGO)
        target = fixture.root / "target/sanitizers"
        target.mkdir(parents=True)
        (target / "prepared-sentinel").write_bytes(b"prepared sanitizer output\n")
        self.seed_retained_evidence(fixture)
        return fixture, target

    def test_blocking_stage_failure_cleans_prepared_target_and_preserves_primary(self):
        for stage, aggregate in (
            ("supply-chain", True),
            ("runtime-tests", False),
            ("jose-boundaries", False),
        ):
            with self.subTest(stage=stage, aggregate=aggregate):
                fixture, target = self.pre_sanitizer_failure_fixture()
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    stages=None if aggregate else (stage, "sanitizers"),
                    SANITIZER_PRE_STAGE=stage,
                    SANITIZER_PRE_STAGE_EXIT="67",
                )
                self.assertEqual(result.returncode, 67, result.stdout + result.stderr)
                self.assertTrue(self.calls(fixture, "pre-sanitizer-stage"))
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "nix-other"), [])
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                self.assertFalse(target.exists())
                evidence = fixture.artifacts / "sanitizers"
                summary = json.loads((evidence / "run-summary.json").read_text())
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["exit_code"], 67)
                self.assertEqual(summary["cleanup_exit_code"], 0)
                prior = list(evidence.glob(".previous-attempt-*/run-summary.json"))
                self.assertEqual(len(prior), 1)
                self.assertEqual(prior[0].read_text(), '{"status": "retained"}')
                self.assertEqual(
                    (evidence / "raw.stderr.log").read_text(),
                    "retained sanitizer raw diagnostic",
                )

    def test_blocking_stage_cleanup_failure_keeps_primary_and_prepared_output(self):
        fixture, target = self.pre_sanitizer_failure_fixture()
        result = self.run_suite(
            fixture,
            stages=("supply-chain", "sanitizers"),
            SANITIZER_PRE_STAGE="supply-chain",
            SANITIZER_PRE_STAGE_EXIT="67",
            SANITIZER_CLEANUP_EXIT="79",
        )
        self.assertEqual(result.returncode, 67, result.stdout + result.stderr)
        self.assertEqual(self.calls(fixture, "sanitizer"), [])
        self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
        self.assertEqual(
            (target / "prepared-sentinel").read_bytes(), b"prepared sanitizer output\n"
        )
        summary = json.loads((fixture.artifacts / "sanitizers/run-summary.json").read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["exit_code"], 67)
        self.assertEqual(summary["cleanup_exit_code"], 79)

    def test_blocking_stage_replaced_target_is_preserved_during_exit_cleanup(self):
        for swap in ("target-directory", "target-symlink"):
            with self.subTest(swap=swap):
                fixture, target = self.pre_sanitizer_failure_fixture()
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinel = external / "external-sentinel"
                sentinel.write_bytes(b"preserve external output\n")
                result = self.run_suite(
                    fixture,
                    stages=("supply-chain", "sanitizers"),
                    SANITIZER_PRE_STAGE="supply-chain",
                    SANITIZER_PRE_STAGE_EXIT="67",
                    SANITIZER_PRE_STAGE_SWAP=swap,
                    SANITIZER_EXTERNAL=str(external),
                )
                self.assertEqual(result.returncode, 67, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(
                    len(self.calls(fixture, "cleanup")), int(swap == "target-directory")
                )
                held = target.with_name(target.name + ".held")
                self.assertEqual(
                    (held / "prepared-sentinel").read_bytes(), b"prepared sanitizer output\n"
                )
                self.assertEqual(sentinel.read_bytes(), b"preserve external output\n")
                if swap == "target-directory":
                    self.assertEqual(list(target.iterdir()), [target / "replacement-sentinel"])
                else:
                    self.assertTrue(target.is_symlink())
                summary = json.loads(
                    (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                )
                self.assertEqual(summary["status"], "failed")
                if swap == "target-directory":
                    self.assertEqual(summary["exit_code"], 67)
                    self.assertNotEqual(summary["cleanup_exit_code"], 0)
                else:
                    # Route admission rejects the alias before cleanup or a
                    # replacement receipt can claim a completed recovery.
                    self.assertEqual(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text(),
                        self.calls(fixture, "pre-sanitizer-stage")[0]["initial_summary"],
                    )
                    self.assertNotIn("cleanup_exit_code", summary)

    def test_blocking_stage_replaced_evidence_keeps_bytes_and_cleans_unchanged_target(self):
        for swap in ("evidence-directory", "evidence-symlink"):
            with self.subTest(swap=swap):
                fixture, target = self.pre_sanitizer_failure_fixture()
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinel = external / "external-sentinel"
                sentinel.write_bytes(b"preserve external evidence\n")
                result = self.run_suite(
                    fixture,
                    stages=("supply-chain", "sanitizers"),
                    SANITIZER_PRE_STAGE="supply-chain",
                    SANITIZER_PRE_STAGE_EXIT="67",
                    SANITIZER_PRE_STAGE_SWAP=swap,
                    SANITIZER_EXTERNAL=str(external),
                )
                self.assertEqual(result.returncode, 67, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                self.assertFalse(target.exists())
                evidence = fixture.artifacts / "sanitizers"
                held = evidence.with_name(evidence.name + ".held")
                self.assertEqual(
                    (held / "run-summary.json").read_text(),
                    self.calls(fixture, "pre-sanitizer-stage")[0]["initial_summary"],
                )
                self.assertEqual(sentinel.read_bytes(), b"preserve external evidence\n")
                if swap == "evidence-directory":
                    self.assertEqual(list(evidence.iterdir()), [evidence / "replacement-sentinel"])
                else:
                    self.assertTrue(evidence.is_symlink())
                    self.assertEqual(list(external.iterdir()), [sentinel])

    def test_artifact_overlap_cleanup_is_rejected_and_all_evidence_is_preserved(self):
        for setting in (
            "root",
            "descendant",
            "ancestor",
            "normalized",
            "root-symlink",
            "ancestor-symlink",
            "descendant-symlink",
            "artifact-symlink",
            "absolute-artifacts",
        ):
            with self.subTest(setting=setting):
                fixture = self.fixture()
                target = self.artifact_target_directory(fixture, setting)
                retained = self.seed_retained_evidence(fixture)
                result = self.run_suite(fixture, SANITIZER_TARGET_DIR=target)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                for path, text in retained.items():
                    if path != "sanitizers/run-summary.json" or setting == "artifact-symlink":
                        self.assertEqual((fixture.artifacts / path).read_text(), text)
                if setting != "artifact-symlink":
                    summary = json.loads(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                    )
                    self.assertEqual(summary["status"], "failed")
                    old = (
                        fixture.artifacts
                        / "sanitizers"
                        / summary["previous_attempt"]
                        / "run-summary.json"
                    )
                    self.assertEqual(old.read_text(), retained["sanitizers/run-summary.json"])

    def test_history_overlap_refuses_launch_and_cleanup_without_history_loss(self):
        for aggregate in (False, True):
            for relation in ("equal", "ancestor", "descendant", "normalized", "relative", "alias"):
                with self.subTest(aggregate=aggregate, relation=relation):
                    fixture = self.fixture()
                    history = (
                        (fixture.root if relation == "relative" else fixture.root.parent)
                        / "retained-history"
                        / "runs\n"
                    )
                    history.mkdir(parents=True)
                    retained = history / "previous-run.json"
                    raw = b'{"status":"retained","run":"prior"}\n'
                    retained.write_bytes(raw)
                    history_route = str(history)
                    target = {
                        "equal": str(history),
                        "ancestor": str(history.parent),
                        "descendant": str(history / "child"),
                        "normalized": str(history) + "/missing/..",
                        "relative": os.path.relpath(history, fixture.root),
                        "alias": str(history),
                    }[relation]
                    if relation == "relative":
                        history_route = os.path.relpath(history, fixture.root)
                    elif relation == "alias":
                        alias = fixture.root / "history-alias"
                        alias.symlink_to(history, target_is_directory=True)
                        history_route = str(alias)
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SECURITY_HISTORY_DIR=history_route,
                        SANITIZER_TARGET_DIR=target,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.calls(fixture, "sanitizer"), [])
                    self.assertEqual(self.calls(fixture, "cleanup"), [])
                    self.assertEqual(retained.read_bytes(), raw)
                    self.assertEqual(list(history.iterdir()), [retained])

    def test_history_prefix_sibling_allows_cleanup_and_preserves_history(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                history = fixture.root / "history"
                history.mkdir()
                retained = history / "previous-run.json"
                retained.write_bytes(b"retained history\n")
                target = history.with_name("history-build")
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    SECURITY_HISTORY_DIR=os.path.relpath(history, fixture.root),
                    SANITIZER_TARGET_DIR=str(target),
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(self.calls(fixture, "sanitizer")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                self.assertFalse(target.exists())
                self.assertEqual(retained.read_bytes(), b"retained history\n")

    def test_sibling_target_cleanup_preserves_retained_evidence(self):
        for aggregate in (False, True):
            for child in (0, 71):
                with self.subTest(aggregate=aggregate, child=child):
                    fixture = self.fixture()
                    self.artifact_target_directory(fixture, "root")
                    retained = self.seed_retained_evidence(fixture)
                    # Preserve similarly named artifact root ending in a newline.
                    target = str(fixture.artifacts).rstrip("\n")
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_TARGET_DIR=target,
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], child)
                    self.assertFalse(Path(target).exists())
                    self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                    self.assertEqual(self.calls(fixture, "artifact-overlap-cleanup"), [])
                    for path, text in retained.items():
                        if path == "sanitizers/run-summary.json":
                            histories = list(
                                (fixture.artifacts / "sanitizers").glob(
                                    ".previous-attempt-*/run-summary.json"
                                )
                            )
                            self.assertTrue(
                                any(previous.read_text() == text for previous in histories)
                            )
                        else:
                            self.assertEqual((fixture.artifacts / path).read_text(), text)
                    self.assertTrue((fixture.artifacts / "summary/security.log").is_file())

    def test_unsafe_target_cleanup_is_rejected_without_removal(self):
        for setting in (
            ".",
            "workspace-absolute",
            "..",
            "parent-absolute",
            "/",
            "workspace-symlink",
            "parent-symlink",
            "missing-parent/..",
            "missing-parent/../..",
        ):
            with self.subTest(setting=setting):
                fixture = self.fixture()
                target = self.unsafe_target_directory(fixture, setting)
                marker = fixture.root / "workspace-marker"
                marker.write_text("preserve checkout")
                parent_marker = fixture.root.parent / "parent-marker"
                parent_marker.write_text("preserve parent")
                result = self.run_suite(fixture, SANITIZER_TARGET_DIR=target)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                self.assertEqual(marker.read_text(), "preserve checkout")
                self.assertEqual(parent_marker.read_text(), "preserve parent")

    def test_configured_target_cleanup_preserves_unrelated_directories(self):
        for aggregate in (False, True):
            for setting in (
                None,
                "",
                "target/sanitizers",
                "custom sanitizer outputs",
                "absolute",
                "missing-parent/../normalized outputs",
                "-custom",
            ):
                with self.subTest(aggregate=aggregate, setting=setting):
                    fixture = self.fixture(intercept_tee=False)
                    target = self.target_directory(fixture, setting)
                    default = fixture.root / "target/sanitizers"
                    if target and target != "target/sanitizers":
                        default.mkdir(parents=True)
                        (default / "unrelated-output").write_text("keep default directory")
                    unrelated = fixture.root / "target/unrelated-output"
                    unrelated.parent.mkdir(parents=True, exist_ok=True)
                    unrelated.write_text("keep unrelated output")
                    environment = {} if target is None else {"SANITIZER_TARGET_DIR": target}
                    result = self.run_suite(fixture, aggregate=aggregate, **environment)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                    expected = str((fixture.root / (target or "target/sanitizers")).resolve())
                    cleanup = self.calls(fixture, "cleanup")
                    self.assertEqual(len(cleanup), 1)
                    self.assertEqual(cleanup[0]["args"], ["fd-relative", "--", expected])
                    self.assertFalse(Path(expected).exists())
                    if setting == "symlink":
                        self.assertTrue((fixture.root / target).is_symlink())
                    self.assertEqual(unrelated.read_text(), "keep unrelated output")
                    if target and target != "target/sanitizers":
                        self.assertEqual(
                            (default / "unrelated-output").read_text(), "keep default directory"
                        )

    def test_trailing_newline_target_cleanup_preserves_similarly_named_sibling(self):
        for aggregate in (False, True):
            for suffix in ("\n", "\n\n"):
                with self.subTest(aggregate=aggregate, suffix=suffix):
                    fixture = self.fixture()
                    target = "custom sanitizer outputs" + suffix
                    sibling = fixture.root / target.rstrip("\n")
                    sibling.mkdir()
                    preserved = sibling / "unrelated-output"
                    preserved.write_text("keep similarly named sibling")
                    result = self.run_suite(
                        fixture, aggregate=aggregate, SANITIZER_TARGET_DIR=target
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                    self.assertEqual(preserved.read_text(), "keep similarly named sibling")
                    expected = str((fixture.root / target).resolve())
                    cleanup = self.calls(fixture, "cleanup")
                    self.assertEqual(len(cleanup), 1)
                    self.assertEqual(cleanup[0]["args"], ["fd-relative", "--", expected])
                    self.assertFalse(Path(expected).exists())

    def test_custom_target_failure_codes_and_outputs_are_preserved(self):
        for aggregate in (False, True):
            for setting in ("custom sanitizer outputs", "absolute", "newline outputs\n"):
                for child, cleanup in ((71, 0), (71, 79), (0, 79)):
                    with self.subTest(
                        aggregate=aggregate, setting=setting, child=child, cleanup=cleanup
                    ):
                        fixture = self.fixture(intercept_tee=False)
                        target = self.target_directory(fixture, setting)
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_TARGET_DIR=target,
                            SANITIZER_CHILD_EXIT=str(child),
                            SANITIZER_CLEANUP_EXIT=str(cleanup),
                        )
                        self.assertEqual(
                            result.returncode, child or cleanup, result.stdout + result.stderr
                        )
                        self.assertEqual(self.receipt(fixture)["exit_code"], child)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                        output = fixture.root / target / "child-output"
                        self.assertEqual(output.exists(), cleanup != 0)
                        if cleanup:
                            self.assertEqual(output.read_text(), "transient sanitizer output")

    def test_resolution_failure_preserves_outputs_and_child_status(self):
        for aggregate in (False, True):
            for child in (0, 71):
                with self.subTest(aggregate=aggregate, child=child):
                    fixture = self.fixture()
                    fixture.install(
                        "python3",
                        "import sys\n"
                        "if sys.argv[1:4] == ['-I', '-', 'cleanup']:\n"
                        "    raise SystemExit(81)\n" + PYTHON,
                    )
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_TARGET_DIR="custom sanitizer outputs",
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child or 81, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], child)
                    self.assertEqual(self.calls(fixture, "cleanup"), [])
                    self.assertTrue(
                        (fixture.root / "custom sanitizer outputs/child-output").is_file()
                    )

    def test_selected_and_aggregate_success_preserve_artifacts_after_cleanup(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture(full_fuzz=True)
                result = self.run_suite(fixture, aggregate=aggregate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(len(self.calls(fixture, "sanitizer")), 1)
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                self.assertFalse((fixture.root / "target/sanitizers").exists())
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertEqual(log.count("<<< sanitizer smoke: ok"), 1)
                self.assertNotIn("sanitizer cleanup: failed", log)

    def test_child_failure_code_survives_successful_or_failed_cleanup(self):
        for aggregate in (False, True):
            for cleanup in (0, 79):
                with self.subTest(aggregate=aggregate, cleanup=cleanup):
                    fixture = self.fixture()
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_CHILD_EXIT="71",
                        SANITIZER_CLEANUP_EXIT=str(cleanup),
                    )
                    self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 71)
                    self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                    self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                    self.assertEqual((fixture.root / "target/sanitizers").exists(), cleanup != 0)
                    log = (fixture.artifacts / "summary/security.log").read_text()
                    self.assertNotIn("<<< sanitizer smoke: ok", log)
                    self.assertIn("sanitizer smoke: failed (exit=71)", log)
                    summary = json.loads(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                    )
                    self.assertEqual(summary["exit_code"], 71)
                    self.assertEqual(summary["commands"], [{"phase": "run", "exit_code": 71}])
                    self.assertEqual(
                        summary["units"],
                        [{"package": "ffi", "targets": [{"name": "ffi", "status": "failed"}]}],
                    )
                    self.assertNotIn("logging_exit_code", summary)
                    if cleanup:
                        self.assertIn(f"sanitizer cleanup: failed (exit={cleanup})", log)
                        self.assertEqual(summary["preflight_phase"], "cleanup")
                        self.assertEqual(summary["cleanup_exit_code"], cleanup)
                    else:
                        self.assertNotIn("preflight_phase", summary)
                        self.assertNotIn("cleanup_exit_code", summary)

    def test_cleanup_failure_blocks_a_successful_child(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(fixture, aggregate=aggregate, SANITIZER_CLEANUP_EXIT="79")
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
                self.assertTrue((fixture.root / "target/sanitizers/child-output").is_file())
                summary = json.loads(
                    (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                )
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["exit_code"], 79)
                self.assertEqual(summary["cleanup_exit_code"], 79)
                self.assertEqual(summary["commands"], [{"phase": "run", "exit_code": 0}])
                self.assertEqual(
                    summary["units"],
                    [{"package": "ffi", "targets": [{"name": "ffi", "status": "completed"}]}],
                )
                self.assertNotIn("logging_exit_code", summary)
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertNotIn("<<< sanitizer smoke: ok", log)
                self.assertIn("sanitizer cleanup: failed (exit=79)", log)

    def test_failed_cleanup_diagnostic_write_preserves_cleanup_status(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    SANITIZER_CLEANUP_EXIT="79",
                    SANITIZER_LOG_FAILURE="<<< sanitizer cleanup: failed",
                )
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
                self.assertTrue((fixture.root / "target/sanitizers/child-output").is_file())
                summary = json.loads(
                    (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                )
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["exit_code"], 79)
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertNotIn("<<< sanitizer smoke: ok", log)

    def test_artifact_directory_failure_does_not_launch_the_child(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                fixture.artifacts.mkdir()
                (fixture.artifacts / "sanitizers").write_text("not a directory")
                result = self.run_suite(fixture, aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual((fixture.artifacts / "sanitizers").read_text(), "not a directory")

    def test_entry_and_completion_log_write_failures_are_blocking(self):
        for aggregate in (False, True):
            for marker, launched in (
                (">>> sanitizer smoke", False),
                ("<<< sanitizer smoke: ok", True),
            ):
                with self.subTest(aggregate=aggregate, marker=marker):
                    fixture = self.fixture()
                    result = self.run_suite(
                        fixture, aggregate=aggregate, SANITIZER_LOG_FAILURE=marker
                    )
                    self.assertEqual(result.returncode, 74, result.stdout + result.stderr)
                    self.assertEqual(bool(self.calls(fixture, "sanitizer")), launched)
                    if launched:
                        self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)

    def test_initial_logging_failure_cleans_bound_target_and_records_cleanup(self):
        for aggregate in (False, True):
            for marker in (">>> sanitizer smoke", "starting security suite"):
                for cleanup in (0, 79):
                    with self.subTest(aggregate=aggregate, marker=marker, cleanup=cleanup):
                        fixture = self.fixture()
                        target = fixture.root / "target/sanitizers"
                        target.mkdir(parents=True)
                        (target / "prepared-sentinel").write_text("prepared output")
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_LOG_FAILURE=marker,
                            SANITIZER_CLEANUP_EXIT=str(cleanup),
                        )
                        self.assertEqual(result.returncode, 74, result.stdout + result.stderr)
                        self.assertEqual(self.calls(fixture, "sanitizer"), [])
                        self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                        self.assertEqual(target.exists(), bool(cleanup))
                        summary = json.loads(
                            (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                        )
                        self.assertEqual(summary["exit_code"], 74)
                        self.assertEqual(summary["logging_exit_code"], 74)
                        self.assertEqual(summary["cleanup_exit_code"], cleanup)

    def test_post_binding_log_setup_failure_cleans_target(self):
        for aggregate in (False, True):
            for failure, code in (("mkdir", 76), ("inherited-fd", 1), ("opener", 1)):
                for cleanup in (0, 79):
                    with self.subTest(aggregate=aggregate, failure=failure, cleanup=cleanup):
                        fixture = self.fixture()
                        target = fixture.root / "target/sanitizers"
                        target.mkdir(parents=True)
                        (target / "prepared-sentinel").write_text("prepared output")
                        settings = {"SANITIZER_CLEANUP_EXIT": str(cleanup)}
                        sentinel = Path(fixture.temporary) / "external-log"
                        sentinel.write_bytes(b"external log sentinel\n")
                        if failure == "mkdir":
                            settings["SANITIZER_MKDIR_FAILURE"] = "1"
                        elif failure == "inherited-fd":
                            settings["SANITIZER_SECURITY_LOG_FD"] = "99999"
                        else:
                            # Introduce the unsafe leaf after binding so aggregate
                            # fuzz preflight cannot reject this control earlier.
                            settings["SANITIZER_OPENER_LOG_SYMLINK"] = str(sentinel)
                        result = self.run_suite(fixture, aggregate=aggregate, **settings)
                        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                        self.assertEqual(self.calls(fixture, "sanitizer"), [])
                        self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                        self.assertEqual(target.exists(), bool(cleanup))
                        self.assertEqual(sentinel.read_bytes(), b"external log sentinel\n")
                        summary = json.loads(
                            (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                        )
                        self.assertEqual(summary["exit_code"], code)
                        self.assertEqual(summary["logging_exit_code"], code)
                        self.assertEqual(summary["cleanup_exit_code"], cleanup)

    def test_existing_evidence_binding_rejects_replacement_before_stage_preparation(self):
        for swap in ("leaf-symlink", "leaf-directory", "ancestor-symlink"):
            with self.subTest(swap=swap):
                fixture = self.fixture()
                target = fixture.root / "target/sanitizers"
                target.mkdir(parents=True)
                (target / "prepared-sentinel").write_text("prepared output")
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinels = {
                    "run-summary.json": b"external completed sentinel\n",
                    "sanitizers/run-summary.json": b"external nested completed sentinel\n",
                    "summary/security.log": b"external log sentinel\n",
                }
                for name, data in sentinels.items():
                    destination = external / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                result = self.run_suite(
                    fixture,
                    stages=("sanitizers", "sbom"),
                    SANITIZER_INITIAL_EVIDENCE_SWAP=swap,
                    SANITIZER_EXTERNAL=str(external),
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "nix-other"), [])
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertFalse(target.exists())
                self.assertFalse(Path(fixture.env["SECURITY_HISTORY_DIR"]).exists())
                self.assertIn("remaining output stages held", result.stdout)
                for name, data in sentinels.items():
                    self.assertEqual((external / name).read_bytes(), data)
                if swap == "leaf-directory":
                    self.assertEqual(
                        list((fixture.artifacts / "sanitizers").iterdir()),
                        [fixture.artifacts / "sanitizers/replacement-sentinel"],
                    )

    def test_opener_handoff_cleans_original_target_on_early_evidence_rejection(self):
        for aggregate, swaps in (
            (
                False,
                ("evidence-symlink", "evidence-directory", "artifact-symlink", "artifact-file"),
            ),
            (True, ("artifact-symlink", "artifact-file")),
        ):
            for swap in swaps:
                for cleanup in (0, 79):
                    with self.subTest(aggregate=aggregate, swap=swap, cleanup=cleanup):
                        fixture = self.fixture()
                        self.install_handoff_wrapper(fixture)
                        target = fixture.root / "target/sanitizers"
                        target.mkdir(parents=True)
                        (target / "prepared-sentinel").write_text("prepared output")
                        retained = self.seed_retained_evidence(fixture)
                        external = Path(fixture.temporary) / "external"
                        external.mkdir()
                        sentinel = external / "run-summary.json"
                        sentinel.write_bytes(b"preserve external completed receipt\n")
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_HANDOFF_SWAP=swap,
                            SANITIZER_EXTERNAL=str(external),
                            SANITIZER_CLEANUP_EXIT=str(cleanup),
                        )
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertEqual(self.calls(fixture, "sanitizer"), [])
                        handoff = self.calls(fixture, "handoff")
                        self.assertEqual(len(handoff), 1)
                        self.assertEqual(
                            (
                                handoff[0]["target"],
                                json.loads(handoff[0]["cleanup_binding"])["target"],
                                json.loads(handoff[0]["evidence_binding"])["target"],
                            ),
                            (str(target), str(target), str(fixture.artifacts / "sanitizers")),
                        )
                        self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                        self.assertEqual(target.exists(), bool(cleanup))
                        self.assertEqual(
                            sentinel.read_bytes(), b"preserve external completed receipt\n"
                        )
                        held = (
                            fixture.artifacts.with_name(fixture.artifacts.name + ".held")
                            / "sanitizers"
                            if swap.startswith("artifact-")
                            else fixture.artifacts / "sanitizers.held"
                        )
                        self.assertEqual(
                            (held / "run-summary.json").read_text(), handoff[0]["summary"]
                        )
                        histories = list(held.glob(".previous-attempt-*/run-summary.json"))
                        self.assertEqual(len(histories), 1)
                        self.assertEqual(
                            histories[0].read_text(), retained["sanitizers/run-summary.json"]
                        )
                        if swap.endswith("file"):
                            self.assertEqual(
                                fixture.artifacts.read_bytes(), b"preserve replacement\n"
                            )
                        elif swap.endswith("directory"):
                            self.assertEqual(
                                list((fixture.artifacts / "sanitizers").iterdir()),
                                [fixture.artifacts / "sanitizers/replacement-sentinel"],
                            )

    def test_resumed_preparation_and_log_rejection_preserve_primary_cleanup_status(self):
        for failure, code in (
            ("log-symlink", 1),
            ("log-directory", 1),
            ("flags", 1),
            ("cargo-home", 76),
        ):
            for cleanup in (0, 79):
                with self.subTest(failure=failure, cleanup=cleanup):
                    fixture = self.fixture()
                    self.install_handoff_wrapper(fixture)
                    target = fixture.root / "target/sanitizers"
                    target.mkdir(parents=True)
                    (target / "prepared-sentinel").write_text("prepared output")
                    external = Path(fixture.temporary) / "external"
                    external.mkdir()
                    sentinel = external / "security.log"
                    sentinel.write_bytes(b"preserve external log\n")
                    settings = (
                        {"SANITIZER_HANDOFF_FLAGS": "--target-dir crates/server"}
                        if failure == "flags"
                        else {"SANITIZER_RESUMED_HOME_FAILURE": "1"}
                        if failure == "cargo-home"
                        else {"SANITIZER_HANDOFF_SWAP": failure}
                    )
                    result = self.run_suite(
                        fixture,
                        SANITIZER_EXTERNAL=str(external),
                        SANITIZER_CLEANUP_EXIT=str(cleanup),
                        **settings,
                    )
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    self.assertEqual(self.calls(fixture, "sanitizer"), [])
                    self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                    self.assertEqual(target.exists(), bool(cleanup))
                    self.assertEqual(sentinel.read_bytes(), b"preserve external log\n")
                    summary = json.loads(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                    )
                    self.assertEqual(summary["exit_code"], code)
                    self.assertEqual(summary["cleanup_exit_code"], cleanup)

    def test_replaced_handoff_target_is_preserved_without_rebinding(self):
        for swap in ("target-symlink", "target-directory", "ancestor-symlink"):
            with self.subTest(swap=swap):
                fixture = self.fixture()
                self.install_handoff_wrapper(fixture)
                target = fixture.root / "target/sanitizers"
                target.mkdir(parents=True)
                (target / "prepared-sentinel").write_text("preserve held output")
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinel = external / "external-sentinel"
                sentinel.write_bytes(b"preserve external output\n")
                result = self.run_suite(
                    fixture, SANITIZER_HANDOFF_TARGET_SWAP=swap, SANITIZER_EXTERNAL=str(external)
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(sentinel.read_bytes(), b"preserve external output\n")
                held = (
                    target.parent.with_name(target.parent.name + ".held") / target.name
                    if swap == "ancestor-symlink"
                    else target.with_name(target.name + ".held")
                )
                self.assertEqual((held / "prepared-sentinel").read_text(), "preserve held output")
                if swap == "target-directory":
                    self.assertEqual(list(target.iterdir()), [target / "replacement-sentinel"])
                self.assertEqual(
                    len(list((fixture.artifacts / "sanitizers").glob(".previous-attempt-*"))), 0
                )

    def test_early_recovery_preserves_child_and_replaced_summary_bytes(self):
        for receipt, child_status in (
            ("detailed", "completed"),
            ("detailed", "failed"),
            ("replacement-initial", ""),
            ("summary-symlink", ""),
            ("summary-directory", ""),
        ):
            with self.subTest(receipt=receipt, child_status=child_status):
                fixture = self.fixture()
                self.install_handoff_wrapper(fixture)
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinel = external / "run-summary.json"
                sentinel.write_bytes(b"preserve external receipt\n")
                result = self.run_suite(
                    fixture,
                    SANITIZER_HANDOFF_RECEIPT=receipt,
                    SANITIZER_HANDOFF_RECEIPT_STATUS=child_status,
                    SANITIZER_RESUMED_HOME_FAILURE="1",
                    SANITIZER_EXTERNAL=str(external),
                )
                self.assertEqual(result.returncode, 76, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                self.assertFalse((fixture.root / "target/sanitizers").exists())
                self.assertEqual(sentinel.read_bytes(), b"preserve external receipt\n")
                summary = fixture.artifacts / "sanitizers/run-summary.json"
                if receipt == "detailed":
                    self.assertEqual(
                        summary.read_text(),
                        json.dumps(
                            {
                                "status": child_status,
                                "commands": [{"phase": "run", "exit_code": 71}],
                                "units": [
                                    {
                                        "package": "ffi",
                                        "targets": [{"name": "ffi", "status": "failed"}],
                                    }
                                ],
                            }
                        ),
                    )
                elif receipt == "replacement-initial":
                    self.assertEqual(
                        summary.read_text(), self.calls(fixture, "handoff")[0]["summary"]
                    )
                    self.assertEqual(
                        summary.with_name(summary.name + ".held").read_text(), summary.read_text()
                    )
                elif receipt == "summary-symlink":
                    self.assertTrue(summary.is_symlink())
                else:
                    self.assertEqual(list(summary.iterdir()), [summary / "replacement-sentinel"])

    def test_successful_handoff_retains_original_binding_and_checks_literal_marker(self):
        for marker in ("0", "1+0", "unset_sanitizer_marker"):
            with self.subTest(marker=marker):
                fixture = self.fixture()
                self.install_handoff_wrapper(fixture)
                retained = self.seed_retained_evidence(fixture)
                result = self.run_suite(fixture, SANITIZER_HANDOFF_MARKER=marker)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                handoff = self.calls(fixture, "handoff")[0]
                cleanup = self.calls(fixture, "cleanup")
                self.assertEqual(len(cleanup), 1)
                self.assertEqual(cleanup[0]["args"], ["fd-relative", "--", handoff["target"]])
                histories = list(
                    (fixture.artifacts / "sanitizers").glob(".previous-attempt-*/run-summary.json")
                )
                self.assertEqual(len(histories), 1)
                self.assertEqual(histories[0].read_text(), retained["sanitizers/run-summary.json"])

    def test_unrelated_stage_ignores_inherited_sanitizer_marker_and_cleanup(self):
        for marker in ("1", "1+0", "unset_sanitizer_marker"):
            with self.subTest(marker=marker):
                fixture = self.fixture()
                unrelated = Path(fixture.temporary) / "unrelated-target"
                unrelated.mkdir()
                sentinel = unrelated / "preserved-output"
                sentinel.write_text("preserve unrelated output")
                result = self.run_suite(
                    fixture,
                    stages=("sbom",),
                    SANITIZER_EVIDENCE_ROUTE_CHANGED=marker,
                    SANITIZER_CLEANUP_BINDING=json.dumps({"target": str(unrelated)}),
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(self.calls(fixture, "nix-other")), 1)
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                self.assertNotIn("remaining output stages held", result.stdout)
                self.assertEqual(sentinel.read_text(), "preserve unrelated output")

    def test_unavailable_opener_recovery_preserves_primary_and_does_not_claim_cleanup(self):
        for failure in ("missing-bash", "exec-failure"):
            with self.subTest(failure=failure):
                fixture = self.fixture()
                target = fixture.root / "target/sanitizers"
                target.mkdir(parents=True)
                sentinel = target / "prepared-sentinel"
                sentinel.write_text("preserve uncollected output")
                external = Path(fixture.temporary) / "external-log"
                external.write_bytes(b"preserve log\n")
                log = fixture.artifacts / "summary/security.log"
                log.parent.mkdir(parents=True)
                log.symlink_to(external)
                result = self.run_suite(fixture, SANITIZER_OPENER_RECOVERY_UNAVAILABLE=failure)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("safe log descriptor unavailable (exit=1)", result.stderr)
                self.assertIn("bound cleanup/evidence recovery unavailable", result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                self.assertEqual(sentinel.read_text(), "preserve uncollected output")
                self.assertEqual(external.read_bytes(), b"preserve log\n")
                summary = json.loads(
                    (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                )
                self.assertEqual(summary["status"], "failed")
                self.assertNotIn("cleanup_exit_code", summary)

    def test_optional_cleanup_receipt_preserves_rich_evidence_and_absent_field(self):
        for cleanup in (None, 0, 79):
            with self.subTest(cleanup=cleanup):
                fixture = self.fixture()
                evidence = fixture.artifacts / "sanitizers"
                evidence.mkdir(parents=True)
                receipt = {
                    "status": "completed",
                    "commands": [{"phase": "run", "exit_code": 0}],
                    "units": [{"targets": [{"name": "ffi", "status": "completed"}]}],
                }
                (evidence / "run-summary.json").write_text(json.dumps(receipt))
                result = subprocess.run(  # noqa: S603 - fixed shell/helper and owned test evidence
                    [
                        str(fixture.bin / "bash"),
                        "--noprofile",
                        "--norc",
                        "-p",
                        "-c",
                        (
                            'source "$1"; SANITIZER_ARTIFACT_DIR=$2; '
                            'binding=$(sanitizer_target_binding prepare "$2") && '
                            'sanitizer_target_binding validate "$binding" && '
                            'preflight_receipt initial-log 74 74 "${3:-}"'
                        ),
                        "receipt-control",
                        str(fixture.root / "scripts/sanitizers/sanitizer_paths.sh"),
                        str(evidence),
                        *([] if cleanup is None else [str(cleanup)]),
                    ],
                    cwd=fixture.root,
                    env=fixture.env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observed = json.loads((evidence / "run-summary.json").read_text())
                expected = {
                    **receipt,
                    "status": "failed",
                    "stage": "preflight",
                    "preflight_phase": "initial-log",
                    "exit_code": 74,
                    "logging_exit_code": 74,
                }
                if cleanup is not None:
                    expected["cleanup_exit_code"] = cleanup
                self.assertEqual(observed, expected)
                self.assertEqual(
                    (evidence / "run-summary.json").read_text(),
                    json.dumps(expected, indent=2) + "\n",
                )

    def test_bound_opener_rejects_unadmitted_cleanup_context(self):
        for failure in ("source-target", "evidence-overlap", "token-mismatch"):
            with self.subTest(failure=failure):
                fixture = self.fixture()
                evidence = fixture.artifacts / "sanitizers"
                evidence.mkdir(parents=True)
                (evidence / "run-summary.json").write_text('{"status":"failed"}')
                target = fixture.root / "target/sanitizers"
                target.mkdir(parents=True)
                (target / "prepared-sentinel").write_text("preserve output")
                source = fixture.root / "crates/server/src/lib.rs"
                original_source = source.read_bytes()
                supplied_target = (
                    fixture.root / "crates/server"
                    if failure == "source-target"
                    else evidence
                    if failure == "evidence-overlap"
                    else target
                )
                token_target = (
                    fixture.root / "crates/server"
                    if failure == "token-mismatch"
                    else supplied_target
                )
                binding = subprocess.run(  # noqa: S603 - existing helper creates only owned fixture bindings
                    [
                        str(fixture.bin / "bash"),
                        "--noprofile",
                        "--norc",
                        "-p",
                        "-c",
                        (
                            'source "$1"; sanitizer_target_binding prepare "$2"; '
                            'sanitizer_target_binding prepare "$3"'
                        ),
                        "binding-control",
                        str(fixture.root / "scripts/sanitizers/sanitizer_paths.sh"),
                        str(evidence),
                        str(token_target),
                    ],
                    cwd=fixture.root,
                    env=fixture.env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(binding.returncode, 0, binding.stderr)
                evidence_binding, cleanup_binding = binding.stdout.splitlines()
                external = Path(fixture.temporary) / "external-log"
                external.write_bytes(b"preserve external log\n")
                log = fixture.artifacts / "summary/security.log"
                log.parent.mkdir()
                log.symlink_to(external)
                result = subprocess.run(  # noqa: S603 - actual opener with owned negative context
                    [
                        str(fixture.bin / "python3"),
                        "-I",
                        str(fixture.root / "scripts/sanitizers/open_security_log.py"),
                        "open-exec-bound",
                        str(log),
                        str(evidence),
                        evidence_binding,
                        str(supplied_target),
                        cleanup_binding,
                        "--",
                        "--stage",
                        "sanitizers",
                    ],
                    cwd=fixture.root,
                    env=fixture.env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                self.assertEqual(source.read_bytes(), original_source)
                self.assertEqual((target / "prepared-sentinel").read_text(), "preserve output")
                self.assertEqual((evidence / "run-summary.json").read_text(), '{"status":"failed"}')
                self.assertEqual(external.read_bytes(), b"preserve external log\n")

    def test_preexec_failure_closes_the_owned_log_descriptor(self):
        fixture = self.fixture()
        source = fixture.root / "scripts/sanitizers/open_security_log.py"
        spec = importlib.util.spec_from_file_location("security_log_control", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        log = Path(fixture.temporary) / "owned-log"
        descriptor = module.checked_log(str(log))
        try:
            with (
                mock.patch.object(sys, "argv", [str(source), "open-exec", str(log)]),
                mock.patch.object(module, "checked_log", return_value=descriptor),
                mock.patch.object(module.shutil, "which", return_value=str(fixture.bin / "bash")),
                mock.patch.object(
                    module.os, "execve", side_effect=OSError("controlled exec failure")
                ),
                contextlib.redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(module.main(), 1)
            self.assertIn("exit=1", diagnostic.getvalue())
            with self.assertRaises(OSError):  # noqa: PT027 - standalone unittest control
                os.fstat(descriptor)
        finally:
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def test_bound_recovery_encoding_and_diagnostic_failure_preserve_primary(self):
        fixture = self.fixture()
        source = fixture.root / "scripts/sanitizers/open_security_log.py"
        spec = importlib.util.spec_from_file_location("security_log_recovery_control", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        log = Path(fixture.temporary) / "owned-log"
        for failure in (
            OSError("recovery unavailable"),
            UnicodeEncodeError("utf-8", "x", 0, 1, "controlled"),
        ):
            with self.subTest(failure=type(failure).__name__):
                descriptor = module.checked_log(str(log))
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        [
                            str(source),
                            "open-exec-bound",
                            str(log),
                            "/evidence",
                            "{}",
                            "/target",
                            "{}",
                            "--",
                        ],
                    ),
                    mock.patch.object(module, "checked_log", return_value=descriptor),
                    mock.patch.object(
                        module.shutil, "which", return_value=str(fixture.bin / "bash")
                    ),
                    mock.patch.object(
                        module.os, "execve", side_effect=OSError("controlled exec failure")
                    ),
                    mock.patch.object(module.subprocess, "run", side_effect=failure) as recovery,
                    mock.patch.object(
                        module, "print", create=True, side_effect=OSError("diagnostic unavailable")
                    ),
                ):
                    self.assertEqual(module.main(), 1)
                    recovery.assert_called_once()
                with self.assertRaises(OSError):  # noqa: PT027 - standalone unittest control
                    os.fstat(descriptor)

    def test_failed_diagnostic_write_does_not_replace_the_child_failure(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    SANITIZER_CHILD_EXIT="71",
                    SANITIZER_LOG_FAILURE="<<< sanitizer smoke: failed",
                )
                self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 71)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)

    def test_aggregate_runs_sanitizers_after_fuzz_failure_and_preserves_both_results(self):
        fixture = self.fixture(full_fuzz=True)
        result = self.run_suite(
            fixture,
            aggregate=True,
            case="run-fail",
            FAIL_TARGET=fuzz_fixture.TARGETS[0],
            SANITIZER_CHILD_EXIT="71",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(fixture.summary()["status"], "failed")
        self.assertEqual(fixture.summary()["execution"]["targets"][0]["run"]["exit_code"], 23)
        self.assertEqual(self.receipt(fixture)["exit_code"], 71)
        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
        log = (fixture.artifacts / "summary/security.log").read_text()
        self.assertLess(log.index("cargo fuzz smoke: failed"), log.index(">>> sanitizer smoke"))
        self.assertIn("sanitizer smoke: failed (exit=71)", log)
        self.assertTrue((fixture.artifacts / "fuzz/collection.ok").is_file())

    def test_optional_vet_and_sbom_findings_remain_non_blocking(self):
        fixture = self.fixture(full_fuzz=True)
        result = self.run_suite(fixture, aggregate=True, VET_EXIT="37", SBOM_EXIT="43")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.receipt(fixture)["exit_code"], 0)
        self.assertTrue(self.calls(fixture, "vet"))
        self.assertTrue(all(row["exit_code"] == 37 for row in self.calls(fixture, "vet")))
        self.assertEqual(self.calls(fixture, "nix-other")[0]["exit_code"], 43)
        log = (fixture.artifacts / "summary/security.log").read_text()
        self.assertIn("cargo vet check: reported findings (non-blocking)", log)
        self.assertIn("SBOM scan: reported findings (non-blocking)", log)

    def test_protected_source_and_external_symlink_targets_reject_before_child(self):
        for setting in (
            "crates/server",
            "scripts",
            "generated/nested",
            ".git",
            "external-link",
            "external-link/../target/sanitizers",
            "custom-parent/alias/target",
        ):
            with self.subTest(setting=setting):
                fixture = self.fixture()
                external = Path(fixture.temporary) / "external"
                external.mkdir()
                sentinel = external / "sentinel"
                sentinel.write_bytes(b"external sentinel\n")
                if setting.startswith("external-link"):
                    (fixture.root / "external-link").symlink_to(external, target_is_directory=True)
                elif setting == "custom-parent/alias/target":
                    (fixture.root / "custom-parent").mkdir()
                    (fixture.root / "custom-parent/alias").symlink_to(
                        external, target_is_directory=True
                    )
                else:
                    target = fixture.root / setting
                    target.mkdir(parents=True, exist_ok=True)
                    (target / "sentinel").write_bytes(b"source sentinel\n")
                result = self.run_suite(fixture, SANITIZER_TARGET_DIR=setting)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual(self.calls(fixture, "cleanup"), [])
                self.assertEqual(sentinel.read_bytes(), b"external sentinel\n")
                if not setting.startswith("external-link") and "alias" not in setting:
                    self.assertEqual((target / "sentinel").read_bytes(), b"source sentinel\n")

    def test_child_target_and_ancestor_swaps_cannot_redirect_cleanup(self):
        for swap in ("target-symlink", "target-directory", "ancestor-symlink"):
            for child in (0, 71):
                with self.subTest(swap=swap, child=child):
                    fixture = self.fixture()
                    external = Path(fixture.temporary) / "external"
                    external.mkdir()
                    (external / "sentinel").write_bytes(b"external sentinel\n")
                    result = self.run_suite(
                        fixture,
                        SANITIZER_TARGET_DIR="custom-parent/target",
                        SANITIZER_SWAP=swap,
                        SANITIZER_EXTERNAL=str(external),
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child or 1, result.stdout + result.stderr)
                    self.assertEqual((external / "sentinel").read_bytes(), b"external sentinel\n")
                    held = fixture.root / (
                        "custom-parent.held/target"
                        if swap == "ancestor-symlink"
                        else "custom-parent/target.held"
                    )
                    self.assertEqual(
                        (held / "child-output").read_text(), "transient sanitizer output"
                    )
                    if swap == "target-directory":
                        self.assertEqual(
                            (
                                fixture.root / "custom-parent/target/replacement-sentinel"
                            ).read_text(),
                            "preserve replacement",
                        )
                    self.assertNotIn("<<< sanitizer smoke: ok", result.stdout)

    def test_nested_child_symlink_is_unlinked_without_following_external_target(self):
        fixture = self.fixture()
        external = Path(fixture.temporary) / "external"
        external.mkdir()
        (external / "sentinel").write_bytes(b"external sentinel\n")
        result = self.run_suite(
            fixture, SANITIZER_SWAP="nested-symlink", SANITIZER_EXTERNAL=str(external)
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((fixture.root / "target/sanitizers").exists())
        self.assertEqual((external / "sentinel").read_bytes(), b"external sentinel\n")

    def test_unsafe_evidence_route_is_never_initialized_or_logged(self):
        fixture = self.fixture()
        external = Path(fixture.temporary) / "external"
        external.mkdir()
        sentinel = external / "run-summary.json"
        sentinel.write_bytes(b"external completed sentinel\n")
        (fixture.root / "external-evidence").symlink_to(external, target_is_directory=True)
        result = self.run_suite(fixture, SECURITY_ARTIFACT_DIR="external-evidence")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(fixture, "sanitizer"), [])
        self.assertEqual(list(external.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"external completed sentinel\n")

    def test_child_evidence_swaps_preserve_external_and_hold_completed_summary(self):
        for swap in ("evidence-symlink", "evidence-ancestor"):
            for child, aggregate in ((0, False), (71, False), (0, True), (71, True)):
                with self.subTest(swap=swap, child=child, aggregate=aggregate):
                    fixture = self.fixture()
                    external = Path(fixture.temporary) / "external"
                    external.mkdir()
                    sentinel = external / "run-summary.json"
                    sentinel.write_bytes(b"external completed sentinel\n")
                    (external / "sanitizers").mkdir()
                    nested = external / "sanitizers/run-summary.json"
                    nested.write_bytes(b"external nested completed sentinel\n")
                    (external / "summary").mkdir()
                    log = external / "summary/security.log"
                    log.write_bytes(b"external log sentinel\n")
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_SWAP=swap,
                        SANITIZER_EXTERNAL=str(external),
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child or 1, result.stdout + result.stderr)
                    self.assertEqual(sentinel.read_bytes(), b"external completed sentinel\n")
                    self.assertEqual(nested.read_bytes(), b"external nested completed sentinel\n")
                    self.assertEqual(log.read_bytes(), b"external log sentinel\n")
                    held = (
                        fixture.artifacts / "sanitizers.held"
                        if swap == "evidence-symlink"
                        else fixture.artifacts.with_name(fixture.artifacts.name + ".held")
                        / "sanitizers"
                    )
                    self.assertEqual(
                        json.loads((held / "run-summary.json").read_text())["status"],
                        "completed" if child == 0 else "failed",
                    )
                    self.assertNotIn("<<< sanitizer smoke: ok", result.stdout)
                    self.assertEqual(self.calls(fixture, "nix-other"), [])

    def test_private_evidence_stop_flag_is_initialized_by_current_attempt(self):
        fixture = self.fixture()
        unrelated = Path(fixture.temporary) / "unrelated-target"
        unrelated.mkdir()
        sentinel = unrelated / "preserved-output"
        sentinel.write_text("preserve unrelated output")
        result = self.run_suite(
            fixture,
            aggregate=True,
            SANITIZER_EVIDENCE_ROUTE_CHANGED="1",
            SANITIZER_CLEANUP_BINDING=json.dumps({"target": str(unrelated)}),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.calls(fixture, "nix-other"))
        self.assertNotIn("remaining output stages held", result.stdout)
        self.assertEqual(self.receipt(fixture)["exit_code"], 0)
        self.assertEqual(sentinel.read_text(), "preserve unrelated output")


if __name__ == "__main__":
    unittest.main()
