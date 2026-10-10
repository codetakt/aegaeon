# ruff: noqa: S603 - controlled subprocess test fixture
"""Synthetic native package for exercising the real observation runner end to end."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/constant_time"))
from dudect_candidate import CANDIDATE_CASES, CONTROL_CASES
from dudect_results import PROFILES
from run_candidate import source_paths
from test_dudect_candidate import observation

ROOT = Path(__file__).resolve().parents[2]

NATIVE = r"""
import json, os, signal, sys
from pathlib import Path
rows = ROWS
options = json.loads(Path(os.environ['FIXTURE_OPTIONS']).read_text())
with Path(os.environ['FIXTURE_EVENTS']).open('a') as out:
    out.write(json.dumps({'binary': NAME, 'argv': sys.argv[1:]}) + '\n')
if options.get('signal'): os.kill(os.getpid(), signal.SIGTERM)
if options.get('exit'): raise SystemExit(options['exit'])
if options.get('empty'): raise SystemExit(0)
for row in rows[sys.argv[1]]:
    if options.get('invalid'): row['schema_version'] = 2
    print(json.dumps(row), flush=True)
    if sys.stdin.buffer.read(1) != b'c': raise SystemExit(2)
if options.get('trailing'): print('{}', flush=True)
if options.get('late_exit'): raise SystemExit(17)
"""

COMPILER = r"""
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name == 'pkg-config': raise SystemExit(0)
if name == 'ldd': print('synthetic native executable'); raise SystemExit(0)
if '--version' in sys.argv: print('synthetic compiler 1'); raise SystemExit(0)
options = json.loads(Path(os.environ['FIXTURE_OPTIONS']).read_text())
if options.get('compiler_exit'): raise SystemExit(options['compiler_exit'])
if options.get('omit_binary'): raise SystemExit(0)
out = Path(sys.argv[sys.argv.index('-o') + 1])
if options.get('directory_binary'): out.mkdir(); raise SystemExit(0)
rows = json.loads(Path(os.environ['FIXTURE_ROWS']).read_text())[out.name]
macros = dict(arg[2:].split('=', 1) for arg in sys.argv if arg.startswith('-DAEGAEON_DUDECT_'))
for profile in rows:
    for row in rows[profile]:
        row['binding'].update({
            'contract_sha256': macros['AEGAEON_DUDECT_CONTRACT_SHA256'].strip('"'),
            'build_sha256': macros['AEGAEON_DUDECT_BUILD_SHA256'].strip('"'),
            'numerical_sha256': macros['AEGAEON_DUDECT_NUMERICAL_SHA256'].strip('"'),
            'case_id': macros['AEGAEON_DUDECT_SUITE'].strip('"') + '/' + row['case']})
source = Path(os.environ['FIXTURE_NATIVE']).read_text()
source = source.replace('ROWS', repr(rows)).replace('NAME', repr(out.name))
out.write_text('' if options.get('empty_binary') else '#!' + sys.executable + '\n' + source)
out.chmod(0o400 if options.get('nonexecutable_binary') else 0o700)
"""


class NativeFixture:
    def __init__(self, test):
        self.directory = Path(test.enterContext(tempfile.TemporaryDirectory()))
        self.root = self.directory / "repository with spaces"
        for source in source_paths(ROOT):
            destination = self.root / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        for name in ("tests/constant_time/run.sh", "scripts/flake/verify_dudect.sh"):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.bin = self.directory / "karamel/bin"
        self.bin.mkdir(parents=True)
        for name in ("cc", "gcc", "pkg-config", "ldd", "krml"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n{COMPILER}")
            path.chmod(0o700)
        self.output = self.directory / "out"
        self.output.mkdir()
        self.options = self.directory / "options.json"
        self.options.write_text("{}")
        self.events = self.directory / "events.jsonl"
        self.rows = self.directory / "rows.json"
        self.rows.write_text(json.dumps(self.native_rows()))
        self.native = self.directory / "native.py"
        self.native.write_text(NATIVE)

    @staticmethod
    def native_rows():
        rows = {}
        names = set(CANDIDATE_CASES["legacy"]) | set(CANDIDATE_CASES["nix"])
        for name in names:
            rows[name] = {}
            for profile, (looks, _, _) in PROFILES.items():
                observations = []
                for look in range(1, len(looks) + 1):
                    row = observation(name, profile, look, effect=name == "control_mean_shift")
                    if name == "control_variance_shift":
                        row["statistics"][101][2] = 60
                    observations.append(row)
                rows[name][profile] = observations
        for executable, cases in (
            ("dudect_controls", CONTROL_CASES),
            ("dudect_harness", CANDIDATE_CASES["nix"][: -len(CONTROL_CASES)]),
        ):
            rows[executable] = {
                profile: [row for name in cases for row in rows[name][profile]]
                for profile in PROFILES
            }
        return rows

    def environment(self):
        return {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "FIXTURE_OPTIONS": str(self.options),
            "FIXTURE_EVENTS": str(self.events),
            "FIXTURE_ROWS": str(self.rows),
            "FIXTURE_NATIVE": str(self.native),
            "PYTHONDONTWRITEBYTECODE": "1",
            "OUT_DIR": str(self.output),
            "EVERCRYPT_DIST": str(self.directory / "evercrypt"),
        }

    def invoke(self, *args, wrapper=False, **options):
        self.options.write_text(json.dumps(options))
        command = (
            [shutil.which("bash"), str(self.root / "scripts/flake/verify_dudect.sh")]
            if wrapper
            else [
                sys.executable,
                str(self.root / "tests/constant_time/run_contract.py"),
                "--output",
                str(self.output / "evidence"),
                *args,
            ]
        )
        return subprocess.run(
            command,
            cwd=self.root,
            env=self.environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=40,
        )

    def report_path(self):
        return self.output / "evidence/report.json"

    def evidence(self):
        return sorted(
            (self.output / "evidence/runs").glob("run-*"), key=lambda p: p.stat().st_mtime
        )
