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
from dudect_results import CANDIDATE_PROFILES as PROFILES
from run_candidate import source_paths
from test_dudect_candidate import observation

ROOT = Path(__file__).resolve().parents[2]

NATIVE = r"""
import array, json, math, os, signal, struct, sys
from collections import Counter
from itertools import accumulate
from pathlib import Path
rows = ROWS
options = json.loads(Path(os.environ['FIXTURE_OPTIONS']).read_text())
with Path(os.environ['FIXTURE_EVENTS']).open('a') as out:
    out.write(json.dumps({'binary': NAME, 'argv': sys.argv[1:]}) + '\n')
if options.get('signal'): os.kill(os.getpid(), signal.SIGTERM)
if options.get('exit'): raise SystemExit(options['exit'])
if options.get('empty'): raise SystemExit(0)
sys.path.insert(0, str(Path.cwd() / 'tests/constant_time'))
from dudect_timing import INPUTS, STRIDES, input_width
from dudect_support import transformed_support
profile = rows[sys.argv[1]]
binding = profile[0]['binding']
keys = ('build_sha256','contract_sha256','numerical_sha256')
header = b''.join(binding[k].encode() for k in keys)
timing = None
if 'AEGAEON_DUDECT_TIMING_FD' in os.environ and not options.get('omit_timing'):
    timing = os.fdopen(os.dup(int(os.environ['AEGAEON_DUDECT_TIMING_FD'])), 'wb', buffering=0)
    timing.write(b'AEGTIM05' + header)
trace = None
if 'AEGAEON_DUDECT_TRACE_FD' in os.environ and not options.get('omit_trace'):
    trace = os.fdopen(os.dup(int(os.environ['AEGAEON_DUDECT_TRACE_FD'])), 'wb', buffering=0)
    trace.write(b'AEGTRC02' + header)
stamp = 1
for name in dict.fromkeys(row['case'] for row in profile):
    planned = [row for row in profile if row['case'] == name]
    first = planned[0]
    sparse = first['statistics'][1][0] < first['statistics'][0][0]
    degenerate = first['support'][1][0]['tick_min'] == first['support'][1][0]['tick_max']
    shift = first['statistics'][0][2] - first['statistics'][0][3]
    width = input_width(name,b'AEGTIM05')
    if timing: timing.write(struct.pack('<64s6Q',name.encode(),STRIDES[name],width,16,16,16,16))
    hist = [Counter(),Counter()]
    cursor = 0
    for batch in range(planned[-1]['batches']+1):
        labels = bytes((i+batch)%2 for i in range(65536))
        if not batch:
            # A real independent pilot: its lower boundary is 110 only in the
            # deliberate sparse-crop fixture, and 300 elsewhere.
            low = int(65525*(1-math.pow(.5,.1)))+1 if sparse else 0
            deltas = [110 if 10 <= i < 10+low else 300 for i in range(65536)]
            accepted=deltas[10:-1]
            center=sum(float(x) for x in accepted)/len(accepted)
            ordered=sorted(accepted)
            cutoffs=[ordered[int(len(ordered)*(1-math.pow(.5,(j+1)/10)))] for j in range(100)]
            pilot={'count':len(accepted),'center':center,'cutoffs':cutoffs}
        else:
            deltas=[]
            for i,g in enumerate(labels):
                sign=1 if (i//2)%2 else -1
                spread=32 if name=='control_variance_shift' and g==0 else 3
                delta=100 + spread*sign + (int(shift) if g==0 else 0)
                if sparse and not (10 <= i < 610): delta += 100
                if degenerate and g==0: delta=100
                deltas.append(delta)
            for i in range(10,65535): hist[labels[i]][deltas[i]]+=1
        ticks=array.array('q',[0,*accumulate(deltas[:-1])]).tobytes()
        inputs=b''
        if name in INPUTS: inputs=bytes([INPUTS[name]])*(65536*width)
        elif width:
            values=[]
            for i,g in enumerate(labels):
                if name=='control_variance_shift': value=2048 if not g else (1024 if i&2 else 3072)
                else: value=320 if name=='control_mean_shift' and g else 256
                values.append(value)
            inputs=array.array('I',values).tobytes()
        if timing:
            timing.write(struct.pack('<18Q',batch,65536,stamp,stamp+1,*([0]*14)))
            timing.write(ticks+labels+inputs)
        stamp+=2
        if trace and name=='ct_eq_128':
            trace.write(struct.pack('<4Q',batch,65536,128,128))
            trace.write(ticks+labels+bytes(65536*128))
        if not batch or batch!=planned[cursor]['batches']: continue
        row=planned[cursor]; cursor+=1
        row['pilot']=pilot
        for j in range(102):
            values=[]; supports=[]
            for g in (0,1):
                h={t:n for t,n in hist[g].items() if j in (0,101) or t<=pilot['cutoffs'][j-1]}
                mapped={t:float((float(t)-center)**2 if j==101 else t) for t in h}
                n=sum(h.values()); mean=sum(mapped[t]*k for t,k in h.items())/n
                m2=sum(k*(mapped[t]-mean)**2 for t,k in h.items())
                values.append((n,mean,m2))
                lo,hi=min(h),max(h)
                supports.append({'count':n,'tick_min':lo,'tick_max':hi,'tick_min_count':h[lo],'tick_max_count':h[hi],
                    'value_min_hex':min(mapped.values()).hex(),'value_max_hex':max(mapped.values()).hex()})
            row['statistics'][j]=[values[0][0],values[1][0],values[0][1],values[1][1],values[0][2],values[1][2]]
            row['support'][j]=supports
        if options.get('invalid') or options.get('invalid_binary')==NAME: row['schema_version']=2
        print(json.dumps(row),flush=True)
        if sys.stdin.buffer.read(1)!=b'c': raise SystemExit(2)
if timing:
    if options.get('truncate_timing'): timing.truncate(timing.tell()-1)
    timing.close()
if trace:
    if options.get('truncate_trace'): trace.truncate(trace.tell()-1)
    trace.close()
if options.get('trailing'): print('{}',flush=True)
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
        for name in (
            "tests/constant_time/run.sh",
            "scripts/flake/verify_dudect.sh",
            "scripts/flake/dudect_output_permissions.sh",
        ):
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
            timeout=600 if "periodic" in args else 180,
        )

    def report_path(self):
        return self.output / "evidence/report.json"

    def evidence(self):
        return sorted(
            (self.output / "evidence/runs").glob("run-*"), key=lambda p: p.stat().st_mtime
        )
