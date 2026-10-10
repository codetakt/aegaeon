# ruff: noqa: PT009, S603 - unittest assertions and controlled subprocess argv
"""Legacy adapter compatibility and false-success controls; no native execution."""

from __future__ import annotations

import fcntl
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("compare", "hmac", "ed25519", "rsa", "jwe")
TOOL = r"""import json, os, shlex, sys
from pathlib import Path

tool = Path(sys.argv[0]).name
with Path(os.environ['EVENTS']).open('a') as out:
    out.write(json.dumps({'tool':tool, 'args':sys.argv[1:]})+'\n')
if tool == 'pkg-config':
    if os.environ.get('PKG_EXIT'):
        print('controlled pkg-config failure',file=sys.stderr)
        raise SystemExit(int(os.environ['PKG_EXIT']))
    flag = '-I'+os.environ['SUPPLIER_INCLUDE'] if '--cflags' in sys.argv else '-levercrypt -pthread'
    print(shlex.quote(flag) if '--cflags' in sys.argv else flag)
    raise SystemExit(0)
if tool == 'krml':
    raise SystemExit('krml must be discovered only')
output = Path(sys.argv[sys.argv.index('-o')+1])
name = output.name.removesuffix('_timing_test')
if name == os.environ.get('COMPILE_FAIL'):
    print('controlled compiler failure',file=sys.stderr)
    raise SystemExit(37)
if os.environ.get('OMIT_BINARY'):
    raise SystemExit(0)
if os.environ.get('DIRECTORY_BINARY'):
    output.mkdir()
    raise SystemExit(0)
if os.environ.get('SYMLINK_BINARY'):
    output.symlink_to(os.environ['PYTHON'])
    raise SystemExit(0)
prefix = '#!'+os.environ['PYTHON']+'\n'
contents = '' if os.environ.get('EMPTY_BINARY') else prefix+os.environ['BINARY']
output.write_text(contents)
output.chmod(0o600 if os.environ.get('NONEXECUTABLE_BINARY') else 0o755)
"""
BINARY = r"""import json, os, signal, sys
from pathlib import Path

name = Path(sys.argv[0]).name.removesuffix('_timing_test')
with Path(os.environ['EVENTS']).open('a') as out:
    out.write(json.dumps({'tool':'binary','name':name})+'\n')
if name == os.environ.get('BINARY_FAIL'):
    print('controlled harness failure',file=sys.stderr)
    raise SystemExit(43)
if name == os.environ.get('BINARY_SIGNAL'):
    os.kill(os.getpid(),signal.SIGTERM)
if os.environ.get('RAW_HEX'):
    sys.stdout.buffer.write(bytes.fromhex(os.environ['RAW_HEX']))
    sys.stdout.buffer.flush()
    raise SystemExit(0)
profile = sys.argv[1]
looks = [1,2,3,4,5,6,7] if profile == 'pr' else [1,2,4,8,16,32,64,98]
for look,batches in enumerate(looks,1):
    count=batches*(65536-11)
    n0=count//2; n1=count-n0
    stats=[[n0,n1,100.0,100.0,(n0-1)*4.0,(n1-1)*4.0] for _ in range(102)]
    if name == os.environ.get('LEAK'):
        stats[0][2]=150.0
    value={'schema_version':2,'case':name,'profile':profile,'batch_size':65536,
           'batches':batches,'look':look,'executed':65536*(batches+1),
           'warmup':65536,'rejected':0,'statistics':stats,
           'pilot':{'count':65525,'center':100,'cutoffs':[200]*100}}
    if name == os.environ.get('BAD_COUNT'):
        value['executed']+=1
    print(json.dumps(value),flush=True)
    if sys.stdin.buffer.read(1)!=b'c':
        raise SystemExit(2)
if name == 'jwe' and os.environ.get('STATUS_DIRECTORY'):
    runs = Path('artifacts/ct/dudect/runs').glob('run-*')
    run = sorted(runs,key=lambda p:p.stat().st_mtime_ns)[-1]
    (run/'status.json').mkdir()
if name == 'jwe' and os.environ.get('REPORT_DIRECTORY'):
    Path('artifacts/ct/dudect/report.json').mkdir()
"""


class LegacyDudectTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = self.directory / "repository with spaces"
        self.runner = self.root / "tests/constant_time/run.py"
        self.runner.parent.mkdir(parents=True)
        for filename in ("run.py", "dudect_process.py", "dudect_results.py"):
            shutil.copyfile(ROOT / "tests/constant_time" / filename, self.runner.parent / filename)
        self.bin = self.directory / "karamel with spaces/bin"
        self.bin.mkdir(parents=True)
        for name in ("cc", "gcc", "pkg-config", "krml"):
            tool = self.bin / name
            tool.write_text("#!" + sys.executable + "\n" + TOOL)
            tool.chmod(0o755)
        for name in ("python3", "dirname"):
            (self.bin / name).symlink_to(
                sys.executable if name == "python3" else shutil.which(name)
            )
        self.events = self.directory / "events.jsonl"
        self.output = self.root / "artifacts/ct/dudect"

    def invoke(self, *, xtask=False, extra=(), **changes):
        environment = {
            "PATH": str(self.bin),
            "EVENTS": str(self.events),
            "PYTHON": sys.executable,
            "BINARY": BINARY,
            "SUPPLIER_INCLUDE": str(self.directory / "evercrypt headers"),
            "RESULTS": json.dumps({}),
            "PYTHONDONTWRITEBYTECODE": "1",
            **changes,
        }
        command = (
            [sys.executable, str(self.runner), "--xtask-adapter"]
            if xtask
            else [sys.executable, str(self.runner)]
        )
        return subprocess.run(
            [*command, *extra],
            cwd=self.directory,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

    def test_unavailable_unix_locking_fails_clearly(self):
        script = (
            "import runpy, sys; sys.modules['fcntl'] = None; "
            f"sys.path.insert(0, {str(self.runner.parent)!r}); "
            f"runpy.run_path({str(self.runner)!r}, run_name='__main__')"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unix platform", result.stderr)
        self.assertFalse(self.output.exists())

    def test_retired_threshold_overrides_fail_without_reusing_report(self):
        self.seed_previous()
        result = self.invoke(DUDECT_MIN_TRACES="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retired", result.stderr)
        self.assertFalse((self.output / "report.json").exists())

    def recorded(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def runs(self):
        return sorted(
            (self.output / "runs").glob("run-*"), key=lambda path: path.stat().st_mtime_ns
        )

    def seed_previous(self, *, xtask=False):
        self.output.mkdir(parents=True)
        previous = {"state": 1, "p": 0.9, "num_traces": 20000, "previous": True}
        for name in ("report", *NAMES):
            (self.output / f"{name}.json").write_text(json.dumps(previous))
        target = self.root / ("target/ct" if xtask else "target")
        target.mkdir(parents=True)
        stale = target / "compare_timing_test"
        stale.write_text("#!" + sys.executable + "\nraise SystemExit('STALE MUST NOT EXECUTE')\n")
        stale.chmod(0o755)

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.output / "report.json").is_file())

    def test_shell_keeps_five_harness_order_and_original_compile_link_profiles(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.recorded()
        self.assertEqual([e["name"] for e in events if e["tool"] == "binary"], list(NAMES))
        compiler = [e for e in events if e["tool"] == "cc"]
        self.assertEqual(len(compiler), 5)
        self.assertEqual(
            compiler[0]["args"],
            [
                "tests/constant_time/compare_timing_test.c",
                "-Iinclude",
                "-Ic",
                "-O2",
                "-std=c11",
                "-D_DEFAULT_SOURCE",
                "-o",
                "target/compare_timing_test",
                "-lm",
            ],
        )
        self.assertEqual(
            compiler[1]["args"],
            [
                "tests/constant_time/hmac_timing_test.c",
                "c/rsa_signatures.c",
                "c/jws.c",
                "-Iinclude",
                "-Ic",
                f"-I{self.bin.parent / 'include'}",
                f"-I{self.bin.parent / 'lib/krml/c'}",
                f"-I{self.bin.parent / 'lib/krml/dist/generic'}",
                "-I" + str(self.directory / "evercrypt headers"),
                "-O2",
                "-std=c11",
                "-D_DEFAULT_SOURCE",
                "-o",
                "target/hmac_timing_test",
                "-levercrypt",
                "-pthread",
                "-lmbedcrypto",
                "-lmbedx509",
                "-lm",
            ],
        )
        self.assertEqual([e["tool"] for e in events].count("pkg-config"), 2)
        self.assertTrue((self.output / "report.json").is_file())

    def test_xtask_keeps_gcc_includes_binary_layout_and_link_order(self):
        result = self.invoke(xtask=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        compiler = [e for e in self.recorded() if e["tool"] == "gcc"]
        self.assertEqual(len(compiler), 5)
        self.assertEqual(
            compiler[0]["args"],
            [
                "tests/constant_time/compare_timing_test.c",
                "-I",
                "include",
                "-I",
                "c",
                "-I",
                "tests/constant_time",
                "-O2",
                "-std=c11",
                "-D_DEFAULT_SOURCE",
                "-o",
                "target/ct/compare_timing_test",
                f"-I{self.bin.parent / 'include'}",
                f"-I{self.bin.parent / 'lib/krml/c'}",
                f"-I{self.bin.parent / 'lib/krml/dist/generic'}",
                "-I" + str(self.directory / "evercrypt headers"),
                "-lm",
                "-levercrypt",
                "-pthread",
            ],
        )
        self.assertEqual(
            compiler[1]["args"][-5:],
            ["-lmbedcrypto", "-lmbedx509", "-lm", "-levercrypt", "-pthread"],
        )
        self.assertEqual([e["name"] for e in self.recorded() if e["tool"] == "binary"], list(NAMES))

    def test_report_contains_all_actual_observations_and_profile(self):
        for profile, count in (("pr", 7), ("periodic", 8)):
            result = self.invoke(extra=("--profile", profile))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((self.output / "report.json").read_text())
            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["profile"], profile)
            self.assertEqual(set(report["cases"]), set(NAMES))
            self.assertNotIn("num_traces", report)
            self.assertEqual(len(report["cases"]["compare"]), count)

    def test_individual_leakage_or_bad_counts_stop_before_later_cases(self):
        for variable in ("LEAK", "BAD_COUNT"):
            with self.subTest(variable=variable):
                result = self.invoke(**{variable: "hmac"})
                self.assert_failed(result)
                run = self.runs()[-1]
                self.assertFalse(json.loads((run / "status.json").read_text())["accepted"])
                self.assertTrue((run / "hmac.stdout").is_file())
                self.assertEqual(
                    [e["name"] for e in self.recorded() if e["tool"] == "binary"][-2:],
                    ["compare", "hmac"],
                )

    def test_missing_malformed_nonfinite_and_ambiguous_json_is_rejected(self):
        samples = (
            b"{}\n",
            b'{"state":true,"p":0.8}\n',
            b'{"state":2,"p":0.8}\n',
            b'{"state":1,"p":"0.8"}\n',
            b'{"state":1,"p":true}\n',
            b'{"state":1,"p":NaN}\n',
            b'{"state":1,"p":Infinity}\n',
            b'{"state":1,"p":1e400}\n',
            b'{"state":1,"p":-0.1}\n',
            b'{"state":1,"p":1.1}\n',
            b'{"state":1,"p":0.8,"p":0.001}\n',
            b"[]\n",
            b'{"state":1,"p":0.8}\ntrailing\n',
            b"\xff\n",
            b"\n",
            b'{"state":1,"p":' + b"9" * 400 + b"}\n",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                result = self.invoke(RAW_HEX=sample.hex())
                self.assert_failed(result)
                self.assertIn(sample, (self.runs()[-1] / "compare.stdout").read_bytes())

    def test_nested_duplicate_and_nonfinite_fields_reject_before_publication(self):
        for sample in (
            b'{"state":1,"p":0.8,"extra":1e400}\n',
            b'{"state":1,"p":0.8,"extra":{"value":1e400}}\n',
            b'{"state":1,"p":0.8,"extra":{"value":1,"value":2}}\n',
        ):
            with self.subTest(sample=sample):
                self.assert_failed(self.invoke(RAW_HEX=sample.hex()))

    def test_compiler_failure_retains_stale_outputs_without_reusing_them(self):
        self.seed_previous()
        result = self.invoke(COMPILE_FAIL="compare")
        self.assert_failed(result)
        self.assertEqual(result.returncode, 37)
        run = self.runs()[0]
        self.assertTrue((run / "previous-results/report.json").is_file())
        self.assertTrue((run / "previous-binaries/compare_timing_test").is_file())
        self.assertIn("controlled compiler failure", (run / "compare-compile.stderr").read_text())
        self.assertFalse(any(e["tool"] == "binary" for e in self.recorded()))

    def test_exit_zero_compiler_without_valid_fresh_binary_cannot_succeed(self):
        for variable in (
            "OMIT_BINARY",
            "EMPTY_BINARY",
            "NONEXECUTABLE_BINARY",
            "DIRECTORY_BINARY",
            "SYMLINK_BINARY",
        ):
            with self.subTest(variable=variable):
                result = self.invoke(**{variable: "1"})
                self.assert_failed(result)
                self.assertFalse(any(e["tool"] == "binary" for e in self.recorded()))

    def test_harness_failure_and_signal_keep_raw_evidence_and_nonzero_status(self):
        for variable, expected in (("BINARY_FAIL", 43), ("BINARY_SIGNAL", 143)):
            with self.subTest(variable=variable):
                result = self.invoke(**{variable: "compare"})
                self.assert_failed(result)
                self.assertEqual(result.returncode, expected)
                self.assertTrue((self.runs()[-1] / "compare.process.json").is_file())

    def test_pkg_config_failure_is_nonzero_before_any_compilation(self):
        self.seed_previous()
        result = self.invoke(PKG_EXIT="29")
        self.assert_failed(result)
        self.assertEqual(result.returncode, 29)
        self.assertEqual([e["tool"] for e in self.recorded()], ["pkg-config"])
        self.assertTrue((self.runs()[0] / "previous-results/report.json").is_file())

    def test_concurrent_legacy_attempt_cannot_touch_owned_outputs(self):
        self.seed_previous()
        previous = (self.output / "report.json").read_bytes()
        with (self.output / ".legacy-run.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Another legacy dudect run", result.stderr)
        self.assertEqual((self.output / "report.json").read_bytes(), previous)
        self.assertFalse(self.events.exists())

    def test_unknown_public_options_are_rejected_by_shell_adapter(self):
        result = self.invoke(extra=("--unknown",))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.output.exists())

    def test_driver_rejects_arbitrary_profiles_without_side_effects(self):
        result = self.invoke(xtask=True, extra=("--profile", "arbitrary"))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.output.exists())

    def test_status_and_report_write_faults_do_not_publish_success(self):
        for variable in ("STATUS_DIRECTORY", "REPORT_DIRECTORY"):
            with self.subTest(variable=variable):
                result = self.invoke(**{variable: "1"})
                self.assert_failed(result)
                self.assertTrue((self.runs()[-1] / "report.json").is_file())


if __name__ == "__main__":
    unittest.main()
