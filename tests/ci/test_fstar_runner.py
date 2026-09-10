"""Exercise required F* passes with controlled tools, including false-success logs."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PASS_IDS = ("1", "1b", "2a-1", "2a-2", "2b")
PROVIDERS = (
    "HACL_FSTAR_PATH",
    "KRMLLIB_PATH",
    "STEEL_PATH",
    "EVERPARSE_FSTAR_PATH",
    "EVERPARSE_PRELUDE_PATH",
    "EVERPARSE_LOWPARSER_PATH",
)


class FstarRunnerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for path in (
            "scripts/flake/verify_fstar.sh",
            "scripts/validation/run_fstar_invocation.py",
            "scripts/validation/admit_fstar_modules.py",
            "scripts/validation/authcode_redis_fixtures.py",
            "tests/fixtures/authcode-redis-grant.json",
            "scripts/verify/verify_fstar_ci.sh",
            "scripts/verify/verify_fstar_abstract.sh",
            "scripts/flake/verify_fstar_abstract.sh",
        ):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        # Each fixture declares its own module name; no proof tool runs here.
        for directory in ("fstar", "generated/everparse", "tests/fstar"):
            for path in (ROOT / directory).rglob("*.fst*"):
                target = self.root / path.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                if path.name == "TestAuthCodeRedisGrant.fst":
                    # Keep the generated-case drift preflight real. The mock
                    # verifier still only reports requested module identities.
                    shutil.copyfile(path, target)
                else:
                    target.write_text(f"module {path.name.rsplit('.', 1)[0]}\n")
        (self.root / "fstar/Steel.Effect.fst").write_text("module Steel.Effect\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # The mock reproduces the pinned F* result grammar: one result line per
        # requested source, the completion marker and the argv echo.
        self.install_tool(
            "fstar.exe",
            """
import json, os, pathlib, signal, sys
calls = pathlib.Path(os.environ['MOCK_CALLS'])
entries = json.loads(calls.read_text()) if calls.exists() else []
entries.append(sys.argv[1:])
calls.write_text(json.dumps(entries))
print('[OK] apparent textual success', flush=True)
print('verifier stderr retained', file=sys.stderr, flush=True)
if len(entries) == int(os.environ.get('FAIL_AT', '0')):
    if os.environ.get('KILL_TOOL'):
        os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(23)
sources = [a for a in sys.argv[1:] if a.endswith(('.fst', '.fsti'))]
stems = {pathlib.Path(s).name.rsplit('.', 1)[0] for s in sources if s.endswith('.fst')}
omit = os.environ.get('OMIT_MODULE')
for source in sources:
    stem = pathlib.Path(source).name.rsplit('.', 1)[0]
    if stem == omit:
        continue
    if source.endswith('.fst'):
        print(f'Verified module: {stem}', flush=True)
    elif stem not in stems:
        print(f"Verified i'face (or impl+i'face): {stem}", flush=True)
print('All verification conditions discharged successfully', flush=True)
print('TOTAL TIME 1 ms: ' + ' '.join(sys.argv), flush=True)
""",
        )
        self.output = self.root / "output"
        self.environment = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "OUT_DIR": str(self.output),
            "MOCK_CALLS": str(self.root / "calls.json"),
        }
        for name in PROVIDERS:
            provider = self.root / "external includes" / name
            provider.mkdir(parents=True)
            self.environment[name] = str(provider)

    def install_tool(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o755)

    def invoke(self, script="scripts/flake/verify_fstar.sh", **environment):
        return subprocess.run(  # noqa: S603 - fixed script and fixture environment
            ["bash", script],  # noqa: S607 - supported shell
            cwd=self.root,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_failure_in_each_required_pass_is_fatal(self):
        for number, pass_id in enumerate(PASS_IDS, 1):
            with self.subTest(pass_id=pass_id):
                output = self.root / f"failure-{number}"
                (self.root / "calls.json").unlink(missing_ok=True)
                result = self.invoke(OUT_DIR=str(output), FAIL_AT=str(number))
                assert result.returncode == 23, result.stderr
                records = list((output / "invocations").glob("*/result.json"))
                assert len(records) == number
                record = json.loads((output / "invocations" / pass_id / "result.json").read_text())
                assert record["status"] == "failed"
                assert record["returncode"] == 23
                assert "verifier stderr retained" in (output / "verify.log").read_text()
                failure = f"[FAIL] Pass {pass_id}: F* invocation failed (exit 23)"
                assert failure in result.stderr
                assert failure in (output / "verify.log").read_text()
                assert "All five required" not in result.stderr

    def test_success_records_exact_commands_sources_and_context(self):
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        calls = json.loads((self.root / "calls.json").read_text())
        assert len(calls) == len(PASS_IDS)
        events = [
            json.loads(line.removeprefix("FSTAR-EVIDENCE "))
            for line in result.stdout.splitlines()
            if line.startswith("FSTAR-EVIDENCE ")
        ]
        for pass_id, arguments in zip(PASS_IDS, calls, strict=True):
            directory = self.output / "invocations" / pass_id
            inputs = json.loads((directory / "inputs.json").read_text())
            record = json.loads((directory / "result.json").read_text())
            assert inputs["argv"] == ["fstar.exe", *arguments]
            assert inputs["executed_argv"] == [inputs["tool"]["path"], *arguments]
            # A failed Nix build retains only the stream. Reconstruct its full
            # input record and confirm the same digest without the output tree.
            start = next(e for e in events if e["event"] == "start" and e["pass_id"] == pass_id)
            reconstructed = start["inputs"]
            for field in ("modules", "local_context"):
                entries = [e for e in events if e["event"] == field and e["pass_id"] == pass_id]
                assert [e["index"] for e in entries] == list(range(len(entries)))
                reconstructed[field] = [e["source"] for e in entries]
            encoded = (json.dumps(reconstructed, indent=2, sort_keys=True) + "\n").encode()
            assert hashlib.sha256(encoded).hexdigest() == start["inputs_sha256"]
            assert record["status"] == "succeeded"
            assert (
                record["inputs_sha256"]
                == hashlib.sha256((directory / "inputs.json").read_bytes()).hexdigest()
            )
            assert inputs["loops_origin"] == "builder-generated-assumptions"
            assert any(item["path"].endswith("/C.Loops.fst") for item in inputs["local_context"])
            for module in inputs["modules"]:
                source = self.root / "fstar" / module["path"]
                assert module["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert self.environment["HACL_FSTAR_PATH"] in calls[1]
        assert "--expose_interfaces" not in calls[0]
        assert "--expose_interfaces" in calls[1]
        assert "oidc/IdToken.fst" in calls[-1]
        assert "All five required" in result.stderr
        assert "Every requested F* module was admitted" in result.stderr
        self.assert_admission_records()

    def assert_admission_records(self):
        admission = json.loads((self.output / "admission.json").read_text())
        assert admission["status"] == "accepted"
        assert sorted(admission["passes"]) == sorted(PASS_IDS)
        for pass_id in PASS_IDS:
            path = self.output / "invocations" / pass_id / "modules.json"
            record = json.loads(path.read_text())
            assert record["status"] == "accepted"
            assert {e["disposition"] for e in record["requested"]} <= {
                "verified",
                "paired-interface",
            }
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assert admission["passes"][pass_id]["modules_sha256"] == digest

    def test_omitted_module_result_is_fatal_despite_zero_exit(self):
        result = self.invoke(OMIT_MODULE="Jose.Federation.Policy.Merge")
        assert result.returncode != 0
        assert len(json.loads((self.root / "calls.json").read_text())) == len(PASS_IDS)
        assert "All five required" in result.stderr
        assert "[FAIL] Per-module admission rejected the F* evidence" in result.stderr
        assert "Every requested F* module was admitted" not in result.stderr
        record = json.loads((self.output / "invocations/1/modules.json").read_text())
        assert record["status"] == "rejected"
        assert [e["disposition"] for e in record["requested"]] == [
            "verified",
            "missing",
            "verified",
            "verified",
        ]
        assert not (self.output / "admission.json").exists()
        events = [
            json.loads(line.removeprefix("FSTAR-ADMISSION "))
            for line in result.stdout.splitlines()
            if line.startswith("FSTAR-ADMISSION ")
        ]
        assert events[0]["pass_id"] == "1"  # noqa: S105 - pass identifier, not a secret
        assert events[0]["dispositions"] == {"verified": 3, "missing": 1}
        assert events[-1]["status"] == "rejected"

    def test_signal_termination_is_not_success(self):
        result = self.invoke(FAIL_AT="5", KILL_TOOL="1")
        assert result.returncode == 143
        record = json.loads((self.output / "invocations/2b/result.json").read_text())
        assert record["returncode"] == -15

    def test_unlaunchable_verifier_is_fatal(self):
        (self.bin / "fstar.exe").write_text("#!/nonexistent/fstar-interpreter\n")
        fallback = self.root / "fallback"
        fallback.mkdir()
        other = fallback / "fstar.exe"
        other.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
        other.chmod(0o755)
        result = self.invoke(PATH=f"{self.bin}:{fallback}:{os.environ['PATH']}")
        assert result.returncode != 0
        record = json.loads((self.output / "invocations/1/result.json").read_text())
        assert record["status"] == "failed"
        assert record["returncode"] is None
        assert record["argv"][0] == "fstar.exe"
        assert "All five required" not in result.stderr

    def test_missing_selected_source_is_fatal_before_launch(self):
        (self.root / "fstar/jose/Jose.Federation.Policy.Types.fst").unlink()
        result = self.invoke()
        assert result.returncode != 0
        assert not (self.root / "calls.json").exists()
        record = json.loads((self.output / "invocations/1/result.json").read_text())
        assert "jose/Jose.Federation.Policy.Types.fst" in record["argv"]

    def test_prior_success_cannot_be_reused(self):
        assert self.invoke().returncode == 0
        assert self.invoke(FAIL_AT="5").returncode != 0

    def test_evidence_write_failure_is_fatal(self):
        self.output.mkdir()
        (self.output / "verify.log").symlink_to("/dev/full")
        result = self.invoke()
        assert result.returncode != 0
        assert not (self.root / "calls.json").exists()

    def test_experimental_matrix_runs_all_cases_and_remembers_any_failure(self):
        for number in range(1, 6):
            with self.subTest(number=number):
                output = self.root / f"abstract-{number}"
                output.mkdir()
                (self.root / "calls.json").unlink(missing_ok=True)
                result = self.invoke(
                    "scripts/flake/verify_fstar_abstract.sh",
                    OUT_DIR=str(output),
                    FAIL_AT=str(number),
                    AEG_FSTAR_ABSTRACT_TMPDIR=str(self.root / "original"),
                    AEG_FSTAR_ABSTRACT_TMP_BASE=str(self.root / "matrix"),
                )
                assert result.returncode != 0, result.stdout
                calls = json.loads((self.root / "calls.json").read_text())
                assert len(calls) == 5, result.stdout + result.stderr
                records = [
                    json.loads(path.read_text())
                    for path in output.glob("invocations/*/result.json")
                ]
                assert sum(record["status"] == "failed" for record in records) == 1

    def test_malformed_include_is_recorded_as_a_failed_invocation(self):
        output = self.root / "malformed"
        result = subprocess.run(  # noqa: S603 - fixed script and fixture environment
            [  # noqa: S607 - supported interpreter lookup
                "python3",
                "scripts/validation/run_fstar_invocation.py",
                "--out-dir",
                str(output),
                "--pass-id",
                "probe",
                "--",
                "fstar.exe",
                "fstar/jose/Jose.Federation.Policy.Types.fst",
                "--include",
            ],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1, result.stderr
        assert "Traceback" not in result.stderr
        assert not (self.root / "calls.json").exists()
        record = json.loads((output / "invocations/probe/result.json").read_text())
        assert record["status"] == "failed"
        assert record["returncode"] is None
        assert "--include" in record["error"]
        events = [
            json.loads(line.removeprefix("FSTAR-EVIDENCE "))
            for line in result.stdout.splitlines()
            if line.startswith("FSTAR-EVIDENCE ")
        ]
        assert [e["event"] for e in events] == ["request", "finish"]
        assert events[-1]["status"] == "failed"

    def test_experiments_rerun_without_out_dir_use_fresh_directories(self):
        # The fixture environment sets OUT_DIR for the production script; the
        # direct experiment script must also be repeatable without it.
        environment = {
            **{key: value for key, value in self.environment.items() if key != "OUT_DIR"},
            "AEG_FSTAR_ABSTRACT_TMPDIR": str(self.root / "original"),
            "AEG_FSTAR_ABSTRACT_TMP_BASE": str(self.root / "matrix"),
        }
        for attempt in range(2):
            (self.root / "calls.json").unlink(missing_ok=True)
            result = subprocess.run(
                ["bash", "scripts/verify/verify_fstar_abstract.sh"],  # noqa: S607
                cwd=self.root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, f"attempt {attempt}: {result.stdout}{result.stderr}"
            assert len(json.loads((self.root / "calls.json").read_text())) == 5
        runs = sorted((self.root / "artifacts/fstar/abstract").glob("run.*"))
        assert len(runs) == 2
        for run in runs:
            assert (run / "invocations/original/result.json").exists()
            assert (run / "run.log").exists()

    def test_experiments_can_succeed_without_claiming_production_evidence(self):
        self.output.mkdir()
        result = self.invoke(
            "scripts/flake/verify_fstar_abstract.sh",
            AEG_FSTAR_ABSTRACT_TMPDIR=str(self.root / "original"),
            AEG_FSTAR_ABSTRACT_TMP_BASE=str(self.root / "matrix"),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "experimental; not production evidence" in result.stdout

    def setup_nix(self):
        self.install_tool(
            "nix",
            """
import os, pathlib, sys
print('nix build diagnostic retained')
status = int(os.environ.get('NIX_EXIT', '0'))
if status == 0:
    output = pathlib.Path(os.environ['NIX_OUTPUT'])
    pathlib.Path(sys.argv[sys.argv.index('--out-link') + 1]).symlink_to(output)
sys.exit(status)
""",
        )
        store = self.root / "store"
        # The mock build output is a real production-script run over the mock
        # verifier, so it carries invocation and admission records.
        assert self.invoke(OUT_DIR=str(store)).returncode == 0
        return {
            "FSTAR_CI_ARTIFACT_DIR": str(self.root / "hosted"),
            "NIX_OUTPUT": str(store),
        }

    def test_hosted_wrapper_retains_failed_build_log_without_stale_result(self):
        environment = self.setup_nix()
        (self.root / "result").symlink_to(self.root / "store")
        result = self.invoke("scripts/verify/verify_fstar_ci.sh", **environment, NIX_EXIT="42")
        assert result.returncode != 0
        run = next((self.root / "hosted").iterdir())
        assert "diagnostic retained" in (run / "build.log").read_text()
        assert json.loads((run / "build-result.json").read_text())["build_status"] == 42
        assert not (run / "verified-output").exists()

    def test_hosted_wrapper_retains_successful_output(self):
        result = self.invoke("scripts/verify/verify_fstar_ci.sh", **self.setup_nix())
        assert result.returncode == 0, result.stderr
        run = next((self.root / "hosted").iterdir())
        assert "All five required" in (run / "verified-output/verify.log").read_text()
        assert (run / "verified-output/admission.json").exists()
        assert "[OK] pass 2b:" in result.stdout

    def test_hosted_wrapper_rejects_output_without_replayable_admission(self):
        environment = self.setup_nix()
        store = self.root / "store"
        output = store / "invocations/2b/output.log"
        output.write_text(output.read_text().replace("Verified module: Bearer\n", "", 1))
        result = self.invoke("scripts/verify/verify_fstar_ci.sh", **environment)
        assert result.returncode != 0
        assert "F* build and evidence capture succeeded" not in result.stdout
        assert "output.log digest differs" in result.stderr
        (store / "admission.json").unlink()
        result = self.invoke("scripts/verify/verify_fstar_ci.sh", **environment)
        assert result.returncode != 0

    def test_hosted_log_capture_failure_blocks_successful_build(self):
        environment = self.setup_nix()
        self.install_tool("tee", "import sys\nsys.stdin.read()\nsys.exit(9)\n")
        result = self.invoke("scripts/verify/verify_fstar_ci.sh", **environment)
        assert result.returncode != 0
        run = next((self.root / "hosted").iterdir())
        record = json.loads((run / "build-result.json").read_text())
        assert record == {"build_status": 0, "log_status": 9}
        assert not (run / "verified-output").exists()


if __name__ == "__main__":
    unittest.main()
