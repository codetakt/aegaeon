"""Run the KMS parity wrapper with controlled Cargo and service outcomes."""

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
WRAPPER = ROOT / "scripts/validation/run_oidc_kms_parity.sh"
VALIDATOR = ROOT / "scripts/validation/validate_oidc_kms_execution.py"
TEST_NAME = (
    "oidc::config::tests::kms_parity::"
    "test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt"
)
SUCCESS = (
    "    Finished `test` profile [unoptimized + debuginfo]\n"
    "running 1 test\n"
    f"test {TEST_NAME} ... ok\n\n"
    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
    "2510 filtered out; finished in 0.31s\n"
)
FAKE_TOOL = """import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
if name == "cargo":
    with Path("commands.jsonl").open("a") as stream:
        stream.write(json.dumps(sys.argv[1:]) + "\\n")
    sys.stdout.write(Path("cargo-output.txt").read_text())
    raise SystemExit(int(os.environ.get("CARGO_FIXTURE_EXIT", "0")))
if name == "curl":
    print("{}")
    raise SystemExit(int(os.environ.get("CURL_FIXTURE_EXIT", "0")))
if name == "nix":
    with Path("nix-commands.jsonl").open("a") as stream:
        stream.write(json.dumps(sys.argv[1:]) + "\\n")
    print(os.environ["NIX_FIXTURE_OUTPUT"])
    raise SystemExit(int(os.environ.get("NIX_FIXTURE_EXIT", "0")))
if name == "tee":
    counter = Path("tee-count")
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    if count == int(os.environ.get("TEE_FIXTURE_FAIL_AT", "2")):
        sys.stdin.buffer.read()
        raise SystemExit(41)
    os.execv(os.environ["REAL_TEE"], ["tee", *sys.argv[1:]])
raise SystemExit("unexpected test tool")
"""


class KmsExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ("cargo", "curl"):
            self.tool(tool)
        self.environment = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.root),
            "LC_ALL": "C",
            "REAL_TEE": shutil.which("tee"),
        }

    def tool(self, name):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n{FAKE_TOOL}")
        path.chmod(0o755)

    def run_wrapper(self, output=SUCCESS, *, mode="localstack", arguments=(), **environment):
        (self.root / "cargo-output.txt").write_text(output)
        env = {**self.environment, "AEG_OIDC_KMS_MODE": mode, **environment}
        if mode == "aws":
            env.update(
                AWS_REGION="us-east-1",
                AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID="fixture-key",
                AEGAEON_OIDC_SIGNING_KID="fixture-kid",
            )
        return subprocess.run(  # noqa: S603 - checked-in wrapper with isolated controlled tools
            [shutil.which("bash"), str(WRAPPER), *arguments],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def summary(self):
        return json.loads((self.root / "artifacts/oidc-kms/summary.json").read_text())

    def test_both_modes_require_the_same_exact_test_and_bind_its_log(self):
        for mode in ("localstack", "aws"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode=mode)
                assert result.returncode == 0, result.stderr
                assert self.summary()["status"] == "passed"
                receipt = json.loads((self.root / "artifacts/oidc-kms/execution.json").read_text())
                assert receipt["test"] == TEST_NAME
                assert receipt["log_sha256"] == hashlib.sha256(SUCCESS.encode()).hexdigest()
                assert receipt["log_bytes"] == len(SUCCESS.encode())
                command = json.loads((self.root / "commands.jsonl").read_text().splitlines()[-1])
                assert command == [
                    "test",
                    "-p",
                    "aegaeon-server",
                    "--features",
                    "kms-aws",
                    "--lib",
                    TEST_NAME,
                    "--",
                    "--exact",
                    "--nocapture",
                    "--color",
                    "never",
                ]

    def test_zero_test_success_cannot_be_reported_as_parity(self):
        output = (
            "running 0 tests\n"
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2511 filtered out\n"
        )
        result = self.run_wrapper(output)
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"

    def test_missing_wrong_duplicate_ignored_and_incomplete_results_fail(self):
        cases = (
            "",
            "Compilation finished successfully\n",
            SUCCESS.replace(TEST_NAME, "unrelated::parity_test"),
            SUCCESS + SUCCESS,
            SUCCESS.replace(" ... ok", " ... ignored"),
            SUCCESS.replace("1 passed; 0 failed", "0 passed; 1 failed"),
            SUCCESS.replace("0 ignored", "1 ignored"),
            SUCCESS.replace("0 measured", "1 measured"),
            SUCCESS.replace("running 1 test", "running 2 tests"),
            "\n".join(SUCCESS.splitlines()[:-1]),
            SUCCESS + f"test {TEST_NAME}_other ... ok\n",
        )
        for output in cases:
            with self.subTest(output=output):
                result = self.run_wrapper(output)
                assert result.returncode != 0
                assert self.summary()["status"] == "failed"

    def test_optional_localstack_skip_is_incomplete_even_when_libtest_reports_ok(self):
        output = "LocalStack not available, skipping OIDC AWS KMS signing test\n" + SUCCESS
        result = self.run_wrapper(output, AEG_KMS_REQUIRE_LOCALSTACK="0")
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"

    def test_cargo_failure_with_success_text_remains_failure(self):
        result = self.run_wrapper(CARGO_FIXTURE_EXIT="37")
        assert result.returncode == 37
        assert self.summary()["status"] == "failed"
        assert not (self.root / "artifacts/oidc-kms/execution.json").exists()

    def test_log_write_failure_cannot_produce_execution_receipt(self):
        self.tool("tee")
        result = self.run_wrapper()
        assert result.returncode == 41
        assert self.summary()["status"] == "failed"
        assert (self.root / "commands.jsonl").is_file()
        assert (self.root / "tee-count").read_text() == "2"
        assert not (self.root / "artifacts/oidc-kms/execution.json").exists()

    def test_failed_service_preflight_removes_stale_success_evidence(self):
        result = self.run_wrapper()
        assert result.returncode == 0, result.stderr
        calls = (self.root / "commands.jsonl").read_bytes()
        result = self.run_wrapper(CURL_FIXTURE_EXIT="22", AEG_OIDC_KMS_LOCALSTACK_WAIT_SECONDS="0")
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"
        assert (self.root / "commands.jsonl").read_bytes() == calls
        assert not (self.root / "artifacts/oidc-kms/test.log").exists()
        assert not (self.root / "artifacts/oidc-kms/execution.json").exists()

    def test_invalid_mode_retry_clears_success_without_running_cargo(self):
        assert self.run_wrapper().returncode == 0
        calls = (self.root / "commands.jsonl").read_bytes()
        result = self.run_wrapper(mode="invalid")
        assert result.returncode == 2
        assert "must be localstack or aws" in result.stderr
        assert self.summary()["status"] == "failed"
        assert self.summary()["mode"] == "invalid"
        assert (self.root / "commands.jsonl").read_bytes() == calls
        assert not (self.root / "artifacts/oidc-kms/test.log").exists()
        assert not (self.root / "artifacts/oidc-kms/execution.json").exists()

    def test_failed_retry_cannot_reuse_previous_execution_receipt(self):
        assert self.run_wrapper().returncode == 0
        assert self.run_wrapper("running 0 tests\n").returncode != 0
        assert self.summary()["status"] == "failed"
        assert (self.root / "artifacts/oidc-kms/execution.json").read_text() == ""

    def test_execution_receipt_write_failure_keeps_failed_status(self):
        # A directory prevents both stale-file removal and receipt publication.
        target = self.root / "artifacts/oidc-kms/execution.json"
        target.mkdir(parents=True)
        result = self.run_wrapper()
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"
        assert not (self.root / "commands.jsonl").exists()

    def test_validator_rejects_missing_and_non_utf8_logs(self):
        log = self.root / "log"
        for contents in (None, b"\xff"):
            with self.subTest(contents=contents):
                if contents is not None:
                    log.write_bytes(contents)
                result = subprocess.run(  # noqa: S603 - checked-in parser with owned invalid input
                    [sys.executable, str(VALIDATOR), str(log)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                assert result.returncode != 0
                assert result.stdout == ""

    def compiled_package(self):
        self.tool("nix")
        package = self.root / "compiled-test"
        executable = package / "libexec/oidc-kms-test"
        executable.parent.mkdir(parents=True)
        executable.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\nfrom pathlib import Path\n"
            f"root = Path({str(self.root)!r})\n"
            "with (root / 'executions.jsonl').open('a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "(root / 'execution-cwd.txt').write_text(str(Path.cwd()))\n"
            "print((root / 'cargo-output.txt').read_text(), end='')\n"
            "raise SystemExit(int(os.environ.get('COMPILED_FIXTURE_EXIT', '0')))\n"
        )
        executable.chmod(0o755)
        receipt = {
            "schema_version": 1,
            "scope": "compilation-only",
            "test": TEST_NAME,
            "executable": "libexec/oidc-kms-test",
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "features": ["default", "kms-aws", "telemetry"],
            "profile": {"test": True, "debug_assertions": True, "opt_level": "0"},
            "build": {"source": "fixture-source"},
        }
        (package / "build.json").write_text(json.dumps(receipt))
        self.environment["NIX_FIXTURE_OUTPUT"] = str(package)
        return package

    def test_compiled_package_runs_fresh_exact_test_on_every_attempt(self):
        package = self.compiled_package()
        for _ in range(2):
            result = self.run_wrapper(arguments=("--nix",))
            assert result.returncode == 0, result.stderr
            assert self.summary()["status"] == "passed"
            assert self.summary()["execution_backend"] == "nix"
        expected = [TEST_NAME, "--exact", "--nocapture", "--color", "never"]
        calls = [
            json.loads(line) for line in (self.root / "executions.jsonl").read_text().splitlines()
        ]
        assert calls == [expected, expected]
        assert (self.root / "execution-cwd.txt").read_text() == str(ROOT / "crates/server")
        assert not (self.root / "commands.jsonl").exists()
        builds = [
            json.loads(line) for line in (self.root / "nix-commands.jsonl").read_text().splitlines()
        ]
        assert builds == [["build", "--no-link", "--print-out-paths", f"{ROOT}#oidc-kms-test"]] * 2
        receipt = json.loads((self.root / "artifacts/oidc-kms/build.json").read_text())
        assert receipt["package"] == str(package)
        assert receipt["scope"] == "compilation-only"

    def test_compiled_execution_keeps_failure_and_completion_checks(self):
        self.compiled_package()
        for env, output in (({"COMPILED_FIXTURE_EXIT": "37"}, SUCCESS), ({}, "running 0 tests\n")):
            with self.subTest(env=env, output=output):
                result = self.run_wrapper(output, arguments=("--nix",), **env)
                assert result.returncode != 0
                assert self.summary()["status"] == "failed"

    def test_compiled_package_build_failure_or_mutation_never_falls_back(self):
        package = self.compiled_package()
        assert self.run_wrapper(arguments=("--nix",)).returncode == 0
        calls = (self.root / "executions.jsonl").read_bytes()
        result = self.run_wrapper(arguments=("--nix",), NIX_FIXTURE_EXIT="23")
        assert result.returncode == 23
        (package / "libexec/oidc-kms-test").write_text("changed")
        assert self.run_wrapper(arguments=("--nix",)).returncode != 0
        assert self.summary()["status"] == "failed"
        assert (self.root / "executions.jsonl").read_bytes() == calls
        assert not (self.root / "commands.jsonl").exists()
        assert not (self.root / "artifacts/oidc-kms/execution.json").exists()

    def test_compiled_path_still_requires_live_service_preflight(self):
        self.compiled_package()
        result = self.run_wrapper(
            arguments=("--nix",), CURL_FIXTURE_EXIT="22", AEG_OIDC_KMS_LOCALSTACK_WAIT_SECONDS="0"
        )
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"
        assert not (self.root / "executions.jsonl").exists()

    def test_invalid_arguments_or_package_output_cannot_run_a_test(self):
        self.compiled_package()
        for arguments in (("--other",), ("--nix", "extra")):
            result = self.run_wrapper(arguments=arguments)
            assert result.returncode == 2
        for output in ("", "relative/path", "/first\n/second", "/missing/output"):
            result = self.run_wrapper(arguments=("--nix",), NIX_FIXTURE_OUTPUT=output)
            assert result.returncode != 0
        assert not (self.root / "executions.jsonl").exists()
        assert not (self.root / "commands.jsonl").exists()


if __name__ == "__main__":
    unittest.main()
