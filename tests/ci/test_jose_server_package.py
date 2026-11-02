"""Check compile identity and fresh execution of the selected server profiles."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = ROOT / "scripts/validation/jose_server_test_package.py"
PROFILE = {
    "test": True,
    "opt_level": "0",
    "debuginfo": 2,
    "debug_assertions": True,
    "overflow_checks": True,
}


class JoseServerPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.executable = self.root / "target/debug/deps/aegaeon_server-fixture"
        self.executable.parent.mkdir(parents=True)
        (self.root / "crates/server").mkdir(parents=True)
        (self.root / "crates/server/Cargo.toml").touch()
        self.fixture("test result: ok. 1 passed; 0 failed; 0 ignored;")
        self.row = {
            "reason": "compiler-artifact",
            "executable": str(self.executable),
            "manifest_path": str(self.root / "crates/server/Cargo.toml"),
            "target": {"name": "aegaeon_server", "kind": ["lib"], "test": True},
            "profile": PROFILE,
            "features": ["default", "telemetry"],
        }

    def fixture(self, output, status=0):
        self.executable.write_text(
            f"#!{sys.executable}\nimport json,os,sys\n"
            f"with open({str(self.root / 'calls.jsonl')!r}, 'a') as f:\n"
            " f.write(json.dumps({'argv':sys.argv[1:],'cwd':os.getcwd()})+'\\n')\n"
            f"print({output!r})\nraise SystemExit({status})\n"
        )
        self.executable.chmod(0o755)

    def command(self, *arguments):
        return subprocess.run(  # noqa: S603 - checked-in tool and owned fixtures
            [sys.executable, str(PACKAGER), *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def install(self, *, profile="default", rows=None):
        shutil.rmtree(self.root / "output", ignore_errors=True)
        features = ["default", "telemetry"] + (["verified-claim"] if profile == "strict" else [])
        rows = (
            rows
            if rows is not None
            else [
                self.row | {"features": features},
                {"reason": "build-finished", "success": True},
            ]
        )
        (self.root / "messages.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        (self.root / "identity.json").write_text(
            json.dumps({"source": "fixture", "profile": profile})
        )
        return self.command("install", "messages.jsonl", "identity.json", "output")

    def arguments(self, profile="default"):
        return (
            ["-p", "aegaeon-server", "--lib", "selected"]
            + (["--features", "verified-claim"] if profile == "strict" else [])
            + ["--", "--nocapture"]
        )

    def test_both_profiles_execute_from_the_crate_with_original_arguments(self):
        for profile in ("default", "strict"):
            with self.subTest(profile=profile):
                result = self.install(profile=profile)
                assert result.returncode == 0, result.stderr
                receipt = json.loads((self.root / "output/build.json").read_text())
                assert receipt["scope"] == "jose-server-compilation-v1"
                assert receipt["build"] == {"source": "fixture", "profile": profile}
                for _ in range(2):
                    result = self.command("run", "output", *self.arguments(profile))
                    assert result.returncode == 0, result.stderr
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        assert (
            calls
            == [{"argv": ["selected", "--nocapture"], "cwd": str(self.root / "crates/server")}] * 4
        )

    def test_incomplete_duplicate_and_failed_builds_are_rejected(self):
        for rows in (
            [],
            [self.row],
            [{"reason": "build-finished", "success": True}],
            [self.row, self.row, {"reason": "build-finished", "success": True}],
            [self.row, {"reason": "build-finished", "success": False}],
            [self.row, {"reason": "build-finished", "success": True}] * 2,
        ):
            with self.subTest(rows=rows):
                assert self.install(rows=rows).returncode != 0
                assert not (self.root / "output/build.json").exists()

    def test_wrong_target_build_profile_features_or_executable_are_rejected(self):
        changes = [
            {"manifest_path": "/another/crates/server/Cargo.toml"},
            {"target": {"name": "other", "kind": ["lib"], "test": True}},
            {"target": {"name": "aegaeon_server", "kind": ["bin"], "test": True}},
            {"features": ["default", "telemetry", "kms-aws"]},
            {"features": ["default", "telemetry", "verified-claim"]},
            {"executable": "/bin/sh"},
            {"executable": str(self.root / "target/missing")},
        ]
        changes += [
            {"profile": PROFILE | {key: value}}
            for key, value in (
                ("test", False),
                ("opt_level", "3"),
                ("debuginfo", 0),
                ("debug_assertions", False),
                ("overflow_checks", False),
            )
        ]
        for change in changes:
            with self.subTest(change=change):
                assert (
                    self.install(
                        rows=[self.row | change, {"reason": "build-finished", "success": True}]
                    ).returncode
                    != 0
                )

    def test_changed_missing_symlinked_or_nonexecutable_package_is_rejected(self):
        for mutation in ("changed", "missing", "symlink", "mode", "receipt"):
            with self.subTest(mutation=mutation):
                assert self.install().returncode == 0
                binary = self.root / "output/libexec/jose-server-test"
                if mutation == "changed":
                    binary.write_text("changed")
                elif mutation in ("missing", "symlink"):
                    binary.unlink()
                    if mutation == "symlink":
                        binary.symlink_to(self.executable)
                elif mutation == "mode":
                    binary.chmod(0o644)
                else:
                    (self.root / "output/build.json").write_text("{}")
                assert self.command("run", "output", *self.arguments()).returncode != 0
                assert not (self.root / "calls.jsonl").exists()

    def test_profile_mismatch_and_unhandled_arguments_never_execute(self):
        assert self.install().returncode == 0
        for arguments in (
            self.arguments("strict"),
            [],
            ["--workspace"],
            ["-p", "aegaeon-server", "--lib", "", "--", "--nocapture"],
            ["-p", "aegaeon-server", "--lib", "selected", "--release", "--", "--nocapture"],
            [*self.arguments()[:-1], "--list"],
            [*self.arguments()[:-1], "--ignored"],
        ):
            with self.subTest(arguments=arguments):
                assert self.command("run", "output", *arguments).returncode != 0
                assert not (self.root / "calls.jsonl").exists()

    def test_required_helper_rejects_empty_ignored_failed_or_incomplete_execution(self):
        helper = self.root / "scripts/validation/run_required_cargo_test.sh"
        helper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/validation/run_required_cargo_test.sh", helper)
        shutil.copy2(PACKAGER, helper.with_name(PACKAGER.name))
        for output, status, expected in (
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", 0, 0),
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", 37, 37),
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", 0, 1),
            ("test result: ok. 0 passed; 0 failed; 1 ignored;", 0, 1),
            ("test result: FAILED. 0 passed; 1 failed; 0 ignored;", 0, 1),
            ("running 1 test", 0, 1),
        ):
            with self.subTest(output=output, status=status):
                self.fixture(output, status)
                assert self.install().returncode == 0
                environment = dict(os.environ, JOSE_SERVER_TEST_PACKAGE=str(self.root / "output"))
                for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
                    environment.pop(key, None)
                bash = shutil.which("bash")
                assert bash
                result = subprocess.run(  # noqa: S603 - owned fixture through the real required guard
                    [bash, str(helper), *self.arguments()],
                    cwd=self.root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                assert result.returncode == expected, result.stderr


if __name__ == "__main__":
    unittest.main()
