"""Keep the complete RFC execution inventory, failures and nonempty obligations."""

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
PACKAGER = ROOT / "scripts/validation/rfc_test_package.py"
PROFILE = {
    "test": True,
    "opt_level": "0",
    "debuginfo": 2,
    "debug_assertions": True,
    "overflow_checks": True,
}


class RfcTestPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.build = self.root / "build"
        self.build.mkdir()
        self.rows = {}
        packages = []
        for group, targets in (
            ("server", (("aegaeon_server", "lib"), ("server", "bin"), ("rfc_extra", "test"))),
            ("jose", (("rfc7520_vectors", "test"),)),
        ):
            manifest = self.root / f"crates/{group}/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.touch()
            metadata = []
            rows = []
            for name, kind in targets:
                target = {"name": name, "kind": [kind], "test": True}
                metadata.append(target)
                binary = self.root / "target/debug" / name
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text(
                    f"#!{sys.executable}\nimport os,sys,json\n"
                    f"with open({str(self.root / 'calls.jsonl')!r},'a') as f:\n"
                    f" f.write(json.dumps({{'target':{name!r},'args':sys.argv[1:],"
                    "'cwd':os.getcwd()})+'\\n')\n"
                    "print(os.environ.get('RFC_OUTPUT',"
                    "'test result: ok. 1 passed; 0 failed; 0 ignored;'))\n"
                    f"raise SystemExit(41 if os.environ.get('FAIL_TARGET')=={name!r} else 0)\n"
                )
                binary.chmod(0o755)
                rows.append(
                    {
                        "reason": "compiler-artifact",
                        "target": target,
                        "manifest_path": str(manifest),
                        "executable": str(binary),
                        "profile": dict(PROFILE),
                        "features": ["default", "telemetry"] if group == "server" else ["default"],
                    }
                )
            packages.append({"manifest_path": str(manifest), "targets": metadata})
            self.rows[group] = [*rows, {"reason": "build-finished", "success": True}]
        (self.build / "metadata.json").write_text(json.dumps({"packages": packages}))
        (self.build / "doc-list.txt").write_text("0 tests, 0 benchmarks\n")
        (self.root / "identity").write_text('{"source":"owned-fixture"}')
        self.tools = self.root / "tools"
        self.tools.mkdir()
        cargo = self.tools / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\nimport os,pathlib,sys\n"
            "assert sys.argv[1:] == ['metadata','--locked','--no-deps','--format-version=1']\n"
            "if os.environ.get('METADATA_EXIT'): sys.exit(int(os.environ['METADATA_EXIT']))\n"
            f"print(pathlib.Path({str(self.build / 'metadata.json')!r}).read_text())\n"
        )
        cargo.chmod(0o755)

    def command(self, *args, **environment):
        return subprocess.run(  # noqa: S603 - checked-in module and owned fixture
            [sys.executable, str(PACKAGER), *args],
            cwd=self.root,
            env={**os.environ, "PATH": f"{self.tools}:{os.environ['PATH']}", **environment},
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def install(self):
        shutil.rmtree(self.root / "out", ignore_errors=True)
        for group, rows in self.rows.items():
            (self.build / f"{group}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        return self.command("install", "build", "identity", "out")

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []

    def run_group(self, group, **environment):
        args = (
            ["--package", "aegaeon-server", "rfc_tests", "--no-fail-fast"]
            if group == "server"
            else ["--package", "aegaeon-jose", "--test", "rfc7520_vectors"]
        )
        return self.command("run", "out", *args, **environment)

    def test_all_targets_filters_crate_directories_and_fresh_execution(self):
        result = self.install()
        assert result.returncode == 0, result.stderr
        for _ in range(2):
            for group in ("server", "jose"):
                assert self.run_group(group).returncode == 0
        expected = [
            {
                "target": n,
                "args": ["rfc_tests"] if g == "server" else [],
                "cwd": str(self.root / f"crates/{g}"),
            }
            for g, n in (
                ("server", "aegaeon_server"),
                ("server", "server"),
                ("server", "rfc_extra"),
                ("jose", "rfc7520_vectors"),
            )
        ]
        assert self.calls() == expected * 2

    def test_no_fail_fast_runs_later_targets_without_losing_failure(self):
        assert self.install().returncode == 0
        assert self.run_group("server", FAIL_TARGET="aegaeon_server").returncode == 41
        assert [r["target"] for r in self.calls()] == ["aegaeon_server", "server", "rfc_extra"]

    def test_missing_duplicate_failed_or_changed_build_is_rejected(self):
        original = self.rows["server"]
        mutations = [
            [],
            original[1:],
            original[:-1],
            [*original, original[0]],
            [*original[:-1], {"reason": "build-finished", "success": False}],
        ]
        mutations += [
            [original[0] | change, *original[1:]]
            for change in (
                {"profile": PROFILE | {"opt_level": "3"}},
                {"features": ["default"]},
                {"manifest_path": "/elsewhere/Cargo.toml"},
                {"executable": "/bin/sh"},
            )
        ]
        for rows in mutations:
            with self.subTest(rows=rows):
                self.rows["server"] = rows
                assert self.install().returncode != 0
                assert not (self.root / "out/build.json").exists()
        self.rows["server"] = original

    def test_matching_or_unknown_doctest_inventory_cannot_be_omitted(self):
        for value in (
            "",
            "1 test, 0 benchmarks",
            "rfc_tests (line 1): test\n1 test, 0 benchmarks",
            "unknown",
        ):
            with self.subTest(value=value):
                (self.build / "doc-list.txt").write_text(value)
                assert self.install().returncode != 0

    def test_bad_receipt_or_executable_prevents_any_target_execution(self):  # noqa: PLR0912 - independent corruption matrix
        for mutation in (
            "missing",
            "bytes",
            "mode",
            "symlink",
            "inventory",
            "profile",
            "order",
            "doctest",
        ):
            with self.subTest(mutation=mutation):
                assert self.install().returncode == 0
                path = self.root / "out/libexec/server/test:rfc_extra"
                if mutation == "missing":
                    path.unlink()
                elif mutation == "bytes":
                    path.write_text("changed")
                elif mutation == "mode":
                    path.chmod(0o644)
                elif mutation == "symlink":
                    path.unlink()
                    path.symlink_to(self.root / "target/debug/rfc_extra")
                else:
                    path = self.root / "out/build.json"
                    data = json.loads(path.read_text())
                    if mutation == "inventory":
                        del data["groups"]["server"]["binaries"]["test:rfc_extra"]
                    elif mutation == "profile":
                        data["groups"]["server"]["binaries"]["test:rfc_extra"]["profile"][
                            "test"
                        ] = False
                    elif mutation == "order":
                        data["groups"]["server"]["order"].append("lib:aegaeon_server")
                    else:
                        data["matching_doctests"] = 1
                    path.write_text(json.dumps(data))
                assert self.run_group("server").returncode != 0
                assert not self.calls()

    def test_consistently_removed_target_is_rejected_before_execution(self):
        assert self.install().returncode == 0
        receipt = self.root / "out/build.json"
        data = json.loads(receipt.read_text())
        target = "test:rfc_extra"
        data["groups"]["server"]["order"].remove(target)
        del data["groups"]["server"]["binaries"][target]
        receipt.write_text(json.dumps(data))
        (self.root / "out/libexec/server" / target).unlink()
        result = self.run_group("server")
        assert result.returncode != 0, result.stdout + result.stderr
        assert not self.calls()

    def test_current_metadata_failure_added_target_and_order_change_are_rejected(self):
        assert self.install().returncode == 0
        result = self.run_group("server", METADATA_EXIT="31")
        assert result.returncode != 0
        assert not self.calls()
        metadata = self.build / "metadata.json"
        original = metadata.read_text()
        for target in (
            {"name": "new_rfc", "kind": ["test"], "test": True},
            {"name": "new_example", "kind": ["example"], "test": True},
        ):
            data = json.loads(original)
            data["packages"][0]["targets"].append(target)
            metadata.write_text(json.dumps(data))
            assert self.run_group("server").returncode != 0
            assert not self.calls()
        metadata.write_text(original)
        receipt = self.root / "out/build.json"
        data = json.loads(receipt.read_text())
        data["groups"]["server"]["order"].reverse()
        receipt.write_text(json.dumps(data))
        assert self.run_group("server").returncode != 0
        assert not self.calls()

    def test_unhandled_cargo_or_runtime_flags_do_not_execute(self):
        assert self.install().returncode == 0
        for args in (
            ["--workspace"],
            ["--package", "aegaeon-server", "--lib", "rfc_tests"],
            ["--package", "aegaeon-server", "rfc_tests", "--no-fail-fast", "--", "--list"],
        ):
            assert self.command("run", "out", *args).returncode != 0
        assert not self.calls()

    def test_real_required_guard_rejects_empty_or_failed_component(self):
        assert self.install().returncode == 0
        scripts = self.root / "scripts/validation"
        scripts.mkdir(parents=True)
        for name in (
            "run_required_cargo_test.sh",
            "rfc_test_package.py",
            "jose_server_test_package.py",
        ):
            shutil.copy2(ROOT / "scripts/validation" / name, scripts / name)
        bash = shutil.which("bash")
        assert bash
        for output, expected in (
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", 0),
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", 1),
            ("test result: ok. 0 passed; 0 failed; 1 ignored;", 1),
            ("running 1 test", 1),
            ("test result: FAILED. 0 passed; 1 failed; 0 ignored;", 1),
        ):
            result = subprocess.run(  # noqa: S603 - real guard and owned fixture
                [
                    bash,
                    str(scripts / "run_required_cargo_test.sh"),
                    "--package",
                    "aegaeon-server",
                    "rfc_tests",
                    "--no-fail-fast",
                ],
                cwd=self.root,
                env={
                    **os.environ,
                    "PATH": f"{self.tools}:{os.environ['PATH']}",
                    "AEGAEON_RFC_TEST_PACKAGE": str(self.root / "out"),
                    "RFC_OUTPUT": output,
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == expected, result.stderr

    def test_whole_script_requires_both_components_without_retry(self):
        scripts = self.root / "scripts/validation"
        scripts.mkdir(parents=True)
        for name in ("run_required_cargo_test.sh", "test_rfc_compliance.sh"):
            shutil.copy2(ROOT / "scripts/validation" / name, scripts / name)
        cargo = self.root / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\nimport os,sys,json\n"
            "group='SERVER' if 'aegaeon-server' in sys.argv else 'JOSE'\n"
            "with open('cargo-calls','a') as f: f.write(group+'\\n')\n"
            "count=os.environ[group+'_COUNT']\n"
            "print('test result: ok. '+count+' passed; 0 failed; 0 ignored;')\n"
            "raise SystemExit(int(os.environ.get(group+'_EXIT','0')))\n"
        )
        cargo.chmod(0o755)
        bash = shutil.which("bash")
        assert bash
        for server, jose, status, expected in (
            ("1", "1", "0", 0),
            ("0", "1", "0", 1),
            ("1", "0", "0", 1),
            ("1", "1", "31", 1),
        ):
            (self.root / "cargo-calls").unlink(missing_ok=True)
            env = {
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "SERVER_COUNT": server,
                "JOSE_COUNT": jose,
                "SERVER_EXIT": status,
            }
            for key in (
                "AEGAEON_RFC_TEST_PACKAGE",
                "AEGAEON_DATABASE_TEST_PACKAGE",
                "JOSE_SERVER_TEST_PACKAGE",
                "BASH_ENV",
                "ENV",
            ):
                env.pop(key, None)
            result = subprocess.run(  # noqa: S603 - actual script and controlled Cargo
                [bash, str(scripts / "test_rfc_compliance.sh")],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == expected, result.stdout + result.stderr
            assert (self.root / "cargo-calls").read_text().splitlines() == ["SERVER", "JOSE"]
