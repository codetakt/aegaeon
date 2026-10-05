"""Directed immutable supplier controls using inert binaries, not native builds."""
# ruff: noqa: PT009, PT027 - unittest controls remain effective under Python -O

from __future__ import annotations

import contextlib
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_perf_source_manifest as source_controls
from perf_supplier_fixture import module, prepare

PRODUCER = source_controls.PRODUCER
SOURCE = source_controls.SOURCE


class PerfSupplierTests(unittest.TestCase):
    setUp = source_controls.PerfSourceManifestTests.setUp
    git = source_controls.PerfSourceManifestTests.git
    write = source_controls.PerfSourceManifestTests.write
    restore_runner_mode = source_controls.PerfSourceManifestTests.restore_runner_mode
    invoke = source_controls.PerfSourceManifestTests.invoke
    freeze = source_controls.PerfSourceManifestTests.freeze
    runner = source_controls.PerfSourceManifestTests.runner

    def fixture_context(self):
        workload = self.write("target/release/aegaeon-loadtest", b"inert workload\n", 0o755)
        controller = prepare(
            SOURCE,
            self.root,
            self.owner,
            PRODUCER,
            workload,
            runtime_path=self.environment["PATH"],
        )
        supplier = module(SOURCE)
        context_path = self.owner / "supplier/context.json"
        helper = supplier.source_module(self.owner / "supplier/source")
        context = supplier.SupplierContext(
            helper,
            str(context_path),
            supplier.sha256(context_path.read_bytes()),
            str(shutil.which("git")),
        )
        return supplier, context, controller

    def test_supplier_pair_requires_real_selected_observations_and_exact_installation(self):
        supplier = module(SOURCE)
        original = self.owner / "original"
        original.mkdir()
        for name in supplier.BINARIES:
            path = original / name
            path.write_bytes(("inert " + name).encode())
            path.chmod(0o755)
        graph = {"packages": [{"name": "aegaeon-loadtest", "id": "control-package"}]}
        observations = [
            {
                "reason": "compiler-artifact",
                "package_id": "control-package",
                "target": {"name": name, "kind": ["bin"]},
                "executable": str(original / name),
            }
            for name in supplier.BINARIES
        ]
        observations.append({"reason": "build-finished", "success": True})
        with contextlib.chdir(self.owner):
            pathlib.Path("loadtest-graph.json").write_text(json.dumps(graph))
            pathlib.Path("Cargo.lock").write_bytes(b"control locked dependencies\n")
            for case, rows in (
                ("missing", observations[1:]),
                ("duplicate", [observations[0], *observations]),
                ("failed", [*observations[:-1], {"reason": "build-finished", "success": False}]),
            ):
                with self.subTest(case=case):
                    pathlib.Path("loadtest-build.jsonl").write_text(
                        "\n".join(json.dumps(row) for row in rows) + "\n"
                    )
                    with self.assertRaises(ValueError):
                        supplier.install_pair(self.owner / case, ["controlled-cargo"], {})
            pathlib.Path("loadtest-build.jsonl").write_text(
                "\n".join(json.dumps(row) for row in observations) + "\n"
            )
            output = self.owner / "installed"
            supplier.install_pair(output, ["controlled-cargo"], {})
            build = json.loads((output / "share/aegaeon-perf/build.json").read_bytes())
            for name in supplier.BINARIES:
                self.assertEqual(
                    (output / "bin" / name).read_bytes(), (original / name).read_bytes()
                )
                self.assertEqual(
                    build["executables"][name]["original_build_path"], str(original / name)
                )
                self.assertEqual(
                    build["executables"][name]["sha256"],
                    build["executables"][name]["original_sha256"],
                )
            alias = original / supplier.BINARIES[0]
            raw = alias.read_bytes()
            alias.unlink()
            alias.symlink_to(original / supplier.BINARIES[1])
            with self.assertRaises(ValueError):
                supplier.install_pair(self.owner / "alias", ["controlled-cargo"], {})
            self.assertEqual((output / "bin" / supplier.BINARIES[0]).read_bytes(), raw)

    def test_missing_changed_supplier_members_fail_before_worktree_reads(self):
        _supplier, context, _controller = self.fixture_context()
        _, producer, _ = context.validate()
        paths = [
            context.path,
            pathlib.Path(producer["source_inventory"]["path"]),
            *(pathlib.Path(row["path"]) for row in producer["executables"].values()),
            pathlib.Path(producer["build"]["cargo_log"]["path"]),
            pathlib.Path(producer["build"]["resolved_graph"]["path"]),
        ]
        for path in paths:
            for change in ("missing", "bytes"):
                with self.subTest(path=path.name, change=change):
                    raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
                    if change == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(raw + b"changed")
                    with (
                        patch.object(
                            context.helper,
                            "read_source",
                            side_effect=RuntimeError("source read reached"),
                        ),
                        self.assertRaises((OSError, ValueError)),
                    ):
                        context.admit(self.root)
                    path.write_bytes(raw)
                    path.chmod(mode)
        context.admit(self.root)
        self.assertFalse(self.evidence.exists())

    def test_unknown_or_mixed_supplier_schema_and_package_are_rejected(self):
        supplier, context, _controller = self.fixture_context()
        raw, producer, _ = context.validate()
        for changed in (
            {**producer, "schema_version": True},
            {**producer, "caller_hash": "untrusted"},
            {**producer, "build": {**producer["build"], "features": "changed", "unknown": 1}},
        ):
            with self.subTest(change=changed.keys()):
                context.path.write_bytes(supplier.canonical(changed))
                modeled = supplier.SupplierContext(
                    context.helper,
                    str(context.path),
                    supplier.sha256(context.path.read_bytes()),
                    context.git,
                )
                with self.assertRaises(ValueError):
                    modeled.validate()
        mixed = copy.deepcopy(producer)
        mixed["executables"]["aegaeon-loadtest-url-check"]["package_id"] = "other-package"
        context.path.write_bytes(supplier.canonical(mixed))
        modeled = supplier.SupplierContext(
            context.helper,
            str(context.path),
            supplier.sha256(context.path.read_bytes()),
            context.git,
        )
        with self.assertRaisesRegex(ValueError, "selected package"):
            modeled.validate()
        context.path.write_bytes(raw)
        context.admit(self.root)

    def test_complete_source_admits_dirty_staged_bytes_then_rejects_docs_modes_and_extra_files(
        self,
    ):
        self.write("tracked.txt", b"worktree after a different staged blob\n")
        self.write("docs/supplier-control.md", b"full domain\n")
        self.write("ROOT-CONTROL.md", b"root prose\n")
        self.git(self.root, "add", "--force", "docs/supplier-control.md", "ROOT-CONTROL.md")
        _supplier, context, _controller = self.fixture_context()
        domain = context.helper.git_domain(self.root)
        files, _ = context.helper.read_source(self.root, domain)
        self.assertNotEqual(
            domain["index"]["tracked.txt"]["git_blob"], files["tracked.txt"]["git_blob"]
        )
        context.admit(self.root)
        index = (self.root / ".git/index").read_bytes()
        for name, mutation in (
            ("docs/supplier-control.md", "bytes"),
            ("ROOT-CONTROL.md", "mode"),
            ("untracked-source", "extra"),
        ):
            with self.subTest(name=name, mutation=mutation):
                path = self.root / name
                previous = path.read_bytes() if path.exists() else None
                if mutation == "mode":
                    path.chmod(0o755)
                else:
                    path.write_bytes(b"changed full-domain member\n")
                with self.assertRaises((ValueError, context.helper.SourceError)):
                    context.admit(self.root)
                if previous is None:
                    path.unlink()
                else:
                    path.write_bytes(previous)
                    path.chmod(0o644)
        self.assertEqual((self.root / ".git/index").read_bytes(), index)
        self.assertFalse(self.evidence.exists())

    def test_early_issuer_rejection_preserves_prior_outputs_without_setup_or_probe(self):
        directory = self.root / "artifacts/perf/runner"
        directory.mkdir(parents=True)
        previous = directory / "source-status.json"
        previous.write_bytes(b"preserve prior status\n")
        before_index = (self.root / ".git/index").read_bytes()
        result = self.runner(
            managed=True,
            arguments=("--discovery-expected-issuer", "https://ISSUER.example.test"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("https://ISSUER.example.test", result.stdout + result.stderr)
        self.assertEqual(previous.read_bytes(), b"preserve prior status\n")
        self.assertEqual(list(directory.iterdir()), [previous])
        self.assertEqual((self.root / ".git/index").read_bytes(), before_index)
        self.assertFalse((self.owner / "tool-calls").exists())

    def test_workload_binding_keeps_source_and_actual_hash_and_rejects_evidence_changes(self):
        source_sha256 = self.freeze()
        workload = self.write(
            "target/release/aegaeon-loadtest", b"inert selected workload\n", 0o755
        )
        result = self.invoke("bind", "--sha256", source_sha256, "--name", "aegaeon-loadtest")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(workload))
        path = self.evidence / "aegaeon-loadtest.json"
        binding = json.loads(path.read_bytes())
        supplier = module(SOURCE)
        self.assertEqual(binding["schema_version"], 2)
        self.assertEqual(binding["source_manifest_sha256"], source_sha256)
        self.assertEqual(binding["artifact_sha256"], supplier.sha256(workload.read_bytes()))
        for filename in (
            "LOADTEST-SUPPLIER.json",
            "LOADTEST-SUPPLIER-BUILD.jsonl",
            "LOADTEST-SUPPLIER-GRAPH.json",
        ):
            with self.subTest(retained=filename):
                retained = self.evidence / filename
                original = retained.read_bytes()
                retained.chmod(0o644)
                retained.write_bytes(original + b"changed retained evidence")
                retained.chmod(0o444)
                self.assertNotEqual(
                    self.invoke(
                        "binary", "--sha256", source_sha256, "--name", "aegaeon-loadtest"
                    ).returncode,
                    0,
                )
                retained.chmod(0o644)
                retained.write_bytes(original)
                retained.chmod(0o444)
        for key, replacement in (
            ("schema_version", True),
            ("build_success", 1),
            ("supplier_binding_sha256", "0" * 64),
            ("executable", "caller-controlled"),
        ):
            with self.subTest(field=key):
                path.chmod(0o644)
                path.write_text(json.dumps({**binding, key: replacement}))
                path.chmod(0o444)
                self.assertNotEqual(
                    self.invoke(
                        "binary", "--sha256", source_sha256, "--name", "aegaeon-loadtest"
                    ).returncode,
                    0,
                )
        path.chmod(0o644)
        path.write_text(json.dumps(binding))
        path.chmod(0o444)
        self.assertEqual(
            self.invoke(
                "binary", "--sha256", source_sha256, "--name", "aegaeon-loadtest"
            ).returncode,
            0,
        )

    def test_generated_entry_ignores_caller_tools_python_and_shell_startup(self):
        result = self.runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        # A second invocation with a fresh report directory uses the same fixed closure.
        controller = self.owner / "supplier/controller/aegaeon-perf-load"
        marker = self.owner / "startup-reached"
        hostile = self.owner / "hostile-tools"
        hostile.mkdir()
        for name in ("git", "python3"):
            path = hostile / name
            path.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n"
            )
            path.chmod(0o755)
        startup = self.owner / "bash-startup"
        startup.write_text(f"touch {str(marker)!r}\n")
        environment = {
            **self.last_runner_environment,
            "PATH": str(hostile),
            "PYTHONPATH": str(hostile),
            "BASH_ENV": str(startup),
            "AEG_LOADTEST_SUPPLIER_PATH": "caller-controlled",
        }
        rejected = subprocess.run(  # noqa: S603 - actual generated entry with owned hostile startup fixtures
            [str(controller), "--url", "https://example.invalid"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertFalse(marker.exists())
        environment.pop("AEG_LOADTEST_SUPPLIER_PATH")
        environment.update(
            {
                "ARTIFACT_DIR": "artifacts/perf/repeated",
                "REPORT_PATH": "artifacts/perf/repeated/report.json",
                "SERVER_LOG": "artifacts/perf/repeated/server.log",
                "LOADTEST_LOG": "artifacts/perf/repeated/loadtest.log",
                "LEGACY_REPORT": "artifacts/perf/repeated/legacy-report.json",
            }
        )
        admitted = subprocess.run(  # noqa: S603 - fixed producer tools override owned hostile caller PATH
            [str(controller), "--url", "https://example.invalid"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        self.assertFalse(marker.exists())
        environment["BASH_FUNC_git%%"] = "() { exit 91; }"
        rejected = subprocess.run(  # noqa: S603 - reject imported function before Bash
            [str(controller)],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertFalse(marker.exists())

    def test_managed_probe_uses_parsed_host_instead_of_environment_fallback(self):
        source = (SOURCE / "scripts/perf/run_load_tests.sh").read_text()
        parser = source[source.index("# Load-test tunables") : source.index("cleanup() {")]
        port_start = source.index("pick_server_port() {")
        port_end = source.index('\nif [ "$MANAGE_SERVER" = "1" ]; then', port_start)
        function = source[port_start:port_end]
        mode_end = source.index('\n"$SOURCE_PYTHON"', port_end)
        mode = source[port_end:mode_end]
        observed = self.owner / "probe.json"
        python = self.owner / "controlled-python"
        python.write_text(
            f"#!{sys.executable}\nimport json,pathlib,sys,types\n"
            "class Socket:\n"
            " def setsockopt(self,*args): pass\n"
            " def bind(self,address):\n"
            f"  pathlib.Path({str(observed)!r}).write_text(json.dumps(address))\n"
            " def getsockname(self): return ('modeled',18095)\n"
            " def close(self): pass\n"
            "sys.modules['socket']=types.SimpleNamespace(socket=Socket,AF_INET=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_REUSEADDR=1)\n"
            "sys.argv=sys.argv[3:]\nexec(compile(sys.stdin.read(),'<controlled-port-probe>','exec'))\n"
        )
        python.chmod(0o755)
        script = self.owner / "port-control.sh"
        script.write_text(
            "set -euo pipefail\n"
            + parser
            + function
            + f"\nSOURCE_PYTHON={str(python)!r}\n"
            + mode
            + '\nprintf "%s\\n" "$BASE_URL"\n'
        )
        result = subprocess.run(  # noqa: S603 - original parser/probe blocks, modeled socket only
            [str(shutil.which("bash")), str(script), "--server-host", "127.0.0.3"],
            env={**self.environment, "PERF_SERVER_HOST": "127.0.0.4", "PERF_SERVER_PORT": ""},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(observed.read_bytes()), ["127.0.0.3", 8080])
        self.assertEqual(result.stdout.strip(), "http://127.0.0.3:18095")

    def test_fixed_package_caller_changes_reject_under_isolated_generated_helper(self):
        _supplier, context, _controller = self.fixture_context()
        admitted = self.invoke("urls", "--url", "https://issuer.example.test")
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        prior = self.evidence.parent / "source-status.json"
        prior.parent.mkdir(parents=True)
        prior.write_bytes(b"prior status bytes\n")
        for name in (*PRODUCER.MODULE_FILES, "scripts/perf/loadtest_supplier.py"):
            path = self.root / name
            raw, mode = path.read_bytes(), path.lstat().st_mode & 0o777
            for change in ("missing", "bytes"):
                with self.subTest(path=name, change=change):
                    if change == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(raw + b"\n# changed caller source\n")
                    result = self.invoke(
                        "paths", "--artifact-directory", str(self.evidence.parent), immutable=True
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("evidence validation failed", result.stderr)
                    self.assertEqual(prior.read_bytes(), b"prior status bytes\n")
                    self.assertFalse(self.evidence.exists())
                    self.assertFalse(list(self.private.iterdir()))
                    path.write_bytes(raw)
                    path.chmod(mode)
        context.admit(self.root)
        self.assertFalse(self.evidence.exists())


if __name__ == "__main__":
    unittest.main()
