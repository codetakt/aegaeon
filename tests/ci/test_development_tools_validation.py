"""Regression controls for the bounded root development-tools profile."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import validate_development_tools as tools

ROOT = Path(__file__).resolve().parents[2]


def sample_lock():
    return {"packages": {"": {}, "node_modules/tool": {"dev": True}}}


def clean_audit():
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {
            "vulnerabilities": dict.fromkeys(
                ["info", "low", "moderate", "high", "critical", "total"], 0
            ),
            "dependencies": {
                "prod": 1,
                "dev": 1,
                "optional": 0,
                "peer": 0,
                "peerOptional": 0,
                "total": 1,
            },
        },
    }


class DevelopmentToolsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.package = json.loads((ROOT / "package.json").read_text())
        self.lock = json.loads((ROOT / "package-lock.json").read_text())
        (self.root / "package.json").write_text(json.dumps(self.package))
        (self.root / "package-lock.json").write_text(json.dumps(self.lock))

    def test_current_consumer_and_lifecycle_profile(self):
        package, lock = tools.package_contract(self.root)
        assert package["devDependencies"]
        assert len(lock["packages"]) > 1

    def test_bootstrap_hash_mismatch_rejected_before_extraction(self):
        with (
            patch.object(tools.urllib.request, "urlopen", return_value=io.BytesIO(b"invalid")),
            patch.object(tools, "extract_archive") as extract,
            pytest.raises(ValueError, match="integrity mismatch"),
        ):
            tools.bootstrap_npm(self.root, self.root)
        extract.assert_not_called()
        assert (self.root / "npm-10.9.7.tgz").read_bytes() == b"invalid"

    def test_archive_unsafe_members_and_duplicate_aliases_rejected(self):
        candidates = [
            [("/package/escape", tarfile.REGTYPE)],
            [("package/../escape", tarfile.REGTYPE)],
            [("package/./alias", tarfile.REGTYPE)],
            [("other/file", tarfile.REGTYPE)],
            [("package/link", tarfile.SYMTYPE)],
            [("package/link", tarfile.LNKTYPE)],
            [("package/device", tarfile.CHRTYPE)],
            [("package/", tarfile.DIRTYPE), ("package", tarfile.DIRTYPE)],
        ]
        for index, members in enumerate(candidates):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name, kind in members:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    archive.addfile(member)
            with self.subTest(members=members), pytest.raises(ValueError, match=r"."):
                tools.extract_archive(buffer.getvalue(), self.root / str(index))

    def test_archive_file_contents_and_bounds(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/bin/npm-cli.js")
            member.size = 5
            archive.addfile(member, io.BytesIO(b"hello"))
        raw = buffer.getvalue()
        assert tools.extract_archive(raw, self.root / "valid") == 1
        assert (self.root / "valid/package/bin/npm-cli.js").read_bytes() == b"hello"
        for constant, bound in [("MAX_MEMBERS", 0), ("MAX_UNPACKED_BYTES", 4)]:
            with (
                patch.object(tools, constant, bound),
                pytest.raises(ValueError, match=r"excessive|bound"),
            ):
                tools.extract_archive(raw, self.root / constant)
        with patch.object(tools, "MAX_ARCHIVE_BYTES", 1), pytest.raises(ValueError, match="bound"):
            tools.verify_archive(raw)

    def test_bootstrap_manifest_version_and_engines_checked(self):
        for index, package in enumerate(
            [
                {"version": "10.9.8", "engines": {"node": "^18.17.0 || >=20.5.0"}},
                {"version": "10.9.7", "engines": {"node": ">=26"}},
            ]
        ):
            work = self.root / str(index)
            work.mkdir()

            def extract(_raw, destination, package=package):
                (destination / "package").mkdir()
                (destination / "package/package.json").write_text(json.dumps(package))
                return 1

            with (
                patch.object(tools.urllib.request, "urlopen", return_value=io.BytesIO(b"fixture")),
                patch.object(tools, "verify_archive"),
                patch.object(tools, "extract_archive", side_effect=extract),
                pytest.raises(ValueError, match=r"version|engine"),
            ):
                tools.bootstrap_npm(work, work)

    def test_malformed_package_and_lock_objects_rejected(self):
        for key, value in [("scripts", []), ("devDependencies", None)]:
            candidate = {**self.package, key: value}
            (self.root / "package.json").write_text(json.dumps(candidate))
            with pytest.raises(ValueError, match="Malformed"):
                tools.package_contract(self.root)
        (self.root / "package.json").write_text(json.dumps(self.package))
        self.lock["packages"]["node_modules/tool"] = []
        (self.root / "package-lock.json").write_text(json.dumps(self.lock))
        with pytest.raises(ValueError, match="Malformed"):
            tools.package_contract(self.root)

    def test_noop_consumer_cannot_report_success(self):
        for name in tools.EXPECTED_SCRIPTS:
            candidate = copy.deepcopy(self.package)
            candidate["scripts"][name] = "true"
            (self.root / "package.json").write_text(json.dumps(candidate))
            with self.subTest(name=name), pytest.raises(ValueError, match="consumer script"):
                tools.package_contract(self.root)

    def test_root_lifecycle_addition_or_changed_postinstall_rejected(self):
        for name in ("prepare", "install", "prelint:ts", "posttypecheck:ts", "postinstall"):
            candidate = copy.deepcopy(self.package)
            candidate["scripts"][name] = "echo unreviewed"
            with self.subTest(name=name), pytest.raises(ValueError, match=r"lifecycle|postinstall"):
                tools.lifecycle_contract(candidate)

    def test_root_production_dependencies_need_new_consumer_profile(self):
        self.package["dependencies"] = {"production": "1.0.0"}
        (self.root / "package.json").write_text(json.dumps(self.package))
        with pytest.raises(ValueError, match="Production dependencies"):
            tools.package_contract(self.root)

    def test_project_npm_config_rejected(self):
        (self.root / ".npmrc").write_text("omit=dev\n")
        with pytest.raises(ValueError, match="npm configuration"):
            tools.package_contract(self.root)

    def test_unreviewed_lock_entries_rejected(self):
        path, entry = next((p, v) for p, v in self.lock["packages"].items() if p)
        for field, value in [
            ("link", True),
            ("hasInstallScript", True),
            ("resolved", "http://example.test/a.tgz"),
            ("integrity", "unknown"),
        ]:
            candidate = {**entry, field: value}
            with self.subTest(field=field), pytest.raises(ValueError, match=r"."):
                tools.locked_entry(path, candidate)

    def test_sha256_and_sha512_lock_integrity_accepted(self):
        path, entry = next((p, v) for p, v in self.lock["packages"].items() if p)
        for algorithm in ("sha256", "sha512"):
            digest = base64.b64encode(hashlib.new(algorithm, b"package").digest()).decode()
            candidate = {**entry, "integrity": f"{algorithm}-{digest}"}
            with self.subTest(algorithm=algorithm):
                tools.locked_entry(path, candidate)

    def test_weak_missing_and_malformed_lock_integrity_rejected(self):
        path, entry = next((p, v) for p, v in self.lock["packages"].items() if p)
        sha1_digest = base64.b64encode(
            hashlib.sha1(b"package", usedforsecurity=False).digest()
        ).decode()
        cases = [
            (f"sha1-{sha1_digest}", "SHA-1 package integrity is not supported"),
            ("sha384-YWJj", "Missing or unknown package integrity"),
            ("md5-YWJj", "Missing or unknown package integrity"),
            ("SHA256-YWJj", "Missing or unknown package integrity"),
            ("sha256-", "Missing or unknown package integrity"),
            ("sha512-***", "Missing or unknown package integrity"),
            ("sha256-YWJj extra", "Missing or unknown package integrity"),
            ("", "Missing or unknown package integrity"),
            (None, "Missing or unknown package integrity"),
        ]
        for integrity, diagnostic in cases:
            candidate = {**entry, "integrity": integrity}
            with self.subTest(integrity=integrity), pytest.raises(ValueError, match=diagnostic):
                tools.locked_entry(path, candidate)
        candidate = {key: value for key, value in entry.items() if key != "integrity"}
        with (
            self.subTest(integrity="absent"),
            pytest.raises(ValueError, match="Missing or unknown package integrity"),
        ):
            tools.locked_entry(path, candidate)

    def test_audit_complete_dev_graph_passes(self):
        tools.audit_contract(clean_audit(), sample_lock())

    def test_audit_gate_precedes_every_consumer_and_rejects_failures(self):
        advisory = clean_audit()
        advisory["vulnerabilities"]["tool"] = {"severity": "high"}
        for audit in (
            ValueError("npm-audit failed with exit 1"),
            "not JSON",
            "{}",
            json.dumps(advisory),
            json.dumps(clean_audit()),
        ):
            calls = []

            def run(_commands, name, _argv, _cwd, audit=audit, calls=calls):
                calls.append(name)
                if name == "npm-audit":
                    if isinstance(audit, Exception):
                        raise audit
                    return audit
                return "{}"

            with (
                self.subTest(audit=audit),
                patch.object(tools, "snapshot", return_value={}),
                patch.object(tools, "package_contract", return_value=({}, sample_lock())),
                patch.object(tools, "bootstrap_npm", return_value=(Path("npm"), {})),
                patch.object(tools, "environment", return_value={}),
                patch.object(tools, "tool_identity", return_value={}),
                patch.object(tools, "installed_graph", return_value={}),
                patch.object(tools, "graph_contract", return_value=[]),
                patch.object(tools.Commands, "run", run),
                patch.object(tools, "consumer_entrypoints", return_value={}) as entrypoints,
                patch.object(
                    tools,
                    "consumers",
                    side_effect=lambda *_, calls=calls: calls.append("consumers"),
                ) as consumers,
            ):
                report = tools.execute(self.root, self.root, {"node": "node"})
            if audit == json.dumps(clean_audit()):
                assert report["status"] == "passed"
                assert calls == ["npm-ci", "npm-ls", "npm-audit", "consumers"]
                assert consumers.call_count == entrypoints.call_count == 1
            else:
                assert report["status"] == "failed"
                assert calls == ["npm-ci", "npm-ls", "npm-audit"]
                consumers.assert_not_called()
                entrypoints.assert_not_called()

    def install_consumer_fixtures(self):
        installed = {}
        for package, command, relative in (
            ("eslint", "eslint", "bin/eslint.js"),
            ("typescript", "tsc", "bin/tsc"),
        ):
            directory = self.root / "node_modules" / package
            (directory / "bin").mkdir(parents=True)
            manifest = directory / "package.json"
            manifest.write_text(json.dumps({"name": package, "bin": {command: relative}}))
            (directory / relative).write_text("print('validated consumer executed')\n")
            installed["node_modules/" + package] = {
                "name": package,
                "manifest_sha256": tools.sha(manifest.read_bytes()),
            }
        return installed

    def test_consumer_entrypoints_reject_identity_path_and_bin_changes(self):
        installed = self.install_consumer_fixtures()
        tools.consumer_entrypoints(self.root, installed)
        manifest = self.root / "node_modules/eslint/package.json"
        original = manifest.read_bytes()
        for value in (
            "../other.js",
            str(self.root / "other.js"),
            "bin/noop.js",
            "bin/./eslint.js",
            [],
        ):
            manifest.write_text(json.dumps({"name": "eslint", "bin": {"eslint": value}}))
            installed["node_modules/eslint"]["manifest_sha256"] = tools.sha(manifest.read_bytes())
            with self.subTest(value=value), pytest.raises(ValueError, match="entrypoint"):
                tools.consumer_entrypoints(self.root, installed)
        manifest.write_bytes(original)
        with pytest.raises(ValueError, match="validated graph"):
            tools.consumer_entrypoints(self.root, installed)
        installed["node_modules/eslint"]["manifest_sha256"] = tools.sha(original)
        installed["node_modules/eslint"]["name"] = "another-package"
        with pytest.raises(ValueError, match="validated graph"):
            tools.consumer_entrypoints(self.root, installed)

    def test_consumer_entrypoints_reject_symlink_file_or_parent(self):
        installed = self.install_consumer_fixtures()
        package = self.root / "node_modules/eslint"
        for relative in ("bin/eslint.js", "package.json", "bin"):
            path = package / relative
            saved = package / "saved"
            path.rename(saved)
            path.symlink_to(saved)
            with self.subTest(relative=relative), pytest.raises(ValueError, match="Symlink"):
                tools.consumer_entrypoints(self.root, installed)
            path.unlink()
            saved.rename(path)

    def test_dependency_bin_shadowing_cannot_replace_consumers(self):
        installed = self.install_consumer_fixtures()
        # Use an explicit fixture interpreter so this regression needs no Node installation.
        runtime = self.root / "pinned-node-fixture"
        runtime.write_text(
            f"#!{sys.executable}\nimport os, sys\n"
            "args = [arg for arg in sys.argv[1:] if arg != '--experimental-strip-types']\n"
            "os.execv(sys.executable, [sys.executable, *args])\n"
        )
        runtime.chmod(0o755)
        bins = self.root / "node_modules/.bin"
        bins.mkdir()
        for name in ("eslint", "tsc", "node"):
            poisoned = bins / name
            poisoned.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\nPath('hijacked').touch()\n"
            )
            poisoned.chmod(0o755)
        for relative in ("scripts/check-strict-types.ts", *tools.TESTS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("print('validated consumer executed')\n")
        commands = tools.Commands(self.root, {"PATH": str(bins)})
        entrypoints = tools.consumer_entrypoints(self.root, installed)
        tools.consumers(commands, self.root, {"node": str(runtime), "npm": "unused"}, entrypoints)
        assert len(commands.records) == 6
        assert all(record["argv"][0] == str(runtime) for record in commands.records)
        assert all(
            (self.root / record["stdout"]).read_text() == "validated consumer executed\n"
            for record in commands.records
        )
        assert not (self.root / "hijacked").exists()
        Path(entrypoints["eslint"]["path"]).write_text("raise SystemExit(7)\n")
        with pytest.raises(ValueError, match="lint-ts failed with exit 7"):
            tools.consumers(commands, self.root, {"node": str(runtime)}, entrypoints)

    def test_audit_errors_unknown_schema_and_incomplete_reports_rejected(self):
        candidates = [
            None,
            [],
            {},
            {"error": "registry unavailable"},
            {**clean_audit(), "auditReportVersion": 3},
        ]
        for key in ("metadata", "vulnerabilities"):
            candidate = clean_audit()
            del candidate[key]
            candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(report=candidate), pytest.raises(ValueError, match=r"."):
                tools.audit_contract(candidate, sample_lock())

    def test_audit_omitted_dev_dependencies_and_false_zero_rejected(self):
        for field, value in [("dev", 0), ("total", 0), ("total", True)]:
            candidate = clean_audit()
            candidate["metadata"]["dependencies"][field] = value
            with self.subTest(field=field, value=value), pytest.raises(ValueError, match=r"."):
                tools.audit_contract(candidate, sample_lock())
        candidate = clean_audit()
        candidate["metadata"]["vulnerabilities"]["low"] = 1
        with pytest.raises(ValueError, match="vulnerabilities"):
            tools.audit_contract(candidate, sample_lock())

    def test_audit_advisory_without_summary_count_rejected(self):
        candidate = clean_audit()
        candidate["vulnerabilities"]["tool"] = {"severity": "high"}
        with pytest.raises(ValueError, match="vulnerabilities"):
            tools.audit_contract(candidate, sample_lock())

    def test_installed_graph_missing_or_problem_nodes_rejected(self):
        package = {"name": "aegaeon", "devDependencies": {"tool": "1.0.0"}}
        graph = {
            "name": "aegaeon",
            "version": "0.0.0",
            "dependencies": {"tool": {"version": "1.0.0"}},
        }
        tools.graph_contract(graph, package, {})
        for key in ("problems", "missing", "invalid", "extraneous", "error"):
            candidate = copy.deepcopy(graph)
            candidate["dependencies"]["tool"][key] = True
            with self.subTest(key=key), pytest.raises(ValueError, match="problems"):
                tools.graph_contract(candidate, package, {})
        with pytest.raises(ValueError, match="incomplete"):
            tools.graph_contract({"name": "aegaeon", "dependencies": {}}, package, {})

    def test_empty_graph_node_requires_actual_optional_peer_declaration(self):
        package = {"name": "aegaeon", "devDependencies": {"tool": "1.0.0"}}
        graph = {
            "name": "aegaeon",
            "version": "0.0.0",
            "dependencies": {"tool": {"version": "1.0.0", "dependencies": {"optional": {}}}},
        }
        installed = {
            "node_modules/tool": {
                "name": "tool",
                "version": "1.0.0",
                "optional_peers": {"optional": "^1.0.0"},
            }
        }
        assert tools.graph_contract(graph, package, installed) == [
            {
                "parent": "tool",
                "parent_version": "1.0.0",
                "peer": "optional",
                "declared_range": "^1.0.0",
            }
        ]
        installed["node_modules/tool"]["optional_peers"] = {}
        with pytest.raises(ValueError, match="declared optional peer"):
            tools.graph_contract(graph, package, installed)
        with pytest.raises(ValueError, match="declared optional peer"):
            tools.graph_contract(graph, package, {})

    def test_installed_manifest_mismatch_and_lifecycle_detected(self):
        package_dir = self.root / "node_modules/tool"
        package_dir.mkdir(parents=True)
        installed = package_dir / "package.json"
        locked = {
            "packages": {
                "": {},
                "node_modules/tool": {"version": "1.0.0", "integrity": "sha512-test"},
            }
        }
        for actual in [
            {"name": "tool", "version": "2.0.0"},
            {"name": "tool", "version": "1.0.0", "scripts": {"install": "build"}},
        ]:
            installed.write_text(json.dumps(actual))
            with pytest.raises(ValueError, match=r"version|lifecycle"):
                tools.installed_graph(self.root, locked)

    def test_inherited_npm_and_node_configuration_removed(self):
        with patch.dict(
            os.environ,
            {
                "NPM_CONFIG_OMIT": "dev",
                "npm_config_ignore_scripts": "false",
                "NODE_OPTIONS": "--require=bad",
                "GH_TOKEN": "secret",
            },
        ):
            env = tools.environment(self.root, "/nix/store/node/bin/node")
        assert "NPM_CONFIG_OMIT" not in env
        assert "npm_config_ignore_scripts" not in env
        assert "NODE_OPTIONS" not in env
        assert "GH_TOKEN" not in env
        assert env["HOME"] == os.environ["HOME"]
        assert env["NODE_ENV"] == "development"
        assert env["NPM_CONFIG_USERCONFIG"] != env["NPM_CONFIG_GLOBALCONFIG"]

    def test_command_nonzero_and_timeout_preserve_logs(self):
        commands = tools.Commands(self.root, {})
        failed = subprocess.CompletedProcess(["node"], 1, b"partial", b"audit error")
        with (
            patch.object(subprocess, "run", return_value=failed),
            pytest.raises(ValueError, match="failed"),
        ):
            commands.run("failure", ["node"], self.root)
        assert (self.root / "failure.stderr").read_bytes() == b"audit error"
        timeout = subprocess.TimeoutExpired(["node"], 300, b"output", b"timeout")
        with (
            patch.object(subprocess, "run", side_effect=timeout),
            pytest.raises(subprocess.TimeoutExpired),
        ):
            commands.run("timeout", ["node"], self.root)
        assert (self.root / "timeout.stdout").read_bytes() == b"output"
        assert len(json.loads((self.root / "commands.json").read_text())) == 2

    def test_package_manager_mismatch_fails_before_install(self):
        commands = tools.Commands(self.root, {})
        with (
            patch.object(commands, "run", side_effect=["v24.19.0\n", "10.9.8\n"]),
            pytest.raises(ValueError, match="packageManager"),
        ):
            tools.tool_identity(
                commands, self.root, {"node": "node", "npm": "npm", "nix": "nix"}, self.package
            )

    def test_lock_rewrite_rejected(self):
        path = self.root / "package-lock.json"
        inputs = {path.name: tools.identity(path)}
        path.write_text("{}")
        with pytest.raises(ValueError, match="Source or lock changed"):
            tools.unchanged(self.root, inputs)

    def test_snapshot_preserves_tracked_bytes_without_installing_dependencies(self):
        subprocess.run(["git", "init", str(self.root)], check=True, capture_output=True)  # noqa: S603, S607 - disposable local repository
        subprocess.run(  # noqa: S603 - fixed arguments in disposable local repository
            ["git", "-C", str(self.root), "add", "package.json", "package-lock.json"],  # noqa: S607
            check=True,
            capture_output=True,
        )
        destination = self.root / "copy"
        inputs = tools.snapshot(self.root, destination)
        assert set(inputs) == {"package.json", "package-lock.json"}
        assert not (self.root / "node_modules").exists()
        tools.unchanged(self.root, inputs)
        tools.unchanged(destination, inputs)

    def test_external_consumer_symlink_rejected_before_copy(self):
        external = Path(self.enterContext(tempfile.TemporaryDirectory())) / "consumer.ts"
        external.write_text("throw new Error('external consumer executed');\n")
        consumer = self.root / "scripts/check-strict-types.ts"
        consumer.parent.mkdir()
        consumer.symlink_to(external)
        with (
            patch.object(tools, "tracked_inputs", return_value=["scripts/check-strict-types.ts"]),
            pytest.raises(ValueError, match="Unreviewed source symlink"),
        ):
            tools.snapshot(self.root, self.root / "copy")
        assert not (self.root / "copy/scripts/check-strict-types.ts").is_symlink()

    def test_only_exact_nonconsumer_kani_link_is_allowed(self):
        relative = "crates/kani-harness/kani"
        link = self.root / relative
        link.parent.mkdir(parents=True)
        link.symlink_to("result/bin/cargo-kani")
        with patch.object(tools, "tracked_inputs", return_value=[relative]):
            inputs = tools.snapshot(self.root, self.root / "accepted")
            tools.unchanged(self.root / "accepted", inputs)
            for index, target in enumerate(
                [
                    str(self.root / "other-cargo-kani"),
                    "result/./bin/cargo-kani",
                    "result//bin/cargo-kani",
                ]
            ):
                link.unlink()
                link.symlink_to(target)
                with pytest.raises(ValueError, match="Unreviewed source symlink"):
                    tools.snapshot(self.root, self.root / f"rejected-{index}")


if __name__ == "__main__":
    unittest.main()
