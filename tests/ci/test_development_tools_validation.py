"""Regression controls for the bounded root development-tools profile."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
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

    def test_audit_complete_dev_graph_passes(self):
        tools.audit_contract(clean_audit(), sample_lock())

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
