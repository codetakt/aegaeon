# Security assertions remain active under Python -O.
# ruff: noqa: PT009
"""Regression controls for the bounded root development-tools profile."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import shutil
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
        self.assertTrue(package["devDependencies"])
        self.assertGreater(len(lock["packages"]), 1)

    def test_root_package_missing_blank_and_nonstring_names_raise_value_error(self):
        for name in (None, False, 7, [], {}, "", " \t\n"):
            with self.subTest(name=name):
                package = {**self.package, "name": name}
                (self.root / "package.json").write_text(json.dumps(package))
                with pytest.raises(ValueError, match="Malformed root package name"):
                    tools.package_contract(self.root)
        package = dict(self.package)
        package.pop("name")
        (self.root / "package.json").write_text(json.dumps(package))
        with pytest.raises(ValueError, match="Malformed root package name"):
            tools.package_contract(self.root)

    def test_invalid_root_names_write_failed_receipts_before_bootstrap(self):
        for index, name in enumerate((None, [])):
            package = dict(self.package)
            if name is None:
                package.pop("name")
            else:
                package["name"] = name
            (self.root / "package.json").write_text(json.dumps(package))
            output = self.root / f"root-name-failure-{index}"

            def controlled_snapshot(_root, destination):
                destination.mkdir()
                for filename in ("package.json", "package-lock.json"):
                    shutil.copyfile(self.root / filename, destination / filename)
                return {}

            with (
                patch.object(tools, "snapshot", side_effect=controlled_snapshot),
                patch.object(tools, "bootstrap_npm") as bootstrap,
                patch.object(tools, "consumers") as consumers,
                patch.object(tools.shutil, "which", side_effect=lambda tool: f"/nix/store/{tool}"),
                patch.object(
                    sys,
                    "argv",
                    ["validate-tools", "--root", str(self.root), "--output", str(output)],
                ),
            ):
                self.assertEqual(tools.main(), 1)
            bootstrap.assert_not_called()
            consumers.assert_not_called()
            receipt = json.loads((output / "summary.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "Malformed root package name")
            self.assertEqual(receipt["runner_sha256"], tools.sha(Path(tools.__file__).read_bytes()))

    def test_bootstrap_hash_mismatch_rejected_before_extraction(self):
        with (
            patch.object(tools.urllib.request, "urlopen", return_value=io.BytesIO(b"invalid")),
            patch.object(tools, "extract_archive") as extract,
            pytest.raises(ValueError, match="integrity mismatch"),
        ):
            tools.bootstrap_npm(self.root, self.root)
        extract.assert_not_called()
        self.assertEqual((self.root / "npm-10.9.7.tgz").read_bytes(), b"invalid")

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
        self.assertEqual(tools.extract_archive(raw, self.root / "valid"), 1)
        self.assertEqual((self.root / "valid/package/bin/npm-cli.js").read_bytes(), b"hello")
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

    def test_short_long_and_noncanonical_lock_integrity_rejected(self):
        path, entry = next((p, v) for p, v in self.lock["packages"].items() if p)
        for algorithm, size in (("sha256", 32), ("sha512", 64)):
            valid = base64.b64encode(bytes(size)).decode()
            plain = valid.rstrip("=")
            noncanonical = plain[:-1] + "B" + valid[len(plain) :]
            encodings = (
                "YWJj",
                base64.b64encode(bytes(size - 1)).decode(),
                base64.b64encode(bytes(size + 1)).decode(),
                plain,
                valid + "=",
                "=" + valid,
                plain[:2] + "=" + plain[2:] + valid[len(plain) :],
                noncanonical,
            )
            self.assertEqual(base64.b64decode(noncanonical), bytes(size))
            for encoded in encodings:
                with (
                    self.subTest(algorithm=algorithm, encoded=encoded),
                    pytest.raises(ValueError, match="Invalid package integrity digest"),
                ):
                    tools.locked_entry(path, {**entry, "integrity": algorithm + "-" + encoded})

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
                patch.object(tools, "installed_closure", return_value={}) as closure,
                patch.object(tools, "consumer_entrypoints", return_value={}) as entrypoints,
                patch.object(
                    tools,
                    "consumers",
                    side_effect=lambda *_, calls=calls, **__: calls.append("consumers"),
                ) as consumers,
            ):
                report = tools.execute(self.root, self.root, {"node": "node"})
            if audit == json.dumps(clean_audit()):
                self.assertEqual(report["status"], "passed")
                self.assertEqual(calls, ["npm-ci", "npm-ls", "npm-audit", "consumers"])
                self.assertTrue(
                    consumers.call_count == entrypoints.call_count == closure.call_count == 1
                )
            else:
                self.assertEqual(report["status"], "failed")
                self.assertEqual(calls, ["npm-ci", "npm-ls", "npm-audit"])
                consumers.assert_not_called()
                entrypoints.assert_not_called()
                closure.assert_not_called()

    def consumer_fixture_inputs(self):
        return {
            str(path.relative_to(self.root)): tools.identity(path)
            for path in self.root.rglob("*")
            if path.relative_to(self.root).parts[0] != "node_modules"
            and (path.is_file() or path.is_symlink())
        }

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
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))
        inputs = self.consumer_fixture_inputs()
        commands = tools.Commands(output, {"PATH": str(bins)})
        entrypoints = tools.consumer_entrypoints(self.root, installed)
        closure = tools.installed_closure(self.root)
        tools.consumers(
            commands,
            self.root,
            {"node": str(runtime), "npm": "unused"},
            entrypoints,
            inputs,
            closure=closure,
        )
        self.assertEqual(len(commands.records), 6)
        self.assertTrue(all(record["argv"][0] == str(runtime) for record in commands.records))
        self.assertTrue(
            all(
                (output / record["stdout"]).read_text() == "validated consumer executed\n"
                for record in commands.records
            )
        )
        self.assertFalse((self.root / "hijacked").exists())
        Path(entrypoints["eslint"]["path"]).write_text("raise SystemExit(7)\n")
        with pytest.raises(ValueError, match="Installed consumer closure changed"):
            tools.consumers(
                commands, self.root, {"node": str(runtime)}, entrypoints, inputs, closure=closure
            )
        self.assertEqual(len(commands.records), 6)
        entrypoints = tools.consumer_entrypoints(self.root, installed)
        closure = tools.installed_closure(self.root)
        with pytest.raises(ValueError, match="lint-ts failed with exit 7"):
            tools.consumers(
                commands, self.root, {"node": str(runtime)}, entrypoints, inputs, closure=closure
            )

    def test_successful_earlier_consumer_cannot_replace_later_entrypoint(self):
        installed = self.install_consumer_fixtures()
        tsc = self.root / "node_modules/typescript/bin/tsc"
        marker = self.root / "noop-tsc-executed"
        replacement = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        eslint = self.root / "node_modules/eslint/bin/eslint.js"
        eslint.write_text(
            f"from pathlib import Path\nPath({str(tsc)!r}).write_text({replacement!r})\n"
            "print('earlier consumer passed')\n"
        )
        entrypoints = tools.consumer_entrypoints(self.root, installed)
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))
        inputs = self.consumer_fixture_inputs()
        commands = tools.Commands(output, {})
        closure = tools.installed_closure(self.root)
        with pytest.raises(ValueError, match="Installed consumer closure changed") as caught:
            tools.consumers(
                commands, self.root, {"node": sys.executable}, entrypoints, inputs, closure=closure
            )
        (output / "rejection.txt").write_text(str(caught.value))
        self.assertEqual([row["name"] for row in commands.records], ["lint-ts"])
        self.assertEqual(commands.records[0]["exit"], 0)
        self.assertFalse(marker.exists())
        self.assertEqual((output / "lint-ts.stdout").read_text(), "earlier consumer passed\n")

    def sequential_replacement_fixture(self, earlier_index, target_name):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with patch.object(self, "root", root):
            installed = self.install_consumer_fixtures()
            sequence = [
                root / "node_modules/eslint/bin/eslint.js",
                root / "node_modules/typescript/bin/tsc",
                root / "scripts/check-strict-types.ts",
                *(root / name for name in tools.TESTS),
            ]
            for path in sequence:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("print('consumer passed')\n")
            target = root / target_name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target not in sequence:
                target.write_text("reviewed policy/config input\n")
            original = target.read_text()
            marker = output / "altered-later-input-executed"
            restore = (
                "from pathlib import Path\n"
                f"Path({str(target)!r}).write_text({original!r})\n"
                f"Path({str(marker)!r}).touch()\n"
                "print('altered later consumer passed and restored inputs')\n"
            )
            if target not in sequence:
                # Config/policy replacement is restored by the next consumer.
                sequence[earlier_index + 1].write_text(restore)
                replacement = "altered policy/config input\n"
            else:
                replacement = restore
            sequence[earlier_index].write_text(
                "from pathlib import Path\n"
                f"Path({str(target)!r}).write_text({replacement!r})\n"
                "print('successful earlier consumer replaced tracked input')\n"
            )
            runtime = output / "pinned-node-fixture"
            runtime.write_text(
                f"#!{sys.executable}\nimport os, sys\n"
                "args = [arg for arg in sys.argv[1:] "
                "if arg != '--experimental-strip-types']\n"
                "os.execv(sys.executable, [sys.executable, *args])\n"
            )
            runtime.chmod(0o755)
            inputs = self.consumer_fixture_inputs()
            entrypoints = tools.consumer_entrypoints(root, installed)
            commands = tools.Commands(output, {})
        return root, output, target, original, marker, runtime, inputs, entrypoints, commands

    def test_successful_consumer_cannot_replace_tracked_source_policy_or_config(self):
        # Each later source can restore itself while returning success. Reject it
        # before execution, including when a preceding consumer returned zero.
        cases = [
            (0, "scripts/check-strict-types.ts"),
            (1, "scripts/check-strict-types.ts"),
            (2, tools.TESTS[0]),
            (3, tools.TESTS[1]),
            (4, tools.TESTS[2]),
            (0, "tsconfig.json"),
            (0, ".github/workflows/ci.yml"),
        ]
        for earlier_index, target_name in cases:
            with self.subTest(earlier_index=earlier_index, target=target_name):
                (
                    root,
                    _output,
                    target,
                    original,
                    marker,
                    runtime,
                    inputs,
                    entrypoints,
                    commands,
                ) = self.sequential_replacement_fixture(earlier_index, target_name)
                closure = tools.installed_closure(root)
                with pytest.raises(ValueError, match="Source or lock changed"):
                    tools.consumers(
                        commands, root, {"node": str(runtime)}, entrypoints, inputs, closure=closure
                    )
                self.assertEqual(len(commands.records), earlier_index + 1)
                self.assertTrue(all(row["exit"] == 0 for row in commands.records))
                self.assertFalse(marker.exists())
                self.assertNotEqual(target.read_text(), original)

    def installed_implementation_replacement_fixture(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with patch.object(self, "root", root):
            installed = self.install_consumer_fixtures()
            target = root / "node_modules/typescript/lib/tsc.js"
            target.parent.mkdir()
            original = "print('reviewed implementation passed')\n"
            target.write_text(original)
            launcher = root / "node_modules/typescript/bin/tsc"
            launcher.write_text(
                f"from pathlib import Path\nexec(Path({str(target)!r}).read_text())\n"
            )
            for name in ("scripts/check-strict-types.ts", *tools.TESTS):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("print('consumer passed')\n")
            marker = output / "altered-implementation-executed"
            replacement = (
                "from pathlib import Path\n"
                f"Path({str(target)!r}).write_text({original!r})\n"
                f"Path({str(marker)!r}).touch()\n"
                "print('altered implementation passed and restored itself')\n"
            )
            (root / "node_modules/eslint/bin/eslint.js").write_text(
                "from pathlib import Path\n"
                f"Path({str(target)!r}).write_text({replacement!r})\n"
                "print('earlier consumer passed')\n"
            )
            runtime = output / "pinned-node-fixture"
            runtime.write_text(
                f"#!{sys.executable}\nimport os, sys\n"
                "args = [arg for arg in sys.argv[1:] if arg != '--experimental-strip-types']\n"
                "os.execv(sys.executable, [sys.executable, *args])\n"
            )
            runtime.chmod(0o755)
            inputs = self.consumer_fixture_inputs()
            entrypoints = tools.consumer_entrypoints(root, installed)
        return root, output, target, original, marker, runtime, inputs, entrypoints

    def test_successful_consumer_cannot_replace_installed_implementation(self):
        root, output, target, original, marker, runtime, inputs, entrypoints = (
            self.installed_implementation_replacement_fixture()
        )
        closure = tools.installed_closure(root)
        commands = tools.Commands(output, {})
        with pytest.raises(ValueError, match="Installed consumer closure changed"):
            tools.consumers(
                commands, root, {"node": str(runtime)}, entrypoints, inputs, closure=closure
            )
        self.assertEqual([row["name"] for row in commands.records], ["lint-ts"])
        self.assertEqual(commands.records[0]["exit"], 0)
        self.assertFalse(marker.exists())
        self.assertNotEqual(target.read_text(), original)
        self.assertEqual(
            {
                "path": str(root / "node_modules/typescript/bin/tsc"),
                **tools.identity(root / "node_modules/typescript/bin/tsc"),
            },
            entrypoints["tsc"],
        )
        tools.unchanged(root, inputs)

    def test_final_consumer_cannot_leave_installed_closure_changed(self):
        root, output, target, _original, marker, runtime, _inputs, entrypoints = (
            self.installed_implementation_replacement_fixture()
        )
        Path(entrypoints["eslint"]["path"]).write_text("print('reviewed earlier consumer')\n")
        (root / tools.TESTS[-1]).write_text(
            "from pathlib import Path\n"
            f"Path({str(target)!r}).write_text('altered after final consumer')\n"
            f"Path({str(marker)!r}).touch()\n"
            "print('final consumer passed')\n"
        )
        with patch.object(self, "root", root):
            inputs = self.consumer_fixture_inputs()
        entrypoints["eslint"] = {
            "path": str(Path(entrypoints["eslint"]["path"])),
            **tools.identity(Path(entrypoints["eslint"]["path"])),
        }
        closure = tools.installed_closure(root)
        commands = tools.Commands(output, {})
        with pytest.raises(ValueError, match="Installed consumer closure changed"):
            tools.consumers(
                commands, root, {"node": str(runtime)}, entrypoints, inputs, closure=closure
            )
        self.assertEqual(len(commands.records), 6)
        self.assertTrue(all(row["exit"] == 0 for row in commands.records))
        self.assertTrue(marker.is_file())
        self.assertEqual(target.read_text(), "altered after final consumer")
        tools.unchanged(root, inputs)

    def test_installed_closure_rejects_missing_additional_bytes_modes_and_directories(self):
        self.install_consumer_fixtures()
        root = self.root / "node_modules"
        target = root / "typescript/bin/tsc"
        for change in (
            "missing",
            "additional",
            "bytes",
            "mode",
            "empty directory",
            "directory mode",
            "directory identity",
        ):
            with self.subTest(change=change):
                source = Path(self.enterContext(tempfile.TemporaryDirectory())) / "source"
                shutil.copytree(self.root, source)
                closure = tools.installed_closure(source)
                installed = source / "node_modules"
                current = installed / target.relative_to(root)
                if change == "missing":
                    current.unlink()
                elif change == "additional":
                    (installed / "injected.js").write_text("unreviewed")
                elif change == "bytes":
                    current.write_text("altered")
                elif change == "mode":
                    current.chmod(0o700)
                elif change == "empty directory":
                    (installed / "empty").mkdir()
                elif change == "directory mode":
                    (installed / "typescript/lib").mkdir()
                    closure = tools.installed_closure(source)
                    (installed / "typescript/lib").chmod(0o700)
                else:
                    directory = installed / "typescript/bin"
                    saved = source / "saved-bin"
                    directory.rename(saved)
                    shutil.copytree(saved, directory)
                with pytest.raises(ValueError, match="closure changed"):
                    tools.checked_installed_closure(source, closure)

    def test_installed_closure_links_are_literal_internal_and_complete(self):
        self.install_consumer_fixtures()
        root = self.root / "node_modules"
        link = root / "tsc-link"
        link.symlink_to("typescript/bin/tsc")
        directory_link = root / "typescript-link"
        directory_link.symlink_to("typescript", target_is_directory=True)
        closure = tools.installed_closure(self.root)
        self.assertEqual(closure["tsc-link"]["target"], "typescript/bin/tsc")
        self.assertEqual(closure["typescript-link"]["kind"], "symlink")
        tools.checked_installed_closure(self.root, closure)
        link.unlink()
        link.symlink_to("./typescript/bin/tsc")
        with pytest.raises(ValueError, match="closure changed"):
            tools.checked_installed_closure(self.root, closure)
        outside = self.root / "outside.js"
        outside.write_text("outside")
        for target in ("missing", "../outside.js", "tsc-link"):
            with self.subTest(target=target):
                link.unlink()
                link.symlink_to(target)
                with pytest.raises(ValueError, match="closure symlink"):
                    tools.installed_closure(self.root)
        link.unlink()
        (root / "special").touch()
        (root / "special").unlink()
        os.mkfifo(root / "special")
        with pytest.raises(ValueError, match="Special installed closure input"):
            tools.installed_closure(self.root)

    def test_installed_closure_rejects_root_symlink(self):
        self.install_consumer_fixtures()
        closure = tools.installed_closure(self.root)
        root = self.root / "node_modules"
        saved = self.root / "saved-installation"
        root.rename(saved)
        root.symlink_to(saved, target_is_directory=True)
        with pytest.raises(ValueError, match="Installed closure root changed"):
            tools.checked_installed_closure(self.root, closure)

    def test_tracked_consumer_inventory_rejects_missing_additional_and_symlink_inputs(self):
        config = self.root / "tsconfig.json"
        config.write_text("reviewed config\n")
        inputs = self.consumer_fixture_inputs()
        tools.checked_consumer_inputs(self.root, inputs)
        for change in ("missing", "additional", "symlink", "parent symlink"):
            with self.subTest(change=change):
                source = Path(self.enterContext(tempfile.TemporaryDirectory())) / "source"
                shutil.copytree(self.root, source)
                if change == "missing":
                    (source / "tsconfig.json").unlink()
                elif change == "additional":
                    (source / "eslint.config.js").write_text("unreviewed config\n")
                elif change == "symlink":
                    (source / "tsconfig.json").unlink()
                    (source / "tsconfig.json").symlink_to(config)
                else:
                    saved = source.with_name("saved")
                    source.rename(saved)
                    source.symlink_to(saved, target_is_directory=True)
                with pytest.raises(ValueError, match="changed"):
                    tools.checked_consumer_inputs(source, inputs)

    def test_invocation_revalidation_rejects_changed_path_identity_and_symlinks(self):
        installed = self.install_consumer_fixtures()
        entrypoints = tools.consumer_entrypoints(self.root, installed)
        for command, recorded in entrypoints.items():
            target = Path(recorded["path"])
            original = target.read_bytes()
            for field, value in (
                ("path", str(self.root / "other")),
                ("sha256", "changed"),
                ("mode", 0),
            ):
                with (
                    self.subTest(command=command, field=field),
                    pytest.raises(ValueError, match="entrypoint changed"),
                ):
                    tools.checked_consumer_entrypoint(
                        self.root, command, {**recorded, field: value}
                    )
            for alias in (target, target.parent):
                saved = alias.with_name("saved")
                alias.rename(saved)
                alias.symlink_to(saved)
                with (
                    self.subTest(command=command, alias=alias),
                    pytest.raises(ValueError, match="Symlink"),
                ):
                    tools.checked_consumer_entrypoint(self.root, command, recorded)
                alias.unlink()
                saved.rename(alias)
            target.unlink()
            with pytest.raises(ValueError, match="Missing regular"):
                tools.checked_consumer_entrypoint(self.root, command, recorded)
            target.write_bytes(original)
            self.assertEqual(
                tools.checked_consumer_entrypoint(self.root, command, recorded), str(target)
            )

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
        self.assertEqual(
            tools.graph_contract(graph, package, installed),
            [
                {
                    "parent": "tool",
                    "parent_version": "1.0.0",
                    "peer": "optional",
                    "declared_range": "^1.0.0",
                }
            ],
        )
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
                "node_modules/tool": {
                    "version": "1.0.0",
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(b"tool").digest()).decode(),
                },
            }
        }
        for actual in [
            {"name": "tool", "version": "2.0.0"},
            {"name": "tool", "version": "1.0.0", "scripts": {"install": "build"}},
        ]:
            installed.write_text(json.dumps(actual))
            with pytest.raises(ValueError, match=r"version|lifecycle"):
                tools.installed_graph(self.root, locked)

    def installed_name_fixture(self, actual, *, path="node_modules/tool"):
        package_dir = self.root / path
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "package.json").write_text(json.dumps(actual))
        locked = {
            "packages": {
                "": {},
                path: {"version": "1.0.0", "integrity": "fixture-integrity"},
            }
        }
        (self.root / "node_modules/.package-lock.json").write_text(
            json.dumps({"packages": {path: locked["packages"][path]}})
        )
        return locked

    def test_installed_manifest_missing_empty_and_nonstring_names_raise_value_error(self):
        candidates = [{"version": "1.0.0"}]
        candidates.extend(
            {"name": value, "version": "1.0.0"} for value in (None, False, 7, [], {}, "", " \t\n")
        )
        for actual in candidates:
            with self.subTest(manifest=actual):
                locked = self.installed_name_fixture(actual)
                with pytest.raises(ValueError, match="Malformed installed package name"):
                    tools.installed_graph(self.root, locked)

    def test_installed_manifest_malformed_json_and_objects_raise_value_error(self):
        locked = self.installed_name_fixture({"name": "tool", "version": "1.0.0"})
        manifest = self.root / "node_modules/tool/package.json"
        for content in ("{", "[]", "null", "7"):
            with self.subTest(content=content):
                manifest.write_text(content)
                with pytest.raises(ValueError, match=r"."):
                    tools.installed_graph(self.root, locked)

    def test_installed_manifest_valid_names_preserve_graph_and_alias_identity(self):
        actual = {
            "name": "tool",
            "version": "1.0.0",
            "peerDependencies": {"optional": "^1.0.0"},
            "peerDependenciesMeta": {"optional": {"optional": True}},
        }
        locked = self.installed_name_fixture(actual)
        installed = tools.installed_graph(self.root, locked)
        row = installed["node_modules/tool"]
        self.assertEqual(row["name"], "tool")
        self.assertEqual(row["version"], locked["packages"]["node_modules/tool"]["version"])
        self.assertEqual(row["locked_integrity"], "fixture-integrity")
        self.assertEqual(
            row["manifest_sha256"],
            tools.sha((self.root / "node_modules/tool/package.json").read_bytes()),
        )
        omissions = tools.graph_contract(
            {
                "name": "aegaeon",
                "version": "0.0.0",
                "dependencies": {"tool": {"version": "1.0.0", "dependencies": {"optional": {}}}},
            },
            {"name": "aegaeon", "devDependencies": {"tool": "1.0.0"}},
            installed,
        )
        self.assertEqual(omissions[0]["parent"], "tool")
        shutil.rmtree(self.root / "node_modules")
        actual = {"name": "@scope/tool", "version": "1.0.0"}
        locked = self.installed_name_fixture(actual, path="node_modules/alias")
        self.assertEqual(
            tools.installed_graph(self.root, locked)["node_modules/alias"]["name"],
            "@scope/tool",
        )

    def test_installed_manifest_invalid_names_write_failed_main_receipts(self):
        for index, actual in enumerate([{"version": "1.0.0"}, {"name": [], "version": "1.0.0"}]):
            locked = self.installed_name_fixture(actual)
            output = self.root / f"failed-evidence-{index}"

            def controlled_snapshot(_root, destination):
                destination.mkdir()
                shutil.copytree(self.root / "node_modules", destination / "node_modules")
                return {}

            with (
                patch.object(tools, "snapshot", side_effect=controlled_snapshot),
                patch.object(tools, "package_contract", return_value=({"name": "aegaeon"}, locked)),
                patch.object(tools, "bootstrap_npm", return_value=(self.root / "npm-cli.js", {})),
                patch.object(tools, "tool_identity", return_value={}),
                patch.object(tools.Commands, "run", return_value="{}"),
                patch.object(tools, "consumers") as consumers,
                patch.object(
                    tools.shutil, "which", side_effect=lambda name: f"/nix/store/fixture/{name}"
                ),
                patch.object(
                    sys,
                    "argv",
                    ["validate-tools", "--root", str(self.root), "--output", str(output)],
                ),
            ):
                result = tools.main()
            self.assertEqual(result, 1)
            consumers.assert_not_called()
            receipt = json.loads((output / "summary.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("Malformed installed package name", receipt["error"])
            self.assertEqual(receipt["runner_sha256"], tools.sha(Path(tools.__file__).read_bytes()))

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
        self.assertNotIn("NPM_CONFIG_OMIT", env)
        self.assertNotIn("npm_config_ignore_scripts", env)
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertNotIn("GH_TOKEN", env)
        self.assertEqual(env["HOME"], os.environ["HOME"])
        self.assertEqual(env["NODE_ENV"], "development")
        self.assertNotEqual(env["NPM_CONFIG_USERCONFIG"], env["NPM_CONFIG_GLOBALCONFIG"])

    def test_command_nonzero_and_timeout_preserve_logs(self):
        commands = tools.Commands(self.root, {})
        failed = subprocess.CompletedProcess(["node"], 1, b"partial", b"audit error")
        with (
            patch.object(subprocess, "run", return_value=failed),
            pytest.raises(ValueError, match="failed"),
        ):
            commands.run("failure", ["node"], self.root)
        self.assertEqual((self.root / "failure.stderr").read_bytes(), b"audit error")
        timeout = subprocess.TimeoutExpired(["node"], 300, b"output", b"timeout")
        with (
            patch.object(subprocess, "run", side_effect=timeout),
            pytest.raises(subprocess.TimeoutExpired),
        ):
            commands.run("timeout", ["node"], self.root)
        self.assertEqual((self.root / "timeout.stdout").read_bytes(), b"output")
        self.assertEqual(len(json.loads((self.root / "commands.json").read_text())), 2)

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
        self.assertEqual(set(inputs), {"package.json", "package-lock.json"})
        self.assertFalse((self.root / "node_modules").exists())
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
        self.assertFalse((self.root / "copy/scripts/check-strict-types.ts").is_symlink())

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
