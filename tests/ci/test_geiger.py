"""Exercise Geiger failures, incomplete evidence, and one scan per member."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))

from geiger_report import check_report, identity  # noqa: E402


def package(root, name):
    return {
        "id": name,
        "name": name,
        "version": "0.1.0",
        "manifest_path": str(root / "crates" / name / "Cargo.toml"),
    }


def report(member):
    counters = {
        category: {"safe": 1, "unsafe_": 0}
        for category in ("functions", "exprs", "item_impls", "item_traits", "methods")
    }
    return {
        "packages": [
            {
                "package": {"id": identity(member)},
                "unsafety": {
                    "used": counters,
                    "unused": copy.deepcopy(counters),
                    "forbids_unsafe": False,
                },
            }
        ],
        "packages_without_metrics": [],
        "used_but_not_scanned_files": [],
    }


class GeigerTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.member = package(self.root, "server")
        self.metadata = {"workspace_members": ["server"], "packages": [self.member]}
        self.report = report(self.member)
        self.manifest = Path(self.member["manifest_path"])

    def validate(self, evidence=None, diagnostics=""):
        return check_report(
            self.metadata,
            self.manifest,
            self.report if evidence is None else evidence,
            diagnostics,
        )

    def test_complete_metrics_do_not_claim_absence_of_unsafe(self):
        self.report["packages"][0]["unsafety"]["used"]["exprs"]["unsafe_"] = 5
        assert self.validate()["status"] == "complete"

    def test_missing_duplicate_or_wrong_identity_is_rejected(self):
        for mode in ("missing", "duplicate", "wrong-source"):
            data = copy.deepcopy(self.report)
            if mode == "missing":
                data["packages"] = []
            elif mode == "duplicate":
                data["packages"] *= 2
            else:
                data["packages"][0]["package"]["id"]["source"] = {"Registry": {}}
            with self.subTest(mode=mode), pytest.raises(ValueError, match="metrics"):
                self.validate(data)

    def test_pinned_geiger_package_id_quirk_is_bound_to_metadata(self):
        old_id = self.member["id"]
        self.member["id"] = f"path+{self.manifest.parent.as_uri()}#server@0.1.0"
        self.metadata["workspace_members"] = [self.member["id"]]
        source = f"{self.manifest.parent.as_uri()}%23server@0.1."
        self.report["packages"][0]["package"]["id"]["source"] = {"Path": source}
        assert self.validate()["status"] == "complete"
        self.metadata["workspace_members"] = [old_id]
        with pytest.raises(KeyError):
            self.validate()

    def test_workspace_missing_metrics_or_source_is_rejected(self):
        for field, value in (
            ("packages_without_metrics", identity(self.member)),
            ("used_but_not_scanned_files", str(self.manifest.parent / "src/lib.rs")),
        ):
            data = copy.deepcopy(self.report)
            data[field].append(value)
            with self.subTest(field=field), pytest.raises(ValueError, match="workspace"):
                self.validate(data)

    def test_unused_workspace_parse_failure_is_rejected(self):
        for filename in ("unused.rs", "artifacts/cargo-home/registry/dependency/src/lib.rs"):
            diagnostics = f"Failed to parse file: {self.manifest.parent}/{filename}, Parse(error)\n"
            with self.subTest(filename=filename), pytest.raises(ValueError, match="not scanned"):
                self.validate(diagnostics=diagnostics)

    def test_incomplete_dependency_inventory_remains_visible(self):
        self.report["packages_without_metrics"] = [{"name": "external"}]
        self.report["used_but_not_scanned_files"] = ["/external/generated.rs"]
        result = self.validate()
        assert result["dependency_packages_without_metrics"] == [{"name": "external"}]
        assert result["dependency_files_not_scanned"] == ["/external/generated.rs"]

    def test_invalid_counter_and_missing_collection_are_rejected(self):
        for group in ("used", "unused"):
            for invalid in (-1, True, "0"):
                data = copy.deepcopy(self.report)
                data["packages"][0]["unsafety"][group]["exprs"]["safe"] = invalid
                with (
                    self.subTest(group=group, invalid=invalid),
                    pytest.raises(ValueError, match="count"),
                ):
                    self.validate(data)
        del self.report["used_but_not_scanned_files"]
        with pytest.raises(KeyError):
            self.validate()

    def install_cargo_fixture(self):
        self.root.joinpath("metadata.json").write_text(json.dumps(self.metadata))
        self.root.joinpath("report.json").write_text(json.dumps(self.report))
        cargo = self.root / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\n"
            """
import json
import os
import pathlib
import sys
root = pathlib.Path(os.environ['GEIGER_FIXTURE'])
with (root / 'calls').open('a') as out:
    out.write(json.dumps(sys.argv[1:]) + '\\n')
with (root / 'cargo-homes').open('a') as out:
    out.write(json.dumps(os.environ.get('CARGO_HOME')) + '\\n')
if sys.argv[1] == 'metadata':
    print((root / 'metadata.json').read_text())
elif sys.argv[1] == 'geiger':
    print((root / 'report.json').read_text())
    sys.exit(int(os.environ.get('GEIGER_FIXTURE_EXIT', '0')))
"""
        )
        cargo.chmod(0o755)
        (self.root / "cargo-geiger").symlink_to(cargo)

    def run_gate(self, exit_code="0", *args, suite=False, cwd=None):
        script = "run_geiger.sh"
        if suite:
            (self.root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
            script = "run_security_suite.sh"
            args = ("--stage", "geiger", *args)
        # Execute only the repository runner and controlled fixture commands.
        return subprocess.run(  # noqa: S603
            ["bash", str(ROOT / "scripts/security" / script), *args],  # noqa: S607
            cwd=cwd or self.root,
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "GEIGER_FIXTURE": str(self.root),
                "GEIGER_FIXTURE_EXIT": exit_code,
                "GEIGER_ARTIFACT_DIR": str(self.root / "evidence"),
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_suite_preserves_caller_cargo_configuration(self):
        self.install_cargo_fixture()
        cache = self.root / "caller-cache"
        cache.mkdir()
        (cache / "config.toml").write_text("[net]\noffline = true\n")
        with patch.dict(os.environ, {"CARGO_HOME": str(cache)}):
            result = self.run_gate(suite=True)
        assert result.returncode == 0, result.stderr
        homes = [json.loads(line) for line in (self.root / "cargo-homes").read_text().splitlines()]
        assert homes == [str(cache), str(cache)]
        assert not (self.root / "artifacts/security/latest/cargo-home").exists()

    def test_relative_cargo_home_is_resolved_before_scanning(self):
        self.install_cargo_fixture()
        caller = self.root / "caller"
        caller.mkdir()
        git = self.root / "git"
        git.write_text(f"#!{sys.executable}\nimport os\nprint(os.environ['GEIGER_FIXTURE'])\n")
        git.chmod(0o755)
        with patch.dict(os.environ, {"CARGO_HOME": "caller-cache"}):
            result = self.run_gate(cwd=caller)
        assert result.returncode == 0, result.stderr
        expected = str(caller / "caller-cache")
        homes = [json.loads(line) for line in (self.root / "cargo-homes").read_text().splitlines()]
        assert homes == [expected, expected]

    def test_one_scan_supplies_both_reports(self):
        self.install_cargo_fixture()
        result = self.run_gate()
        assert result.returncode == 0, result.stderr
        calls = [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]
        scans = [call for call in calls if call[0] == "geiger"]
        assert len(scans) == 1
        assert "--no-deps" not in scans[0]
        assert "--include-tests" in scans[0]
        assert (self.root / "evidence/gate.json").is_file()

    def test_exit_failure_cannot_reuse_a_successful_report(self):
        self.install_cargo_fixture()
        assert self.run_gate().returncode == 0
        result = self.run_gate("7")
        assert result.returncode != 0
        assert "exit 7" in result.stderr
        assert not (self.root / "evidence/gate.json").exists()

    def test_zero_exit_with_missing_or_malformed_report_fails(self):
        self.install_cargo_fixture()
        for output in ("", "{}", "{invalid"):
            (self.root / "report.json").write_text(output)
            assert self.run_gate().returncode != 0

    def test_empty_selection_and_weakening_options_fail(self):
        self.install_cargo_fixture()
        assert self.run_gate("0", "--forbid-only").returncode != 0
        self.metadata["workspace_members"] = []
        (self.root / "metadata.json").write_text(json.dumps(self.metadata))
        assert self.run_gate().returncode != 0


if __name__ == "__main__":
    unittest.main()
