"""Namespace qualification must preserve isolation and clean up its own policy."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import with_organization_userns as subject  # noqa: E402
from database_execution import owned_command  # noqa: E402

EXECUTABLE = "/nix/store/" + "a" * 32 + "-util-linux-2.42.3-bin/bin/unshare"
DENIED = {
    "passed": False,
    "attempts": [{"stderr": "unshare: write failed /proc/self/uid_map: Operation not permitted"}],
}


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.report = self.root / "report.json"
        policy_directory = self.root / "policy"
        policy_directory.mkdir()
        self.enterContext(
            patch.object(subject.tempfile, "mkdtemp", return_value=str(policy_directory))
        )
        self.commands = []
        self.loaded = False
        self.name = None
        self.fail_action = None
        self.probe = self.enterContext(
            patch.object(subject, "probe", side_effect=[DENIED, {"passed": True}])
        )
        self.enterContext(patch.object(subject, "restriction", return_value="1"))
        self.enterContext(patch.object(subject.Path, "is_file", return_value=True))
        self.enterContext(patch.object(subject.Path, "is_symlink", return_value=False))
        self.enterContext(patch.object(subject, "execute", side_effect=self.execute))
        self.child = self.enterContext(patch.object(subject, "run_command", return_value=0))

    def execute(self, command, *, timeout=120):
        self.commands.append(command)
        stdout = ""
        code = 0
        if command[:2] == ["nix", "eval"]:
            stdout = EXECUTABLE
        elif command[:3] == ["sudo", "-n", "cat"]:
            stdout = "unrelated-existing (enforce)\n"
            if self.loaded:
                stdout += self.name + " (unconfined)\n"
        else:
            text = Path(command[-1]).read_text()
            self.name = text.splitlines()[1].split()[1]
            if self.fail_action in command:
                code = 1
            elif "--add" in command:
                assert not self.loaded
                self.loaded = True
            elif "--remove" in command:
                assert self.loaded
                self.loaded = False
            else:
                raise AssertionError(command)
        return {"command": command, "returncode": code, "stdout": stdout, "stderr": ""}

    def invoke(self):
        code = subject.run(["build", "all-cases"], self.report)
        return code, json.loads(self.report.read_text())

    def test_scoped_permission_is_removed_and_host_policy_preserved(self):
        code, record = self.invoke()
        assert code == 0
        assert record["profile_removed"]
        assert not self.loaded
        assert record["restriction_before"] == record["restriction_after"] == "1"
        assert record["executable"] == EXECUTABLE
        assert record["before"] == DENIED
        assert record["after"]["passed"]
        assert len([c for c in self.commands if "--add" in c]) == 1
        assert len([c for c in self.commands if "--remove" in c]) == 1
        self.child.assert_called_once_with(["build", "all-cases"])

    def test_working_namespace_needs_no_host_mutation(self):
        self.probe.side_effect = [{"passed": True}]
        assert self.invoke()[0] == 0
        assert self.commands == []

    def test_unrelated_failure_does_not_grant_permission_or_run_checks(self):
        self.probe.side_effect = [{"passed": False, "attempts": [{"stderr": "disk full"}]}]
        assert self.invoke()[0] == 1
        assert not self.commands
        self.child.assert_not_called()

    def test_permission_error_without_restriction_fails_closed(self):
        with patch.object(subject, "restriction", return_value="absent"):
            assert self.invoke()[0] == 1
        assert not self.commands
        self.child.assert_not_called()

    def test_failed_post_install_probe_cleans_up_without_running_checks(self):
        self.probe.side_effect = [DENIED, DENIED]
        code, record = self.invoke()
        assert code == 1
        assert record["profile_removed"]
        assert not self.loaded
        self.child.assert_not_called()

    def test_build_failure_is_preserved_after_cleanup(self):
        self.child.return_value = 42
        code, record = self.invoke()
        assert code == 42
        assert record["profile_removed"]

    def test_handled_cancellation_cleans_up_and_fails(self):
        self.child.side_effect = InterruptedError("fixture cancelled")
        code, record = self.invoke()
        assert code == 1
        assert record["profile_removed"]

    def test_interrupted_install_that_loaded_a_profile_is_cleaned_up(self):
        original = self.execute

        def interrupted_install(command, **kwargs):
            result = original(command, **kwargs)
            if "--add" in command:
                message = "reply lost after profile load"
                raise InterruptedError(message)
            return result

        with patch.object(subject, "execute", side_effect=interrupted_install):
            code, record = self.invoke()
        assert code == 1
        assert record["profile_removed"]
        assert not self.loaded
        self.child.assert_not_called()

    def test_cleanup_failure_cannot_be_reported_as_success(self):
        self.fail_action = "--remove"
        code, record = self.invoke()
        assert code == 1
        assert not record["profile_removed"]

    def test_cleanup_failure_precedes_recovery_receipt_failure(self):
        self.fail_action = "--remove"
        original_write = subject.Path.write_text

        def write(path, *args, **kwargs):
            if path.name == "recovery.json":
                message = "controlled recovery receipt failure"
                raise OSError(message)
            return original_write(path, *args, **kwargs)

        with patch.object(subject.Path, "write_text", write):
            code, record = self.invoke()
        assert code == 1
        assert record["error"] == "temporary AppArmor profile was not removed"
        assert record["policy_recovery_error"] == "controlled recovery receipt failure"
        assert Path(record["recovery"]["policy_path"]).is_file()

    def test_install_failure_does_not_remove_someone_elses_profile(self):
        self.fail_action = "--add"
        assert self.invoke()[0] == 1
        assert not any("--remove" in c for c in self.commands)
        self.child.assert_not_called()

    def test_existing_profile_is_not_replaced(self):
        with patch.object(subject, "present", return_value=True):
            assert self.invoke()[0] == 1
        assert not any("--add" in c or "--remove" in c for c in self.commands)
        self.child.assert_not_called()

    def test_changed_global_restriction_is_a_failure(self):
        with patch.object(subject, "restriction", side_effect=["1", "0"]):
            code, record = self.invoke()
        assert code == 1
        assert record["profile_removed"]

    def test_policy_attachment_rejects_globs_aliases_and_injection(self):
        name = "aegaeon-userns-" + "a" * 32
        for path in ("/usr/bin/unshare", EXECUTABLE + '" {}', EXECUTABLE.replace("a" * 32, "*")):
            with pytest.raises(ValueError, match="invalid namespace"):
                subject.profile_text(path, name)
        with pytest.raises(ValueError, match="invalid namespace"):
            subject.profile_text(EXECUTABLE, name + '"')
        text = subject.profile_text(EXECUTABLE, name)
        assert text.count("userns,") == 1
        assert "*" not in text

    def test_probe_rebuilds_even_an_existing_output_and_rebuild_failure_counts(self):
        # Bypass setUp's orchestration mock to exercise the actual probe.
        with patch.object(
            subject, "execute", side_effect=[{"returncode": 0}, {"returncode": 1}]
        ) as execute:
            result = ORIGINAL_PROBE()
        assert not result["passed"]
        assert len(execute.call_args_list) == 2
        assert "--rebuild" in execute.call_args_list[1].args[0]
        assert all(call.args[0][-3:-1] == ["--builders", ""] for call in execute.call_args_list[:1])
        assert "--builders" in execute.call_args_list[1].args[0]

    def test_required_workflows_qualify_both_build_paths_and_keep_receipts(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        for name, suffix in (("ci", "core"), ("db-integration", "db")):
            steps = jobs[name]["steps"]
            wrappers = [s for s in steps if "with_organization_userns.py" in s.get("run", "")]
            if name == "db-integration":
                wrappers = [
                    s
                    for s in steps
                    if "database_execution.py run --name production" in s.get("run", "")
                ]
                command = owned_command({"suites": {}}, "production")
                assert command[:4] == [
                    "python3",
                    "scripts/ci/with_organization_userns.py",
                    "--report",
                    "artifacts/organization-userns-db.json",
                ]
                assert command[4:] == [
                    "--",
                    "nix",
                    "build",
                    ".#checks.x86_64-linux.organizations-production-runtime",
                    "--no-link",
                ]
            assert len(wrappers) == 1
            assert "if" not in wrappers[0]
            assert any(
                s.get("if") in ("always()", "${{ always() }}")
                and f"organization-userns-{suffix}.json" in s.get("with", {}).get("path", "")
                for s in steps
            )


ORIGINAL_PROBE = subject.probe


if __name__ == "__main__":
    unittest.main()
