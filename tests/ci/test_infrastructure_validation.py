"""Fail-closed controls for isolated infrastructure validation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import validate_infrastructure as infra

ROOT = Path(__file__).resolve().parents[2]


class InfrastructureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        shutil.copytree(ROOT / "infra/tofu", self.root / "infra/tofu")

    def module(self, name="aegaeon-aws-staging"):
        return self.root / "infra/tofu" / name

    def test_selects_only_affected_modules(self):
        paths = ["infra/tofu/perf-aws-ec2/versions.tf", "infra/tofu/perf-aws-ec2/deleted.tf"]
        assert infra.select_modules(self.root, paths) == [self.module("perf-aws-ec2")]
        assert len(infra.select_modules(self.root, None)) == 3

    def test_rejects_empty_unknown_traversal_and_unrelated_paths(self):
        for paths in [
            [],
            ["infra/tofu/unknown/versions.tf"],
            ["infra/tofu/../versions.tf"],
            ["/infra/tofu/perf-aws-ec2/versions.tf"],
            ["infra//tofu/perf-aws-ec2/versions.tf"],
            ["infra/tofu/perf-aws-ec2/nested/file.tf"],
            ["infra/tofu/perf-aws-ec2/bad\n.tf"],
            ["Cargo.toml"],
        ]:
            with self.subTest(paths=paths), pytest.raises(ValueError, match=r"."):
                infra.select_modules(self.root, paths)

    def test_unknown_or_missing_module_fails(self):
        (self.root / "infra/tofu/unknown").mkdir()
        with pytest.raises(ValueError, match="Unknown or missing"):
            infra.select_modules(self.root, None)
        (self.root / "infra/tofu/unknown").rmdir()
        shutil.rmtree(self.module("perf-aws-ec2"))
        with pytest.raises(ValueError, match="Unknown or missing"):
            infra.select_modules(self.root, None)

    def test_symlink_and_state_inputs_rejected(self):
        module = self.module()
        (module / "injected.tf").symlink_to(ROOT / "flake.nix")
        with pytest.raises(ValueError, match="Symlink"):
            infra.module_inputs(module)
        (module / "injected.tf").unlink()
        (module / "terraform.tfstate").write_text("{}")
        with pytest.raises(ValueError, match="Unexpected input"):
            infra.module_inputs(module)

    def test_missing_lock_rejected_and_initialized_data_ignored(self):
        module = self.module()
        (module / ".terraform").mkdir()
        (module / ".terraform/terraform.tfstate").write_text("private state")
        assert not any(".terraform/" in str(p) for p in infra.module_inputs(module))
        (module / ".terraform.lock.hcl").unlink()
        with pytest.raises(ValueError, match="Missing provider"):
            infra.module_inputs(module)

    def test_stale_lock_constraints_rejected(self):
        module = self.module()
        lock = module / ".terraform.lock.hcl"
        lock.write_text(
            re.sub(r'(constraints\s*=\s*)"[^"\n]+"', r'\1"~> 999.0"', lock.read_text(), count=1)
        )
        with pytest.raises(ValueError, match="Stale lock constraints"):
            infra.lock_contract(module)

    def test_unreviewed_provider_rejected(self):
        path = self.module() / "versions.tf"
        path.write_text(
            path.read_text().replace('source  = "hashicorp/aws"', 'source  = "example/aws"')
        )
        with pytest.raises(ValueError, match="provider source"):
            infra.lock_contract(self.module())

    def test_comments_cannot_satisfy_assignment(self):
        value = (
            'resource "test" "test" {\n# enabled = true\n/* enabled = true */\n'
            'enabled = false\nurl = "https://example.test/a#b"\n}'
        )
        body = infra.block(value, 'resource "test" "test"')
        assert infra.assignment(body, "enabled") == "false"
        assert infra.assignment(body, "url") == '"https://example.test/a#b"'
        with pytest.raises(ValueError, match=r"."):
            infra.assignment("# enabled = true\n", "enabled")

    def test_aws6_requires_explicit_auth_rotation(self):
        path = self.module() / "redis.tf"
        path.write_text(re.sub(r"(?m)^\s*auth_token_update_strategy\s*=.*\n", "", path.read_text()))
        with pytest.raises(ValueError, match="auth_token_update_strategy"):
            infra.resource_contract(self.module(), {"aws": "6.66.0"})
        path.write_text(
            path.read_text().replace(
                "  apply_immediately",
                '  auth_token_update_strategy = "ROTATE"\n\n  apply_immediately',
            )
        )
        infra.resource_contract(self.module(), {"aws": "6.66.0"})

    def test_encryption_and_key_type_regressions_rejected(self):
        for filename, before, after in [
            ("redis.tf", "transit_encryption_enabled = true", "transit_encryption_enabled = false"),
            (
                "kms.tf",
                'customer_master_key_spec = "RSA_2048"',
                'customer_master_key_spec = "ECC_NIST_P256"',
            ),
        ]:
            path = self.module() / filename
            original = path.read_text()
            path.write_text(original.replace(before, after))
            with self.subTest(filename=filename), pytest.raises(ValueError, match=r"."):
                infra.resource_contract(self.module(), {"aws": "5.100.0"})
            path.write_text(original)

    def test_imdsv2_and_replacement_contracts_rejected(self):
        module = self.module("perf-aws-ec2")
        path = module / "instances.tf"
        original = path.read_text()
        for before, after in [
            ('http_tokens = "required"', 'http_tokens = "optional"'),
            ("user_data_replace_on_change = true", "user_data_replace_on_change = false"),
        ]:
            path.write_text(original.replace(before, after))
            with pytest.raises(ValueError, match=r"."):
                infra.resource_contract(module, {"aws": "6.66.0"})
        path.write_text(original)
        infra.resource_contract(module, {"aws": "6.66.0"})

    def test_unknown_runtime_environment_name_rejected(self):
        path = self.module() / "locals.tf"
        path.write_text(
            path.read_text().replace("AEGAEON_DATABASE_URL", "AEGAEON_DATABASE_URl_TYPO")
        )
        with pytest.raises(ValueError, match="Unknown runtime"):
            infra.runtime_contract(self.module(), ROOT)

    def test_aws_and_cli_configuration_not_inherited(self):
        inherited = {
            "AWS_ACCESS_KEY_ID": "secret",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/secret",
            "TF_CLI_ARGS_init": "-upgrade",
            "TF_PLUGIN_CACHE_DIR": "/poison",
            "TOFU_CLI_ARGS": "bad",
        }
        with patch.dict(os.environ, inherited):
            env = infra.isolated_environment(self.root)
        assert not (set(inherited) & set(env))
        assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        assert Path(env["AWS_SHARED_CREDENTIALS_FILE"]).read_text() == ""
        assert env.get("HOME") == os.environ.get("HOME")

    def test_command_failures_preserve_diagnostics(self):
        commands = infra.Commands(self.root, {})
        result = subprocess.CompletedProcess(["tofu"], 2, "bad schema", "failure")
        with (
            patch.object(subprocess, "run", return_value=result),
            pytest.raises(ValueError, match="Command failed"),
        ):
            commands.run(["tofu", "validate"], self.root)
        records = json.loads((self.root / "commands.json").read_text())
        assert records[0]["exit"] == 2
        assert (self.root / records[0]["stdout"]).read_text() == "bad schema"

    def test_invalid_template_inventory_fails(self):
        module = self.module("perf-aws-ec2")
        (module / "extra.sh.tftpl").write_text("echo bad")
        with pytest.raises(ValueError, match="template inventory"):
            infra.check_templates(module, infra.Commands(self.root, {}), "tofu", "bash", self.root)

    def test_rendered_contract_missing_secret_reference_fails(self):
        with pytest.raises(ValueError, match="password stdin"):
            infra.rendered_contract("echo broken", "server", enabled=True)

    def test_support_and_mixed_paths_select_union(self):
        paths = ["scripts/perf/aws_sweep.sh", "infra/tofu/oidc-aws-kms-parity/kms.tf"]
        assert {p.name for p in infra.select_modules(self.root, paths)} == {
            "perf-aws-ec2",
            "oidc-aws-kms-parity",
        }
        paths.append("scripts/ci/validate_infrastructure.py")
        assert len(infra.select_modules(self.root, paths)) == 3

    def test_nested_tags_cannot_satisfy_security_contract(self):
        text = 'tags {\n key_usage = "SIGN_VERIFY"\n}\n'
        with pytest.raises(ValueError, match="Expected one explicit"):
            infra.assignment(text, "key_usage")

    def test_schema_false_success_and_malformed_json_rejected(self):
        commands = infra.Commands(self.root, {})
        for result in [
            "null",
            "[]",
            '{"valid": false, "error_count": 0}',
            '{"valid": true, "error_count": 1}',
            "{}",
            "invalid json",
        ]:
            with (
                patch.object(commands, "run", return_value=result),
                pytest.raises(ValueError, match=r"."),
            ):
                infra.validate_schema(commands, "tofu", self.root)

    def test_readonly_lock_rewrite_fails_and_source_is_unchanged(self):
        original = (self.module() / ".terraform.lock.hcl").read_bytes()

        def rewrite(argv, cwd, stdin=None):
            if argv[1] == "init":
                (cwd / ".terraform.lock.hcl").write_text("rewritten lock")
            return "{}"

        with patch.object(infra.Commands, "run", side_effect=rewrite):
            report = infra.validate_module(
                self.module(), self.root, self.root / "report", {"tofu": "tofu", "bash": "bash"}
            )
        assert report["status"] == "failed"
        assert "rewrote readonly lock" in report["error"]
        assert (self.module() / ".terraform.lock.hcl").read_bytes() == original

    def test_command_timeout_preserves_partial_output(self):
        commands = infra.Commands(self.root, {})
        failure = subprocess.TimeoutExpired(["tofu"], 1, b"partial output", b"diagnostic")
        with (
            patch.object(subprocess, "run", side_effect=failure),
            pytest.raises(subprocess.TimeoutExpired),
        ):
            commands.run(["tofu", "init"], self.root)
        record = json.loads((self.root / "commands.json").read_text())[0]
        assert (self.root / record["stdout"]).read_bytes() == b"partial output"
        assert "error" in record

    def test_cli_rejects_timeout_malformed_validation_and_lock_rewrite(self):
        paths = self.root / "paths.json"
        paths.write_text(json.dumps(["infra/tofu/aegaeon-aws-staging/versions.tf"]))
        for failure in ("timeout", "malformed", "invalid", "rewrite"):
            output = self.root / failure

            def fake_run(argv, cwd, stdin=None, failure=failure):
                if argv[1] == "init" and failure == "timeout":
                    raise subprocess.TimeoutExpired(argv, 300)
                if argv[1] == "init" and failure == "rewrite":
                    (cwd / ".terraform.lock.hcl").write_text("unexpected rewrite")
                if argv[1] == "validate":
                    return "null" if failure == "malformed" else '{"valid":false,"error_count":1}'
                return "{}"

            with (
                self.subTest(failure=failure),
                patch(
                    "sys.argv",
                    [
                        "validate_infrastructure.py",
                        "--root",
                        str(self.root),
                        "--paths-json",
                        str(paths),
                        "--output",
                        str(output),
                    ],
                ),
                patch.object(shutil, "which", return_value=sys.executable),
                patch.object(infra, "toolchain_provenance", return_value={"toolchain_sources": {}}),
                patch.object(infra, "installed_providers", return_value={"fixture": "hash"}),
                patch.object(infra.Commands, "run", side_effect=fake_run),
            ):
                assert infra.main() == 1
            summary = json.loads((output / "summary.json").read_text())
            assert summary["status"] == "failed"
            assert summary["modules"][0]["status"] == "failed"
            assert "error" in summary["modules"][0]

    def test_unavailable_tools_fail(self):
        output = self.root / "output"
        with (
            patch(
                "sys.argv",
                ["validate_infrastructure.py", "--root", str(self.root), "--output", str(output)],
            ),
            patch.object(shutil, "which", return_value=None),
        ):
            assert infra.main() == 1
        result = json.loads((output / "summary.json").read_text())
        assert "tools unavailable" in result["error"]


if __name__ == "__main__":
    unittest.main()
