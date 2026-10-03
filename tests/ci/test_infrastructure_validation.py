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
        for name in infra.CONTRACT_SOURCES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)

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
        with pytest.raises(ValueError, match="environment assignments"):
            infra.runtime_contract(self.module(), ROOT)

    def valid_staging(self):
        path = self.module() / "locals.tf"
        text = path.read_text()
        for name in (
            "AEGAEON_CSRF_REDIS_URL",
            "AEGAEON_RATE_LIMIT_REDIS_URL",
            "AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL",
            "AEGAEON_EXPOSE_METRICS_ON_MAIN",
        ):
            text = re.sub(r"(?m)^.*\b" + name + r"\b.*\n", "", text)
        path.write_text(text)
        return path

    def test_explicit_legacy_profiles_report_complete_name_only_failures(self):
        path = self.valid_staging()
        removed = (
            "AEGAEON_CSRF_REDIS_URL",
            "AEGAEON_EXPOSE_METRICS_ON_MAIN",
            "AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL",
            "AEGAEON_RATE_LIMIT_REDIS_URL",
        )
        text = path.read_text()
        for name in removed:
            if name.endswith("_REDIS_URL"):
                text = text.replace(
                    "redis_secret_env_names = toset([",
                    f'redis_secret_env_names = toset([\n    "{name}",',
                    1,
                )
            else:
                text = text.replace(
                    "container_environment = [",
                    f'container_environment = [\n    {{ name = "{name}", value = "legacy" }},',
                    1,
                )
        path.write_text(text)
        with pytest.raises(infra.RuntimeContractError) as staging:
            infra.runtime_contract(self.module(), self.root)
        assert len(staging.value.report["violations"]) == 4
        assert all(
            v["reason"] == "removed startup variable" for v in staging.value.report["violations"]
        )
        path = self.module("perf-aws-ec2") / "user_data_server.sh.tftpl"
        legacy = (
            "cat >/etc/aegaeon/server.env <<EOF\n"
            "BASE_URL=http://server.example:8080\n"
            "AEGAEON_EXPOSE_METRICS_ON_MAIN=1\n"
            "AEGAEON_TRUSTED_PROXIES=127.0.0.1/32\nEOF"
        )
        template, replacements = re.subn(
            r"(?m)^cat >/etc/aegaeon/server\.env <<EOF\n.*?\nEOF$",
            lambda _: legacy,
            path.read_text(),
            flags=re.DOTALL,
        )
        assert replacements == 1
        path.write_text(template)
        with pytest.raises(infra.RuntimeContractError) as perf:
            infra.runtime_contract(self.module("perf-aws-ec2"), self.root)
        violations = perf.value.report["violations"]
        assert len(violations) == 21
        assert {v["name"] for v in violations if v["reason"] == "removed startup variable"} == {
            "BASE_URL",
            "AEGAEON_EXPOSE_METRICS_ON_MAIN",
        }
        assert all(set(v) == {"process", "name", "reason"} for v in violations)

    def test_corrected_staging_and_separate_parity_profiles_bind_sources(self):
        self.valid_staging()
        report = infra.runtime_contract(self.module(), self.root)
        assert report["status"] == "passed"
        assert set(report["processes"]) == {"server", "migrate", "hosted_bootstrap"}
        assert report["processes"]["migrate"] == ["DATABASE_URL"]
        assert set(report["runtime_sources"]) == set(infra.CONTRACT_SOURCES)
        parity = infra.runtime_contract(self.module("oidc-aws-kms-parity"), self.root)
        assert parity["status"] == "passed"
        assert "AEGAEON_OIDC_SIGNING_BACKEND" in parity["processes"]["kms_parity"]

    def test_each_removed_empty_variable_rejected(self):
        path = self.valid_staging()
        original = path.read_text()
        _, removed, _ = infra.server_inventory(self.root)
        for name in sorted(removed):
            sensitive = name.endswith("_REDIS_URL") or name in {
                "AEGAEON_DATABASE_URL",
                "AEGAEON_KEY_ENCRYPTION_KEY",
                "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
            }
            marker = (
                "secret_environment = concat(\n    [" if sensitive else "container_environment = ["
            )
            attribute = "valueFrom" if sensitive else "value"
            path.write_text(
                original.replace(
                    marker, marker + f'\n    {{ name = "{name}", {attribute} = "" }},', 1
                )
            )
            with self.subTest(name=name):
                with pytest.raises(infra.RuntimeContractError) as failure:
                    infra.runtime_contract(self.module(), self.root)
                assert {v["name"] for v in failure.value.report["violations"]} == {name}

    def test_explicit_removed_inventory_overrides_classified_allow_entry(self):
        path = self.root / infra.CONTRACT_SOURCES[0]
        declaration = "const MAIN_ENV_INVENTORY: &[(&str, MainEnvAuthority)] = &["
        path.write_text(
            path.read_text().replace(
                declaration,
                declaration
                + '\n("AEGAEON_EXPOSE_METRICS_ON_MAIN", MainEnvAuthority::SystemBootstrap),',
                1,
            )
        )
        allowed, removed, _ = infra.server_inventory(self.root)
        assert "AEGAEON_EXPOSE_METRICS_ON_MAIN" in removed
        assert "AEGAEON_EXPOSE_METRICS_ON_MAIN" not in allowed

    def test_migration_does_not_accept_server_database_alias(self):
        self.valid_staging()
        path = self.module() / "ecs.tf"
        path.write_text(
            path.read_text().replace('name = "DATABASE_URL"', 'name = "AEGAEON_DATABASE_URL"')
        )
        with pytest.raises(infra.RuntimeContractError) as failure:
            infra.runtime_contract(self.module(), self.root)
        assert {v["process"] for v in failure.value.report["violations"]} == {"migrate"}

    def test_nested_container_metadata_cannot_supply_process_environment(self):
        self.valid_staging()
        path = self.module() / "ecs.tf"
        path.write_text(
            path.read_text().replace(
                "      environment = local.container_environment",
                "      metadata = {\n        environment = local.container_environment\n      }",
                1,
            )
        )
        report = infra.runtime_contract_report(self.module(), self.root)
        assert report["status"] == "failed"
        assert set(report["runtime_sources"]) == set(infra.CONTRACT_SOURCES)
        assert "explicit environment expression" in report["violations"][0]["reason"]

    def test_perf_server_inputs_must_feed_actual_container_command(self):
        module = self.module("perf-aws-ec2")
        path = module / "user_data_server.sh.tftpl"
        original = path.read_text()
        infra.perf_server_environment_wiring(original)
        marker = "--env-file /etc/aegaeon/server.env "
        for replacement in [
            "",
            "--env-file /etc/aegaeon/unused.env ",
            marker + "--env-file /etc/aegaeon/override.env ",
        ]:
            path.write_text(original.replace(marker, replacement))
            report = infra.runtime_contract_report(module, self.root)
            assert report["status"] == "failed"
            assert "environment-file wiring" in report["violations"][0]["reason"]

    def test_every_required_assignment_must_exist_despite_comments(self):
        path = self.valid_staging()
        original = path.read_text()
        _, _, required = infra.server_inventory(self.root)
        for name in sorted(required):
            mutated = re.sub(r"(?m)^.*\b" + name + r"\b.*\n", "", original)
            assert mutated != original
            path.write_text(mutated + f'\n# {name} = "present only in a comment"\n')
            with self.subTest(name=name), pytest.raises(infra.RuntimeContractError) as failure:
                infra.runtime_contract(self.module(), self.root)
            assert {v["name"] for v in failure.value.report["violations"]} == {name}

    def test_test_only_other_process_and_comment_names_cannot_authorize_server(self):
        path = self.valid_staging()
        original = path.read_text()
        source = self.root / infra.CONTRACT_SOURCES[0]
        source.write_text(source.read_text() + "\n// AEGAEON_FAKE_RUNTIME_INPUT\n")
        for name in [
            "AEGAEON_FAKE_RUNTIME_INPUT",
            "AEGAEON_JWKS_INSECURE_SKIP_VERIFY",
            "AEGAEON_HOSTED_BOOTSTRAP_ISSUER_URL",
            "AEGAEON_OIDC_SIGNING_BACKEND",
            "BASE_URl",
        ]:
            path.write_text(
                original.replace(
                    "container_environment = [",
                    "container_environment = [\n"
                    f'    {{ name = "{name}", value = "secret-marker" }},',
                )
            )
            with self.subTest(name=name), pytest.raises(ValueError, match=r".") as failure:
                infra.runtime_contract(self.module(), self.root)
            assert "secret-marker" not in str(failure.value)

    def test_empty_required_value_and_duplicate_assignment_rejected(self):
        path = self.valid_staging()
        original = path.read_text()
        path.write_text(original.replace("value = local.runtime_issuer_host", 'value = ""'))
        with pytest.raises(infra.RuntimeContractError, match="empty required value"):
            infra.runtime_contract(self.module(), self.root)
        path.write_text(
            original.replace(
                "container_environment = [",
                "container_environment = [\n"
                '    { name = "AEGAEON_RUNTIME_ISSUER_HOST", value = "example.test" },',
            )
        )
        with pytest.raises(ValueError, match="Duplicate"):
            infra.runtime_contract(self.module(), self.root)

    def test_malformed_unknown_and_duplicate_authority_entries_rejected(self):
        path = self.root / infra.CONTRACT_SOURCES[0]
        original = path.read_text()
        for mutated in [
            original.replace(
                "MainEnvAuthority::SystemBootstrap,", "MainEnvAuthority::UnknownClass,", 1
            ),
            original.replace('"AEGAEON_DB_MAX_CONNECTIONS"', '"AEGAEON_DATABASE_URL"', 1),
            original.replace('"AEGAEON_DB_MAX_CONNECTIONS"', "dynamic_name()", 1),
        ]:
            path.write_text(mutated)
            with pytest.raises(ValueError, match=r"."):
                infra.server_inventory(self.root)

    def test_unresolved_and_nested_assignments_cannot_supply_environment(self):
        for expression in [
            '[{ name = var.dynamic_name, value = "x" }]',
            '[{ name = "RUST_LOG", value = unknown() }]',
            '[{ name = "RUST_LOG", value = "x", extra = true }]',
        ]:
            with pytest.raises(ValueError, match=r"."):
                infra.environment_objects(expression, "value")
        with pytest.raises(ValueError, match="explicit environment expression"):
            infra.expression("metadata = {\n environment = []\n}\n", "environment")

    def test_main_provenance_timeout_preserves_summary_and_partial_logs(self):
        output = self.root / "provenance-timeout"
        failure = subprocess.TimeoutExpired(["nix", "path-info"], 300, b"partial", b"timeout")

        def provenance(root, directory, tools):
            return infra.Commands(directory, {}).run(["nix", "path-info"], root)

        with (
            patch(
                "sys.argv",
                ["validate_infrastructure.py", "--root", str(self.root), "--output", str(output)],
            ),
            patch.object(infra, "toolchain_provenance", side_effect=provenance),
            patch.object(infra.shutil, "which", return_value=sys.executable),
            patch.object(infra.subprocess, "run", side_effect=failure),
        ):
            assert infra.main() == 1
        summary = json.loads((output / "summary.json").read_text())
        assert summary["status"] == "failed"
        assert "timed out" in summary["error"]
        commands = json.loads((output / "commands.json").read_text())
        assert (output / commands[0]["stdout"]).read_bytes() == b"partial"

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

    def fixture_rendered_template(self, role, enabled=True, registry_enabled=True):
        text = (self.module("perf-aws-ec2") / f"user_data_{role}.sh.tftpl").read_text()
        # Bounded substitution fixture; no OpenTofu execution is implied.
        text = text.replace("$${", "@@SHELL_DOLLAR@@")
        values = infra.template_values()
        values.update(
            expose_metrics_on_main=enabled,
            auto_run_loadtest=enabled,
            ghcr_auth_enabled=registry_enabled,
        )
        for name, value in values.items():
            text = text.replace("${" + name + "}", str(value))
            text = text.replace("${" + name + ' ? "1" : "0"}', "1" if value else "0")
        text = text.replace(
            "%{ if auto_run_loadtest }\nsystemctl start aegaeon-loadtest.service\n%{ endif }",
            "systemctl start aegaeon-loadtest.service" if enabled else "",
        )
        return text.replace("@@SHELL_DOLLAR@@", "${")

    def test_ecs_credentials_remain_in_typed_secret_collections(self):
        self.valid_staging()
        module = self.module()
        assert infra.runtime_contract(module, self.root)["status"] == "passed"
        locals_path = module / "locals.tf"
        ecs_path = module / "ecs.tf"
        original_locals = locals_path.read_text()
        original_ecs = ecs_path.read_text()
        profiles = {
            "server": [
                "AEGAEON_DATABASE_URL",
                "AEGAEON_KEY_ENCRYPTION_KEY",
                "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
            ],
            "migrate": ["DATABASE_URL"],
            "hosted_bootstrap": [
                "AEGAEON_DATABASE_URL",
                "AEGAEON_KEY_ENCRYPTION_KEY",
                "AEGAEON_HOSTED_BOOTSTRAP_OWNER_PASSWORD",
            ],
        }
        for process, names in profiles.items():
            for name in names:
                locals_path.write_text(original_locals)
                ecs_path.write_text(original_ecs)
                path = locals_path if process == "server" else ecs_path
                text = path.read_text()
                body = (
                    text
                    if process == "server"
                    else infra.block(text, f'resource "aws_ecs_task_definition" "{process}"')
                )
                pattern = (
                    r'\{\s*name\s*=\s*"' + name + r'"\s*,?\s*valueFrom\s*=\s*([^{}]+?)\s*\}\s*,?'
                )
                matches = list(re.finditer(pattern, body))
                assert len(matches) == 1
                entry = matches[0].group(0)
                changed = body.replace(entry, "", 1)
                marker = "container_environment = [" if process == "server" else "environment = ["
                assert marker in changed
                plain = entry.replace("valueFrom", "value").rstrip().rstrip(",")
                changed = changed.replace(marker, marker + "\n" + plain + ",", 1)
                path.write_text(changed if process == "server" else text.replace(body, changed, 1))
                with (
                    self.subTest(process=process, name=name),
                    pytest.raises(
                        ValueError, match="sensitive names must use ECS secrets"
                    ) as failure,
                ):
                    infra.runtime_contract(module, self.root)
                assert name in str(failure.value)
                assert "aws_secretsmanager_secret" not in str(failure.value)

    def test_ecs_field_kinds_and_sensitive_redis_names_rejected(self):
        self.valid_staging()
        module = self.module()
        locals_path = module / "locals.tf"
        original_locals = locals_path.read_text()
        for attribute, replacement in [("valueFrom", "value"), ("value", "valueFrom")]:
            marker = (
                'name = "AEGAEON_DATABASE_URL", valueFrom'
                if attribute == "valueFrom"
                else 'name = "AWS_REGION", value'
            )
            locals_path.write_text(
                original_locals.replace(marker, marker.replace(attribute, replacement), 1)
            )
            with (
                self.subTest(attribute=attribute),
                pytest.raises(ValueError, match="assignments requiring"),
            ):
                infra.runtime_contract(module, self.root)
        locals_path.write_text(original_locals)
        server = infra.staging_processes(module)["server"]
        redis_name = next(name for name in server if name.endswith("_REDIS_URL"))
        with pytest.raises(ValueError, match="sensitive names must use ECS secrets"):
            infra.ecs_process_inputs("server", {redis_name: "credential-sentinel"}, {})
        with pytest.raises(ValueError, match="Duplicate process environment"):
            infra.ecs_process_inputs("server", {"AWS_REGION": "region"}, {"AWS_REGION": "region"})

    def test_hosted_region_alternatives_follow_nonempty_runtime_pair(self):
        self.valid_staging()
        module = self.module()
        path = module / "ecs.tf"
        original = path.read_text()
        body = infra.block(original, 'resource "aws_ecs_task_definition" "hosted_bootstrap"')
        assert body in original
        without_fallback = re.sub(r'(?m)^.*name = "AWS_REGION".*\n', "", body)
        original = original.replace(body, without_fallback, 1)
        name = "AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION"
        marker = next(
            line for line in original.splitlines(keepends=True) if f'name = "{name}"' in line
        )
        cases = [
            ('"us-east-1"', None, True),
            (None, '"us-east-1"', True),
            ('"us-east-1"', '"us-west-2"', True),
            ('""', '"us-east-1"', True),
            ('"   "', '"us-east-1"', True),
            ('"us-east-1"', '""', True),
            (None, None, False),
            ('""', '""', False),
            ('"   "', '"\\t"', False),
            ('""', None, False),
            (None, '"   "', False),
            ("data.aws_region.current.region", None, True),
        ]
        for preferred, fallback, accepted in cases:
            assignments = ""
            for key, value in [(name, preferred), ("AWS_REGION", fallback)]:
                if value is not None:
                    assignments += f'        {{ name = "{key}", value = {value} }},\n'
            path.write_text(
                original.replace(marker, assignments + "        # " + marker.strip() + "\n")
            )
            report = infra.runtime_contract_report(module, self.root)
            with self.subTest(preferred=preferred, fallback=fallback):
                assert (report["status"] == "passed") == accepted
                if not accepted:
                    assert any(
                        v["reason"] == "missing or empty required region alternative"
                        for v in report["violations"]
                    )
        path.write_text(original)
        source = self.root / "crates/server/src/bin/aegaeon-hosted-bootstrap.rs"
        source.write_text(
            source.read_text().replace(
                'env_or_required_env("AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", "AWS_REGION")',
                'env_or_required_env("AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", "AWS_DEFAULT_REGION")',
            )
        )
        with pytest.raises(ValueError, match="Changed hosted-bootstrap region alternatives"):
            infra.process_profiles(self.root)

    def test_perf_loadgen_execution_binds_validated_envfile_and_argv(self):
        module = self.module("perf-aws-ec2")
        path = module / "user_data_loadgen.sh.tftpl"
        original = path.read_text()
        assert "loadgen" in infra.process_inputs(module)
        changes = [
            ("source /etc/aegaeon/loadtest.env", "source /etc/aegaeon/unused.env"),
            ("source /etc/aegaeon/loadtest.env", "# source /etc/aegaeon/loadtest.env"),
            (
                "source /etc/aegaeon/loadtest.env",
                "source /etc/aegaeon/loadtest.env\nsource /etc/aegaeon/override.env",
            ),
            (
                "source /etc/aegaeon/loadtest.env\nset +a",
                "source /etc/aegaeon/loadtest.env\nset +a\nSERVER_URL=http://unused.example",
            ),
            ("set -a\nsource /etc/aegaeon/loadtest.env", "source /etc/aegaeon/loadtest.env"),
            ('--url "$${SERVER_URL}"', '--url "$${OTHER_URL}"'),
            ("ExecStart=/usr/local/bin/aegaeon-run-loadtest", "ExecStart=/usr/local/bin/unused"),
            (
                "ExecStart=/usr/local/bin/aegaeon-run-loadtest",
                "# ExecStart=/usr/local/bin/aegaeon-run-loadtest\nExecStart=/usr/local/bin/unused",
            ),
            (
                "ExecStart=/usr/local/bin/aegaeon-run-loadtest",
                "ExecStart=/usr/local/bin/aegaeon-run-loadtest\nExecStart=/usr/local/bin/unused",
            ),
            (
                '/usr/local/bin/aegaeon-docker-login "$${SERVER_IMAGE}"',
                '/usr/local/bin/unused "$${SERVER_IMAGE}"',
            ),
            (
                "source /etc/aegaeon/loadtest.env\nset +a",
                "source /etc/aegaeon/loadtest.env\nset +a\nunset SERVER_URL",
            ),
            (
                "cat >/usr/local/bin/aegaeon-run-loadtest <<'EOF'",
                "if false; then\ncat >/usr/local/bin/aegaeon-run-loadtest <<'EOF'",
            ),
        ]
        for old, new in changes:
            assert old in original
            path.write_text(original.replace(old, new, 1))
            with (
                self.subTest(change=new),
                pytest.raises(ValueError, match=r"wiring|shape|scaffold"),
            ):
                infra.process_inputs(module)
        path.write_text(original)
        report = infra.runtime_contract_report(module, self.root)
        assert report["status"] == "failed"
        assert len(report["violations"]) == 21
        assert sum(v["reason"] == "missing required assignment" for v in report["violations"]) == 19

    def test_source_and_rendered_dollar_escapes_remain_distinct(self):
        for role in ("server", "loadgen"):
            rendered = self.fixture_rendered_template(role)
            infra.rendered_contract(rendered, role, enabled=True)
            variable = "${GHCR_TOKEN_SSM_PARAMETER_NAME:-}"
            branch = 'if [[ -n "' + variable + '" ]]; then'
            assert branch in rendered
            mutated = rendered.replace(branch, branch.replace(variable, "$" + variable), 1)
            with (
                self.subTest(role=role),
                pytest.raises(ValueError, match="active registry credential branch"),
            ):
                infra.rendered_contract(mutated, role, enabled=True)
        rendered = self.fixture_rendered_template("loadgen")
        assert "${SERVER_URL}" in rendered
        mutated = rendered.replace('--url "${SERVER_URL}"', '--url "$${SERVER_URL}"', 1)
        with pytest.raises(ValueError, match="workload argv wiring"):
            infra.rendered_contract(mutated, "loadgen", enabled=True)
        module = self.module("perf-aws-ec2")
        for role in ("server", "loadgen"):
            path = module / f"user_data_{role}.sh.tftpl"
            original = path.read_text()
            assert "$${GHCR_TOKEN_SSM_PARAMETER_NAME:-}" in original
            path.write_text(
                original.replace(
                    "$${GHCR_TOKEN_SSM_PARAMETER_NAME:-}", "${GHCR_TOKEN_SSM_PARAMETER_NAME:-}", 1
                )
            )
            with (
                self.subTest(source_role=role),
                pytest.raises(ValueError, match="reviewed active process/service shape"),
            ):
                infra.process_inputs(module)
            path.write_text(original)

    def test_active_registry_pipelines_and_rendered_inputs_are_bound(self):
        for role in ("server", "loadgen"):
            for enabled in (False, True):
                for registry_enabled in (False, True):
                    rendered = self.fixture_rendered_template(role, enabled, registry_enabled)
                    with self.subTest(
                        role=role, enabled=enabled, registry_enabled=registry_enabled
                    ):
                        infra.rendered_contract(
                            rendered, role, enabled=enabled, registry_enabled=registry_enabled
                        )
            rendered = self.fixture_rendered_template(role)
            decryption_line = "      --with-decryption " + chr(92) + "\n"
            changes = [
                (decryption_line, "      # --with-decryption " + chr(92) + "\n"),
                (decryption_line, ""),
                ("--password-stdin >/dev/null", "> /dev/null # --password-stdin"),
                ('--name "$GHCR_TOKEN_SSM_PARAMETER_NAME"', '--name "$OTHER_PARAMETER"'),
                ("'Parameter.Value'", "'Parameter.ARN'"),
                ("| docker login ghcr.io", "; docker login ghcr.io"),
                (
                    '--secret-id "$GHCR_TOKEN_SECRETSMANAGER_SECRET_ID"',
                    '--secret-id "$OTHER_SECRET"',
                ),
                ("'SecretString'", "'ARN'"),
                ("source /etc/aegaeon/registry.env", "source /etc/aegaeon/unused.env"),
            ]
            for old, new in changes:
                assert old in rendered
                mutated = rendered.replace(old, new, 1) + "\n# --with-decryption --password-stdin\n"
                with (
                    self.subTest(role=role, change=new),
                    pytest.raises(
                        ValueError, match=r"pipeline|branch|wiring|environment|shape|scaffold"
                    ),
                ):
                    infra.rendered_contract(mutated, role, enabled=True)
            # Decoy flags in unrelated active commands cannot satisfy the reviewed helper.
            mutated = rendered.replace(decryption_line, "", 1)
            mutated += "\necho --with-decryption --password-stdin\n"
            with pytest.raises(ValueError, match=r"pipeline|scaffold"):
                infra.rendered_contract(mutated, role, enabled=True)

    def test_actual_ec2_template_arguments_have_exact_role_ownership(self):
        module = self.module("perf-aws-ec2")
        path = module / "instances.tf"
        original = path.read_text()
        infra.resource_contract(module, {"aws": "6.66.0"})
        for before, after in (
            (
                "trusted_proxies                  = local.server_trusted_proxies",
                "trusted_proxies                  = var.server_image",
            ),
            (
                "ghcr_auth_enabled                = var.ghcr_auth_enabled",
                "ghcr_auth_enabled                = false",
            ),
            ("    scenario                         = var.loadtest_scenario\n", ""),
            (
                "    warmup                           = var.loadtest_warmup",
                "    extra = var.loadtest_warmup\n    warmup = var.loadtest_warmup",
            ),
            ("user_data_server.sh.tftpl", "user_data_loadgen.sh.tftpl"),
            ("  user_data = templatefile", "  user_data_base64 = templatefile"),
            ('ghcr_username == null ? ""', 'ghcr_username == null ? " "'),
        ):
            assert before in original
            path.write_text(
                original.replace(before, after, 1) + "\nlocals { decorative = templatefile("
                '"${path.module}/user_data_server.sh.tftpl", {}) }\n'
            )
            with self.subTest(change=after), pytest.raises(ValueError, match=r"."):
                infra.resource_contract(module, {"aws": "6.66.0"})
        path.write_text(original)

    def test_actual_template_checks_request_both_registry_states(self):
        module = self.module("perf-aws-ec2")
        cases = []

        def fake_command(argv, cwd, stdin=None):
            if argv[1] == "console":
                role = "server" if "user_data_server" in stdin else "loadgen"
                encoded = stdin.split(", ", 1)[1].rsplit("))", 1)[0]
                values = json.loads(encoded)
                cases.append((role, values["auto_run_loadtest"], values["ghcr_auth_enabled"]))
                rendered = self.fixture_rendered_template(
                    role, values["auto_run_loadtest"], values["ghcr_auth_enabled"]
                )
                return json.dumps(json.dumps(rendered))
            return ""

        with patch.object(infra.Commands, "run", side_effect=fake_command):
            assert (
                infra.check_templates(
                    module, infra.Commands(self.root, {}), "tofu", "bash", self.root
                )
                == 8
            )
        assert set(cases) == {
            (role, auto, registry)
            for role in ("server", "loadgen")
            for auto in (False, True)
            for registry in (False, True)
        }

    def test_rendered_contract_missing_secret_reference_fails(self):
        rendered = self.fixture_rendered_template("server")
        rendered = rendered.replace(
            "GHCR_TOKEN_SSM_PARAMETER_NAME=/aegaeon/registry-token\n",
            "# GHCR_TOKEN_SSM_PARAMETER_NAME=/aegaeon/registry-token\n",
        )
        with pytest.raises(ValueError, match="bound input/secret reference"):
            infra.rendered_contract(rendered, "server", enabled=True)

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
