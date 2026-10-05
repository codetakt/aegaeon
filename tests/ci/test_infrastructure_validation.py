"""Fail-closed controls for isolated infrastructure validation."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import pytest
import validate_infrastructure as infra
import yaml
from infrastructure_support import common, delivery, orchestration, provider, runtime

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

    def test_infrastructure_workflow_automatically_runs_full_static_contract(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/infrastructure-validation.yml").read_text()
        )
        events = workflow.get("on", workflow.get(True))  # YAML 1.1 treats "on" as Boolean.
        assert events["pull_request"] == {
            "types": ["opened", "synchronize", "reopened", "ready_for_review"]
        }
        assert events["merge_group"] == {"types": ["checks_requested"]}
        assert set(events) == {"pull_request", "merge_group", "workflow_call", "workflow_dispatch"}
        assert events["workflow_call"]["inputs"]["paths-json"]["default"] == ""
        assert workflow["permissions"] == {"contents": "read"}
        steps = workflow["jobs"]["infrastructure"]["steps"]
        regression = next(
            step for step in steps if step["name"] == "Check infrastructure runner regressions"
        )
        commands = [
            shlex.split(line) for line in regression["run"].replace("\\\n", "").splitlines()
        ]
        prefix = [
            "nix",
            "develop",
            ".#integrity",
            "--command",
            "env",
            "PYTHONPATH=scripts/ci",
            "python3",
        ]
        assert commands == [
            [
                *prefix,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests/ci",
                "-p",
                "test_infrastructure_validation.py",
            ],
            [
                *prefix,
                "-m",
                "pytest",
                "-q",
                "tests/ci/test_perf_delivery_package.py",
                "tests/ci/test_perf_runtime_delivery.py",
            ],
        ]
        validation = next(
            step for step in steps if step["name"] == "Validate infrastructure inputs"
        )
        assert validation["env"] == {"INFRASTRUCTURE_PATHS_JSON": "${{ inputs.paths-json }}"}
        assert 'if [[ -n "$INFRASTRUCTURE_PATHS_JSON" ]]; then' in validation["run"]
        assert 'python3 scripts/ci/validate_infrastructure.py "${args[@]}"' in validation["run"]
        assert len(infra.select_modules(self.root, None)) == 3
        diagnostics = next(
            step for step in steps if step["name"] == "Preserve infrastructure diagnostics"
        )
        assert diagnostics["if"] == "always()"
        assert diagnostics["with"]["path"] == "artifacts/infrastructure-validation"
        assert diagnostics["with"]["if-no-files-found"] == "error"

    def test_infrastructure_workflow_import_path_survives_nix_environment_replacement(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/infrastructure-validation.yml").read_text()
        )
        regression = next(
            step
            for step in workflow["jobs"]["infrastructure"]["steps"]
            if step["name"] == "Check infrastructure runner regressions"
        )
        commands = [
            shlex.split(line) for line in regression["run"].replace("\\\n", "").splitlines()
        ]
        tools = self.root / "workflow-probes"
        tools.mkdir()
        python_probe = tools / "python3"
        python_probe.write_text(
            f"#!{sys.executable}\n"
            "import importlib.util, json, os, sys\n"
            "spec = importlib.util.find_spec('validate_infrastructure')\n"
            "if os.environ.get('PYTHONPATH') != 'scripts/ci' or spec is None:\n"
            "    raise SystemExit('infrastructure import path was replaced by Nix')\n"
            "with open(os.environ['WORKFLOW_PROBE_RECORD'], 'w') as record:\n"
            "    json.dump({'args': sys.argv[1:], 'origin': spec.origin}, record)\n"
        )
        nix_probe = tools / "nix"
        nix_probe.write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys\n"
            "assert sys.argv[1:4] == ['develop', '.#integrity', '--command']\n"
            "environment = {**os.environ, 'PYTHONPATH': '/nix/replaced-python-environment'}\n"
            "raise SystemExit(subprocess.call(sys.argv[4:], env=environment))\n"
        )
        python_probe.chmod(0o755)
        nix_probe.chmod(0o755)
        record = self.root / "workflow-probe.json"
        environment = {
            **os.environ,
            "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
            "PYTHONPATH": "scripts/ci",
            "WORKFLOW_PROBE_RECORD": str(record),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for command in commands:
            for command_local_path in (True, False):
                with self.subTest(command=command, command_local_path=command_local_path):
                    invocation = (
                        command[1:] if command_local_path else [*command[1:4], *command[6:]]
                    )
                    result = subprocess.run(  # noqa: S603 - fixed local probes, no production tests
                        [str(nix_probe), *invocation],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if command_local_path:
                        assert result.returncode == 0, result.stderr
                        observed = json.loads(record.read_text())
                        assert observed["args"] == command[7:]
                        assert (
                            Path(observed["origin"])
                            == ROOT / "scripts/ci/validate_infrastructure.py"
                        )
                    else:
                        assert result.returncode != 0
                        assert "infrastructure import path was replaced by Nix" in result.stderr

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

    def test_untouched_staging_runtime_contract_passes(self):
        report = infra.runtime_contract(self.module(), self.root)
        self.assertEqual(report["status"], "passed")  # noqa: PT009 - active under -O
        self.assertEqual(report["violations"], [])  # noqa: PT009 - active under -O

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
        path.write_text(
            path.read_text()
            + "\ncat >/etc/aegaeon/server.env <<EOF\nBASE_URL=http://server.example:8080\nEOF\n"
        )
        report = infra.runtime_contract_report(self.module("perf-aws-ec2"), self.root)
        assert report["status"] == "failed"
        assert report["violations"][0]["process"] == "input parser"
        assert all(set(v) == {"process", "name", "reason"} for v in report["violations"])

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
        marker = "--env-file /run/aegaeon-supplies/server.env "
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
            patch.object(orchestration, "toolchain_provenance", side_effect=provenance),
            patch.object(shutil, "which", return_value=sys.executable),
            patch.object(subprocess, "run", side_effect=failure),
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
        text = infra.source_template(self.module("perf-aws-ec2"), role)
        # Bounded substitution fixture; no OpenTofu execution is implied.
        text = text.replace("$${", "@@SHELL_DOLLAR@@")
        values = infra.template_values()
        values.update(
            auto_run_loadtest=enabled,
            ghcr_auth_enabled=registry_enabled,
        )

        sections, _ = infra.template_sections(text)
        registry = {
            "AWS_REGION": values["aws_region"],
            "AWS_DEFAULT_REGION": values["aws_region"],
            "GHCR_AUTH_ENABLED": "1" if registry_enabled else "0",
            "GHCR_USERNAME": values["ghcr_username"],
            "GHCR_TOKEN_SSM_PARAMETER_NAME": values["ghcr_token_ssm_parameter_name"],
            "GHCR_TOKEN_SECRETSMANAGER_SECRET_ID": values["ghcr_token_secretsmanager_secret"],
        }
        text = text.replace(sections["/etc/aegaeon/registry.json"].strip(), json.dumps(registry))
        if "/etc/aegaeon/loadtest.json" in sections:
            loadtest = {
                "SERVER_URL": str(values["server_url"]),
                "SERVER_IMAGE": str(values["server_image"]),
                "ARTIFACT_BUCKET": str(values["artifact_bucket"]),
                "ARTIFACT_PREFIX": str(values["artifact_prefix"]),
                "WORKERS": str(values["workers"]),
                "RPS": str(values["rps"]),
                "RUN_TIME": str(values["run_time"]),
                "WARMUP": str(values["warmup"]),
                "SCENARIO": str(values["scenario"]),
                "LOADTEST_BIN": str(values["loadgen_entrypoint"]),
                "artifact": {
                    "receipt_path": values["loadgen_artifact_receipt_path"],
                    "receipt_sha256": values["loadgen_artifact_receipt_sha256"],
                    "source_manifest_path": values["loadgen_source_manifest_path"],
                    "source_manifest_sha256": values["loadgen_source_manifest_sha256"],
                    "executable_sha256": values["loadgen_executable_sha256"],
                },
            }
            text = text.replace(
                sections["/etc/aegaeon/loadtest.json"].strip(), json.dumps(loadtest)
            )

        def json_config(match):
            fields = dict(re.findall(r"(\w+)\s*=\s*(\w+)", match[1]))
            return json.dumps({key: values[value] for key, value in fields.items()})

        text = re.sub(r"\$\{jsonencode\(\{([^{}]+)\}\)\}", json_config, text)
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
            ("data.aws_region.current.name", None, True),
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
        self.assertIn("loadgen", infra.process_inputs(module, self.root))  # noqa: PT009 - active under -O
        changes = [
            ('--env-file "$${SUPPLY_DIR}/client.env"', "--env-file /tmp/unused.env"),
            ('--env-file "$${SUPPLY_DIR}/client.env"', '# --env-file "$${SUPPLY_DIR}/client.env"'),
            (
                '--env-file "$${SUPPLY_DIR}/client.env"',
                '--env-file "$${SUPPLY_DIR}/client.env" --env-file /tmp/override.env',
            ),
            (
                'done <"$${OUT_DIR}/validated-config.env"',
                'done <"$${OUT_DIR}/validated-config.env"\nSERVER_URL=http://unused.example',
            ),
            (
                '/usr/local/bin/aegaeon-deliver-supplies run-config "$CONFIG_FILE" "$OUT_DIR"',
                '# /usr/local/bin/aegaeon-deliver-supplies run-config "$CONFIG_FILE" "$OUT_DIR"',
            ),
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
                'done <"$${OUT_DIR}/validated-config.env"',
                'done <"$${OUT_DIR}/validated-config.env"\nunset SERVER_URL',
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
                infra.process_inputs(module, self.root)
        path.write_text(original)
        report = infra.runtime_contract_report(module, self.root)
        assert report["status"] == "passed"
        assert report["violations"] == []
        assert "live connectivity" in report["external_conditions"]

    def test_performance_external_interface_passes_without_local_consumer_sources(self):
        module = self.module("perf-aws-ec2")
        self.assertFalse((self.root / "crates/loadtest").exists())  # noqa: PT009 - active under -O
        report = infra.runtime_contract(module, self.root)
        self.assertEqual(report["status"], "passed")  # noqa: PT009 - active under -O
        interface = report["external_consumer"]
        self.assertEqual(interface["static_delivery_wiring"], "passed")  # noqa: PT009 - active under -O
        self.assertEqual(  # noqa: PT009 - active under -O
            interface["external_artifact_interface_runtime"]["status"], "required_not_observed"
        )
        self.assertEqual(interface["artifact_receipt_version"], 1)  # noqa: PT009 - active under -O
        self.assertEqual(interface["report"]["schema_version"], 2)  # noqa: PT009 - active under -O
        self.assertEqual(interface["report"]["max_bytes"], 16_777_216)  # noqa: PT009 - active under -O
        self.assertEqual(  # noqa: PT009 - active under -O
            interface["report"]["request_unit"], "scenario_invocations"
        )
        self.assertEqual(  # noqa: PT009 - active under -O
            interface["report"]["memory_subject"], "load_generator_process"
        )
        self.assertEqual(  # noqa: PT009 - active under -O
            interface["report"]["discovery_expected_issuer"], "required null for this driver"
        )
        self.assertEqual(  # noqa: PT009 - active under -O
            set(interface["report"]["config_fields"]),
            {
                "target_url",
                "discovery_expected_issuer",
                "workers",
                "duration",
                "target_rps",
                "warmup_duration",
                "scenario",
                "debug",
            },
        )
        self.assertIn(  # noqa: PT009 - active under -O
            "crates/loadtest/src/accounting.rs", interface["source_manifest"]["required_paths"]
        )
        for name in (
            "README.md",
            "user_data_server.sh.tftpl",
            "user_data_loadgen.sh.tftpl",
            "delivery_helper.py",
            *("runtime_delivery/" + name for name in infra.DELIVERY_PACKAGE_SHA256),
        ):
            path = "infra/tofu/perf-aws-ec2/" + name
            self.assertEqual(  # noqa: PT009 - active under -O
                interface["interface_sources"][path], infra.digest(module / name)
            )
            self.assertEqual(  # noqa: PT009 - active under -O
                report["runtime_sources"][path], interface["interface_sources"][path]
            )

    def test_performance_external_interface_rejects_missing_or_unknown_process_input(self):
        template = infra.source_template(self.module("perf-aws-ec2"), "loadgen")
        original = infra.PERFORMANCE_CLIENT_NAMES
        changes = [tuple(name for name in original if name != missing) for missing in original]
        changes.append((*original, "AEG_LOADTEST_EXTRA256"))
        for names in changes:
            with (
                self.subTest(names=names),
                patch.object(delivery, "PERFORMANCE_CLIENT_NAMES", names),
                self.assertRaisesRegex(ValueError, "exact five process inputs"),  # noqa: PT027 - active under -O
            ):
                infra.performance_delivery_inputs(template, "client", root=self.root)

    def test_performance_external_interface_rejects_changed_config_descriptor(self):
        template = infra.source_template(self.module("perf-aws-ec2"), "loadgen")
        original = infra.PERFORMANCE_CONFIG_NAMES
        for names in (original[1:], (*original, "unknown256")):
            with (
                self.subTest(names=names),
                patch.object(delivery, "PERFORMANCE_CONFIG_NAMES", names),
                self.assertRaisesRegex(ValueError, "exact eight producer config fields"),  # noqa: PT027 - active under -O
            ):
                infra.performance_consumer_interface(template)

    def test_performance_external_interface_rejects_altered_pinned_helper(self):
        template = infra.source_template(self.module("perf-aws-ec2"), "loadgen")
        changes = (
            ('receipt["schema_version"] != 1', 'receipt["schema_version"] != 2'),
            ("REPORT_SCHEMA_VERSION = 2", "REPORT_SCHEMA_VERSION = 1"),
            ('"scenario_invocations"', '"HTTP_requests"'),
            ('"load_generator_process"', '"server_process"'),
            (
                'parsed["discovery_expected_issuer"] is not None',
                'parsed.get("discovery_expected_issuer") is not None',
            ),
            (
                '"AEG_LOADTEST_SOURCE_SHA256": source_sha256',
                '"AEG_LOADTEST_EXTRA256": source_sha256',
            ),
            ('"crates/loadtest/src/accounting.rs",', ""),
            (
                'hashlib.sha256(source_raw).hexdigest() != artifact["source_manifest_sha256"]',
                "False",
            ),
        )
        for before, after in changes:
            self.assertIn(before, template)  # noqa: PT009 - active under -O
            with (
                self.subTest(change=after),
                self.assertRaisesRegex(ValueError, "Changed installed delivery source"),  # noqa: PT027 - active under -O
            ):
                infra.performance_delivery_inputs(
                    template.replace(before, after, 1), "client", root=self.root
                )

    def test_performance_copied_module_uses_explicit_root_and_rejects_wrong_redis_authority(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        scratch = Path(temporary)
        copied = scratch / "perf-aws-ec2"
        shutil.copytree(self.module("perf-aws-ec2"), copied)
        self.assertEqual(  # noqa: PT009 - active under -O
            infra.runtime_contract(copied, self.root)["status"], "passed"
        )
        wrong_root = scratch / "wrong-root"
        shutil.copytree(self.root, wrong_root)
        inventory = (
            wrong_root / "crates/server/src/config/runtime_boundary/shared_store/inventory.rs"
        )
        inventory.write_text(
            inventory.read_text().replace(infra.PERFORMANCE_REDIS_NAMES[0], "UNUSED_REDIS_URL")
        )
        with self.assertRaisesRegex(ValueError, "Runtime supply Redis authority changed"):  # noqa: PT027 - active under -O
            infra.process_inputs(copied, wrong_root)
        report = infra.runtime_contract_report(copied, wrong_root)
        self.assertEqual(report["status"], "failed")  # noqa: PT009 - active under -O
        self.assertIn(  # noqa: PT009 - active under -O
            "Changed bootstrap/shared-store inventory requires review",
            report["violations"][0]["reason"],
        )

    def test_performance_validate_module_scratch_copy_preserves_actual_root(self):
        output = self.root / "perf-validation"
        with (
            patch.object(infra.Commands, "run", return_value="{}"),
            patch.object(
                orchestration, "initialize_providers", return_value={"providers": {"aws": "6.66.0"}}
            ),
            patch.object(orchestration, "validate_schema", return_value={"valid": True}),
            patch.object(orchestration, "check_templates", return_value=[]),
            patch.object(orchestration, "check_support", return_value={}),
        ):
            report = infra.validate_module(
                self.module("perf-aws-ec2"),
                self.root,
                output,
                {"tofu": "fixture-tofu", "bash": "fixture-bash"},
            )
        self.assertEqual(report["status"], "passed")  # noqa: PT009 - active under -O
        self.assertEqual(report["runtime_contract"]["status"], "passed")  # noqa: PT009 - active under -O

    def test_loadgen_process_maps_exact_client_environment_and_validated_driver(self):
        expected = {
            "AEG_LOADTEST_CLIENT_SECRET",
            "AEG_LOADTEST_PROFILE_MANIFEST",
            "AEG_LOADTEST_SESSION_FILE",
            "AEG_LOADTEST_SESSION_PROVENANCE",
            "AEG_LOADTEST_SOURCE_SHA256",
        }
        module = self.module("perf-aws-ec2")
        inputs = infra.process_inputs(module, self.root)
        self.assertEqual(set(inputs["loadgen"]), expected)  # noqa: PT009 - active under -O
        permitted, mandatory = infra.process_profiles(self.root)["loadgen"]
        self.assertEqual(permitted, expected)  # noqa: PT009 - active under -O
        self.assertEqual(mandatory, expected)  # noqa: PT009 - active under -O
        report = infra.runtime_contract(module, self.root)
        self.assertEqual(report["status"], "passed")  # noqa: PT009 - active under -O
        self.assertEqual(set(report["processes"]["loadgen"]), expected)  # noqa: PT009 - active under -O

    def test_loadgen_process_missing_each_client_input_is_rejected(self):
        module = self.module("perf-aws-ec2")
        baseline = infra.process_inputs(module, self.root)
        for name in (
            "AEG_LOADTEST_CLIENT_SECRET",
            "AEG_LOADTEST_PROFILE_MANIFEST",
            "AEG_LOADTEST_SESSION_FILE",
            "AEG_LOADTEST_SESSION_PROVENANCE",
            "AEG_LOADTEST_SOURCE_SHA256",
        ):
            with self.subTest(missing=name):
                inputs = {process: dict(values) for process, values in baseline.items()}
                inputs["loadgen"].pop(name)
                with (
                    mock.patch.object(runtime, "process_inputs", return_value=inputs),
                    self.assertRaises(infra.RuntimeContractError) as failure,  # noqa: PT027 - active under -O
                ):
                    infra.runtime_contract(module, self.root)
                self.assertEqual(  # noqa: PT009 - active under -O
                    failure.exception.report["violations"],
                    [{"process": "loadgen", "name": name, "reason": "missing required assignment"}],
                )

    def test_loadgen_process_rejects_extra_client_and_driver_environment_names(self):
        module = self.module("perf-aws-ec2")
        baseline = infra.process_inputs(module, self.root)
        for name in ("SERVER_URL", "AEG_LOADTEST_EXTRA256"):
            with self.subTest(extra=name):
                inputs = {process: dict(values) for process, values in baseline.items()}
                inputs["loadgen"][name] = "owned fixture value"
                with (
                    mock.patch.object(runtime, "process_inputs", return_value=inputs),
                    self.assertRaises(infra.RuntimeContractError) as failure,  # noqa: PT027 - active under -O
                ):
                    infra.runtime_contract(module, self.root)
                self.assertEqual(  # noqa: PT009 - active under -O
                    failure.exception.report["violations"],
                    [
                        {
                            "process": "loadgen",
                            "name": name,
                            "reason": "unknown or forbidden variable for this process",
                        }
                    ],
                )

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
                infra.process_inputs(module, self.root)
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
                ('path = "/etc/aegaeon/registry.json"', 'path = "/etc/aegaeon/unused.json"'),
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
            (
                "  user_data_base64 = base64gzip(templatefile",
                "  user_data = base64gzip(templatefile",
            ),
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

    def test_all_rendered_loadtest_inputs_are_bound(self):
        rendered = self.fixture_rendered_template("loadgen")
        raw = infra.template_sections(rendered)[0]["/etc/aegaeon/loadtest.json"].strip()
        expected = json.loads(raw)
        infra.rendered_contract(rendered, "loadgen", enabled=True)
        for name in expected:
            for change in ("replace", "remove", "extra"):
                with self.subTest(name=name, change=change):
                    changed = json.loads(raw)
                    if change == "remove":
                        del changed[name]
                    elif change == "extra":
                        changed["EXTRA"] = "unreviewed"
                    else:
                        changed[name] = "unreviewed"
                    with pytest.raises(ValueError, match="bound input"):
                        infra.rendered_contract(
                            rendered.replace(raw, json.dumps(changed)), "loadgen", enabled=True
                        )
        for name in expected["artifact"]:
            changed = json.loads(raw)
            changed["artifact"][name] = "unreviewed"
            with self.subTest(artifact=name), pytest.raises(ValueError, match="bound input"):
                infra.rendered_contract(
                    rendered.replace(raw, json.dumps(changed)), "loadgen", enabled=True
                )
        changed = json.loads(raw)
        changed["WORKERS"], changed["RPS"] = changed["RPS"], changed["WORKERS"]
        with pytest.raises(ValueError, match="bound input"):
            infra.rendered_contract(
                rendered.replace(raw, json.dumps(changed)), "loadgen", enabled=True
            )
        duplicate = raw[:-1] + ',"WORKERS":"2"}'
        with pytest.raises(ValueError, match="bound input"):
            infra.rendered_contract(rendered.replace(raw, duplicate), "loadgen", enabled=True)

    def test_rendered_server_delivery_environment_complete_equality(self):
        for enabled in (False, True):
            rendered = self.fixture_rendered_template("server", enabled=enabled)
            raw = infra.template_sections(rendered)[0]["/etc/aegaeon/delivery.json"].strip()
            expected = json.loads(raw)
            infra.rendered_contract(rendered, "server", enabled=enabled)
            for name in expected:
                for change in ("replace", "remove", "extra"):
                    with self.subTest(enabled=enabled, name=name, change=change):
                        changed = dict(expected)
                        if change == "remove":
                            del changed[name]
                        elif change == "extra":
                            changed["BASE_URL"] = "http://unreviewed.invalid"
                        else:
                            changed[name] = "unreviewed"
                        with pytest.raises(ValueError, match=r"delivery inputs|bound input"):
                            infra.rendered_contract(
                                rendered.replace(raw, json.dumps(changed)),
                                "server",
                                enabled=enabled,
                            )
            duplicate = raw[:-1] + ',"trusted_proxies":"127.0.0.1/32"}'
            with pytest.raises(ValueError, match="bound input"):
                infra.rendered_contract(rendered.replace(raw, duplicate), "server", enabled=enabled)

    def test_rendered_contract_missing_secret_reference_fails(self):
        rendered = self.fixture_rendered_template("server")
        rendered = rendered.replace(
            '"GHCR_TOKEN_SSM_PARAMETER_NAME": "/aegaeon/registry-token"',
            '"GHCR_TOKEN_SSM_PARAMETER_NAME": ""',
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
                patch.object(
                    orchestration, "toolchain_provenance", return_value={"toolchain_sources": {}}
                ),
                patch.object(provider, "installed_providers", return_value={"fixture": "hash"}),
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

    def test_fixed_support_closure_selects_all_modules_and_rejects_unknown_package_paths(self):
        expected = [self.module(name) for name in sorted(infra.MODULES)]
        for name in common.VALIDATOR_SUPPORT_PATHS:
            self.assertEqual(infra.select_modules(self.root, [name]), expected)  # noqa: PT009
        for name in (
            "scripts/ci/infrastructure_support/unknown.py",
            "scripts/ci/infrastructure_support/nested/common.py",
        ):
            with self.assertRaises(ValueError):  # noqa: PT027
                infra.select_modules(self.root, [name])
        self.assertEqual(  # noqa: PT009
            infra.select_modules(self.root, ["infra/tofu/perf-aws-ec2/delivery_helper.py"]),
            [self.module("perf-aws-ec2")],
        )

    def test_shared_helper_is_the_only_admitted_python_module_input(self):
        module = self.module("perf-aws-ec2")
        helper = module / "delivery_helper.py"
        self.assertIn(helper, infra.module_inputs(module))  # noqa: PT009
        (module / "other.py").write_text("pass\n")
        with self.assertRaisesRegex(ValueError, "Unexpected input"):  # noqa: PT027
            infra.module_inputs(module)
        (module / "other.py").unlink()
        staging_helper = self.module() / "delivery_helper.py"
        staging_helper.write_bytes(helper.read_bytes())
        with self.assertRaisesRegex(ValueError, "Unexpected input"):  # noqa: PT027
            infra.module_inputs(self.module())

    def test_shared_helper_and_both_template_sources_are_bound_exactly(self):
        module = self.module("perf-aws-ec2")
        helper = module / "delivery_helper.py"
        original = helper.read_bytes()
        self.assertEqual(infra.digest(helper), infra.DELIVERY_BODY_SHA256)  # noqa: PT009
        for role in ("server", "loadgen"):
            sections, _ = infra.template_sections(infra.source_template(module, role))
            self.assertEqual(  # noqa: PT009
                sections["/usr/local/bin/aegaeon-deliver-supplies"].encode(), original
            )
        helper.write_bytes(original.replace(b"package_sources", b"package_sourcex", 1))
        for role in ("server", "loadgen"):
            with self.assertRaisesRegex(ValueError, "Changed strict runtime supply executable"):  # noqa: PT027
                infra.source_template(module, role)
        helper.unlink()
        helper.symlink_to(ROOT / "infra/tofu/perf-aws-ec2/delivery_helper.py")
        with self.assertRaisesRegex(ValueError, "Missing shared delivery helper"):  # noqa: PT027
            infra.source_template(module, "server")
        with self.assertRaisesRegex(ValueError, "Symlink"):  # noqa: PT027
            infra.module_inputs(module)

    def test_shared_helper_interpolation_and_fixed_file_map_reject_drift(self):
        module = self.module("perf-aws-ec2")
        for role in ("server", "loadgen"):
            template = module / f"user_data_{role}.sh.tftpl"
            original = template.read_text()
            for replacement in (
                "${delivery_helper}",
                "${other_helper~}",
                "${delivery_helper~}extra",
            ):
                template.write_text(original.replace("${delivery_helper~}", replacement, 1))
                with self.assertRaisesRegex(ValueError, "template binding"):  # noqa: PT027
                    infra.source_template(module, role)
            template.write_text(original + "\n# ${delivery_helper}\n")
            with self.assertRaisesRegex(ValueError, "Duplicate guest source interpolation"):  # noqa: PT027
                infra.source_template(module, role)
            template.write_text(original)
        instances = module / "instances.tf"
        original = instances.read_text()
        for replacement in ('file("${path.module}/other.py")', "var.delivery_helper"):
            instances.write_text(
                original.replace('file("${path.module}/delivery_helper.py")', replacement, 1)
            )
            with self.assertRaisesRegex(ValueError, "templatefile argument source or inventory"):  # noqa: PT027
                infra.perf_template_bindings(module)
        instances.write_text(original)

    def test_all_fixed_validator_sources_are_reported_and_drift_fails(self):
        sources = common.validator_sources(self.root)
        self.assertEqual(  # noqa: PT009
            set(sources), {"scripts/ci/validate_infrastructure.py", *common.VALIDATOR_SUPPORT_PATHS}
        )
        module = self.module("perf-aws-ec2")
        report = infra.runtime_contract(module, self.root)
        for name, digest in sources.items():
            self.assertEqual(report["runtime_sources"][name], digest)  # noqa: PT009
            self.assertEqual(report["external_consumer"]["interface_sources"][name], digest)  # noqa: PT009
        changed = self.root / common.VALIDATOR_SUPPORT_PATHS[-1]
        changed.write_bytes(changed.read_bytes() + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "differs from executing code"):  # noqa: PT027
            common.validator_sources(self.root)
        self.assertEqual(infra.runtime_contract_report(module, self.root)["status"], "failed")  # noqa: PT009

    def test_main_default_root_and_runner_digest_remain_public_cli(self):
        output = self.root / "fixed-cli"
        paths = {}

        def selection(root, selected):
            paths["root"] = root
            return []

        with (
            patch("sys.argv", ["validate_infrastructure.py", "--output", str(output)]),
            patch.object(shutil, "which", return_value=sys.executable),
            patch.object(orchestration, "select_modules", side_effect=selection),
            patch.object(
                orchestration, "toolchain_provenance", return_value={"toolchain_sources": {}}
            ),
        ):
            self.assertEqual(infra.main(), 0)  # noqa: PT009
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(paths["root"], ROOT)  # noqa: PT009
        self.assertEqual(  # noqa: PT009
            summary["runner_sha256"], infra.digest(ROOT / "scripts/ci/validate_infrastructure.py")
        )

    def test_toolchain_provenance_includes_complete_fixed_validator_closure(self):
        output = self.root / "toolchain-closure"
        output.mkdir()
        with patch.object(infra.Commands, "run", return_value="[]"):
            report = infra.toolchain_provenance(ROOT, output, {"nix": sys.executable})
        for name, expected in common.validator_sources(ROOT).items():
            self.assertEqual(report["toolchain_sources"][name], expected)  # noqa: PT009

    def test_physical_sibling_loader_ignores_hostile_cwd_and_pythonpath(self):
        shadow = self.root / "infrastructure_support"
        shadow.mkdir()
        (shadow / "__init__.py").write_text('raise RuntimeError("ambient package loaded")\n')
        argv = [sys.executable, str(ROOT / "scripts/ci/validate_infrastructure.py"), "--help"]
        for isolated in (False, True):
            result = subprocess.run(  # noqa: S603 - fixed local CLI help, no native validation
                [argv[0], *(["-I"] if isolated else []), *argv[1:]],
                cwd=self.root,
                env={**os.environ, "PYTHONPATH": str(self.root), "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
            self.assertIn("--paths-json", result.stdout)  # noqa: PT009

    def test_shared_helper_rejects_raw_newline_drift(self):
        module = self.module("perf-aws-ec2")
        helper = module / "delivery_helper.py"
        original = helper.read_bytes()
        for changed in (original.replace(b"\n", b"\r\n"), original.rstrip(b"\n")):
            helper.write_bytes(changed)
            for role in ("server", "loadgen"):
                with self.assertRaisesRegex(ValueError, "Changed strict runtime supply executable"):  # noqa: PT027
                    infra.source_template(module, role)


if __name__ == "__main__":
    unittest.main()
