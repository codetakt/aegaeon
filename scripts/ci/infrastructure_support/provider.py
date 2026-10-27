"""Provider locks, resources, schema and initialization contracts."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from infrastructure_support.common import digest, require
from infrastructure_support.hcl import assignment, block, compact_expression, expression, uncomment
from infrastructure_support.templates import perf_template_bindings

if TYPE_CHECKING:
    from pathlib import Path

    from infrastructure_support.commands import Commands


def lock_contract(module: Path) -> dict[str, str]:
    declarations = block((module / "versions.tf").read_text(), "terraform")
    providers = block(declarations, "required_providers")
    lock = (module / ".terraform.lock.hcl").read_text()
    names = re.findall(r"(?m)^\s*(\w+)\s*=\s*\{", providers)
    require(bool(names) and set(names) <= {"aws", "random"}, "Unreviewed provider declarations")
    locked = re.findall(r'(?m)^provider "([^"]+)"\s*\{', uncomment(lock))
    require(len(locked) == len(names), "Unexpected or missing locked provider")
    result = {}
    for name in names:
        declaration = block(providers, name + " =")
        source = json.loads(assignment(declaration, "source"))
        require(source == f"hashicorp/{name}", "Unexpected provider source")
        selected = block(lock, f'provider "registry.opentofu.org/{source}"')
        wanted = json.loads(assignment(declaration, "version"))
        actual = json.loads(assignment(selected, "constraints"))
        require(wanted == actual, f"Stale lock constraints for {name}: {actual} != {wanted}")
        version = json.loads(assignment(selected, "version"))
        require(bool(re.fullmatch(r"\d+\.\d+\.\d+", version)), "Unrecognized provider version")
        require(bool(re.search(r'"(?:h1|zh):[^"\s]+"', selected)), "Provider checksums missing")
        result[name] = version
    return result


def perf_proxy_network_contract(module: Path) -> None:
    """Bind the IPv4 proxy sources to the entire backend ingress boundary."""
    perf_template_bindings(module)
    server_group = block(
        (module / "network.tf").read_text(), 'resource "aws_security_group" "server"'
    )
    require(
        compact_expression(server_group)
        == compact_expression(
            'name = "${var.name_prefix}-server" description = "Aegaeon server" '
            "vpc_id = local.vpc_id ingress { "
            "from_port = var.server_port to_port = var.server_port "
            'protocol = "tcp" cidr_blocks = local.server_trusted_proxy_cidrs '
            'description = "Trusted TLS proxies to server" } '
            'egress { from_port = 0 to_port = 0 protocol = "-1" '
            'cidr_blocks = ["0.0.0.0/0"] }'
        ),
        "Server ingress must admit only the trusted TLS proxy CIDRs and backend TCP port",
    )
    require(
        not any(
            re.search(
                r'resource\s+"aws_(?:security_group_rule|vpc_security_group_ingress_rule)"',
                uncomment(path.read_text()),
            )
            for path in module.glob("*.tf")
        ),
        "Separate ingress rules bypass the proxy source boundary",
    )
    require(
        not any(
            re.search(
                r'resource\s+"aws_network_interface(?:_[a-z_]+)?"', uncomment(path.read_text())
            )
            for path in module.glob("*.tf")
        ),
        "Additional network interfaces or attachments bypass the proxy source boundary",
    )
    variable = block((module / "variables.tf").read_text(), 'variable "server_trusted_proxies"')
    require(
        assignment(variable, "type") == "string" and assignment(variable, "nullable") == "false",
        "Proxy CIDR input type or nullability changed",
    )
    require(
        compact_expression(expression(block(variable, "validation"), "condition"))
        == compact_expression(
            "length(trimspace(var.server_trusted_proxies)) > 0 && alltrue([ "
            'for cidr in split(",", var.server_trusted_proxies) : ('
            '!strcontains(trimspace(cidr), ":") '
            "&& try(cidrsubnet(trimspace(cidr), 0, 0) == trimspace(cidr), false) "
            '&& try(tonumber(split("/", trimspace(cidr))[1]) > 0, false))])'
        ),
        "Proxy CIDR validation must require canonical bounded IPv4 networks",
    )
    instances = (module / "instances.tf").read_text()
    for name in ("server", "loadgen"):
        require(
            assignment(
                block(instances, f'resource "aws_instance" "{name}"'), "vpc_security_group_ids"
            )
            == f"[aws_security_group.{name}.id]",
            "Node network boundary changed",
        )
    local_source = block((module / "locals.tf").read_text(), "locals")
    for field, wanted in {
        "server_trusted_proxy_cidrs": (
            'distinct([for cidr in split(",", var.server_trusted_proxies) : trimspace(cidr)])'
        ),
        "server_trusted_proxies": 'join(",", local.server_trusted_proxy_cidrs)',
    }.items():
        require(
            compact_expression(expression(local_source, field)) == compact_expression(wanted),
            "Proxy ingress/header trust source changed: " + field,
        )


def resource_contract(module: Path, providers: dict[str, str]) -> None:
    if module.name == "perf-aws-ec2":
        perf_proxy_network_contract(module)
        instances = (module / "instances.tf").read_text()
        for name in ("server", "loadgen"):
            body = block(instances, f'resource "aws_instance" "{name}"')
            require(
                assignment(body, "user_data_replace_on_change") == "true",
                "EC2 replacement contract changed",
            )
            metadata = block(body, "metadata_options")
            require(assignment(metadata, "http_tokens") == '"required"', "EC2 requires IMDSv2")
            require(
                assignment(body, "iam_instance_profile")
                == f'aws_iam_instance_profile.perf_instance["{name}"].name',
                "Node role/profile boundary changed",
            )
        iam = (module / "iam.tf").read_text()
        roles = block(iam, 'resource "aws_iam_role" "perf_instance"')
        require(
            assignment(roles, "for_each") == 'toset(["server", "loadgen"])',
            "Server/loadgen role separation changed",
        )
        artifact = block(iam, 'resource "aws_iam_role_policy_attachment" "artifact_write"')
        require(
            assignment(artifact, "role") == 'aws_iam_role.perf_instance["loadgen"].name',
            "Artifact permissions escaped loadgen role",
        )
        signing = block(iam, 'resource "aws_iam_role_policy" "runtime_signing"')
        require(
            assignment(signing, "role") == 'aws_iam_role.perf_instance["server"].id',
            "Signing permissions escaped server role",
        )
        profile = block(iam, 'resource "aws_iam_instance_profile" "perf_instance"')
        require(
            assignment(profile, "for_each") == "aws_iam_role.perf_instance"
            and assignment(profile, "role") == "each.value.name",
            "Node profile role binding changed",
        )
        local_source = block((module / "locals.tf").read_text(), "locals")
        for field, wanted in {
            "node_secret_arns": (
                "{ server = [var.server_secret_arn] "
                "loadgen = compact([var.client_secret_arn, var.metrics_secret_arn]) }"
            ),
            "node_secret_kms_key_arns": (
                "{ server = var.server_secret_kms_key_arns "
                "loadgen = distinct(concat(var.client_secret_kms_key_arns, "
                "var.metrics_secret_kms_key_arns)) }"
            ),
        }.items():
            require(
                compact_expression(expression(local_source, field)) == compact_expression(wanted),
                "Node supplier ownership changed: " + field,
            )
        for declaration, wanted in {
            'data "aws_iam_policy_document" "runtime_supply"': (
                "for_each = local.node_secret_arns "
                'statement { actions = ["secretsmanager:GetSecretValue"] resources = each.value } '
                'dynamic "statement" { '
                "for_each = length(local.node_secret_kms_key_arns[each.key]) > 0 "
                "? [local.node_secret_kms_key_arns[each.key]] : [] "
                'content { actions = ["kms:Decrypt"] resources = statement.value } }'
            ),
            'resource "aws_iam_role_policy" "runtime_supply"': (
                "for_each = aws_iam_role.perf_instance "
                'name = "${var.name_prefix}-${each.key}-supplies" role = each.value.id '
                "policy = data.aws_iam_policy_document.runtime_supply[each.key].json"
            ),
            'data "aws_iam_policy_document" "runtime_signing"': (
                'statement { actions = ["kms:Sign", "kms:GetPublicKey"] '
                "resources = var.runtime_kms_key_arns }"
            ),
        }.items():
            require(
                compact_expression(block(iam, declaration)) == compact_expression(wanted),
                "Changed runtime supply/signing IAM scope",
            )
        require(
            all(
                'data "aws_secretsmanager_secret_version"' not in path.read_text()
                for path in module.glob("*.tf")
            ),
            "Terraform must not retrieve secret contents",
        )
        return
    key = block((module / "kms.tf").read_text(), 'resource "aws_kms_key" "oidc_signing"')
    require(assignment(key, "key_usage") == '"SIGN_VERIFY"', "OIDC KMS key must sign")
    require(
        assignment(key, "customer_master_key_spec") == '"RSA_2048"',
        "OIDC parity key must be RSA_2048",
    )
    if module.name == "aegaeon-aws-staging":
        redis = block(
            (module / "redis.tf").read_text(), 'resource "aws_elasticache_replication_group" "main"'
        )
        for name in ("at_rest_encryption_enabled", "transit_encryption_enabled"):
            require(assignment(redis, name) == "true", f"Redis requires {name}")
        require(
            assignment(redis, "auth_token") == "random_password.redis_auth_token.result",
            "Redis auth token contract changed",
        )
        if int(providers["aws"].split(".")[0]) >= 6:
            require(
                assignment(redis, "auth_token_update_strategy") == '"ROTATE"',
                "AWS 6 requires preserved explicit Redis ROTATE strategy",
            )


def installed_providers(work: Path) -> dict[str, str]:
    directory = work / "tf-data/providers"
    binaries = sorted(directory.rglob("terraform-provider-*"))
    require(bool(binaries), "Initialized provider binaries missing")
    return {str(path.relative_to(directory)): digest(path) for path in binaries if path.is_file()}


def validate_schema(commands: Commands, tofu: str, module: Path) -> dict[str, Any]:
    validation = json.loads(commands.run([tofu, "validate", "-json", "-no-color"], module))
    require(isinstance(validation, dict), "Malformed validation result")
    require(
        validation.get("valid") is True and validation.get("error_count") == 0,
        "OpenTofu returned invalid validation result",
    )
    return dict(validation)


def initialize_providers(
    copy: Path, source: Path, commands: Commands, tofu: str, work: Path
) -> dict[str, Any]:
    providers = lock_contract(copy)
    commands.run(
        [tofu, "init", "-backend=false", "-lockfile=readonly", "-input=false", "-no-color"],
        copy,
    )
    require(
        digest(copy / ".terraform.lock.hcl") == digest(source / ".terraform.lock.hcl"),
        "OpenTofu rewrote readonly lock",
    )
    return {"providers": providers, "installed_providers": installed_providers(work)}
