"""Aegaeon configuration authority and process profiles."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from infrastructure_support.common import (
    BOOTSTRAP_REGION_INPUTS,
    CONTRACT_SOURCES,
    PERFORMANCE_CLIENT_NAMES,
    require,
)
from infrastructure_support.hcl import (
    ENV_IDENTIFIER,
    STRING,
    block,
    combined,
    environment_objects,
    expression,
    quoted_names,
    strict_matches,
    top_level_position,
    uncomment,
)

if TYPE_CHECKING:
    from pathlib import Path


def server_inventory(root: Path) -> tuple[set[str], set[str], set[str]]:
    source = uncomment((root / CONTRACT_SOURCES[0]).read_text())
    tables = re.findall(r"const MAIN_ENV_INVENTORY:.*?=\s*&\[(.*?)\];", source, re.DOTALL)
    require(len(tables) == 1, "Missing or duplicate classified server inventory")
    entries = strict_matches(
        rf'\s*\(\s*"({ENV_IDENTIFIER})"\s*,\s*MainEnvAuthority::(\w+)\s*,?\s*\)\s*,?\s*',
        tables[0],
        "classified server inventory",
    )
    classes = {entry[1]: entry[2] for entry in entries}
    require(len(classes) == len(entries), "Duplicate classified environment name")
    allowed_classes = {
        "SystemBootstrap",
        "BootstrapSecret",
        "HostLocalObservability",
        "HostLocalTrustBundle",
        "SharedRuntimeStore",
    }
    require(
        set(classes.values()) <= allowed_classes | {"RemovedRejected", "TestOnlyBootstrap"},
        "Unknown environment authority class",
    )
    removed_source = uncomment((root / CONTRACT_SOURCES[1]).read_text())
    prefix = removed_source.split("pub(super) fn reject_removed_database_runtime_envs()", 1)
    require(len(prefix) == 2, "Missing removed-environment rejection entrypoint")
    declarations = prefix[0].replace("use super::ConfigError;", "").strip()
    constants = strict_matches(
        r"\s*const REMOVED_\w+\s*:\s*(&str|&\[&str\])\s*=\s*(.*?)\s*;\s*",
        declarations,
        "removed-environment constants",
    )
    removed: set[str] = {
        name for name, category in classes.items() if category == "RemovedRejected"
    }
    for constant in constants:
        value = constant[2]
        if constant[1] == "&[&str]":
            require(value.startswith("&[") and value.endswith("]"), "Malformed removed-name list")
            value = value[2:-1]
        removed.update(quoted_names(value))
    required = required_server_inputs(root)
    allowed = {name for name, category in classes.items() if category in allowed_classes} - removed
    require(
        len(required) == 19 and required <= allowed,
        "Changed bootstrap/shared-store inventory requires review",
    )
    return allowed | {"AWS_REGION", "RUST_LOG"}, removed, required


def required_server_inputs(root: Path) -> set[str]:
    inventory = uncomment((root / CONTRACT_SOURCES[2]).read_text())
    required = {"AEGAEON_RUNTIME_ISSUER_HOST", "AEGAEON_DATABASE_URL"}
    for name in ("base", "upstream"):
        body = block(
            inventory,
            f"fn {name}_shared_runtime_store_requirements() -> Vec<SharedRuntimeStoreRequirement>",
        )
        match = re.fullmatch(r"\s*vec!\[(.*)\]\s*", body, re.DOTALL)
        require(match is not None, "Malformed shared-store requirement body")
        if match is None:
            raise ValueError("Missing shared-store body")
        entries = strict_matches(
            rf'\s*SharedRuntimeStoreRequirement::new\(\s*{STRING}\s*,\s*"({ENV_IDENTIFIER})"\s*,?\s*\)\s*,?\s*',
            match[1],
            "shared-store requirements",
        )
        names = [entry[1] for entry in entries]
        require(
            not (set(names) & required) and len(names) == len(set(names)),
            "Duplicate shared-store requirement",
        )
        required.update(names)
    return required


def ecs_process_inputs(
    process: str, environment: dict[str, str], secrets: dict[str, str]
) -> dict[str, str]:
    sensitive = {
        "server": {
            "AEGAEON_DATABASE_URL",
            "AEGAEON_KEY_ENCRYPTION_KEY",
            "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
            *(name for name in environment.keys() | secrets.keys() if name.endswith("_REDIS_URL")),
        },
        "migrate": {"DATABASE_URL"},
        "hosted_bootstrap": {
            "AEGAEON_DATABASE_URL",
            "AEGAEON_KEY_ENCRYPTION_KEY",
            "AEGAEON_HOSTED_BOOTSTRAP_OWNER_PASSWORD",
        },
    }[process]
    misplaced = sorted(sensitive & environment.keys())
    require(not misplaced, f"{process}: sensitive names must use ECS secrets: {misplaced}")
    return combined(environment, secrets)


def task_container(ecs: str, task: str) -> str:
    body = block(ecs, f'resource "aws_ecs_task_definition" "{task}"')
    containers = expression(body, "container_definitions")
    match = re.fullmatch(r"jsonencode\(\s*\[\s*\{(.*)\}\s*\]\s*\)", containers, re.DOTALL)
    require(match is not None, "Unsupported container definition shape")
    if match is None:
        raise ValueError("Missing container definition")
    require(top_level_position(match[1], len(match[1])), "Unbalanced container definition")
    expected = {
        "server": "aegaeon-server",
        "migrate": "aegaeon-migrate",
        "hosted_bootstrap": "aegaeon-hosted-bootstrap",
    }[task]
    require(expression(match[1], "name") == json.dumps(expected), "Unexpected process container")
    if task == "hosted_bootstrap":
        require(
            expression(match[1], "entryPoint") == '["/usr/local/bin/aegaeon-hosted-bootstrap"]',
            "Unexpected hosted-bootstrap entrypoint",
        )
    return match[1]


def staging_processes(module: Path) -> dict[str, dict[str, str]]:
    local = block((module / "locals.tf").read_text(), "locals")
    redis = expression(local, "redis_secret_env_names")
    require(
        redis.startswith("toset([") and redis.endswith("])"),
        "Unsupported Redis secret-name collection",
    )
    redis_names = quoted_names(redis[7:-2])
    secret = expression(local, "secret_environment")
    match = re.fullmatch(
        r"concat\(\s*(\[.*?\])\s*,\s*\[for name in local\.redis_secret_env_names\s*:\s*"
        r"\{\s*name\s*=\s*name\s*valueFrom\s*=\s*"
        r"aws_secretsmanager_secret\.redis_url\.arn\s*\}\s*\]\s*,?\s*\)",
        secret,
        re.DOTALL,
    )
    require(match is not None, "Unsupported server secret environment expression")
    if match is None:
        raise ValueError("Missing server secrets")
    server = ecs_process_inputs(
        "server",
        environment_objects(expression(local, "container_environment"), "value"),
        combined(
            environment_objects(match[1], "valueFrom"),
            dict.fromkeys(redis_names, "aws_secretsmanager_secret.redis_url.arn"),
        ),
    )
    ecs = (module / "ecs.tf").read_text()
    server_task = task_container(ecs, "server")
    require(
        expression(server_task, "environment") == "local.container_environment"
        and expression(server_task, "secrets") == "local.secret_environment",
        "Unreviewed server environment wiring",
    )
    result = {"server": server}
    for task in ("migrate", "hosted_bootstrap"):
        body = task_container(ecs, task)
        result[task] = ecs_process_inputs(
            task,
            environment_objects(expression(body, "environment"), "value"),
            environment_objects(expression(body, "secrets"), "valueFrom"),
        )
    return result


def bootstrap_region_inputs(root: Path) -> tuple[str, str]:
    source = uncomment((root / "crates/server/src/bin/aegaeon-hosted-bootstrap.rs").read_text())
    body = block(source, "fn bootstrap_input_from_env() -> Result<HostedBootstrapInput>")
    alternatives = re.findall(
        rf'\benv_or_required_env\("({ENV_IDENTIFIER})",\s*"({ENV_IDENTIFIER})"\)', body
    )
    require(
        alternatives == [BOOTSTRAP_REGION_INPUTS], "Changed hosted-bootstrap region alternatives"
    )
    return BOOTSTRAP_REGION_INPUTS


def nonempty_input(value: str) -> bool:
    value = value.strip()
    if value.startswith('"'):
        decoded = json.loads(value)
        return isinstance(decoded, str) and bool(decoded.strip())
    return value not in {"", "''"}


def process_profiles(root: Path) -> dict[str, tuple[set[str], set[str]]]:
    bootstrap_region_inputs(root)
    source = uncomment((root / "crates/server/src/bin/aegaeon-hosted-bootstrap.rs").read_text())
    body = block(source, "fn bootstrap_input_from_env() -> Result<HostedBootstrapInput>")
    bootstrap = set(
        re.findall(rf'\b(?:required_env|env_or|env_or_required_env)\("({ENV_IDENTIFIER})"', body)
    )
    required = set(re.findall(rf'\brequired_env\("({ENV_IDENTIFIER})"', body)) | {
        "AEGAEON_DATABASE_URL"
    }
    require(len(bootstrap) == 13 and len(required) == 6, "Changed hosted-bootstrap input profile")
    bootstrap |= {"AEGAEON_DATABASE_URL", "AEGAEON_KEY_ENCRYPTION_KEY", "AWS_REGION", "RUST_LOG"}
    parity = {
        "AEGAEON_OIDC_SIGNING_BACKEND",
        "AEGAEON_OIDC_SIGNING_AWS_REGION",
        "AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID",
        "AEGAEON_OIDC_SIGNING_KID",
        "AWS_REGION",
    }
    registry = {
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "GHCR_AUTH_ENABLED",
        "GHCR_USERNAME",
        "GHCR_TOKEN_SSM_PARAMETER_NAME",
        "GHCR_TOKEN_SECRETSMANAGER_SECRET_ID",
    }
    loadgen = set(PERFORMANCE_CLIENT_NAMES)
    return {
        "hosted_bootstrap": (bootstrap, required),
        "migrate": ({"DATABASE_URL"}, {"DATABASE_URL"}),
        "kms_parity": (parity, parity),
        "server_registry": (registry, {"AWS_REGION", "AWS_DEFAULT_REGION", "GHCR_AUTH_ENABLED"}),
        "loadgen_registry": (registry, {"AWS_REGION", "AWS_DEFAULT_REGION", "GHCR_AUTH_ENABLED"}),
        "loadgen": (loadgen, loadgen),
    }
