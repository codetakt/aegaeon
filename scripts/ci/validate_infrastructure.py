#!/usr/bin/env python3
"""Validate repository OpenTofu modules without cloud credentials or deployment.

This checks static provider compatibility and explicit configuration contracts.
It does not read deployed state, plan changes, or establish deployment safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

MODULE_ROOT = PurePosixPath("infra/tofu")
MODULES = ("aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2")
SUPPORT_PATHS = {
    "scripts/ci/validate_infrastructure.py": MODULES,
    "tests/ci/test_infrastructure_validation.py": MODULES,
    ".github/workflows/infrastructure-validation.yml": MODULES,
    "scripts/perf/aws_sweep.sh": ("perf-aws-ec2",),
    "scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh": ("oidc-aws-kms-parity",),
}
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|//[^\n]*|\#[^\n]*|[{}]', re.DOTALL)
COMMAND_TIMEOUT = 300


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - predicate guard
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def uncomment(text: str) -> str:
    return TOKEN.sub(lambda m: m[0] if m[0][0] in '"{}' else " ", text)


def block(text: str, header: str) -> str:
    """Extract one explicit HCL block, respecting strings/comments and nesting."""
    text = uncomment(text)
    matches = list(re.finditer(r"(?m)^\s*" + re.escape(header) + r"\s*\{", text))
    require(len(matches) == 1, f"Expected exactly one {header} block")
    start = matches[0].end()
    depth = 1
    for token in TOKEN.finditer(text, start):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return text[start : token.start()]
    raise ValueError(f"Unclosed {header} block")


def top_level(text: str) -> str:
    text = uncomment(text)
    result = []
    depth = 0
    start = 0
    for token in TOKEN.finditer(text):
        if token[0] == "{":
            if depth == 0:
                result.append(text[start : token.start()])
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                result.append(" {} ")
                start = token.end()
    require(depth == 0, "Unbalanced HCL block")
    result.append(text[start:])
    return "".join(result)


def assignment(text: str, name: str) -> str:
    matches = re.findall(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*([^\n]+)", top_level(text))
    require(len(matches) == 1, f"Expected one explicit {name} assignment")
    return str(matches[0].strip())


def select_modules(root: Path, paths: list[str] | None) -> list[Path]:
    available = root / str(MODULE_ROOT)
    require(available.is_dir(), "Missing infra/tofu directory")
    discovered = sorted(p.name for p in available.iterdir() if p.is_dir())
    require(discovered == sorted(MODULES), "Unknown or missing infrastructure module")
    selected = set(MODULES) if paths is None else set()
    require(paths is None or bool(paths), "Empty infrastructure path selection")
    for raw in paths or []:
        if raw in SUPPORT_PATHS:
            selected.update(SUPPORT_PATHS[raw])
            continue
        path = PurePosixPath(raw)
        require(raw == str(path) and not path.is_absolute(), f"Noncanonical path: {raw!r}")
        require(not any(ord(c) < 32 for c in raw), "Control character in path")
        require(".." not in path.parts and len(path.parts) == 4, f"Invalid module path: {raw}")
        require(path.parts[:2] == MODULE_ROOT.parts, f"Not an infrastructure input: {raw}")
        require(path.parts[2] in MODULES, f"Unknown module: {raw}")
        selected.add(path.parts[2])
    modules = [available / name for name in sorted(selected)]
    for module in modules:
        require(not module.is_symlink(), f"Symlink module: {module}")
        require(module.resolve().is_relative_to(root.resolve()), "Module escapes repository")
    return modules


def module_inputs(module: Path) -> list[Path]:
    inputs = []
    for path in sorted(module.iterdir()):
        require(not path.is_symlink(), f"Symlink module input: {path}")
        if path.name == ".terraform":
            continue  # Never use preexisting initialization or state.
        require(path.is_file(), f"Unsupported module input: {path}")
        allowed = path.name in {".terraform.lock.hcl", ".gitignore", "README.md"}
        require(allowed or path.suffix in {".tf", ".tftpl"}, f"Unexpected input: {path}")
        inputs.append(path)
    names = {p.name for p in inputs}
    require(
        {"versions.tf", ".terraform.lock.hcl"} <= names, "Missing provider declarations or lock"
    )
    require(any(p.suffix == ".tf" for p in inputs), "Empty module")
    return inputs


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


CONTRACT_SOURCES = (
    "crates/server/src/main/tests/env_inventory.rs",
    "crates/server/src/config/removed_env.rs",
    "crates/server/src/config/runtime_boundary/shared_store/inventory.rs",
    "crates/server/src/config/runtime_boundary/shared_store/preflight.rs",
    "crates/server/src/config/environment.rs",
    "crates/server/src/config/database.rs",
    "crates/server/src/config/oidc_boundary.rs",
    "crates/server/src/config/startup_policy_boundary.rs",
    "crates/server/src/config/runtime_boundary/key_material.rs",
    "crates/server/src/main/bootstrap_env.rs",
    "crates/server/src/main/runtime_config.rs",
    "crates/server/src/bin/aegaeon-hosted-bootstrap.rs",
    "crates/server/src/key_encryption.rs",
    "crates/server/src/web/management/state/config/bootstrap_env.rs",
    "scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh",
    "scripts/validation/run_oidc_kms_parity.sh",
    "scripts/perf/aws_sweep.sh",
    "scripts/ci/validate_infrastructure.py",
    "tests/ci/test_infrastructure_validation.py",
    "crates/server/src/main.rs",
    "crates/server/src/config/transport.rs",
    "crates/server/src/config/runtime_boundary/authority.rs",
    "crates/server/src/config/runtime_boundary/raw_json.rs",
    "crates/server/src/oidc/config/tests/kms_parity.rs",
)
ENV_IDENTIFIER = r"[A-Z][A-Z0-9_]*"
STRING = r'"(?:[^"\\]|\\.)*"'
EXPRESSION_TOKEN = re.compile(STRING + r"|[\[\]{}()\n]")
REFERENCE = r"(?:var|local|data|aws_[a-z0-9_]+)(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
VALUE = re.compile(
    rf"(?:{STRING}|{REFERENCE}|true|false|[0-9]+|{REFERENCE}\s*\?\s*{STRING}\s*:\s*{STRING})"
)


class RuntimeContractError(ValueError):
    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        super().__init__(
            "Runtime environment contract rejected: " + json.dumps(report["violations"])
        )


def strict_matches(pattern: str, text: str, label: str) -> list[re.Match[str]]:
    matches = list(re.finditer(pattern, text, re.DOTALL))
    require(
        bool(matches) and not re.sub(pattern, "", text, flags=re.DOTALL).strip(),
        f"Malformed {label}",
    )
    return matches


def quoted_names(text: str) -> list[str]:
    matches = strict_matches(rf'\s*"({ENV_IDENTIFIER})"\s*,?\s*', text, "environment-name list")
    names = [match[1] for match in matches]
    require(len(names) == len(set(names)), "Duplicate environment name")
    return names


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


def top_level_position(text: str, position: int) -> bool:
    stack: list[str] = []
    pairs = {"]": "[", "}": "{", ")": "("}
    for token in EXPRESSION_TOKEN.finditer(text, 0, position):
        if token[0] in ("[", "{", "("):
            stack.append(token[0])
        elif token[0] in pairs:
            require(bool(stack) and stack.pop() == pairs[token[0]], "Unbalanced input scope")
    return not stack


def expression(text: str, name: str) -> str:
    text = uncomment(text)
    matches = [
        match
        for match in re.finditer(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*", text)
        if top_level_position(text, match.end())
    ]
    require(len(matches) == 1, f"Expected one explicit {name} expression")
    start = matches[0].end()
    stack: list[str] = []
    pairs = {"]": "[", "}": "{", ")": "("}
    for token in EXPRESSION_TOKEN.finditer(text, start):
        value = token[0]
        if value in ("[", "{", "("):
            stack.append(value)
        elif value in pairs:
            require(bool(stack) and stack.pop() == pairs[value], "Unbalanced expression")
        elif value == "\n" and not stack:
            return text[start : token.start()].strip().rstrip(",").strip()
    require(not stack, "Unclosed expression")
    return text[start:].strip().rstrip(",").strip()


def environment_objects(text: str, attribute: str) -> dict[str, str]:
    require(attribute in {"value", "valueFrom"}, "Unknown ECS environment attribute")
    require(text.startswith("[") and text.endswith("]"), "Expected literal environment array")
    if not text[1:-1].strip():
        return {}
    objects = strict_matches(
        rf'\s*\{{\s*name\s*=\s*"({ENV_IDENTIFIER})"\s*,?\s*{attribute}\s*=\s*((?:{STRING}|[^{{}}"])+?)\s*,?\s*\}}\s*,?\s*',
        text[1:-1],
        f"environment assignments requiring {attribute}",
    )
    result = {}
    for item in objects:
        require(item[1] not in result, f"Duplicate environment assignment: {item[1]}")
        require(
            VALUE.fullmatch(item[2].strip()) is not None, f"Unsupported value expression: {item[1]}"
        )
        result[item[1]] = item[2].strip()
    return result


def combined(*groups: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in groups:
        require(not (result.keys() & group.keys()), "Duplicate process environment assignment")
        result.update(group)
    return result


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


def heredoc_environment(text: str, name: str) -> dict[str, str]:
    matches = re.findall(
        r"(?m)^cat >/etc/aegaeon/" + re.escape(name) + r"\.env <<EOF\n(.*?)\nEOF$", text, re.DOTALL
    )
    require(len(matches) == 1, f"Missing or duplicate {name} environment heredoc")
    result = {}
    for line in matches[0].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(rf"({ENV_IDENTIFIER})=(.*)", line)
        require(match is not None, f"Malformed {name} environment assignment")
        if match is None:
            raise ValueError("Missing environment assignment")
        require(match[1] not in result, f"Duplicate environment assignment: {match[1]}")
        result[match[1]] = match[2]
    return result


def perf_server_environment_wiring(template: str) -> None:
    units = re.findall(
        r"(?m)^cat >/etc/systemd/system/aegaeon-server\.service <<'EOF'\n(.*?)\nEOF$",
        template,
        re.DOTALL,
    )
    require(len(units) == 1, "Missing or duplicate server service definition")
    starts = re.findall(r"(?m)^ExecStart=.*$", units[0])
    require(
        starts
        == [
            (
                "ExecStart=/usr/bin/docker run --rm --name aegaeon-server --network host "
                "--env-file /etc/aegaeon/server.env ${server_image} "
                "--host 0.0.0.0 --port ${server_port}"
            )
        ],
        "Unsupported server command or environment-file wiring",
    )


# Exact reviewed Bash/service shapes: changes require explicit review, not substring admission.
SHELL_BODY_SHAPES = {
    "/usr/local/bin/aegaeon-docker-login": {
        "source": ("aba0123fbe0d221327d4e961f5f8bb0025c1607fbca6181c34376b8b3619dce6"),
        "rendered": ("3ea9a5647dd87b675648a1f732a49ec6068b21c10cefe186415b857295d0a6db"),
    },
    "/etc/systemd/system/aegaeon-server.service": {
        "source": ("44c733de01cab8c5b62cd8c1c0f43f928eaac0b5cec4bfa8a673a12b90ffef2a"),
        "rendered": ("44c733de01cab8c5b62cd8c1c0f43f928eaac0b5cec4bfa8a673a12b90ffef2a"),
    },
    "/usr/local/bin/aegaeon-run-loadtest": {
        "source": ("ded6b6a5c572ad5db6b035c858074729600660180ca595f45d315ba30d9c1570"),
        "rendered": ("e5fd3ac9a170a09119348a04295c85b8dc24260f9f27d4032ea2c35eaf9010f3"),
    },
    "/etc/systemd/system/aegaeon-loadtest.service": {
        "source": ("88e14cd224ed36367fd9e8c904264812d5bf2a3ecb9a6999086f1a58ec80884f"),
        "rendered": ("88e14cd224ed36367fd9e8c904264812d5bf2a3ecb9a6999086f1a58ec80884f"),
    },
}
TEMPLATE_SCAFFOLD_SHAPES = {
    "server-source": ("bea9a4a278e77be30de66501ac589f5a04af90267e5a9db12a9671a19e2d4a6f"),
    "server-False": ("0cd3b452d3ceb6e92874b10e4358f61f916c9cef4e848b81b2da75addeb79335"),
    "server-True": ("0cd3b452d3ceb6e92874b10e4358f61f916c9cef4e848b81b2da75addeb79335"),
    "loadgen-source": ("86f84e47c93ba87084eb97d95fb727c22a3a38a5ec959c21e019dbc67f755148"),
    "loadgen-False": ("7ac65fe8dd70901ae4875de01f259cff1dc33e28a1fa25e35c9f4c5cb3648ddf"),
    "loadgen-True": ("c0539fe094b71d057bf9a13f0093fe1ad0360d465b3cc6c9288ce2ec22ba22ee"),
}
SHELL_HEREDOC = re.compile(r"(?m)^cat >(/[^\s]+) <<('?)([A-Za-z_]\w*)\2\n")


def active_shape(text: str) -> str:
    return "\n".join(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def semantic_shell_shape(text: str, *, rendered: bool) -> str:
    # Terraform escaping is interpreted only in source mode; rendered dollars are actual Bash.
    return active_shape(text if rendered else text.replace("$${", "${"))


def template_sections(template: str) -> tuple[dict[str, str], str]:
    sections: dict[str, str] = {}
    scaffold = []
    offset = 0
    while match := SHELL_HEREDOC.search(template, offset):
        end = re.search(r"(?m)^" + re.escape(match[3]) + r"$", template[match.end() :])
        require(end is not None, "Unclosed supported template heredoc")
        if end is None:
            raise ValueError("Missing template heredoc terminator")
        stop = match.end() + end.start()
        finish = match.end() + end.end()
        require(match[1] not in sections, "Duplicate template process/service heredoc")
        sections[match[1]] = template[match.end() : stop]
        scaffold.extend(
            [template[offset : match.end()], "<" + match[1] + ">\n", template[stop:finish]]
        )
        offset = finish
    scaffold.append(template[offset:])
    return sections, "".join(scaffold)


def reviewed_template_sections(
    template: str, role: str, *, rendered: bool, enabled: bool = False
) -> dict[str, str]:
    sections, scaffold = template_sections(template)
    expected = {
        "/etc/aegaeon/registry.env",
        "/usr/local/bin/aegaeon-docker-login",
    } | (
        {"/etc/aegaeon/server.env", "/etc/systemd/system/aegaeon-server.service"}
        if role == "server"
        else {
            "/etc/aegaeon/loadtest.env",
            "/usr/local/bin/aegaeon-run-loadtest",
            "/etc/systemd/system/aegaeon-loadtest.service",
        }
    )
    require(set(sections) == expected, "Changed template process/service inventory")
    key = role + "-" + (str(enabled) if rendered else "source")
    require(
        hashlib.sha256(active_shape(scaffold).encode()).hexdigest()
        == TEMPLATE_SCAFFOLD_SHAPES[key],
        "Unsupported active template launch scaffold",
    )
    return sections


def require_body_shape(path: str, body: str, *, rendered: bool) -> None:
    if path.startswith("/usr/local/bin/"):
        require(body.startswith("#!/usr/bin/env bash\n"), "Unsupported process script interpreter")
    require(
        hashlib.sha256(active_shape(body).encode()).hexdigest()
        == SHELL_BODY_SHAPES[path]["rendered" if rendered else "source"],
        "Unsupported reviewed active process/service shape: " + path,
    )


def registry_helper_wiring(
    template: str, role: str, *, rendered: bool, enabled: bool = False
) -> None:
    sections = reviewed_template_sections(template, role, rendered=rendered, enabled=enabled)
    path = "/usr/local/bin/aegaeon-docker-login"
    body = semantic_shell_shape(sections[path], rendered=rendered)
    require(
        "set -a\nsource /etc/aegaeon/registry.env\nset +a" in body,
        "Registry helper must source/export the validated registry environment",
    )
    for variable, command, options in (
        (
            "GHCR_TOKEN_SSM_PARAMETER_NAME",
            ["ssm", "get-parameter"],
            [
                "--with-decryption",
                "--name",
                "$GHCR_TOKEN_SSM_PARAMETER_NAME",
                "--query",
                "Parameter.Value",
            ],
        ),
        (
            "GHCR_TOKEN_SECRETSMANAGER_SECRET_ID",
            ["secretsmanager", "get-secret-value"],
            ["--secret-id", "$GHCR_TOKEN_SECRETSMANAGER_SECRET_ID", "--query", "SecretString"],
        ),
    ):
        branches = re.findall(
            r'(?m)^if \[\[ -n "\$\{' + variable + r':-\}" \]\]; then\n(.*?)\nfi$',
            body,
            re.DOTALL,
        )
        require(
            len(branches) == 1,
            "Missing or duplicate active registry credential branch: " + variable,
        )
        commands = branches[0].replace("\\\n", " ").splitlines()
        require(
            len(commands) == 2 and commands[1] == "exit 0",
            "Unsupported active registry credential branch",
        )
        expected = [
            "AWS_REGION=$region",
            "AWS_DEFAULT_REGION=$region",
            "aws",
            *command,
            *options,
            "--output",
            "text",
            "|",
            "docker",
            "login",
            "ghcr.io",
            "--username",
            "$GHCR_USERNAME",
            "--password-stdin",
            ">/dev/null",
        ]
        require(
            shlex.split(commands[0]) == expected,
            "Invalid active registry secret-to-login pipeline: " + variable,
        )
    require_body_shape(path, sections[path], rendered=rendered)
    if role == "server":
        unit_path = "/etc/systemd/system/aegaeon-server.service"
        unit = active_shape(sections[unit_path])
        image = "registry.example/aegaeon:test" if rendered else "${server_image}"
        port = "8080" if rendered else "${server_port}"
        require(
            unit.splitlines().count("ExecStartPre=/usr/local/bin/aegaeon-docker-login " + image)
            == 1,
            "Actual server service must invoke the validated registry helper",
        )
        require(
            unit.splitlines().count(
                "ExecStart=/usr/bin/docker run --rm --name aegaeon-server --network host "
                "--env-file /etc/aegaeon/server.env " + image + " --host 0.0.0.0 --port " + port
            )
            == 1,
            "Unsupported actual server service command/environment wiring",
        )
        bound = (
            sections[unit_path]
            .replace(image, "${server_image}")
            .replace("--port " + port, "--port ${server_port}")
        )
        require_body_shape(unit_path, bound, rendered=rendered)
    else:
        perf_loadgen_environment_wiring(template, rendered=rendered, enabled=enabled)


def perf_loadgen_environment_wiring(
    template: str, *, rendered: bool, enabled: bool = False
) -> None:
    sections = reviewed_template_sections(template, "loadgen", rendered=rendered, enabled=enabled)
    path = "/usr/local/bin/aegaeon-run-loadtest"
    body = semantic_shell_shape(sections[path], rendered=rendered)
    require(
        "set -a\nsource /etc/aegaeon/loadtest.env\nset +a" in body,
        "Load-generator environment-file sourcing/export wiring changed",
    )
    require(
        body.splitlines().count('/usr/local/bin/aegaeon-docker-login "${SERVER_IMAGE}"') == 1,
        "Actual load-generator registry-helper invocation wiring changed",
    )
    commands = [
        line for line in body.replace("\\\n", " ").splitlines() if line.startswith("docker run ")
    ]
    expected = [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "--entrypoint",
        "${LOADTEST_BIN}",
        "-v",
        "${OUT_DIR}:/results",
        "${SERVER_IMAGE}",
        "--url",
        "${SERVER_URL}",
        "--workers",
        "${WORKERS}",
        "--run-time",
        "${RUN_TIME}",
        "--warmup",
        "${WARMUP}",
        "--rps",
        "${RPS}",
        "--scenario",
        "${SCENARIO}",
        "--report-file",
        "/results/report.json",
        ">${OUT_DIR}/loadtest.stdout.log",
        "2>${OUT_DIR}/loadtest.stderr.log",
    ]
    require(
        len(commands) == 1 and shlex.split(commands[0]) == expected,
        "Actual load-generator workload argv wiring changed",
    )
    unit_path = "/etc/systemd/system/aegaeon-loadtest.service"
    unit = active_shape(sections[unit_path])
    starts = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
    require(
        starts == ["ExecStart=" + path], "Actual load-generator service executable wiring changed"
    )
    require_body_shape(path, sections[path], rendered=rendered)
    require_body_shape(unit_path, sections[unit_path], rendered=rendered)


PERF_TEMPLATE_BINDINGS = {
    "server": {
        "aws_region": "data.aws_region.current.id",
        "server_image": "var.server_image",
        "server_port": "var.server_port",
        "expose_metrics_on_main": "var.expose_metrics_on_main",
        "trusted_proxies": "local.server_trusted_proxies",
        "ghcr_auth_enabled": "var.ghcr_auth_enabled",
        "ghcr_username": 'var.ghcr_username == null ? "" : var.ghcr_username',
        "ghcr_token_ssm_parameter_name": (
            'var.ghcr_token_ssm_parameter_name == null ? "" : var.ghcr_token_ssm_parameter_name'
        ),
        "ghcr_token_secretsmanager_secret": (
            'var.ghcr_token_secretsmanager_secret_id == null ? "" : '
            "var.ghcr_token_secretsmanager_secret_id"
        ),
    },
    "loadgen": {
        "aws_region": "data.aws_region.current.id",
        "server_image": "var.server_image",
        "server_url": "local.loadtest_server_url",
        "artifact_bucket": "local.artifact_bucket_name",
        "artifact_prefix": "var.artifact_prefix",
        "auto_run_loadtest": "var.auto_run_loadtest",
        "workers": "var.loadtest_workers",
        "rps": "var.loadtest_rps",
        "run_time": "var.loadtest_run_time",
        "warmup": "var.loadtest_warmup",
        "scenario": "var.loadtest_scenario",
        "ghcr_auth_enabled": "var.ghcr_auth_enabled",
        "ghcr_username": 'var.ghcr_username == null ? "" : var.ghcr_username',
        "ghcr_token_ssm_parameter_name": (
            'var.ghcr_token_ssm_parameter_name == null ? "" : var.ghcr_token_ssm_parameter_name'
        ),
        "ghcr_token_secretsmanager_secret": (
            'var.ghcr_token_secretsmanager_secret_id == null ? "" : '
            "var.ghcr_token_secretsmanager_secret_id"
        ),
    },
}


def compact_expression(text: str) -> str:
    return re.sub(
        r'"(?:[^"\\]|\\.)*"|\s+', lambda match: match[0] if match[0].startswith('"') else "", text
    )


def perf_template_bindings(module: Path) -> None:
    source = (module / "instances.tf").read_text()
    for role, expected in PERF_TEMPLATE_BINDINGS.items():
        resource = block(source, f'resource "aws_instance" "{role}"')
        names = re.findall(r"(?m)^\s*(user_data(?:_base64)?)\s*=", resource)
        require(names == ["user_data"], "Changed active EC2 userdata ownership")
        value = expression(resource, "user_data")
        header = 'templatefile("${path.module}/user_data_' + role + '.sh.tftpl",'
        require(
            value.startswith(header) and value.endswith("})"),
            "Changed active role-specific template identity",
        )
        mapping = block(value, header)
        entries = strict_matches(
            r"\s*(\w+)\s*=\s*([^\n]+)\n?", mapping, "EC2 templatefile argument map"
        )
        pairs = [(item[1], item[2]) for item in entries]
        require(len(pairs) == len({key for key, _ in pairs}), "Duplicate EC2 templatefile argument")
        actual = {key: compact_expression(value) for key, value in pairs}
        require(
            actual == {key: compact_expression(value) for key, value in expected.items()},
            "Changed active EC2 templatefile argument source or inventory",
        )


def process_inputs(module: Path) -> dict[str, dict[str, str]]:
    if module.name == "aegaeon-aws-staging":
        return staging_processes(module)
    if module.name == "perf-aws-ec2":
        perf_template_bindings(module)
        server = (module / "user_data_server.sh.tftpl").read_text()
        loadgen = (module / "user_data_loadgen.sh.tftpl").read_text()
        perf_server_environment_wiring(server)
        perf_loadgen_environment_wiring(loadgen, rendered=False)
        registry_helper_wiring(server, "server", rendered=False)
        registry_helper_wiring(loadgen, "loadgen", rendered=False)
        return {
            "server": heredoc_environment(server, "server"),
            "server_registry": heredoc_environment(server, "registry"),
            "loadgen_registry": heredoc_environment(loadgen, "registry"),
            "loadgen": heredoc_environment(loadgen, "loadtest"),
        }
    output = block((module / "outputs.tf").read_text(), 'output "oidc_signing_env"')
    value = expression(output, "value")
    require(value.startswith("{") and value.endswith("}"), "Malformed KMS parity environment map")
    pairs = strict_matches(
        rf"\s*({ENV_IDENTIFIER})\s*=\s*([^\n]+)\n?", value[1:-1], "KMS parity map"
    )
    require(len({pair[1] for pair in pairs}) == len(pairs), "Duplicate parity environment name")
    require(all(VALUE.fullmatch(pair[2].strip()) for pair in pairs), "Unsupported parity value")
    return {"kms_parity": {pair[1]: pair[2].strip() for pair in pairs}}


BOOTSTRAP_REGION_INPUTS = ("AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", "AWS_REGION")


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
    loadgen = {
        "SERVER_URL",
        "SERVER_IMAGE",
        "ARTIFACT_BUCKET",
        "ARTIFACT_PREFIX",
        "WORKERS",
        "RPS",
        "RUN_TIME",
        "WARMUP",
        "SCENARIO",
    }
    return {
        "hosted_bootstrap": (bootstrap, required),
        "migrate": ({"DATABASE_URL"}, {"DATABASE_URL"}),
        "kms_parity": (parity, parity),
        "server_registry": (registry, {"AWS_REGION", "AWS_DEFAULT_REGION", "GHCR_AUTH_ENABLED"}),
        "loadgen_registry": (registry, {"AWS_REGION", "AWS_DEFAULT_REGION", "GHCR_AUTH_ENABLED"}),
        "loadgen": (loadgen, loadgen),
    }


def runtime_contract(module: Path, root: Path) -> dict[str, Any]:
    sources = {path: digest(root / path) for path in CONTRACT_SOURCES}
    allowed, removed, required = server_inventory(root)
    profiles = {**process_profiles(root), "server": (allowed, required)}
    processes = process_inputs(module)
    violations = []
    for process, values in processes.items():
        permitted, mandatory = profiles[process]
        for name in sorted(values):
            reason = None
            if process == "server" and name in removed:
                reason = "removed startup variable"
            elif name not in permitted:
                reason = "unknown or forbidden variable for this process"
            elif name in mandatory and values[name].strip() in {"", '""', "''"}:
                reason = "empty required value"
            if reason:
                violations.append({"process": process, "name": name, "reason": reason})
        violations.extend(
            {"process": process, "name": name, "reason": "missing required assignment"}
            for name in sorted(mandatory - values.keys())
        )
    if "hosted_bootstrap" in processes and not any(
        nonempty_input(processes["hosted_bootstrap"].get(name, ""))
        for name in BOOTSTRAP_REGION_INPUTS
    ):
        violations.append(
            {
                "process": "hosted_bootstrap",
                "name": " or ".join(BOOTSTRAP_REGION_INPUTS),
                "reason": "missing or empty required region alternative",
            }
        )
    report = {
        "status": "failed" if violations else "passed",
        "runtime_sources": sources,
        "processes": {name: sorted(values) for name, values in processes.items()},
        "violations": violations,
        "external_conditions": (
            "Database schema, active managed policy/key readiness, conditional stores and live "
            "connectivity are not established by this static check."
        ),
    }
    if violations:
        raise RuntimeContractError(report)
    return report


def runtime_contract_report(module: Path, root: Path) -> dict[str, Any]:
    try:
        return runtime_contract(module, root)
    except RuntimeContractError as error:
        return error.report
    except ValueError as error:
        return {
            "status": "failed",
            "runtime_sources": {path: digest(root / path) for path in CONTRACT_SOURCES},
            "violations": [{"process": "input parser", "name": "unresolved", "reason": str(error)}],
        }


def resource_contract(module: Path, providers: dict[str, str]) -> None:
    if module.name == "perf-aws-ec2":
        perf_template_bindings(module)
        instances = (module / "instances.tf").read_text()
        for name in ("server", "loadgen"):
            body = block(instances, f'resource "aws_instance" "{name}"')
            require(
                assignment(body, "user_data_replace_on_change") == "true",
                "EC2 replacement contract changed",
            )
            metadata = block(body, "metadata_options")
            require(assignment(metadata, "http_tokens") == '"required"', "EC2 requires IMDSv2")
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


def isolated_environment(work: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "TF_", "TOFU_"))}
    empty = work / "empty-aws-config"
    empty.write_text("")
    config = work / "tofurc"
    config.write_text("provider_installation { direct {} }\n")
    env.update(
        {
            "TF_CLI_CONFIG_FILE": str(config),
            "TF_DATA_DIR": str(work / "tf-data"),
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "AWS_SHARED_CREDENTIALS_FILE": str(empty),
            "AWS_CONFIG_FILE": str(empty),
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


class Commands:
    def __init__(self, output: Path, env: dict[str, str]) -> None:
        self.output = output
        self.env = env
        self.records: list[dict[str, Any]] = []

    def run(self, argv: list[str], cwd: Path, stdin: str | None = None) -> str:
        label = f"{len(self.records):02d}-{Path(argv[0]).name}-{argv[1]}"
        started = time.monotonic()
        record: dict[str, Any] = {
            "argv": argv,
            "cwd": str(cwd),
            "stdout": label + ".stdout",
            "stderr": label + ".stderr",
        }
        self.records.append(record)
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=self.env,
                input=stdin,
                text=True,
                capture_output=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )
            record.update(exit=result.returncode, seconds=time.monotonic() - started)
            (self.output / record["stdout"]).write_text(result.stdout)
            (self.output / record["stderr"]).write_text(result.stderr)
            require(
                result.returncode == 0,
                f"Command failed ({result.returncode}): {argv}; see {self.output}",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), seconds=time.monotonic() - started)
            if isinstance(error, subprocess.TimeoutExpired):
                (self.output / record["stdout"]).write_bytes(error.stdout or b"")
                (self.output / record["stderr"]).write_bytes(error.stderr or b"")
            raise
        else:
            return result.stdout
        finally:
            (self.output / "commands.json").write_text(json.dumps(self.records, indent=2) + "\n")


def template_values() -> dict[str, Any]:
    return {
        "aws_region": "us-east-1",
        "server_image": "registry.example/aegaeon:test",
        "server_port": 8080,
        "expose_metrics_on_main": True,
        "trusted_proxies": "127.0.0.1/32",
        "ghcr_auth_enabled": True,
        "ghcr_username": "fixture",
        "ghcr_token_ssm_parameter_name": "/aegaeon/registry-token",
        "ghcr_token_secretsmanager_secret": "",
        "server_url": "http://server.example:8080",
        "artifact_bucket": "aegaeon-fixture",
        "artifact_prefix": "ci/",
        "auto_run_loadtest": True,
        "workers": 2,
        "rps": 10,
        "run_time": "10s",
        "warmup": "1s",
        "scenario": "health",
    }


def rendered_contract(
    rendered: str, role: str, *, enabled: bool, registry_enabled: bool = True
) -> None:
    registry_helper_wiring(rendered, role, rendered=True, enabled=enabled)
    values = template_values()
    registry = heredoc_environment(rendered, "registry")
    expected_registry = {
        "AWS_REGION": values["aws_region"],
        "AWS_DEFAULT_REGION": values["aws_region"],
        "GHCR_AUTH_ENABLED": "1" if registry_enabled else "0",
        "GHCR_USERNAME": values["ghcr_username"],
        "GHCR_TOKEN_SSM_PARAMETER_NAME": values["ghcr_token_ssm_parameter_name"],
        "GHCR_TOKEN_SECRETSMANAGER_SECRET_ID": values["ghcr_token_secretsmanager_secret"],
    }
    require(
        registry == expected_registry,
        "Rendered registry environment lost bound input/secret reference",
    )
    if role == "server":
        require(
            "AEGAEON_TRUSTED_PROXIES=127.0.0.1/32\n" in rendered, "Trusted proxy rendering changed"
        )
        require(
            "registry.example/aegaeon:test --host 0.0.0.0 --port 8080" in rendered,
            "Server CLI rendering changed",
        )
    else:
        require(
            "SERVER_URL=http://server.example:8080\n" in rendered,
            "Loadtest target rendering changed",
        )
        require(
            '--report-file "/results/report.json"' in rendered, "Loadtest report contract changed"
        )
        require(
            ("systemctl start aegaeon-loadtest.service" in rendered) == enabled,
            "Auto-run conditional changed",
        )


def check_templates(module: Path, commands: Commands, tofu: str, bash: str, work: Path) -> int:
    templates = sorted(module.glob("*.tftpl"))
    expected = (
        {"user_data_server.sh.tftpl", "user_data_loadgen.sh.tftpl"}
        if module.name == "perf-aws-ec2"
        else set()
    )
    require({p.name for p in templates} == expected, "Unreviewed template inventory")
    evaluation = work / "template-evaluation"
    evaluation.mkdir()
    for template in templates:
        for enabled in (False, True):
            for registry_enabled in (False, True):
                values = template_values()
                values.update(
                    expose_metrics_on_main=enabled,
                    auto_run_loadtest=enabled,
                    ghcr_auth_enabled=registry_enabled,
                )
                expression = (
                    f"jsonencode(templatefile({json.dumps(str(template))}, {json.dumps(values)}))\n"
                )
                raw = commands.run([tofu, "console", "-no-color"], evaluation, expression)
                rendered = json.loads(json.loads(raw))
                role = template.name.split("_")[2].split(".")[0]
                rendered_contract(
                    rendered, role, enabled=enabled, registry_enabled=registry_enabled
                )
                commands.run([bash, "-n"], evaluation, rendered)
    return len(templates) * 4


def check_support(module: Path, root: Path, commands: Commands, bash: str) -> dict[str, str]:
    sources = {}
    for path, modules in SUPPORT_PATHS.items():
        if path.endswith(".sh") and module.name in modules:
            source = root / path
            require(source.is_file() and not source.is_symlink(), f"Missing support script: {path}")
            raw = source.read_bytes()
            sources[path] = hashlib.sha256(raw).hexdigest()
            commands.run([bash, "-n"], module, raw.decode())
    return sources


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


def validate_module(
    module: Path, root: Path, output: Path, tools: dict[str, str]
) -> dict[str, Any]:
    output.mkdir()
    inputs = {str(p.relative_to(root)): digest(p) for p in module_inputs(module)}
    report: dict[str, Any] = {
        "module": str(module.relative_to(root)),
        "inputs": inputs,
        "status": "failed",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="aegaeon-infra-") as temporary:
            work = Path(temporary)
            copy = work / module.name
            copy.mkdir()
            for source in module_inputs(module):
                shutil.copyfile(source, copy / source.name)
            commands = Commands(output, isolated_environment(work))
            report["commands"] = commands.records
            report["tools"] = json.loads(commands.run([tools["tofu"], "version", "-json"], copy))
            commands.run([tools["tofu"], "fmt", "-check", "-diff"], copy)
            report.update(initialize_providers(copy, module, commands, tools["tofu"], work))
            report["validation"] = validate_schema(commands, tools["tofu"], copy)
            report["runtime_contract"] = runtime_contract_report(copy, root)
            resource_contract(copy, report["providers"])
            report["rendered_template_cases"] = check_templates(
                copy, commands, tools["tofu"], tools["bash"], work
            )
            report["support_scripts"] = check_support(module, root, commands, tools["bash"])
            require(
                digest(copy / ".terraform.lock.hcl") == digest(module / ".terraform.lock.hcl"),
                "OpenTofu rewrote readonly lock",
            )
            checked_sources = {
                **inputs,
                **report["runtime_contract"]["runtime_sources"],
                **report["support_scripts"],
            }
            require(
                all(digest(root / path) == value for path, value in checked_sources.items()),
                "Repository inputs changed during validation",
            )
            require(
                report["runtime_contract"]["status"] == "passed",
                "Runtime environment contract failed; see process/name/reason diagnostics",
            )
            report["status"] = "passed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def toolchain_provenance(root: Path, output: Path, tools: dict[str, str]) -> dict[str, Any]:
    inputs = [
        root / "flake.nix",
        root / "flake.lock",
        root / "pyproject.toml",
        root / ".github/workflows/infrastructure-validation.yml",
    ]
    for path in inputs:
        require(path.is_file() and not path.is_symlink(), f"Missing toolchain input: {path}")
    inputs.extend(sorted((root / "nix").rglob("*.nix")))
    inputs.extend(sorted((root / ".github/actions/setup-nix-ci").rglob("*")))
    source_hashes = {str(p.relative_to(root)): digest(p) for p in inputs if p.is_file()}
    executables = {**tools, "python": sys.executable}
    stores = set()
    for executable in executables.values():
        path = Path(executable).resolve()
        require(path.parts[1:3] == ("nix", "store"), f"Tool is not Nix-pinned: {path}")
        stores.add(str(Path(*path.parts[:4])))
    commands = Commands(output, dict(os.environ))
    closure = json.loads(
        commands.run([tools["nix"], "path-info", "--json", "--recursive", *sorted(stores)], root)
    )
    return {
        "toolchain_sources": source_hashes,
        "executable_paths": executables,
        "nix_closure": closure,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--paths-json",
        type=Path,
        help="JSON array of changed infra/tofu paths; omitted means all modules",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/infrastructure-validation"))
    args = parser.parse_args()
    summary: dict[str, Any] = {
        "status": "failed",
        "scope": "Static infrastructure validation; no deployed state or live AWS assurance",
    }
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        paths = None if args.paths_json is None else json.loads(args.paths_json.read_text())
        require(
            paths is None or (isinstance(paths, list) and all(isinstance(p, str) for p in paths)),
            "Paths must be a JSON string array",
        )
        modules = select_modules(args.root.resolve(), paths)
        tools = {name: shutil.which(name) for name in ("tofu", "bash", "nix")}
        require(all(tools.values()), "Required tools unavailable: tofu, bash and nix")
        resolved = {name: str(path) for name, path in tools.items()}
        summary["tool_hashes"] = {
            name: digest(Path(path).resolve()) for name, path in resolved.items()
        }
        summary["runner_sha256"] = digest(Path(__file__))
        summary["provenance"] = toolchain_provenance(args.root.resolve(), args.output, resolved)
        summary["modules"] = [
            validate_module(module, args.root.resolve(), args.output / module.name, resolved)
            for module in modules
        ]
        require(
            all(item["status"] == "passed" for item in summary["modules"]),
            "Infrastructure validation failed; see module diagnostics",
        )
        require(
            all(
                digest(args.root / path) == value
                for path, value in summary["provenance"]["toolchain_sources"].items()
            ),
            "Toolchain inputs changed during validation",
        )
        summary["status"] = "passed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        summary["error"] = str(error)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Infrastructure validation: {summary['status']}; evidence: {args.output}")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
