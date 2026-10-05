"""Native template rendering, emitted contracts and Bash checks."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from infrastructure_support.common import require
from infrastructure_support.delivery import performance_delivery_inputs
from infrastructure_support.fixtures import template_values
from infrastructure_support.guest import guest_sources
from infrastructure_support.selection import SUPPORT_PATHS
from infrastructure_support.templates import (
    loadgen_configuration,
    registry_configuration,
    registry_helper_wiring,
    template_sections,
)

if TYPE_CHECKING:
    from pathlib import Path

    from infrastructure_support.commands import Commands


def rendered_contract(
    rendered: str, role: str, *, enabled: bool, registry_enabled: bool = True
) -> None:
    registry_helper_wiring(rendered, role, rendered=True, enabled=enabled)
    performance_delivery_inputs(rendered, "server" if role == "server" else "client", rendered=True)
    values = template_values()
    registry = registry_configuration(rendered, rendered=True)
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
        "Rendered registry JSON lost bound input/secret reference",
    )
    if role == "server":
        require(
            template_values()["server_image"] + " --host 0.0.0.0 --port 8080" in rendered,
            "Server CLI rendering changed",
        )
    else:
        loadgen_configuration(rendered, rendered=True)
        require(
            '--report-file "/results/report.json"' in rendered, "Loadtest report contract changed"
        )
        require(
            ("systemctl start aegaeon-loadtest.service" in rendered) == enabled,
            "Auto-run conditional changed",
        )


def check_embedded_bash(
    rendered: str, role: str, commands: Commands, bash: str, work: Path
) -> None:
    sections, _ = template_sections(rendered)
    expected = {"/usr/local/bin/aegaeon-docker-login"} | (
        {"/usr/local/bin/aegaeon-run-loadtest"} if role == "loadgen" else set()
    )
    actual = {path for path, body in sections.items() if body.startswith("#!/usr/bin/env bash\n")}
    require(role in {"server", "loadgen"} and actual == expected, "Embedded Bash inventory changed")
    for path in sorted(expected):
        commands.run([bash, "-n"], work, sections[path])


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
                values.update(guest_sources(module))
                values.update(
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
                check_embedded_bash(rendered, role, commands, bash, evaluation)
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
