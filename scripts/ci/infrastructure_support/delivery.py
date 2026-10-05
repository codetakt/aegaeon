"""Strict delivery-helper and external consumer interface contracts."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from infrastructure_support.common import (
    DELIVERY_BODY_SHA256,
    DELIVERY_PACKAGE_SHA256,
    MODULE_ROOT,
    PERFORMANCE_CLIENT_NAMES,
    PERFORMANCE_CONFIG_NAMES,
    PERFORMANCE_REDIS_NAMES,
    VALIDATOR_SUPPORT_PATHS,
    digest,
    require,
)
from infrastructure_support.fixtures import duplicate_free_object, template_values
from infrastructure_support.guest import guest_sections
from infrastructure_support.templates import (
    loadgen_configuration,
    semantic_shell_shape,
    source_template,
    template_sections,
)

if TYPE_CHECKING:
    from pathlib import Path


def delivery_assignment(tree: ast.AST, name: str) -> ast.expr:
    values = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    require(len(values) == 1, f"Expected one strict delivery assignment: {name}")
    return values[0]


def performance_consumer_interface(template: str) -> dict[str, Any]:
    """Describe the external interface enforced by the exact reviewed helper.

    The body pin binds all parser, version, source, typed-value and argv checks.
    Literal extraction keeps the public descriptor tied to its actual input maps;
    it does not execute the helper or authenticate an external build or artifact.
    """
    sections, _ = template_sections(template)
    helper = sections.get("/usr/local/bin/aegaeon-deliver-supplies", "")
    helper_sha256 = hashlib.sha256(helper.encode()).hexdigest()
    require(helper_sha256 == DELIVERY_BODY_SHA256, "Changed strict runtime supply executable")
    package = guest_sections(sections)
    trees = {name: ast.parse(body) for name, body in package.items()}
    functions = {
        node.name: node
        for name in ("orchestration.py", "reports.py")
        for node in trees[name].body
        if isinstance(node, ast.FunctionDef)
    }
    environment = delivery_assignment(functions["refresh_client"], "env")
    if not isinstance(environment, ast.Dict):
        raise ValueError("Changed external consumer environment map")  # noqa: TRY004 - invalid source shape
    names = [ast.literal_eval(key) for key in environment.keys if key is not None]
    require(
        len(names) == len(PERFORMANCE_CLIENT_NAMES) and set(names) == set(PERFORMANCE_CLIENT_NAMES),
        "Changed external consumer exact five process inputs",
    )
    config_names = ast.literal_eval(
        delivery_assignment(functions["validate_config_witness"], "keys")
    )
    require(
        config_names == set(PERFORMANCE_CONFIG_NAMES),
        "Changed external consumer exact eight producer config fields",
    )
    return {
        "authority": "Normative external artifact delivery interface",
        "helper_sha256": helper_sha256,
        "package_sha256": dict(DELIVERY_PACKAGE_SHA256),
        "required_and_permitted_environment": sorted(names),
        "artifact_receipt_version": 1,
        "report": {
            "schema_version": 2,
            "max_bytes": ast.literal_eval(
                delivery_assignment(trees["filesystem.py"], "MAX_REPORT_BYTES")
            ),
            "request_unit": "scenario_invocations",
            "memory_subject": "load_generator_process",
            "config_fields": sorted(config_names),
            "discovery_expected_issuer": "required null for this driver",
            "config_witness": "Exact UTF-8 config_json/hash; strict typed fields and argv binding",
        },
        "source_manifest": {
            "domain": "Complete independently frozen external tracked inventory",
            "required_paths": list(
                ast.literal_eval(
                    delivery_assignment(trees["artifacts.py"], "REQUIRED_SOURCE_INPUTS")
                )
            ),
            "pins": "Raw source/receipt/executable/image/entrypoint/build/locks/native closure",
        },
        "external_artifact_interface_runtime": {
            "status": "required_not_observed",
            "premise": (
                "Independently trusted producer; consistency does not authenticate source-to-binary"
            ),
            "scope": (
                "Actual artifacts, build/OCI/interface, client/session supplies, "
                "runtime and performance"
            ),
        },
    }


def performance_boundary_report(
    module: Path, sources: dict[str, str], status: str
) -> dict[str, Any]:
    if module.name != "perf-aws-ec2":
        return {}
    boundary_sources = {
        str(MODULE_ROOT / module.name / name): digest(module / name)
        for name in (
            "user_data_server.sh.tftpl",
            "user_data_loadgen.sh.tftpl",
            "delivery_helper.py",
            "README.md",
            *("runtime_delivery/" + name for name in DELIVERY_PACKAGE_SHA256),
        )
    }
    sources.update(boundary_sources)
    return {
        "external_consumer": {
            **performance_consumer_interface(source_template(module, "loadgen")),
            "static_delivery_wiring": status,
            "interface_sources": {
                "scripts/ci/validate_infrastructure.py": sources[
                    "scripts/ci/validate_infrastructure.py"
                ],
                **{path: sources[path] for path in VALIDATOR_SUPPORT_PATHS},
                **boundary_sources,
            },
        }
    }


def performance_delivery_inputs(
    template: str, profile: str, *, root: Path | None = None, rendered: bool = False
) -> dict[str, str]:
    sections, _ = template_sections(template)
    path = "/usr/local/bin/aegaeon-deliver-supplies"
    require(path in sections, "Missing runtime supply executable")
    performance_consumer_interface(template)
    fields = (
        (
            "region",
            "issuer_host",
            "issuer_url",
            "trusted_proxies",
            "server_secret_arn",
            "server_secret_version",
        )
        if profile == "server"
        else (
            "region",
            "issuer_url",
            "client_secret_arn",
            "client_secret_version",
            "metrics_secret_arn",
            "metrics_secret_version",
        )
    )
    config = sections.get("/etc/aegaeon/delivery.json", "").strip()
    if rendered:
        parsed = json.loads(config, object_pairs_hook=duplicate_free_object)
        expected = {
            key: template_values()["aws_region" if key == "region" else key] for key in fields
        }
        require(parsed == expected, "Rendered delivery inputs changed")
    else:
        expected_source = (
            "${jsonencode({"
            + ", ".join(key + " = " + ("aws_region" if key == "region" else key) for key in fields)
            + "})}"
        )
        require(config == expected_source, "Unbound runtime bundle identifiers or selector")
    if root is not None:
        inventory = (
            root / "crates/server/src/config/runtime_boundary/shared_store/inventory.rs"
        ).read_text()
        actual = set(re.findall(r'"(AEGAEON_[A-Z_]+_REDIS_URL)"', inventory))
        require(actual == set(PERFORMANCE_REDIS_NAMES), "Runtime supply Redis authority changed")

    if profile == "server":
        unit = semantic_shell_shape(
            sections["/etc/systemd/system/aegaeon-server.service"], rendered=rendered
        )
        require(
            unit.splitlines().count("ExecStartPre=/usr/bin/python3 -I -B " + path + " server") == 1,
            "Server supply refresh must precede launch",
        )
        return dict.fromkeys(
            (
                *PERFORMANCE_REDIS_NAMES,
                "AEGAEON_DATABASE_URL",
                "AEGAEON_KEY_ENCRYPTION_KEY",
                "AEGAEON_RUNTIME_ISSUER_HOST",
                "AEGAEON_TRUSTED_PROXIES",
            ),
            "runtime-pinned-bundle",
        )
    loadgen_configuration(template, rendered=rendered)
    driver = semantic_shell_shape(
        sections["/usr/local/bin/aegaeon-run-loadtest"], rendered=rendered
    )
    require(
        driver.splitlines().count(
            "/usr/bin/python3 -I -B " + path + ' client "$SUPPLY_DIR" "$SOURCE_SHA256"'
        )
        == 1
        and path + " run-config" in driver
        and "docker run " in driver
        and driver.index(path + " run-config")
        < driver.index(path + " client")
        < driver.index("docker run "),
        "Client supply refresh must precede launch",
    )
    return dict.fromkeys(PERFORMANCE_CLIENT_NAMES, "runtime-pinned-bundle")
