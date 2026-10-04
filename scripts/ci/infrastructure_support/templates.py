"""Performance source template, process/service and argument contracts."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from typing import TYPE_CHECKING, Any

from infrastructure_support.common import DELIVERY_PACKAGE_FIELDS, require
from infrastructure_support.fixtures import (
    LOADTEST_ARTIFACT_FIELDS,
    LOADTEST_CONFIG_FIELDS,
    duplicate_free_object,
    template_values,
)
from infrastructure_support.guest import (
    GUEST_PACKAGE_ROOT,
    source_template as guest_source_template,
)
from infrastructure_support.hcl import block, compact_expression, expression, strict_matches

if TYPE_CHECKING:
    from pathlib import Path


def source_template(module: Path, role: str) -> str:
    return guest_source_template(module, role)


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
                "--env-file /run/aegaeon-supplies/server.env "
                "--entrypoint ${server_entrypoint} ${server_image} "
                "--host 0.0.0.0 --port ${server_port}"
            )
        ],
        "Unsupported server command or environment-file wiring",
    )


SHELL_BODY_SHAPES = {
    "/usr/local/bin/aegaeon-docker-login": {
        "source": "aba0123fbe0d221327d4e961f5f8bb0025c1607fbca6181c34376b8b3619dce6",
        "rendered": "3ea9a5647dd87b675648a1f732a49ec6068b21c10cefe186415b857295d0a6db",
    },
    "/etc/systemd/system/aegaeon-server.service": {
        "source": "2efe69d484aa670f597108dcbb31de088c70c2886c45d00fb10cc4226b788db8",
        "rendered": "2efe69d484aa670f597108dcbb31de088c70c2886c45d00fb10cc4226b788db8",
    },
    "/usr/local/bin/aegaeon-run-loadtest": {
        "source": "6825735514dae1049be0eaf08b3b0bbe8c9d7a11ad73a207cb118230aa150b61",
        "rendered": "46c1d1c7c5aae092a7739a2d2077c8db67022fa84e24cd910067437396c08d31",
    },
    "/etc/systemd/system/aegaeon-loadtest.service": {
        "source": "88e14cd224ed36367fd9e8c904264812d5bf2a3ecb9a6999086f1a58ec80884f",
        "rendered": "88e14cd224ed36367fd9e8c904264812d5bf2a3ecb9a6999086f1a58ec80884f",
    },
}

TEMPLATE_SCAFFOLD_SHAPES = {
    "server-source": "b9ab1c314c7c1a064a80534bb33b9950495b73ff1a5dd95b13eba93e52aba8c1",
    "server-False": "4a9b223327f2382e8eec1ba759cb9e6b7e686ae1772be56ccb6bf607b82f8826",
    "server-True": "4a9b223327f2382e8eec1ba759cb9e6b7e686ae1772be56ccb6bf607b82f8826",
    "loadgen-source": "a546f471af7825c894b8363f364b8a91e2e6f4381deccc04fa3c61533d1859b8",
    "loadgen-False": "076363d630f32cd1046c5eebf02026609e1c6350ab6fd860719a07ff5d20a091",
    "loadgen-True": "86b217d2668321ae6d9d1662c081b93f7eada557f183b480a65e13a8e5597a07",
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
        {
            "/etc/aegaeon/delivery.json",
            "/usr/local/bin/aegaeon-deliver-supplies",
            "/etc/systemd/system/aegaeon-server.service",
        }
        if role == "server"
        else {
            "/etc/aegaeon/loadtest.json",
            "/etc/aegaeon/delivery.json",
            "/usr/local/bin/aegaeon-deliver-supplies",
            "/usr/local/bin/aegaeon-run-loadtest",
            "/etc/systemd/system/aegaeon-loadtest.service",
        }
    )
    expected.update(GUEST_PACKAGE_ROOT + name for name in DELIVERY_PACKAGE_FIELDS.values())
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
        image = template_values()["server_image"] if rendered else "${server_image}"
        entrypoint = template_values()["server_entrypoint"] if rendered else "${server_entrypoint}"
        port = "8080" if rendered else "${server_port}"
        require(
            unit.splitlines().count("ExecStartPre=/usr/local/bin/aegaeon-docker-login " + image)
            == 1,
            "Actual server service must invoke the validated registry helper",
        )
        require(
            unit.splitlines().count(
                "ExecStart=/usr/bin/docker run --rm --name aegaeon-server --network host "
                "--env-file /run/aegaeon-supplies/server.env --entrypoint "
                + entrypoint
                + " "
                + image
                + " --host 0.0.0.0 --port "
                + port
            )
            == 1,
            "Unsupported actual server service command/environment wiring",
        )
        bound = (
            sections[unit_path]
            .replace(image, "${server_image}")
            .replace(entrypoint, "${server_entrypoint}")
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
        "source " not in body
        and "eval " not in body
        and "flock -x 9" in body
        and "aegaeon-deliver-supplies run-config" in body
        and body.index("flock -x 9") < body.index("aegaeon-deliver-supplies run-config"),
        "Load-generator config parsing/whole-invocation lock wiring changed",
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
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--env-file",
        "${SUPPLY_DIR}/client.env",
        "--entrypoint",
        "${LOADTEST_BIN}",
        "-v",
        "${OUT_DIR}:/results",
        "--mount",
        "type=bind,src=${SUPPLY_DIR}/profile.json,dst=/run/aegaeon-inputs/profile.json,readonly",
        "--mount",
        "type=bind,src=${SUPPLY_DIR}/session.txt,dst=/run/aegaeon-inputs/session.txt,readonly",
        "--mount",
        "type=bind,src=${SUPPLY_DIR}/session-provenance.json,dst=/run/aegaeon-inputs/session-provenance.json,readonly",
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
        "delivery_helper": 'file("${path.module}/delivery_helper.py")',
        "delivery_init": 'file("${path.module}/runtime_delivery/__init__.py")',
        "delivery_common": 'file("${path.module}/runtime_delivery/common.py")',
        "delivery_credentials": 'file("${path.module}/runtime_delivery/credentials.py")',
        "delivery_filesystem": 'file("${path.module}/runtime_delivery/filesystem.py")',
        "delivery_artifacts": 'file("${path.module}/runtime_delivery/artifacts.py")',
        "delivery_reports": 'file("${path.module}/runtime_delivery/reports.py")',
        "delivery_metrics": 'file("${path.module}/runtime_delivery/metrics.py")',
        "delivery_orchestration": 'file("${path.module}/runtime_delivery/orchestration.py")',
        "aws_region": "data.aws_region.current.id",
        "server_image": "var.server_image",
        "server_entrypoint": "var.server_entrypoint",
        "issuer_host": "var.issuer_host",
        "issuer_url": "var.issuer_url",
        "server_secret_arn": "var.server_secret_arn",
        "server_secret_version": "var.server_secret_version",
        "server_port": "var.server_port",
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
        "delivery_helper": 'file("${path.module}/delivery_helper.py")',
        "delivery_init": 'file("${path.module}/runtime_delivery/__init__.py")',
        "delivery_common": 'file("${path.module}/runtime_delivery/common.py")',
        "delivery_credentials": 'file("${path.module}/runtime_delivery/credentials.py")',
        "delivery_filesystem": 'file("${path.module}/runtime_delivery/filesystem.py")',
        "delivery_artifacts": 'file("${path.module}/runtime_delivery/artifacts.py")',
        "delivery_reports": 'file("${path.module}/runtime_delivery/reports.py")',
        "delivery_metrics": 'file("${path.module}/runtime_delivery/metrics.py")',
        "delivery_orchestration": 'file("${path.module}/runtime_delivery/orchestration.py")',
        "aws_region": "data.aws_region.current.id",
        "server_image": "var.loadgen_image",
        "loadgen_entrypoint": "var.loadgen_entrypoint",
        "loadgen_artifact_receipt_path": "var.loadgen_artifact_receipt_path",
        "loadgen_artifact_receipt_sha256": "var.loadgen_artifact_receipt_sha256",
        "loadgen_source_manifest_path": "var.loadgen_source_manifest_path",
        "loadgen_source_manifest_sha256": "var.loadgen_source_manifest_sha256",
        "loadgen_executable_sha256": "var.loadgen_executable_sha256",
        "issuer_url": "var.issuer_url",
        "client_secret_arn": "var.client_secret_arn",
        "client_secret_version": "var.client_secret_version",
        "metrics_secret_arn": "var.metrics_secret_arn",
        "metrics_secret_version": "var.metrics_secret_version",
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


def perf_template_bindings(module: Path) -> None:
    source = (module / "instances.tf").read_text()
    for role, expected in PERF_TEMPLATE_BINDINGS.items():
        resource = block(source, f'resource "aws_instance" "{role}"')
        names = re.findall(r"(?m)^\s*(user_data(?:_base64)?)\s*=", resource)
        require(names == ["user_data_base64"], "Changed active EC2 userdata ownership")
        value = expression(resource, "user_data_base64")
        header = 'base64gzip(templatefile("${path.module}/user_data_' + role + '.sh.tftpl",'
        require(
            value.startswith(header) and value.endswith("}))"),
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


def loadgen_configuration(template: str, *, rendered: bool) -> dict[str, Any]:
    sections, _ = template_sections(template)
    config = sections.get("/etc/aegaeon/loadtest.json", "").strip()
    if not rendered:
        fields = [
            name
            + " = "
            + ("tostring(" + field + ")" if name in {"WORKERS", "RPS", "WARMUP"} else field)
            for name, field in LOADTEST_CONFIG_FIELDS.items()
        ]
        artifact = ", ".join(
            name + " = " + field for name, field in LOADTEST_ARTIFACT_FIELDS.items()
        )
        expected_source = (
            "${jsonencode({" + ", ".join(fields) + ", artifact = {" + artifact + "}})}"
        )
        require(config == expected_source, "Loadgen config lost bound input")
        return {}
    parsed = json.loads(config, object_pairs_hook=duplicate_free_object)
    values = template_values()
    expected: dict[str, Any] = {
        name: str(values[field]) for name, field in LOADTEST_CONFIG_FIELDS.items()
    }
    expected["artifact"] = {name: values[field] for name, field in LOADTEST_ARTIFACT_FIELDS.items()}
    require(parsed == expected, "Rendered loadtest config lost bound input")
    return dict(parsed)
