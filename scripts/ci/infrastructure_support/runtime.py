"""Compose process inputs into the runtime contract and diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from infrastructure_support.authority import (
    nonempty_input,
    process_profiles,
    server_inventory,
    staging_processes,
)
from infrastructure_support.common import (
    BOOTSTRAP_REGION_INPUTS,
    CONTRACT_SOURCES,
    RuntimeContractError,
    digest,
    require,
    validator_sources,
)
from infrastructure_support.delivery import performance_boundary_report, performance_delivery_inputs
from infrastructure_support.hcl import (
    ENV_IDENTIFIER,
    VALUE,
    block,
    expression,
    heredoc_environment,
    strict_matches,
)
from infrastructure_support.templates import (
    perf_loadgen_environment_wiring,
    perf_server_environment_wiring,
    perf_template_bindings,
    registry_helper_wiring,
    source_template,
)

if TYPE_CHECKING:
    from pathlib import Path


def process_inputs(module: Path, root: Path) -> dict[str, dict[str, str]]:
    if module.name == "aegaeon-aws-staging":
        return staging_processes(module)
    if module.name == "perf-aws-ec2":
        perf_template_bindings(module)
        server = source_template(module, "server")
        loadgen = source_template(module, "loadgen")
        perf_server_environment_wiring(server)
        perf_loadgen_environment_wiring(loadgen, rendered=False)
        client_inputs = performance_delivery_inputs(loadgen, "client", root=root)
        registry_helper_wiring(server, "server", rendered=False)
        registry_helper_wiring(loadgen, "loadgen", rendered=False)
        return {
            "server": performance_delivery_inputs(server, "server", root=root),
            "server_registry": heredoc_environment(server, "registry"),
            "loadgen_registry": heredoc_environment(loadgen, "registry"),
            "loadgen": client_inputs,
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


def runtime_contract(module: Path, root: Path) -> dict[str, Any]:
    sources = {path: digest(root / path) for path in CONTRACT_SOURCES}
    sources.update(validator_sources(root))
    allowed, removed, required = server_inventory(root)
    profiles = {**process_profiles(root), "server": (allowed, required)}
    processes = process_inputs(module, root)
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
    report: dict[str, Any] = {
        "status": "failed" if violations else "passed",
        "runtime_sources": sources,
        "processes": {name: sorted(values) for name, values in processes.items()},
        "violations": violations,
        "external_conditions": (
            "Database schema, active managed policy/key readiness, conditional stores and live "
            "connectivity are not established by this static check."
        ),
    }
    report.update(performance_boundary_report(module, sources, report["status"]))
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
