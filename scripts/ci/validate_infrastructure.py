#!/usr/bin/env python3
"""Validate repository OpenTofu modules without cloud credentials or deployment.

This checks static provider compatibility and explicit configuration contracts.
It does not read deployed state, plan changes, or establish deployment safety."""

# ruff: noqa: E402 - fixed physical sibling imports support isolated Python
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from infrastructure_support.authority import (
    bootstrap_region_inputs,
    ecs_process_inputs,
    nonempty_input,
    process_profiles,
    required_server_inputs,
    server_inventory,
    staging_processes,
    task_container,
)
from infrastructure_support.commands import (
    Commands,
    isolated_environment,
)
from infrastructure_support.common import (
    BOOTSTRAP_REGION_INPUTS,
    COMMAND_TIMEOUT,
    CONTRACT_SOURCES,
    DELIVERY_BODY_SHA256,
    DELIVERY_PACKAGE_FIELDS,
    DELIVERY_PACKAGE_SHA256,
    MODULE_ROOT,
    MODULES,
    PERFORMANCE_CLIENT_NAMES,
    PERFORMANCE_CONFIG_NAMES,
    PERFORMANCE_REDIS_NAMES,
    RuntimeContractError,
    digest,
    require,
)
from infrastructure_support.delivery import (
    delivery_assignment,
    performance_boundary_report,
    performance_consumer_interface,
    performance_delivery_inputs,
)
from infrastructure_support.fixtures import (
    LOADTEST_ARTIFACT_FIELDS,
    LOADTEST_CONFIG_FIELDS,
    duplicate_free_object,
    template_values,
)
from infrastructure_support.hcl import (
    ENV_IDENTIFIER,
    EXPRESSION_TOKEN,
    REFERENCE,
    STRING,
    TOKEN,
    VALUE,
    assignment,
    block,
    combined,
    compact_expression,
    environment_objects,
    expression,
    heredoc_environment,
    quoted_names,
    strict_matches,
    top_level,
    top_level_position,
    uncomment,
)
from infrastructure_support.orchestration import (
    main,
    toolchain_provenance,
    validate_module,
)
from infrastructure_support.provider import (
    initialize_providers,
    installed_providers,
    lock_contract,
    resource_contract,
    validate_schema,
)
from infrastructure_support.rendering import (
    check_embedded_bash,
    check_support,
    check_templates,
    rendered_contract,
)
from infrastructure_support.runtime import (
    process_inputs,
    runtime_contract,
    runtime_contract_report,
)
from infrastructure_support.selection import (
    SUPPORT_PATHS,
    module_inputs,
    select_modules,
)
from infrastructure_support.templates import (
    PERF_TEMPLATE_BINDINGS,
    SHELL_BODY_SHAPES,
    SHELL_HEREDOC,
    TEMPLATE_SCAFFOLD_SHAPES,
    active_shape,
    loadgen_configuration,
    perf_loadgen_environment_wiring,
    perf_server_environment_wiring,
    perf_template_bindings,
    registry_helper_wiring,
    require_body_shape,
    reviewed_template_sections,
    semantic_shell_shape,
    source_template,
    template_sections,
)

__all__ = [
    "BOOTSTRAP_REGION_INPUTS",
    "COMMAND_TIMEOUT",
    "CONTRACT_SOURCES",
    "DELIVERY_BODY_SHA256",
    "DELIVERY_PACKAGE_FIELDS",
    "DELIVERY_PACKAGE_SHA256",
    "ENV_IDENTIFIER",
    "EXPRESSION_TOKEN",
    "LOADTEST_ARTIFACT_FIELDS",
    "LOADTEST_CONFIG_FIELDS",
    "MODULES",
    "MODULE_ROOT",
    "PERFORMANCE_CLIENT_NAMES",
    "PERFORMANCE_CONFIG_NAMES",
    "PERFORMANCE_REDIS_NAMES",
    "PERF_TEMPLATE_BINDINGS",
    "REFERENCE",
    "SHELL_BODY_SHAPES",
    "SHELL_HEREDOC",
    "STRING",
    "SUPPORT_PATHS",
    "TEMPLATE_SCAFFOLD_SHAPES",
    "TOKEN",
    "VALUE",
    "Commands",
    "RuntimeContractError",
    "active_shape",
    "assignment",
    "block",
    "bootstrap_region_inputs",
    "check_embedded_bash",
    "check_support",
    "check_templates",
    "combined",
    "compact_expression",
    "delivery_assignment",
    "digest",
    "duplicate_free_object",
    "ecs_process_inputs",
    "environment_objects",
    "expression",
    "heredoc_environment",
    "initialize_providers",
    "installed_providers",
    "isolated_environment",
    "loadgen_configuration",
    "lock_contract",
    "main",
    "module_inputs",
    "nonempty_input",
    "perf_loadgen_environment_wiring",
    "perf_server_environment_wiring",
    "perf_template_bindings",
    "performance_boundary_report",
    "performance_consumer_interface",
    "performance_delivery_inputs",
    "process_inputs",
    "process_profiles",
    "quoted_names",
    "registry_helper_wiring",
    "rendered_contract",
    "require",
    "require_body_shape",
    "required_server_inputs",
    "resource_contract",
    "reviewed_template_sections",
    "runtime_contract",
    "runtime_contract_report",
    "select_modules",
    "semantic_shell_shape",
    "server_inventory",
    "source_template",
    "staging_processes",
    "strict_matches",
    "task_container",
    "template_sections",
    "template_values",
    "toolchain_provenance",
    "top_level",
    "top_level_position",
    "uncomment",
    "validate_module",
    "validate_schema",
]

if __name__ == "__main__":
    raise SystemExit(main())
