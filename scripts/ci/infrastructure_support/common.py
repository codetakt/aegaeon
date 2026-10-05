"""Shared fail-closed guards, source closure and reviewed runtime data."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

MODULE_ROOT = PurePosixPath("infra/tofu")

MODULES = ("aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2")

COMMAND_TIMEOUT = 300


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - predicate guard
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


CONTRACT_SOURCES: tuple[str, ...] = (
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


class RuntimeContractError(ValueError):
    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        super().__init__(
            "Runtime environment contract rejected: " + json.dumps(report["violations"])
        )


DELIVERY_BODY_SHA256 = "61b83c3337795dc90a696eefc15c9c640be528a0fab763720069f84e97f6ff0f"

DELIVERY_PACKAGE_FIELDS = {
    "delivery_init": "__init__.py",
    "delivery_common": "common.py",
    "delivery_credentials": "credentials.py",
    "delivery_filesystem": "filesystem.py",
    "delivery_artifacts": "artifacts.py",
    "delivery_reports": "reports.py",
    "delivery_metrics": "metrics.py",
    "delivery_orchestration": "orchestration.py",
}

DELIVERY_PACKAGE_SHA256 = {
    "__init__.py": "a93ecaebc51890db496fda2b5557cb8c510029ef19ae223ca2c0795a78a550d5",
    "common.py": "8fa8adf78bf204df2a16a50cf99909e665e6218da15ff3efbc132bec7bc4b8d5",
    "credentials.py": "46e960c505598bb2d0ad68dfb2cf6719d449822199a7ca62d630e81c35c59de1",
    "filesystem.py": "2c5cc6c6f2d3c7e71f0e69810d5bd7796c09a10153554caf08d298beb4462901",
    "artifacts.py": "495c96705a96d58935f4004f93c9a3d8dfaca190e7bb665afd792f8c1a1ecdaa",
    "reports.py": "a4a8d14c4ab14d88b5e2d8f802e7b61c5bfb3126c9bce8b3c4f3f49386fe75b3",
    "metrics.py": "30efa2e1a66585e2dc85c1147b25244d96249062d3d6e5ccf58ef5c01d53fe1f",
    "orchestration.py": "42d11b1b90d5fe428c564829b6a8e17aee96034ceb9fa6523d71a1e2bda3f0b7",
}

PERFORMANCE_REDIS_NAMES = (
    "AEGAEON_PAR_REDIS_URL",
    "AEGAEON_AUTH_CODE_REDIS_URL",
    "AEGAEON_TOKEN_STORE_REDIS_URL",
    "AEGAEON_DPOP_REDIS_URL",
    "AEGAEON_JWKS_REDIS_URL",
    "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
    "AEGAEON_AUTH_SESSION_REDIS_URL",
    "AEGAEON_DEVICE_CODE_REDIS_URL",
    "AEGAEON_DEVICE_CSRF_REDIS_URL",
    "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
    "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
    "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_STEPUP_REDIS_URL",
    "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
    "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
    "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
    "AEGAEON_DPOP_NONCE_REDIS_URL",
    "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
    "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
)

PERFORMANCE_CLIENT_NAMES = (
    "AEG_LOADTEST_CLIENT_SECRET",
    "AEG_LOADTEST_PROFILE_MANIFEST",
    "AEG_LOADTEST_SESSION_FILE",
    "AEG_LOADTEST_SESSION_PROVENANCE",
    "AEG_LOADTEST_SOURCE_SHA256",
)

PERFORMANCE_CONFIG_NAMES = (
    "target_url",
    "discovery_expected_issuer",
    "workers",
    "duration",
    "target_rps",
    "warmup_duration",
    "scenario",
    "debug",
)

BOOTSTRAP_REGION_INPUTS = ("AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", "AWS_REGION")


RUNNER_PATH = Path(__file__).resolve().parent.parent / "validate_infrastructure.py"
VALIDATOR_SUPPORT_PATHS = (
    "scripts/ci/infrastructure_support/__init__.py",
    "scripts/ci/infrastructure_support/common.py",
    "scripts/ci/infrastructure_support/hcl.py",
    "scripts/ci/infrastructure_support/selection.py",
    "scripts/ci/infrastructure_support/authority.py",
    "scripts/ci/infrastructure_support/fixtures.py",
    "scripts/ci/infrastructure_support/guest.py",
    "scripts/ci/infrastructure_support/templates.py",
    "scripts/ci/infrastructure_support/delivery.py",
    "scripts/ci/infrastructure_support/runtime.py",
    "scripts/ci/infrastructure_support/commands.py",
    "scripts/ci/infrastructure_support/provider.py",
    "scripts/ci/infrastructure_support/rendering.py",
    "scripts/ci/infrastructure_support/orchestration.py",
)
CONTRACT_SOURCES += VALIDATOR_SUPPORT_PATHS


def validator_sources(root: Path) -> dict[str, str]:
    """Bind the selected repository closure to the fixed, executing validator."""
    sources = {}
    for name in ("scripts/ci/validate_infrastructure.py", *VALIDATOR_SUPPORT_PATHS):
        declared = root / name
        physical = RUNNER_PATH.resolve().parents[2] / name
        require(
            declared.is_file() and not declared.is_symlink(),
            "Missing validator source: " + name,
        )
        require(
            physical.is_file() and not physical.is_symlink(),
            "Missing physical validator source: " + name,
        )
        observed = digest(physical)
        require(
            digest(declared) == observed, "Validator source differs from executing code: " + name
        )
        sources[name] = observed
    return sources
