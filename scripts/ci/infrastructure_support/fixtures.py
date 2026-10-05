"""Reviewed static rendering fixtures and exact configuration field maps."""

from __future__ import annotations

from typing import Any

from infrastructure_support.common import require


def template_values() -> dict[str, Any]:
    return {
        "aws_region": "us-east-1",
        "server_image": "registry.example/aegaeon@sha256:" + "a" * 64,
        "server_entrypoint": "/bin/aegaeon-server",
        "loadgen_entrypoint": "/bin/aegaeon-loadtest",
        "loadgen_artifact_receipt_path": "/etc/aegaeon/artifacts/loadtest-receipt.json",
        "loadgen_artifact_receipt_sha256": "c" * 64,
        "loadgen_source_manifest_path": "/etc/aegaeon/artifacts/SOURCE-MANIFEST.json",
        "loadgen_source_manifest_sha256": "d" * 64,
        "loadgen_executable_sha256": "e" * 64,
        "issuer_host": "issuer.example.com",
        "issuer_url": "https://issuer.example.com",
        "server_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:server",
        "server_secret_version": "a" * 32,
        "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:client",
        "client_secret_version": "b" * 32,
        "metrics_secret_arn": "",
        "metrics_secret_version": "",
        "server_port": 8080,
        "trusted_proxies": "127.0.0.1/32",
        "ghcr_auth_enabled": True,
        "ghcr_username": "fixture",
        "ghcr_token_ssm_parameter_name": "/aegaeon/registry-token",
        "ghcr_token_secretsmanager_secret": "",
        "server_url": "https://issuer.example.com",
        "artifact_bucket": "aegaeon-fixture",
        "artifact_prefix": "ci/",
        "auto_run_loadtest": True,
        "workers": 2,
        "rps": 10,
        "run_time": "10s",
        "warmup": "1s",
        "scenario": "smoke",
    }


def duplicate_free_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        require(name not in result, "Duplicate bound input field")
        result[name] = value
    return result


LOADTEST_CONFIG_FIELDS = {
    "SERVER_URL": "server_url",
    "SERVER_IMAGE": "server_image",
    "ARTIFACT_BUCKET": "artifact_bucket",
    "ARTIFACT_PREFIX": "artifact_prefix",
    "WORKERS": "workers",
    "RPS": "rps",
    "RUN_TIME": "run_time",
    "WARMUP": "warmup",
    "SCENARIO": "scenario",
    "LOADTEST_BIN": "loadgen_entrypoint",
}

LOADTEST_ARTIFACT_FIELDS = {
    "receipt_path": "loadgen_artifact_receipt_path",
    "receipt_sha256": "loadgen_artifact_receipt_sha256",
    "source_manifest_path": "loadgen_source_manifest_path",
    "source_manifest_sha256": "loadgen_source_manifest_sha256",
    "executable_sha256": "loadgen_executable_sha256",
}
