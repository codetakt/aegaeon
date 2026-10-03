"""Inventory must not report counts after redis-cli connection setup errors."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest
from scripts.operations import count_legacy_refresh_grants as inventory


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (0, b'["123", "456"]', b"SELECT 13 failed: NOPERM"),
        (0, b'["123", "456"]', b"AUTH failed: WRONGPASS"),
        (0, b'["123", "456"]', b"connection warning"),
        (1, b'["123", "456"]', b""),
        (1, b"", b"command failed"),
        (0, b'error:"NOPERM"', b""),
        (0, b"", b""),
    ],
)
def test_inventory_rejects_incomplete_cli_output(monkeypatch, returncode, stdout, stderr):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    result = subprocess.CompletedProcess([], returncode, stdout, stderr)
    with (
        patch.object(inventory.subprocess, "run", return_value=result),
        pytest.raises(
            RuntimeError, match=r"^Redis read failed; no complete inventory was produced$"
        ),
    ):
        inventory.RedisReader().read("TIME")


def test_inventory_accepts_clean_json_and_requests_command_error_exit(monkeypatch):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    result = subprocess.CompletedProcess([], 0, b'["123", "456"]', b"")
    with patch.object(inventory.subprocess, "run", return_value=result) as run:
        assert inventory.RedisReader().read("TIME") == ["123", "456"]
    argv = run.call_args.args[0]
    assert "-e" in argv
    assert "--no-auth-warning" in argv
    assert argv[argv.index("-n") + 1] == "13"
    assert argv[-1] == "TIME"
