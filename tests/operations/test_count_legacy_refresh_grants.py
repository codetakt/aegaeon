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


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {},
        [],
        ["0"],
        ["0", [], "extra"],
        ["0", "abc"],
        ["0", {"key": 1}],
        ["0", None],
        ["0", [None]],
        ["0", [1]],
        ["0", [True]],
        ["0", [[]]],
        ["0", ["valid", 7]],
        [0, []],
        [False, []],
        [None, []],
        ["", []],
        ["-1", []],
        ["+1", []],
        ["1.0", []],
        [" 0", []],
        ["\uff10", []],
        [str(1 << 64), []],
        ["1" * 100, []],
    ],
)
def test_inventory_rejects_malformed_scan_before_get_or_count_output(monkeypatch, capsys, reply):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    monkeypatch.setattr("sys.argv", ["inventory", "--prefix", "fixture"])
    with (
        patch.object(inventory.RedisReader, "read", side_effect=[["100", "0"], reply]) as read,
        pytest.raises(RuntimeError, match=r"^Malformed SCAN response; inventory incomplete$"),
    ):
        inventory.main()
    assert [call.args[0] for call in read.call_args_list] == ["TIME", "SCAN"]
    assert capsys.readouterr().out == ""


def test_inventory_scan_preserves_cursor_pages_and_deduplicates_keys(monkeypatch):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    cursor = str((1 << 64) - 1)
    replies = [[cursor, ["first", "first"]], ["1", []], ["0", ["first", "last"]]]
    with patch.object(inventory.RedisReader, "read", side_effect=replies) as read:
        assert list(inventory.RedisReader().keys("fixture:*")) == ["first", "last"]
    assert [call.args[1] for call in read.call_args_list] == ["0", cursor, "1"]


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {},
        [],
        ["0"],
        ["0", "0", "extra"],
        [False, False],
        [1.5, 0],
        [1, "0"],
        ["0", 1],
        ["", "0"],
        ["-1", "0"],
        ["+1", "0"],
        [" 1", "0"],
        ["1 ", "0"],
        ["1.5", "0"],
        ["01", "0"],
        ["\uff11", "0"],
        ["0", "-1"],
        ["0", "+1"],
        ["0", " 1"],
        ["0", "1 "],
        ["0", "1.5"],
        ["0", "00"],
        ["0", "\uff11"],
        ["0", "1000000"],
        [str(1 << 63), "0"],
        ["1" * 100, "0"],
        ["0", "1" * 100],
    ],
)
def test_inventory_rejects_malformed_time_before_scan_or_count_output(monkeypatch, capsys, reply):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    monkeypatch.setattr("sys.argv", ["inventory", "--prefix", "fixture"])
    with (
        patch.object(inventory.RedisReader, "read", return_value=reply) as read,
        pytest.raises(RuntimeError, match=r"^Malformed TIME response; inventory incomplete$"),
    ):
        inventory.main()
    assert [call.args for call in read.call_args_list] == [("TIME",)]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (["0", "0"], (0, 0)),
        (["123", "456"], (123, 123_000_456_000)),
        (["123", "999999"], (123, 123_999_999_000)),
        ([str((1 << 63) - 1), "0"], ((1 << 63) - 1, ((1 << 63) - 1) * 1_000_000_000)),
    ],
)
def test_inventory_time_preserves_exact_seconds_and_microseconds(reply, expected):
    assert inventory.time_reply(reply) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("redis://127.0.0.1:6379/13", None),
        ("redis://reader:url%2Dpassword@127.0.0.1:6379/13", "url-password"),
        ("redis://reader:@127.0.0.1:6379/13", ""),
        ("redis://:url%2Dpassword@127.0.0.1:6379/13", "url-password"),
    ],
)
def test_inventory_url_exclusively_controls_authentication(monkeypatch, url, expected):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", url)
    monkeypatch.setenv("REDISCLI_AUTH", "unrelated-ambient-credential")
    monkeypatch.setenv("LANG", "C.UTF-8")
    command, env = inventory.connection()
    assert env.get("REDISCLI_AUTH") == expected
    assert env["LANG"] == "C.UTF-8"
    assert "unrelated-ambient-credential" not in command


@pytest.mark.parametrize("scheme", ["redis", "rediss"])
def test_inventory_named_user_cannot_fall_back_to_default_account(monkeypatch, capsys, scheme):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", f"{scheme}://reader@127.0.0.1:6379/13")
    monkeypatch.setattr("sys.argv", ["inventory", "--prefix", "fixture"])
    with (
        patch.object(inventory.subprocess, "run") as run,
        pytest.raises(ValueError, match=r"^Redis URL username requires an explicit password"),
    ):
        inventory.main()
    run.assert_not_called()
    assert capsys.readouterr().out == ""
