"""Inventory must not report counts after redis-cli connection setup errors."""

from __future__ import annotations

import collections
import json
import subprocess
from unittest.mock import Mock, patch

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


def record_time(seconds=100, nanos=500):
    return {"secs_since_epoch": seconds, "nanos_since_epoch": nanos}


@pytest.mark.parametrize("kind", ["refresh", "bearer"])
def test_inventory_counts_legacy_presence_and_exact_expiry(kind):
    prefix = "fixture:v3:tokens"
    records = {
        "live": {"expires_at": record_time(nanos=501), "refresh_parent": "parent"},
        "null": {"expires_at": record_time(nanos=501), "refresh_grant": None},
        "expired": {"expires_at": record_time(nanos=499)},
        "boundary": {"expires_at": record_time()},
        "modern": {"expires_at": record_time(nanos=501), "refresh_grant": {"id": "new"}},
        "unsupported": {"expires_at": record_time(nanos=501), "refresh_grant": {}},
        "missing": None,
        "no-expiry": {},
        "bad-expiry": {"expires_at": record_time(seconds=True)},
    }
    rows = {f"{prefix}:{kind}:{name}": value for name, value in records.items()}
    reader = Mock(spec=inventory.RedisReader)
    reader.keys.return_value = list(rows)
    reader.record.side_effect = rows.get
    counts = collections.Counter()
    inventory.count_records(reader, prefix, kind, 100_000_000_500, counts)
    expected = {
        f"{kind}_records": 9,
        f"{kind}_missing_or_malformed": 3,
        f"{kind}_without_reference": 4,
        f"{kind}_live_without_reference": 2,
    }
    if kind == "bearer":
        expected["live_legacy_dependent_bearer_records"] = 1
        assert (f"{prefix}:access:live",) in [call.args for call in reader.record.call_args_list]
    assert dict(counts) == expected
    reader.keys.assert_called_once_with(f"{prefix}:{kind}:*")


@pytest.mark.parametrize(
    ("access", "extra_counts"),
    [
        (None, {}),
        ({}, {"dependent_access_malformed_expiry": 1}),
        (
            {"created_at": record_time(), "expires_in": True},
            {"dependent_access_malformed_expiry": 1},
        ),
        ({"created_at": record_time(), "expires_in": -1}, {"dependent_access_malformed_expiry": 1}),
        (
            {"created_at": record_time(), "expires_in": "1"},
            {"dependent_access_malformed_expiry": 1},
        ),
        (
            {"created_at": record_time(nanos=1_000_000_000), "expires_in": 1},
            {"dependent_access_malformed_expiry": 1},
        ),
        (
            {"created_at": record_time(seconds=99, nanos=501), "expires_in": 1},
            {"live_legacy_dependent_access_records": 1},
        ),
        ({"created_at": record_time(seconds=99), "expires_in": 1}, {}),
        ({"created_at": record_time(seconds=99, nanos=499), "expires_in": 1}, {}),
        (
            {"created_at": record_time(nanos=501), "expires_in": 0},
            {"live_legacy_dependent_access_records": 1},
        ),
    ],
)
def test_inventory_correlates_dependent_access_and_exact_lifetime(access, extra_counts):
    reader = Mock(spec=inventory.RedisReader)
    reader.record.return_value = access
    counts = collections.Counter()
    inventory.count_dependent_access(
        reader, "fixture:bearer:token:bearer:suffix", "fixture", 100_000_000_500, counts
    )
    expected = {"live_legacy_dependent_bearer_records": 1, **extra_counts}
    if access is not None:
        expected["live_legacy_dependent_bearer_with_access_record"] = 1
    assert dict(counts) == expected
    reader.record.assert_called_once_with("fixture:access:token:bearer:suffix")


def test_inventory_main_counts_drained_records_without_token_output(monkeypatch, capsys):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    monkeypatch.setattr("sys.argv", ["inventory", "--prefix", "fixture"])
    expiry = record_time(seconds=101)
    replies = [
        ["100", "0"],
        [
            "0",
            [
                "fixture:refresh:private-refresh",
                "fixture:refresh:private-refresh",
                "fixture:refresh:broken",
            ],
        ],
        json.dumps({"expires_at": expiry}),
        "not-json-private-record",
        [
            "0",
            [
                "fixture:bearer:private-access",
                "fixture:bearer:missing-access",
                "fixture:bearer:not-object",
            ],
        ],
        json.dumps({"expires_at": expiry, "refresh_parent": "private-refresh"}),
        json.dumps({"created_at": record_time(), "expires_in": 1}),
        json.dumps({"expires_at": expiry, "refresh_parent": "private-refresh"}),
        None,
        "[]",
    ]
    with patch.object(inventory.RedisReader, "read", side_effect=replies) as read:
        inventory.main()
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "scope": inventory.SCOPE,
        "redis_time_seconds": 100,
        "counts": {
            "refresh_records": 2,
            "refresh_missing_or_malformed": 1,
            "refresh_without_reference": 1,
            "refresh_live_without_reference": 1,
            "bearer_records": 3,
            "bearer_missing_or_malformed": 1,
            "bearer_without_reference": 2,
            "bearer_live_without_reference": 2,
            "live_legacy_dependent_bearer_records": 2,
            "live_legacy_dependent_bearer_with_access_record": 1,
            "live_legacy_dependent_access_records": 1,
        },
    }
    assert "private" not in output
    assert "fixture" not in output
    assert {call.args[0] for call in read.call_args_list} == {"TIME", "SCAN", "GET"}
    assert read.call_count == len(replies)


def test_inventory_suppresses_partial_counts_after_late_read_failure(monkeypatch, capsys):
    monkeypatch.setenv("AEGAEON_TOKEN_STORE_REDIS_URL", "redis://127.0.0.1:6379/13")
    monkeypatch.setattr("sys.argv", ["inventory", "--prefix", "fixture"])
    replies = [
        ["100", "0"],
        ["0", ["fixture:refresh:token"]],
        json.dumps({"expires_at": record_time(seconds=101)}),
        RuntimeError("Redis read failed; no complete inventory was produced"),
    ]
    with (
        patch.object(inventory.RedisReader, "read", side_effect=replies),
        pytest.raises(RuntimeError, match="no complete inventory was produced"),
    ):
        inventory.main()
    assert capsys.readouterr().out == ""
