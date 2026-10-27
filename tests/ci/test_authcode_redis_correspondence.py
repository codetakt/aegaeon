# ruff: noqa: PT009, PT027 - unittest assertions must also run with Python -O
"""Reject Redis observations that a Rust children decoder would not accept."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/validation"
sys.path.insert(0, str(SCRIPTS))
from authcode_redis_fixtures import (  # noqa: E402
    FIXTURE,
    GRANT_SOURCE,
    LUA_SOURCE,
    expired_in_window,
    load_cases,
    lua_script,
)

spec = importlib.util.spec_from_file_location(
    "redis_grant_correspondence", SCRIPTS / "check_authcode_redis_grant.py"
)
assert spec is not None
assert spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ObservationConnection:
    def __init__(self, payload):
        self.payload = payload
        self.commands = []

    def command(self, *parts):
        self.commands.append(parts)
        return {
            "KEYS": ["t:children:r"],
            "TYPE": "string",
            "PEXPIRETIME": -1,
            "GET": self.payload,
            "INFO": "process_id:wrong\r\nrun_id:foreign\r\n",
        }[parts[0]]


class RedisCorrespondenceTests(unittest.TestCase):
    def test_complete_production_envelope_is_required(self):
        source, grant = LUA_SOURCE.read_text(), GRANT_SOURCE.read_text()
        script = lua_script(source, grant)
        self.assertLess(
            script.index("local function commit_refresh_grant()"), script.index("local write_types")
        )
        for bad_source, bad_grant in [
            (
                source.replace("GrantCommit::script(COMMIT_AUTHORIZATION_CODE_GRANT)", "other()"),
                grant,
            ),
            (source, grant.replace("{PREPARE}\\n{body}", "{body}\\n{PREPARE}")),
        ]:
            with self.subTest(source=bad_source == source), self.assertRaises(ValueError):
                lua_script(bad_source, bad_grant)

    def test_old_argument_plan_is_rejected(self):
        fixture = json.loads(FIXTURE.read_text())
        fixture["cases"][0]["requests"][0]["args"] = ["0"] * 21
        with self.assertRaises(ValueError):
            load_cases(json.dumps(fixture).encode())

    def test_clock_window_requires_a_constant_deadline_decision(self):
        request = copy.deepcopy(load_cases()[0]["requests"][0])
        request["args"][27:29] = ["2", "500"]
        for window, expected in [
            ([1_000_000_000, 2_000_000_499], False),
            ([2_000_000_500, 3_000_000_000], True),
        ]:
            request["clock_window_ns"] = window
            self.assertEqual(expired_in_window(request), expected)
        for window in [[2_000_000_499, 2_000_000_500], [2, 1], [-1, 1], [False, 1]]:
            request["clock_window_ns"] = window
            with self.subTest(window=window), self.assertRaises(ValueError):
                expired_in_window(request)

    def test_clock_bracket_must_be_inside_the_fixture_window(self):
        request = copy.deepcopy(load_cases()[0]["requests"][0])
        request["clock_window_ns"] = [1_000_000_000, 2_000_000_000]
        runner.validate_clock_window(request, ["1", "0"], ["2", "0"])
        for before, after in [
            (["0", "999999"], ["1", "0"]),
            (["1", "0"], ["2", "1"]),
            (["2", "0"], ["1", "0"]),
        ]:
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                runner.validate_clock_window(request, before, after)

    def test_duplicate_children_fields_are_not_equivalent(self):
        payload = '{"access_tokens":["a"],"refresh_token":"wrong","refresh_token":"r"}'
        with self.assertRaises(ValueError):
            runner.snapshot(ObservationConnection(payload), {"t:children:r"})

    def test_children_state_requires_exact_fields_and_singleton_array(self):
        for payload in [
            '{"access_tokens":["a"],"refresh_token":"r","extra":true}',
            '{"access_tokens":"a","refresh_token":"r"}',
            '{"access_tokens":["a","a"],"refresh_token":"r"}',
            '{"access_tokens":[],"refresh_token":"r"}',
            '{"access_tokens":[1],"refresh_token":"r"}',
            '{"access_tokens":["a"],"refresh_token":1}',
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                runner.snapshot(ObservationConnection(payload), {"t:children:r"})

    def test_object_key_order_is_not_a_difference(self):
        for payload in [
            '{"access_tokens":["a"],"refresh_token":"r"}',
            '{"refresh_token":"r","access_tokens":["a"]}',
        ]:
            raw = {}
            state, _ = runner.snapshot(ObservationConnection(payload), {"t:children:r"}, raw)
            self.assertEqual(
                state["t:children:r"]["value"], {"access_tokens": ["a"], "refresh_token": "r"}
            )
            self.assertEqual(raw["t:children:r"], payload)

    def test_foreign_redis_is_rejected_before_any_mutation(self):
        connection = ObservationConnection("")
        with self.assertRaises(RuntimeError):
            runner.seed(connection, {}, ("owned-pid", "owned-run"))
        self.assertEqual(connection.commands, [("INFO", "server")])


if __name__ == "__main__":
    unittest.main()
