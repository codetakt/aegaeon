# ruff: noqa: PT009, PT027 - unittest assertions must also run with Python -O
"""Reject Redis observations that a Rust children decoder would not accept."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/validation"
sys.path.insert(0, str(SCRIPTS))
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
