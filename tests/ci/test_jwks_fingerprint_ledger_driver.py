# ruff: noqa: PT009, PT027 - unittest runner
"""Check privilege boundaries before starting contained ledger fixtures."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "jwks_fingerprint_ledger_driver", ROOT / "scripts/validation/test_jwks_fingerprint_ledger.py"
)
assert SPEC is not None
assert SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class FixtureIdentityTests(unittest.TestCase):
    def assert_invalid_identity(self, uid: int, gid: int, euid: int = 0) -> None:
        with (
            patch.object(DRIVER.os, "readlink", return_value="net:[isolated]"),
            patch.object(DRIVER.os, "geteuid", return_value=euid),
            patch.object(DRIVER.subprocess, "run") as run,
            patch.object(
                DRIVER.subprocess,
                "check_output",
                side_effect=[b'[{"ifname":"lo","flags":["UP"]}]', b"[]", b"[]"],
            ),
            patch.object(DRIVER.os, "setgroups") as setgroups,
            patch.object(DRIVER.os, "setgid") as setgid,
            patch.object(DRIVER.os, "setuid") as setuid,
            patch.object(DRIVER.tempfile, "TemporaryDirectory") as fixture_directory,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "privileged namespace must drop to the invoking non-root user"
            ):
                DRIVER.inside_namespace(
                    "/unused/libtest",
                    ["ledger-tests"],
                    "net:[parent]",
                    "/unused/ip",
                    "/unused/redis-server",
                    "redis",
                    [uid, gid],
                )
            setgroups.assert_not_called()
            setgid.assert_not_called()
            setuid.assert_not_called()
            fixture_directory.assert_not_called()
            run.assert_called_once_with(["/unused/ip", "link", "set", "lo", "up"], check=True)

    def test_positive_uid_with_root_primary_group_is_rejected(self) -> None:
        self.assert_invalid_identity(1000, 0)

    def test_invalid_identities_are_rejected_before_privilege_changes(self) -> None:
        for uid, gid, euid in [(0, 1000, 0), (-1, 1000, 0), (1000, -1, 0), (1000, 1000, 1000)]:
            with self.subTest(uid=uid, gid=gid, euid=euid):
                self.assert_invalid_identity(uid, gid, euid)

    def test_positive_identity_starts_fixture_only_after_privilege_drop(self) -> None:
        events: list[object] = []

        def start_fixture(*_args: object, **_kwargs: object) -> str:
            events.append("fixture-directory")
            return "/unused/fixture"

        with (
            patch.object(DRIVER.os, "readlink", return_value="net:[isolated]"),
            patch.object(DRIVER.os, "geteuid", side_effect=[0, 1000, 1000]),
            patch.object(DRIVER.os, "getuid", return_value=1000),
            patch.object(DRIVER.os, "getgid", return_value=100),
            patch.object(DRIVER.os, "getegid", return_value=100),
            patch.object(DRIVER.subprocess, "run") as run,
            patch.object(
                DRIVER.subprocess,
                "check_output",
                side_effect=[b'[{"ifname":"lo","flags":["UP"]}]', b"[]", b"[]"],
            ),
            patch.object(DRIVER.os, "setgroups", side_effect=events.append),
            patch.object(
                DRIVER.os, "setgid", side_effect=lambda value: events.append(("gid", value))
            ),
            patch.object(
                DRIVER.os, "setuid", side_effect=lambda value: events.append(("uid", value))
            ),
            patch.object(DRIVER.tempfile, "TemporaryDirectory") as fixture_directory,
        ):
            fixture_directory.return_value.__enter__.side_effect = start_fixture
            run.return_value.returncode = 7
            result = DRIVER.inside_namespace(
                "/unused/libtest",
                ["ledger-tests"],
                "net:[parent]",
                "/unused/ip",
                "/unused/redis-server",
                "redis",
                [1000, 100],
            )
            self.assertEqual(events, [[], ("gid", 100), ("uid", 1000), "fixture-directory"])
            self.assertEqual(result, 7)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(
                run.call_args_list[0],
                call(["/unused/ip", "link", "set", "lo", "up"], check=True),
            )
            self.assertEqual(
                run.call_args.args[0],
                ["/unused/libtest", "ledger-tests", "--include-ignored", "--test-threads=1"],
            )
            self.assertEqual(
                run.call_args.kwargs["env"]["JWKS_LEDGER_TEST_NETNS"], "net:[isolated]"
            )
            self.assertEqual(run.call_args.kwargs["env"]["JWKS_LEDGER_TEST_DIR"], "/unused/fixture")
            self.assertEqual(
                run.call_args.kwargs["env"]["JWKS_LEDGER_TEST_SERVER"], "/unused/redis-server"
            )


if __name__ == "__main__":
    unittest.main()
