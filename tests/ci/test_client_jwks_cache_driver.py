# ruff: noqa: PT027 - unittest runner
"""Reject privileged identities before starting contained JWKS fixtures."""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "client_jwks_cache_driver", ROOT / "scripts/validation/test_client_jwks_cache.py"
)
assert SPEC is not None
assert SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class FixtureIdentityTests(unittest.TestCase):
    def test_declared_supplier_requirements_match_the_namespace_selection(self) -> None:
        args = DRIVER.libtest_selection("/unused/libtest", "client_registry::jwks_")
        skips = [args[i + 1] for i, value in enumerate(args) if value == "--skip"]
        declaration = re.compile(r'#\[ignore\s*=\s*"([^\"]*)"\]\s*(?:async\s+)?fn\s+(\w+)')
        postgres_cases = namespace_cases = 0
        for source in (ROOT / "crates/server/src/client_registry").rglob("*.rs"):
            for reason, name in declaration.findall(source.read_text()):
                # Module prefixes do not affect the function-name exclusions.
                case = f"client_registry::jwks_fixture::{name}"
                selected = not any(skip in case for skip in skips)
                if "postgres" in reason.lower() or "database_url" in reason.lower():
                    postgres_cases += 1
                    assert not selected, f"{source}: {name}: {reason}"
                if reason == "requires scripts/validation/test_client_jwks_cache.py":
                    namespace_cases += 1
                    assert selected, f"namespace case lost: {source}: {name}"
        assert postgres_cases > 0
        assert namespace_cases > 0

    def assert_invalid_identity(self, uid: int, gid: int) -> None:
        with (
            patch.object(DRIVER.os, "readlink", return_value="net:[isolated]"),
            patch.object(DRIVER.os, "geteuid", return_value=0),
            patch.object(DRIVER.subprocess, "run"),
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
            with self.assertRaisesRegex(RuntimeError, "invalid unprivileged fixture identity"):
                DRIVER.inside_namespace(
                    "/unused/libtest",
                    "client_registry::jwks_",
                    "net:[parent]",
                    ["/unused/ip", "/unused/redis-server", "/unused/redis-cli"],
                    [uid, gid],
                )
            setgroups.assert_not_called()
            setgid.assert_not_called()
            setuid.assert_not_called()
            fixture_directory.assert_not_called()

    def test_positive_uid_with_root_primary_group_is_rejected(self) -> None:
        self.assert_invalid_identity(1000, 0)

    def test_root_uid_and_negative_identities_are_rejected(self) -> None:
        for uid, gid in [(0, 1000), (-1, 1000), (1000, -1)]:
            with self.subTest(uid=uid, gid=gid):
                self.assert_invalid_identity(uid, gid)


if __name__ == "__main__":
    unittest.main()
