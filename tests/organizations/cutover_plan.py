"""Root fixture: retained secrets and actual partial SQL cutover reconciliation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path

import psycopg
import pytest


def main():  # noqa: PLR0915 — exact two-process root custody/recovery fixture
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.operator / "share/aegaeon/scripts/operations"))
    import organization_cutover_credentials as credentials  # noqa: PLC0415
    import organization_cutover_journal as journal  # noqa: PLC0415
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415
    import organization_restore_inspect as restore  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    inspection = config["inspection"]
    expected, operation = inspection["fence"], inspection["operation_id"]
    with ExitStack() as stack:
        all_stores = [recovery.connect(stack, value) for value in inspection["stores"]]
        control, _, target = all_stores
        stores = [control, target]
        if not args.resume:
            args.directory.mkdir(mode=0o700)
            comparison = restore.inspect(inspection, all_stores)
            plan = plans.create(config, stores, args.directory)
            row = journal.register(control, expected, operation, plan.sha256)
            assert row["step"] == 0
            assert "password" not in repr(plan)
            with pytest.raises(Exception, match="already registered"):
                plans.create(config, stores, args.directory)
            with pytest.raises(Exception, match="configuration differs"):
                plans.load(config | {"changed": True}, args.directory, plan.sha256)
            assert plans.load(config, args.directory, plan.sha256).value == plan.value
            journal.advance(
                control,
                expected,
                operation,
                plan.sha256,
                "registered",
                recovery.runtime.digest(comparison),
            )
            journal.advance(
                control, expected, operation, plan.sha256, "content-checked", plan.sha256
            )
            with journal.locked(control, expected):
                credentials.rotate(control, plan.sql(0))
            assert credentials.status(control, plan.sql(0)) == "replaced-disabled"
            assert credentials.status(target, plan.sql(1)) == "excluded"
            # Exit this process without advancing the receipt: the next process
            # must load the original verifier and inspect the actual first store.
            print("partial replacement retained; no activation")
            return

        sha256 = control.one(
            "SELECT plan_sha256 FROM organization_witness.cutover_operations "
            "WHERE deployment_id=%s AND operation_id=%s",
            (expected["deployment_id"], operation),
        )
        secret = args.directory / "plan.json"
        original = secret.read_bytes()
        secret.chmod(0o644)
        try:
            with pytest.raises(Exception, match="private root-owned"):
                plans.load(config, args.directory, sha256)
        finally:
            secret.chmod(0o600)
        secret.write_bytes(original + b" ")
        try:
            with pytest.raises(Exception, match="digest differs"):
                plans.load(config, args.directory, sha256)
        finally:
            secret.write_bytes(original)
        hardlink = args.directory / "duplicate"
        os.link(secret, hardlink)
        try:
            with pytest.raises(Exception, match="private root-owned"):
                plans.load(config, args.directory, sha256)
        finally:
            hardlink.unlink()
        descriptor = plans.directory(args.directory)
        try:
            with pytest.raises(BlockingIOError):
                plans.load(config, args.directory, sha256)
        finally:
            os.close(descriptor)
        saved = args.directory / "held-plan.json"
        secret.rename(saved)
        try:
            with pytest.raises(FileNotFoundError):
                plans.load(config, args.directory, sha256)
            with pytest.raises(Exception, match="already registered"):
                plans.create(config, stores, args.directory)
        finally:
            saved.rename(secret)
        plan = plans.load(config, args.directory, sha256)
        row = journal.inspect(control, expected, operation, sha256)
        assert row["step"] == journal.PREPARATION.index("sql-intent")
        assert credentials.status(control, plan.sql(0)) == "replaced-disabled"
        assert credentials.status(target, plan.sql(1)) == "excluded"
        with journal.locked(control, expected):
            credentials.rotate(target, plan.sql(1))
            assert credentials.status(control, plan.sql(0)) == "replaced-disabled"
            assert credentials.status(target, plan.sql(1)) == "replaced-disabled"
        row = journal.advance(control, expected, operation, sha256, "sql-intent", sha256)
        assert row["step"] == journal.PREPARATION.index("sql-prepared")
        # Fixture-only authentication probes: no product helper enables a login.
        # Both old names remain unusable; the exact retained secret authenticates
        # the renamed destination role, which is disabled again before returning.
        value = inspection["stores"][2]["connection"]
        user = plan.value["sql"][1]["replacements"][0]
        target.connection.execute("ALTER ROLE fresh_worker LOGIN")
        try:
            with psycopg.connect(
                host=value["host"],
                port=value["port"],
                dbname=value["dbname"],
                user=user["new"],
                password=user["password"],
                sslmode="verify-full",
                sslrootcert=value["ca_file"],
                connect_timeout=5,
            ) as probe:
                assert probe.execute("SELECT session_user::text").fetchone()[0] == user["new"]
        finally:
            target.connection.execute("ALTER ROLE fresh_worker NOLOGIN")
        assert credentials.status(target, plan.sql(1)) == "replaced-disabled"
        assert secret.read_bytes() == original
        assert plan.redis().name == config["redis"]["name"]
        print("same retained plan reconciles partial SQL replacement; all credentials disabled")


if __name__ == "__main__":
    main()
