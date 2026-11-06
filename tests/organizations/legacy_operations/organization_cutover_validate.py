"""Explicit root cutover validation, offline activation and retained serving start."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

import organization_cutover_activation as activation
import organization_cutover_epochs as epochs
import organization_cutover_plan as plans
import organization_cutover_prepare as preparation
import organization_cutover_serving as serving
import organization_cutover_startup as startup
import organization_cutover_validation as validation
import organization_recovery as recovery
from organization_recovery_store import RecoveryRefusedError, require


def main() -> None:  # noqa: PLR0915 — bounded root entry and exact lock custody
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--validation-config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--prepare-epochs", action="store_true")
    operation.add_argument("--prepare-startup", type=Path)
    operation.add_argument("--activate-epochs", type=Path)
    operation.add_argument("--start-workers", type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "offline root validation required")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    signal.signal(
        signal.SIGALRM,
        lambda *_: (_ for _ in ()).throw(RecoveryRefusedError("native validation deadline")),
    )
    signal.alarm(600)
    config = preparation.settings(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.validation_config))
    validation.settings(native)
    descriptor = plans.directory(args.directory)
    os.close(descriptor)
    lock = os.open(
        args.directory / ".coordinator-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(lock)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o077
            and info.st_nlink == 1,
            "private coordinator lock required",
        )
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ExitStack() as stack:
            stores = [recovery.connect(stack, value) for value in config["inspection"]["stores"]]
            old = preparation.connect_token(stack, config["preparation"]["retired_token"])
            new = preparation.connect_token(stack, config["preparation"]["destination_token"])
            if args.prepare_startup or args.activate_epochs or args.start_workers:
                settings = json.loads(
                    recovery.private_file(
                        args.prepare_startup or args.activate_epochs or args.start_workers
                    )
                )
                execute = (
                    serving.serve
                    if args.start_workers
                    else activation.activate
                    if args.activate_epochs
                    else startup.prepare
                )
                result = execute(config, native, stores, old, new, args.directory, settings)
            else:
                execute = epochs.prepare if args.prepare_epochs else validation.validate
                result = execute(config, native, stores, old, new, args.directory)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — credentials and supplier errors stay private
        print(
            "cutover unconfirmed; retain all inputs and recover any registered unfinished start",
            file=sys.stderr,
        )
        sys.exit(1)
