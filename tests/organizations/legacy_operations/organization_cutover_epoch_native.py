"""Bounded fixed native epoch call and exact retained lease cleanup."""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from typing import TYPE_CHECKING
from urllib.parse import quote

import organization_cutover_epoch_inputs as inputs
import organization_cutover_login as login
import organization_cutover_phase as phase
import organization_cutover_token as token
import organization_cutover_validation as validation
import organization_recovery as recovery
from organization_recovery_store import require

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager
    from pathlib import Path

MAX_OUTPUT = 1024 * 1024
DEADLINE = 60


def bounded(args: list[str], environment: dict) -> dict:  # noqa: PLR0915 — bounded process ownership
    """Reap the owned process group before the caller disables any login lease."""
    process = subprocess.Popen(  # noqa: S603 — fixed Nix executable and explicit argv
        args,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + DEADLINE
    output = bytearray()
    count = 0
    reaped = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "epoch process deadline exceeded")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(chunk)
                    require(count <= MAX_OUTPUT, "epoch process output budget exceeded")
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "epoch process deadline exceeded")
            code = process.wait(timeout=remaining)
            reaped = True
            require(code == 0, "native epoch preparation refused")
        return json.loads(output)
    finally:
        # Never signal a PID after wait reaped it: it may have been reused.
        if not reaped:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def call(context: validation.Context, directory: Path, *, activate: bool = False) -> dict:
    principal = context.plan.value["token"]
    target = context.configuration["token"]
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": validation.endpoint(
            context.configuration["control"], context.principals["control_maintenance"]
        ),
        "AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": validation.endpoint(
            context.configuration["primary"], context.principals["primary_runtime"]
        ),
        "AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL": (
            f"rediss://{quote(principal['name'], safe='')}:{quote(principal['password'], safe='')}"
            f"@{target['host']}:{target['port']}/{context.new.identity['database']}"
        ),
    }
    return bounded(
        [
            str(inputs.NATIVE),
            "--intent",
            str(directory / "epochs.json"),
            "--root-cert",
            context.configuration["root_cert_file"],
            *(["--activate", str(directory / "activation.json")] if activate else []),
        ],
        environment,
    )


def invoke(  # noqa: PLR0913 — fixed offline inputs and selected transition
    context: validation.Context,
    directory: Path,
    intent_digest: str,
    index: int,
    locked: Callable[[], AbstractContextManager],
    *,
    activate: bool = False,
) -> dict:
    require(index < validation.MAX_ATTEMPTS, "epoch validation attempts exhausted")
    names = [
        {context.principals["control_maintenance"]["new"]},
        {context.principals["primary_runtime"]["new"]},
    ]
    leases = [
        login.plan(store, context.plan.sql(i), names[i]) for i, store in enumerate(context.stores)
    ]
    attempt = {
        "version": 1,
        "mode": "activation" if activate else "epochs",
        "planSha256": context.plan.sha256,
        "intentSha256": intent_digest,
        "leases": leases,
    }
    recovery.retain(context.descriptor, f"validation-attempt-{index:04d}.json", attempt)
    try:
        with locked() as (row, _):
            require(
                row["step"] == (12 if activate else phase.EPOCH_INTENT),
                "epoch native invocation is already completed",
            )
            for i, store in enumerate(context.stores):
                login.enable(store, context.plan.sql(i), leases[i])
            token.validation_enable(
                context.new, context.old.identity["run_id"], context.plan.redis()
            )
        # Release root's locks before the independent native maintenance connection.
        return call(context, directory, activate=activate)
    finally:
        cleaned = validation.cleanup(context, attempt)
        recovery.retain(context.descriptor, f"validation-cleanup-{index:04d}.json", cleaned)
