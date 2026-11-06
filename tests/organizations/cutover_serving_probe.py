"""Actual two-worker serving, process loss and retained accepted work on closure."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

import psycopg


def run(*args, code=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603 — bounded exact owned fixture commands
    assert result.returncode == code, (result.returncode, result.stderr)
    return result.stdout


def command(args):
    return [
        str(args.package / "bin/aegaeon-organization-cutover-validate"),
        "--config",
        str(args.config),
        "--validation-config",
        str(args.native),
        "--directory",
        str(args.directory),
        "--start-workers",
        str(args.directory / "startup-fixture.json"),
    ]


def accepted_work(args, *, pending, context=None):
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415
    from delivery_journey import Management  # noqa: PLC0415

    bootstrap = json.loads(recovery.private_file(args.directory.parent / "bootstrap.json"))
    manifest = json.loads(recovery.private_file(args.directory / "startup-manifest.json"))
    worker = next(
        row["worker"]
        for row in manifest["workers"]
        if row["worker"]["environment_id"] == bootstrap["environment"]
    )
    api = Management(worker["port"], bootstrap)
    api.setup(bootstrap, "Serving-Fixture-Credential-Only-32")
    external = "Serving/保持-CaseSensitive-" + uuid4().hex
    organization, _ = api.call(
        "POST",
        api.path + "/organizations",
        {"externalId": external, "reason": "accepted before cutover completion"},
        key="serving-organization",
    )
    assert organization["externalId"] == external
    result = {
        "organizationId": organization["id"],
        "externalId": external,
        "environmentId": bootstrap["environment"],
        "domainId": api.domain,
        # Retained only in the root-private fixture receipt, never its public result.
        "sessionCookie": api.cookie,
        "http": api.journal,
        "minimumOwnedGenerations": [api.counts[0], api.counts[1]],
    }
    if pending:
        # The actual runtime SQL API acquires an owner; the caller then disappears
        # before progress-begin. Closure must retain this unresolved owner.
        assert context is not None
        native = context.configuration
        principal = context.principals["control_runtime"]
        epoch = json.loads(recovery.private_file(args.directory / "epochs.json"))
        selected = epoch["parent"]["selection"]
        with psycopg.connect(
            validation.endpoint(native["control"], principal),
            sslmode="verify-full",
            sslrootcert=native["root_cert_file"],
            autocommit=True,
        ) as connection:
            result["pending"] = connection.execute(
                "SELECT organization_witness.deployment_acquire(%s,%s,%s,%s,%s)",
                (
                    epoch["deployment_id"],
                    selected["epoch"],
                    selected["primary"],
                    selected["token_store"],
                    str(uuid4()),
                ),
            ).fetchone()[0]
    # When injected into first_start the coordinator already owns this lock.
    # Reopening it in the same process would test self-deadlock, not recovery.
    descriptor = context.descriptor if context else plans.directory(args.directory)
    try:
        recovery.retain(descriptor, "serving-accepted.json", result)
    finally:
        if context is None:
            os.close(descriptor)
    return result


def abandon(args, mode):
    import organization_cutover_serving as serving  # noqa: PLC0415
    import organization_cutover_serving_credentials as credentials  # noqa: PLC0415
    import organization_cutover_serving_phase as phase  # noqa: PLC0415
    import organization_cutover_serving_units as units  # noqa: PLC0415
    import organization_cutover_validate as entry  # noqa: PLC0415

    if mode == "partial-enable":
        original = credentials.sql_enable

        def enabled(*arguments):
            original(*arguments)
            os._exit(95)

        credentials.sql_enable = enabled
    elif mode in ("after-write", "forward"):
        inject_after_write(args, serving, units)
    else:
        assert mode == "final-reply-loss"
        original = phase.advance

        def committed(work, step, digest):
            result = original(work, step, digest)
            if step == phase.COMPLETE:
                os._exit(97)
            return result

        phase.advance = committed
    # Exercise the real entry's private-file checks, process deadline and flock.
    sys.argv = command(args)
    entry.main()
    message = "owned process-loss point did not execute"
    raise AssertionError(message)


def inject_after_write(args, serving, units):
    original = units.start
    first_start = serving.first_start
    contexts = []

    def selected(work, value, digest):
        contexts.append(work.context)
        return first_start(work, value, digest)

    def started(*arguments):
        original(*arguments)
        accepted_work(args, pending=True, context=contexts[0])
        os._exit(96)

    serving.first_start = selected
    units.start = started


def lose_closure_reply(args):
    import organization_cutover_serving_recovery as closure  # noqa: PLC0415
    import organization_cutover_validate as entry  # noqa: PLC0415

    original = closure.close

    def closed(*arguments):
        original(*arguments)
        os._exit(98)

    closure.close = closed
    sys.argv = command(args)
    entry.main()
    message = "closure reply-loss point did not execute"
    raise AssertionError(message)


def closed(args, result, mode):
    import organization_recovery as recovery  # noqa: PLC0415

    assert result["aborted"]
    assert not result["completed"]
    assert not result["workersStarted"]
    receipt = json.loads(recovery.private_file(args.directory / "serving-aborted.json"))
    assert receipt["state"]["parent"]["phase"] == "fenced"
    assert len(receipt["state"]["children"]) == 2
    assert all(row["phase"] == "fenced" for row in receipt["state"]["children"])
    attempts = sorted(args.directory.glob("serving-closure-attempt-*.json"))
    assert json.loads(run(*command(args))) == result
    assert sorted(args.directory.glob("serving-closure-attempt-*.json")) == attempts
    expected_pending = []
    minimum = [0, 0]
    if mode == "after-write":
        accepted = json.loads(recovery.private_file(args.directory / "serving-accepted.json"))
        pending = accepted["pending"]
        expected_pending = [{key: pending[key] for key in ("slot", "generation", "worker_id")}]
        minimum = accepted["minimumOwnedGenerations"]
        minimum[0] += 1
        assert any(
            row["slot"] == pending["slot"]
            and row["generation"] == pending["generation"]
            and row["worker_id"] == pending["worker_id"]
            for row in receipt["state"]["parent_slots"]
        )
        config = json.loads(recovery.private_file(args.config))
        with ExitStack() as stack:
            primary = recovery.connect(stack, config["inspection"]["stores"][2])
            assert (
                primary.one(
                    "SELECT external_id FROM aegaeon.application_organizations "
                    "WHERE environment_id=%s AND id=%s",
                    (accepted["environmentId"], accepted["organizationId"]),
                )
                == accepted["externalId"]
            )
    return {
        "passed": True,
        "mode": mode,
        "environmentCount": 2,
        "aborted": True,
        "acceptedHttpWritePreserved": mode == "after-write",
        "unresolvedRuntimeOwnerPreserved": mode == "after-write",
        "abortedCommitReplyLossReconciled": mode == "after-write",
        "expectedPending": expected_pending,
        "minimumOwnedGenerations": minimum,
        "completedReplayWithoutEffects": True,
        "supplierQualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--abandon", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--close-loss", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_recovery as recovery  # noqa: PLC0415

    if args.close_loss:
        lose_closure_reply(args)
        return
    if args.execute:
        # The packaged entry keeps credentials out of public stderr. Invoke the
        # same main in this private child so initial failure diagnostics survive;
        # completed and interrupted replays also exercise its public wrapper.
        import organization_cutover_validate as entry  # noqa: PLC0415

        sys.argv = command(args)
        entry.main()
        return
    mode = json.loads(recovery.private_file(args.directory.parent / "serving-case.json"))["mode"]
    if args.abandon:
        abandon(args, mode)
        return
    probe(args, mode)


def probe(args, mode):
    if mode != "normal":
        run(
            sys.executable,
            __file__,
            *sys.argv[1:],
            "--abandon",
            code={"partial-enable": 95, "after-write": 96, "forward": 96, "final-reply-loss": 97}[
                mode
            ],
        )
    else:
        run(sys.executable, __file__, *sys.argv[1:], "--execute")
    if mode in ("after-write", "forward"):
        run(sys.executable, __file__, *sys.argv[1:], "--close-loss", code=98)
    if mode == "partial-enable":
        run(sys.executable, __file__, *sys.argv[1:], "--execute")
    result = json.loads(run(*command(args)))
    if mode == "forward":
        from cutover_forward_probe import forward  # noqa: PLC0415

        closure = closed(args, result, "after-write")
        print(json.dumps(forward(args, closure)))
        return
    if mode in ("partial-enable", "after-write"):
        print(json.dumps(closed(args, result, mode)))
        return
    assert result["step"] == 16
    assert result["completed"]
    assert result["workersStarted"]
    assert not result["aborted"]
    accepted = accepted_work(args, pending=False)
    assert json.loads(run(*command(args))) == result
    print(
        json.dumps(
            {
                "passed": True,
                "mode": mode,
                "environmentCount": 2,
                "workersStarted": True,
                "authenticatedHttpWrite": True,
                "externalIdPreserved": accepted["externalId"],
                "expectedPending": [],
                "minimumOwnedGenerations": accepted["minimumOwnedGenerations"],
                "completedReplayWithoutStart": True,
                "supplierQualified": False,
            }
        )
    )


def ownership(report, mode, counts):
    serving = (
        report.get("cutover_journey", {})
        .get("epoch_preparation", {})
        .get("startup_publication", {})
        .get("servingCase", {})
    )
    minimum = serving.get("minimumOwnedGenerations", [])
    actual = [
        {key: row[key] for key in ("slot", "generation", "worker_id")}
        for row in report["parent_slots"]
        if row["pending"]
    ]
    phase = "fenced" if mode in ("partial-enable", "after-write") else "active"
    return (
        {"minimum": minimum, "pending": serving.get("expectedPending")},
        serving.get("passed") is True
        and len(minimum) == 2
        and all(value >= bound for value, bound in zip(counts, minimum, strict=True))
        and (mode != "partial-enable" or counts == [0, 0])
        and actual == serving["expectedPending"]
        and not any(row["pending"] for row in report["child_slots"])
        and len(report["child"]) == 2
        and all(row["phase"] == phase for row in report["parent"] + report["child"]),
    )


if __name__ == "__main__":
    main()
