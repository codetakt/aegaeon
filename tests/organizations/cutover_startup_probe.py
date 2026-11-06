"""Actual protected unit publication, interruption and refusal regressions."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

import pytest


def run(*args, code=0, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 — exact owned fixture argv
    assert result.returncode == code, (result.returncode, result.stderr)
    return result.stdout


def main():  # noqa: PLR0912,PLR0915 — complete owned account/unit lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--abandon", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_cutover_epoch_inputs as inputs  # noqa: PLC0415
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_prepare as preparation  # noqa: PLC0415
    import organization_cutover_startup as startup  # noqa: PLC0415
    import organization_cutover_startup_units as units  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.native))
    settings_path = args.directory / "startup-fixture.json"
    if args.abandon or args.resume:
        settings = json.loads(recovery.private_file(settings_path))
        publish = units.publish

        def lose_reply(row):
            publish(row)
            os._exit(93)

        if args.abandon:
            units.publish = lose_reply
        with ExitStack() as stack:
            stores = [recovery.connect(stack, value) for value in config["inspection"]["stores"]]
            old = preparation.connect_token(stack, config["preparation"]["retired_token"])
            new = preparation.connect_token(stack, config["preparation"]["destination_token"])
            result = startup.prepare(config, native, stores, old, new, args.directory, settings)
        if args.resume:
            print(json.dumps(result))
            return
        message = "publication process did not terminate at owned injection"
        raise AssertionError(message)
    epoch, _ = inputs.read(args.directory, "epochs.json")
    users = []
    workers = []
    try:
        for index, child in enumerate(epoch["children"]):
            name = "aegtest_" + uuid4().hex[:16]
            run(
                "useradd",
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                shutil.which("nologin"),
                name,
            )
            users.append(name)
            workers.append(
                {
                    "unit": "aegaeon-organization-runtime-publish-" + uuid4().hex + ".service",
                    "user": name,
                    "environment_id": child["environment_id"],
                    "host": "127.0.0.1",
                    "port": 19080 + index,
                }
            )
        settings = {"version": 1, "workers": workers, "delivery_trust": []}
        descriptor = plans.directory(args.directory)
        try:
            recovery.retain(descriptor, settings_path.name, settings)
        finally:
            os.close(descriptor)
        run(sys.executable, __file__, *sys.argv[1:], "--abandon", code=93)
        result = probe(args, settings_path, workers, units, recovery)
    finally:
        for worker in workers:
            unit = units.UNIT_DIRECTORY / worker["unit"]
            if unit.exists():
                run("systemctl", "stop", worker["unit"])
                unit.unlink()
        run("systemctl", "daemon-reload")
        for name in users:
            run("userdel", name)
            with pytest.raises(KeyError):
                pwd.getpwnam(name)
    print(json.dumps(result))


def probe(args, settings_path, workers, units, recovery):  # noqa: PLR0915 — real exact replay and fault matrix
    command = [
        str(args.package / "bin/aegaeon-organization-cutover-validate"),
        "--config",
        str(args.config),
        "--validation-config",
        str(args.native),
        "--directory",
        str(args.directory),
        "--prepare-startup",
        str(settings_path),
    ]
    attempts = sorted(args.directory.glob("validation-attempt-*.json"))
    try:
        first = json.loads(run(*command))
    except AssertionError:
        # Preserve the initial wrapper refusal, with private diagnostics for
        # only the same original intent. A diagnostic success is not a pass.
        run(sys.executable, __file__, *sys.argv[1:], "--resume")
        raise
    assert first["step"] == 11
    assert not first["activationAuthorized"]
    import organization_cutover_serving_units as serving_units  # noqa: PLC0415

    manifest = json.loads(recovery.private_file(args.directory / "startup-manifest.json"))
    serving_units.stop(manifest)
    assert json.loads(run(*command)) == first
    assert sorted(args.directory.glob("validation-attempt-*.json")) == attempts
    for name in [
        "startup-manifest.json",
        "startup-00-runtime.json",
        "startup-00-launch.json",
        "startup-published.json",
    ]:
        path = args.directory / name
        saved = path.with_suffix(".saved")
        path.rename(saved)
        try:
            run(*command, code=1)
            assert not path.exists()
        finally:
            saved.rename(path)
    worker = workers[0]
    unit = units.UNIT_DIRECTORY / worker["unit"]
    data = unit.read_bytes()
    try:
        unit.write_bytes(data + b"# changed registered fragment\n")
        run(*command, code=1)
    finally:
        unit.write_bytes(data)
    dropin = unit.with_name(unit.name + ".d")
    dropin.mkdir(mode=0o755)
    try:
        (dropin / "override.conf").write_text("[Service]\nEnvironment=PGHOST=foreign.example\n")
        run(*command, code=1)
    finally:
        (dropin / "override.conf").unlink()
        dropin.rmdir()
    identity = pwd.getpwnam(worker["user"])
    process = subprocess.Popen(  # noqa: S603 — exact owned process under selected account
        [shutil.which("sleep"), "30"],
        user=identity.pw_uid,
        group=identity.pw_gid,
        extra_groups=[],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

        with pytest.raises(RecoveryRefusedError, match="selected worker account already runs"):
            units.no_processes({identity.pw_uid})
        run(*command, code=1)
    finally:
        process.kill()
        process.wait(timeout=5)
    # The same durable manifest can reconstruct an absent runtime-only fragment.
    unit.unlink()
    run("systemctl", "daemon-reload")
    assert json.loads(run(*command)) == first
    assert unit.read_bytes() == data
    assert recovery.stopped(worker["unit"])["MainPID"] == "0"
    activation = json.loads(
        run(sys.executable, str(args.directory.parent / "activation-probe.py"), *sys.argv[1:])
    )
    assert activation["passed"] is True
    serving = None
    if (args.directory.parent / "serving-case.json").exists():
        serving = json.loads(
            run(
                sys.executable,
                str(args.directory.parent / "cutover_serving_probe.py"),
                *sys.argv[1:],
                timeout=300,
            )
        )
        assert serving["passed"] is True
    return {
        "activationCases": activation,
        "servingCase": serving,
        "passed": True,
        "activation": True,
        "serverStarted": bool(serving and serving.get("workersStarted")),
        "cases": [
            "actual exit after fragment publication and exact resume",
            "completed replay without new leases",
            "closure stops never-started selected services without reset of unloaded units",
            "registered manifest/runtime/launch/receipt never regenerated",
            "changed unit refused",
            "drop-in refused",
            "unexpected selected-account process refused",
            "runtime fragment reconstructed from same retained manifest",
            "dedicated root-created accounts removed",
        ],
    }


if __name__ == "__main__":
    main()
