"""Owned root native startup parser and real unprivileged credential-copy probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4


def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)  # noqa: S603 — fixed owned fixture commands
    assert (result.returncode == 0) == success, (result.returncode, result.stderr)
    return result.stdout


def main():  # noqa: PLR0915 — exact owned root fixture setup
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_cutover_epoch_inputs as epoch_inputs  # noqa: PLC0415
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_startup_inputs as startup  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.native))
    receipt, _ = epoch_inputs.read(args.directory, "epoch-prepared.json")
    epoch, digest = epoch_inputs.read(args.directory, "epochs.json")
    plan = plans.load(config, args.directory, receipt["planSha256"])
    context = SimpleNamespace(
        configuration=native,
        principals=validation.selected(plan, native),
        plan=plan,
        new=SimpleNamespace(identity=epoch["stores"]["token"]),
    )
    work = SimpleNamespace(context=context, epoch=epoch)
    workers = [
        {
            "unit": "aegaeon-organization-runtime-startup-" + uuid4().hex + ".service",
            "user": "nobody",
            "environment_id": row["environment_id"],
            "host": "127.0.0.1",
            "port": 18080 + index,
        }
        for index, row in enumerate(epoch["children"])
    ]
    settings = {"version": 1, "workers": workers, "delivery_trust": []}
    startup.settings(settings, epoch)
    certs = startup.certificates(settings, native)
    credential_permissions(startup)
    checks = []
    for index, worker in enumerate(workers):
        with tempfile.TemporaryDirectory(
            prefix="aegaeon-startup-credential-", dir="/run"
        ) as temporary:
            directory = Path(temporary)
            descriptor = plans.directory(directory)
            try:
                built = startup.documents(work, worker, certs)
                recovery.retain(descriptor, "runtime.json", built["runtime"])
            finally:
                os.close(descriptor)
            command = [
                str(epoch_inputs.NATIVE),
                "--intent",
                str(args.directory / "epochs.json"),
                "--root-cert",
                native["root_cert_file"],
                "--check-startup",
                str(directory / "runtime.json"),
            ]
            observed = json.loads(run(*command))
            assert observed["intentSha256"] == digest
            assert (
                observed["configurationSha256"]
                == hashlib.sha256((directory / "runtime.json").read_bytes()).hexdigest()
            )
            assert observed["activationAuthorized"] is False
            startup.bind_selectors(work, built, worker, observed["startupSelectors"])
            descriptor = plans.directory(directory)
            try:
                recovery.retain(descriptor, "launch.json", built["launch"])
            finally:
                os.close(descriptor)
            service(startup, worker, directory, certs)
            checks.append({"nativeParser": True, "credentialCopy": True, "index": index})
    print(
        json.dumps(
            {
                "passed": True,
                "workers": checks,
                "activation": False,
                "freshAccountCustodyQualified": False,
                "serverExec": False,
                "credentialPermissionCases": 10,
            }
        )
    )


def credential_permissions(startup):  # noqa: PLR0915 — actual root inode permission cases
    module = startup.LAUNCHER.parent.parent / "share/aegaeon/organization_selected_worker.py"
    read = runpy.run_path(str(module))["read"]
    with tempfile.TemporaryDirectory(prefix="aegaeon-credential-permission-", dir="/run") as name:
        path = Path(name) / "input"
        path.write_bytes(b"public fixture")
        for mode in [0o400, 0o440]:
            path.chmod(mode)
            assert read(path) == b"public fixture"
        for mode in [0o600, 0o640, 0o444, 0o644, 0o460, 0o450]:
            path.chmod(mode)
            try:
                read(path)
            except ValueError:
                pass
            else:
                raise AssertionError(oct(mode))
        path.chmod(0o440)
        os.chown(path, 0, pwd.getpwnam("nobody").pw_gid)
        try:
            read(path)
        except ValueError:
            pass
        else:
            message = "foreign group credential accepted"
            raise AssertionError(message)
        os.chown(path, 0, 0)
        linked = path.with_name("link")
        os.link(path, linked)
        try:
            read(path)
        except ValueError:
            pass
        else:
            message = "hard-linked credential accepted"
            raise AssertionError(message)


def service(startup, worker, directory, certs):  # noqa: PLR0915 — finite real systemd lifecycle
    module = startup.LAUNCHER.parent.parent / "share/aegaeon/organization_selected_worker.py"
    code = (
        "import os,json,pathlib,runpy;"
        f"m=runpy.run_path({str(module)!r});"
        "a,e=m['inputs'](pathlib.Path(os.environ['CREDENTIALS_DIRECTORY']));"
        "print(json.dumps({'argv':a,'keys':sorted(e),'uid':os.geteuid()}))"
    )
    unit = Path("/run/systemd/system") / worker["unit"]
    assert not unit.exists()
    text = f"[Service]\nType=oneshot\nUser=nobody\nGroup={pwd.getpwnam('nobody').pw_gid}\n"
    text += "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
    text += "KillMode=control-group\nSendSIGKILL=yes\nDelegate=no\nTimeoutStartSec=15\n"
    text += "Environment=PGHOST=foreign.example AEGAEON_DATABASE_URL=foreign\n"
    text += f"ExecStart={sys.executable} -I -c {json.dumps(code)}\n"
    text += f"StandardOutput=append:{directory}/result.json\n"
    text += f"StandardError=append:{directory}/error.log\n"
    for name in ("runtime.json", "launch.json"):
        text += f"LoadCredential={name}:{directory}/{name}\n"
    for row in certs:
        text += f"LoadCredential={row['name']}:{row['source']}\n"
    with unit.open("x") as output:
        output.write(text)
    unit.chmod(0o644)
    try:
        run("systemctl", "daemon-reload")
        run("systemctl", "start", worker["unit"])
        result = json.loads((directory / "result.json").read_text())
        assert result["uid"] != 0
        assert "PGHOST" not in result["keys"]
        assert result["argv"] == [
            str(startup.SERVER),
            "--host",
            worker["host"],
            "--port",
            str(worker["port"]),
        ]
        rejected_stores(directory, worker)
        raw = (directory / "runtime.json").read_bytes()
        try:
            (directory / "runtime.json").write_bytes(raw + b" ")
            run("systemctl", "start", worker["unit"], success=False)
            assert (
                "selected worker credential input refused" in (directory / "error.log").read_text()
            )
        finally:
            (directory / "runtime.json").write_bytes(raw)
        run("systemctl", "start", worker["unit"])
    finally:
        error = directory / "error.log"
        if sys.exc_info()[0] is not None and error.exists():
            # The fixed probe logs only parser/path failures, never input bytes.
            print(error.read_text()[-8192:], file=sys.stderr)
        run("systemctl", "stop", worker["unit"])
        unit.unlink()
        run("systemctl", "daemon-reload")
        subprocess.run(  # noqa: S603 — exact owned unit may already be unloaded
            ["systemctl", "reset-failed", worker["unit"]],  # noqa: S607 — exact host service manager
            check=False,
            capture_output=True,
            timeout=10,
        )


def rejected_stores(directory, worker):
    launch_path = directory / "launch.json"
    launch_raw = launch_path.read_bytes()
    for key, value in [
        ("AEGAEON_DPOP_REDIS_URL", None),
        ("AEGAEON_MANAGEMENT_SESSION_REDIS_URL", "rediss://foreign.example/0"),
        ("PGHOST", "foreign.example"),
    ]:
        changed = json.loads(launch_raw)
        if value is None:
            del changed["environment"][key]
        else:
            changed["environment"][key] = value
        try:
            launch_path.write_text(json.dumps(changed))
            run("systemctl", "start", worker["unit"], success=False)
            assert (
                "selected worker credential input refused" in (directory / "error.log").read_text()
            )
        finally:
            launch_path.write_bytes(launch_raw)


if __name__ == "__main__":
    main()
