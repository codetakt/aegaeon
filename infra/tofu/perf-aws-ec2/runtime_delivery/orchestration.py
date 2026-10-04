"""Fixed guest delivery orchestration responsibility."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from runtime_delivery.artifacts import validate_artifact
from runtime_delivery.common import absolute_path, fail, json_object
from runtime_delivery.credentials import retrieve
from runtime_delivery.filesystem import (
    atomic_write,
    aws_executable,
    prepare_directory,
    prepare_driver,
    protected_path,
)
from runtime_delivery.metrics import metrics
from runtime_delivery.reports import LOADTEST_NAMES, validate_run_config, verify_report


def run_config(config_path: str, output: Path, issuer: str) -> None:
    raw = protected_path(absolute_path(config_path), regular=True).read_bytes()
    config = validate_run_config(raw, issuer)
    receipt, manifest = validate_artifact(config)
    prepare_directory(output)
    atomic_write(output / "driver-config.json", raw)
    atomic_write(output / "artifact-receipt.json", receipt)
    atomic_write(output / "SOURCE-MANIFEST.json", manifest)
    env = {name: config[name] for name in LOADTEST_NAMES}
    env["SOURCE_SHA256"] = config["artifact"]["source_manifest_sha256"]
    env["EXECUTABLE_SHA256"] = config["artifact"]["executable_sha256"]
    atomic_write(
        output / "validated-config.env",
        "".join((name + "=" + value + "\n" for name, value in env.items())).encode(),
    )


def refresh_client(config: dict[str, Any], directory: Path, source_sha256: str) -> None:
    if not re.fullmatch("[0-9a-f]{64}", source_sha256):
        fail("source manifest identity required")
    prepare_directory(directory.parent)
    if directory.exists() or directory.is_symlink():
        fail("input generation already exists")
    values = retrieve(
        "client",
        config["client_secret_arn"],
        config["client_secret_version"],
        config["region"],
        config["issuer_url"],
    )
    stage = Path(tempfile.mkdtemp(dir=directory.parent, prefix=".generation-"))
    try:
        for name, field in (
            ("profile.json", "profile"),
            ("session.txt", "session"),
            ("session-provenance.json", "provenance"),
        ):
            atomic_write(stage / name, values[field])
        env = {
            "AEG_LOADTEST_CLIENT_SECRET": values["secret"],
            "AEG_LOADTEST_PROFILE_MANIFEST": "/run/aegaeon-inputs/profile.json",
            "AEG_LOADTEST_SESSION_FILE": "/run/aegaeon-inputs/session.txt",
            "AEG_LOADTEST_SESSION_PROVENANCE": "/run/aegaeon-inputs/session-provenance.json",
            "AEG_LOADTEST_SOURCE_SHA256": source_sha256,
        }
        atomic_write(
            stage / "client.env",
            "".join((name + "=" + value + "\n" for name, value in sorted(env.items()))).encode(),
        )
        receipt = {
            "arn": config["client_secret_arn"],
            "version": config["client_secret_version"],
            "profile_sha256": values["profile_sha256"],
            "session_sha256": hashlib.sha256(values["session"]).hexdigest(),
            "provenance_sha256": values["provenance_sha256"],
            "source_sha256": source_sha256,
        }
        atomic_write(stage / "client.version.json", json.dumps(receipt).encode())
        stage.rename(directory)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def refresh(profile: str, config: dict[str, Any], directory: Path) -> None:
    prepare_directory(directory)
    output = directory / (profile + ".env")
    output.unlink(missing_ok=True)
    (directory / (profile + ".version.json")).unlink(missing_ok=True)
    values = retrieve(
        profile,
        config[profile + "_secret_arn"],
        config[profile + "_secret_version"],
        config["region"],
        config["issuer_url"],
    )
    if profile == "server":
        values["AEGAEON_RUNTIME_ISSUER_HOST"] = config["issuer_host"]
        values["AEGAEON_TRUSTED_PROXIES"] = config["trusted_proxies"]
    atomic_write(
        output,
        "".join((name + "=" + value + "\n" for name, value in sorted(values.items()))).encode(),
    )
    atomic_write(
        directory / (profile + ".version.json"),
        json.dumps(
            {"arn": config[profile + "_secret_arn"], "version": config[profile + "_secret_version"]}
        ).encode(),
    )


def dispatch() -> int:
    if sys.argv[1] == "preflight-aws":
        aws_executable()
        return 0
    if sys.argv[1] == "prepare-driver":
        prepare_driver()
        return 0
    config = json_object(
        protected_path(Path("/etc/aegaeon/delivery.json"), regular=True).read_bytes()
    )
    directory = Path("/run/aegaeon-supplies")
    if sys.argv[1] == "verify-report":
        verify_report(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == "run-config":
        run_config(sys.argv[2], Path(sys.argv[3]), config["issuer_url"])
    elif sys.argv[1] == "client":
        refresh_client(config, Path(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == "metrics":
        metrics(config, directory, Path(sys.argv[2]))
    else:
        refresh(sys.argv[1], config, directory)
    return 0


def main() -> int:
    try:
        return dispatch()
    except Exception:  # noqa: BLE001 -- public secret boundary must redact every unexpected failure
        sys.stderr.write("performance supply delivery failed\n")
        return 1
