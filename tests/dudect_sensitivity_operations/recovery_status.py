# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Read durable completion without relying on systemd's volatile timestamps.

The monitor only decides whether authenticated recovery may start. Neither a
successful unit exit nor this decision qualifies a statistical result.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def publish_completion(root):
    """Call only after all evidence and the upload index have been uploaded."""
    root = Path(root)
    plan = json.loads((root / "execution-plan.json").read_bytes())
    receipt = json.loads((root / "recovery-receipt.json").read_bytes())
    progress = json.loads((root / "upload-progress.json").read_bytes())
    if (
        receipt.get("complete") is not True
        or receipt.get("generation") != plan["generation"]
        or (root / "recovery-failure.json").exists()
    ):
        raise ValueError("Incomplete recovery cannot publish completion")
    prefix = "results/" + plan["generation"] + "/"
    required = {
        prefix + name
        for name in ("manifest.age", "recovery-receipt.json", "recovery-file-index.json")
    }
    required.update(prefix + f"{i:06d}.age" for i in range(receipt["chunks"]))
    if (
        len(progress) != len(required)
        or {row["key"] for row in progress} != required
        or any(not row.get("version") for row in progress)
    ):
        raise ValueError("Incomplete or repeated upload index")
    marker = {
        "schema": "dudect-recovery-completion/1",
        "generation": plan["generation"],
        "plan_sha256": file_sha256(root / "execution-plan.json"),
        "complete": True,
        "receipt_sha256": file_sha256(root / "recovery-receipt.json"),
        "upload_progress_sha256": file_sha256(root / "upload-progress.json"),
    }
    # A unique, generation-specific directory and exclusive publication prevent
    # a second recovery from replacing an earlier marker.
    path = root / "recovery-completion.json"
    fd, temporary = tempfile.mkstemp(prefix=".completion-", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(marker, sort_keys=True).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic publication, refusing replacement.
    finally:
        os.unlink(temporary)  # noqa: PTH108 -- unlink failure is explicitly recorded
    descriptor = os.open(root, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return marker


def recovery_action(status, generation, plan_sha256):  # noqa: C901, PLR0911, PLR0912 -- ordered evidence checks retain each rejection boundary; each evidence failure retains its distinct reason
    """Return WAIT, RECOVER or FAILED; malformed/mismatched evidence is an error."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,30}", generation):
        raise ValueError("Invalid generation")
    if not re.fullmatch(r"[0-9a-f]{64}", plan_sha256):
        raise ValueError("Invalid plan digest")
    if status.get("generation") != generation or status.get("plan_sha256") != plan_sha256:
        raise ValueError("Status belongs to another plan")
    for name in ("campaign", "recovery"):
        unit = status.get(name)
        if not isinstance(unit, dict) or unit.get("LoadState") != "loaded":
            raise ValueError("Unit missing or not loaded")
        if unit.get("ActiveState") not in (
            "active",
            "activating",
            "deactivating",
            "inactive",
            "failed",
        ):
            raise ValueError("Unknown unit state")
    # Never race a still-running writer, even when a completion file exists.
    if any(
        status[name]["ActiveState"] in ("active", "activating", "deactivating")
        for name in ("campaign", "recovery")
    ):
        return "WAIT"
    if status.get("recovery_failure") is not None:
        return "FAILED"
    marker = status.get("recovery_completion")
    if marker is None:
        return "FAILED" if status["recovery"]["ActiveState"] == "failed" else "WAIT"
    expected = {
        "schema": "dudect-recovery-completion/1",
        "generation": generation,
        "plan_sha256": plan_sha256,
        "complete": True,
    }
    if any(marker.get(key) != value for key, value in expected.items()):
        raise ValueError("Incomplete or mismatched durable recovery marker")
    for key in ("receipt_sha256", "upload_progress_sha256"):
        if not isinstance(marker.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", marker[key]):
            raise ValueError("Missing durable recovery digest")
    if (
        status.get("receipt_sha256") != marker["receipt_sha256"]
        or status.get("upload_progress_sha256") != marker["upload_progress_sha256"]
    ):
        raise ValueError("Recovery files changed after completion")
    if status["recovery"].get("Result") != "success":
        return "FAILED"
    # Acquisition failure is deliberately not rejected here: recover partial
    # evidence too. Its result remains an unsuccessful acquisition.
    return "RECOVER"
