"""Observe allowlisted local Nix inputs without probing or changing any cache."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, urlsplit

if TYPE_CHECKING:
    from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "validation"))
import process_cleanup_receipts as cleanup_receipts
from database_execution import cancellation_scope, check_cancellation, stop_process_group

SETTINGS = (
    "substituters",
    "trusted-substituters",
    "trusted-public-keys",
    "require-sigs",
    "netrc-file",
    "fallback",
    "narinfo-cache-negative-ttl",
)
PUBLIC_HOSTS = {"cache.nixos.org", "cache.flakehub.com", "edge.cache.flakehub.com"}
STORE_PATH = re.compile(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+")
PACKAGE_PATH = re.compile(r"/nix/store/[0-9a-z]{32}-aegaeon-database-tests-[0-9.+_-]+")
HASH = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")
WORK_SECONDS = 30.0
CONFIG_BYTES = 64 * 1024
METADATA_BYTES = 16 * 1024 * 1024
MAX_PATHS = 2048


def query(  # noqa: C901, PLR0912, PLR0915 - one bounded process and pipe lifetime.
    arguments: list[str],
    report: dict[str, Any],
    deadline: float,
    *,
    byte_limit: int = CONFIG_BYTES,
) -> bytes | None:
    """Keep raw output only in memory; stop the owned group even on setup failure."""
    state: dict[str, Any] = {"status": "not_started", "cleanup_confirmed": True}
    report["queries"].append(state)
    check_cancellation()
    if time.monotonic() >= deadline:
        state["status"] = "budget_exhausted"
        return None
    process = None
    receipt = cleanup_receipts.begin()
    output = bytearray()
    primary: BaseException | None = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            ["nix", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        state.update(status="running", cleanup_confirmed=False, pid=process.pid)
        cleanup_receipts.update(receipt, group=process.pid)
        size = 0
        with selectors.DefaultSelector() as watcher:
            for stream in (cast("BinaryIO", process.stdout), cast("BinaryIO", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                watcher.register(stream, selectors.EVENT_READ)
            while watcher.get_map():
                check_cancellation()
                if time.monotonic() >= deadline:
                    state["status"] = "timeout"
                    break
                # Do not await EOF from an inherited writer after the leader exits.
                if process.poll() is not None:
                    stop_process_group(process, grace=0)
                for key, _ in watcher.select(
                    timeout=min(0.05, max(0, deadline - time.monotonic()))
                ):
                    chunk = os.read(key.fd, min(16384, byte_limit - size + 1))
                    if not chunk:
                        watcher.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > byte_limit:
                        state["status"] = "output_limit"
                        break
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
                if state["status"] == "output_limit":
                    break
            if state["status"] == "running":
                while process.poll() is None:
                    check_cancellation()
                    if time.monotonic() >= deadline:
                        state["status"] = "timeout"
                        break
                    time.sleep(0.01)
            state["observed_returncode"] = process.poll()
            state["captured_stdout_bytes"] = len(output)
            state["observed_output_bytes"] = size
            if state["status"] == "running":
                state["status"] = "ok" if process.returncode == 0 else "command_failed"
    except BaseException as error:
        primary = error
        # Exception text/argv/stdout/stderr may contain secrets: never serialize them.
        state["status"] = "interrupted" if isinstance(error, SystemExit) else "observer_failed"
        raise
    finally:
        try:
            if process is not None:
                stop_process_group(process, grace=0)
                cleanup_receipts.update(receipt, confirmed=True)
                state["cleanup_confirmed"] = True
        except BaseException:  # noqa: BLE001 - preserve primary cancellation and record unconfirmed cleanup.
            state["cleanup_confirmed"] = False
            if primary is None:
                raise RuntimeError("cache observation cleanup unconfirmed") from None
            primary.add_note("cache observation cleanup unconfirmed")
        finally:
            if process is not None:
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        pipe.close()
            state["query_duration_seconds"] = time.monotonic() - started
    check_cancellation()
    return bytes(output) if state["status"] == "ok" else None


def public_uri(value: str) -> dict[str, Any]:
    """Only known public cache roots or loopback roots may leave this process."""
    try:
        uri = urlsplit(value)
        if (
            uri.scheme not in {"http", "https"}
            or uri.hostname not in PUBLIC_HOSTS | {"localhost", "127.0.0.1", "::1"}
            or uri.username is not None
            or uri.password is not None
            or uri.path not in {"", "/"}
            or uri.fragment
        ):
            return {"status": "redacted"}
        parameters = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
        safe: dict[str, str] = {}
        for name, item in parameters:
            if name in safe or not (
                (name == "trusted" and item in {"0", "1", "true", "false"})
                or (name == "priority" and re.fullmatch(r"[0-9]{1,6}", item))
                or (name == "compression" and item in {"none", "xz", "zstd", "bzip2", "gzip"})
            ):
                return {"status": "redacted"}
            safe[name] = item
        return {  # noqa: TRY300 - the URI port accessor can also reject malformed input.
            "status": "observed",
            "scheme": uri.scheme,
            "host": uri.hostname,
            "port": uri.port,
            "parameters": safe,
            "role": "public_cache" if uri.hostname in PUBLIC_HOSTS else "local_proxy",
        }
    except ValueError:
        return {"status": "redacted"}


def public_key(value: str) -> dict[str, str]:
    match = re.fullmatch(
        r"(cache\.nixos\.org-1|cache\.flakehub\.com-[0-9]+):([A-Za-z0-9+/]{43}=)", value
    )
    if match is None:
        return {"status": "redacted"}
    decoded = base64.b64decode(match[2], validate=True)
    if len(decoded) != 32:
        return {"status": "redacted"}
    return {
        "status": "observed",
        "name": match[1],
        "key_sha256": hashlib.sha256(decoded).hexdigest(),
    }


def setting(name: str, raw: bytes) -> dict[str, Any]:
    value = raw.decode("utf-8", errors="strict").strip()
    if name in {"substituters", "trusted-substituters"}:
        entries = [public_uri(item) for item in value.split()]
        return {
            "status": "partial"
            if any(item["status"] != "observed" for item in entries)
            else "observed",
            "entries": entries,
        }
    if name == "trusted-public-keys":
        entries = [public_key(item) for item in value.split()]
        return {
            "status": "partial"
            if any(item["status"] != "observed" for item in entries)
            else "observed",
            "entries": entries,
        }
    if name == "netrc-file":
        classification = {"": "unset", "/nix/var/determinate/netrc": "determinate_default"}
        return {
            "status": "observed",
            "classification": classification.get(value, "other_path_redacted"),
        }
    if name in {"require-sigs", "fallback"} and value in {"true", "false"}:
        return {"status": "observed", "value": value == "true"}
    if name == "narinfo-cache-negative-ttl" and re.fullmatch(r"[0-9]{1,10}", value):
        return {"status": "observed", "seconds": int(value)}
    raise ValueError("unsupported setting representation")


def closure(raw: bytes, package: str) -> dict[str, Any]:  # noqa: PLR0912 - validate the entire finite closure before publishing.
    data = json.loads(raw)
    if not isinstance(data, dict) or not 1 <= len(data) <= MAX_PATHS or package not in data:
        raise ValueError("invalid local closure")
    entries: dict[str, Any] = {}
    for path, row in data.items():
        if not STORE_PATH.fullmatch(path) or not isinstance(row, dict):
            raise ValueError("invalid local path")
        nar_hash, size, references = row.get("narHash"), row.get("narSize"), row.get("references")
        if (
            not isinstance(nar_hash, str)
            or not HASH.fullmatch(nar_hash)
            or type(size) is not int
            or not 0 < size < 2**63
            or not isinstance(references, list)
            or len(references) > MAX_PATHS
            or any(not isinstance(ref, str) or ref not in data for ref in references)
        ):
            raise ValueError("incomplete local closure")
        deriver = row.get("deriver")
        if deriver is not None and (
            not isinstance(deriver, str) or not STORE_PATH.fullmatch(deriver)
        ):
            raise ValueError("invalid local deriver")
        signatures = row.get("signatures", [])
        if not isinstance(signatures, list) or any(not isinstance(sig, str) for sig in signatures):
            raise ValueError("invalid local signatures")
        names = sorted({sig.split(":", 1)[0] for sig in signatures})
        entries[path] = {
            "nar_hash": nar_hash,
            "nar_size": size,
            "references": sorted(set(references)),
            "deriver": deriver,
            "signature_names": [
                name
                for name in names
                if re.fullmatch(r"cache\.(nixos\.org-1|flakehub\.com-[0-9]+)", name)
            ],
            "redacted_signature_names": sum(
                re.fullmatch(r"cache\.(nixos\.org-1|flakehub\.com-[0-9]+)", name) is None
                for name in names
            ),
        }
    reached, pending = set(), [package]
    while pending:
        path = pending.pop()
        if path not in reached:
            reached.add(path)
            pending.extend(entries[path]["references"])
    if reached != set(entries):
        raise ValueError("unrelated local paths")
    return {
        "status": "observed",
        "package": package,
        "paths": entries,
        "path_count": len(entries),
        "nar_bytes": sum(row["nar_size"] for row in entries.values()),
        "contents_rehashed": False,
        "signatures_verified": False,
        "observation_scope": "local_daemon_store_metadata",
    }


def context() -> dict[str, str]:
    allowed = {
        "GITHUB_RUN_ID": r"[0-9]+",
        "GITHUB_RUN_ATTEMPT": r"[0-9]+",
        "GITHUB_SHA": r"[0-9a-f]{40}",
        "GITHUB_REPOSITORY": r"codetakt/aegaeon",
        "GITHUB_EVENT_NAME": r"pull_request|merge_group|push|workflow_dispatch|workflow_call",
    }
    return {
        name: value
        for name, pattern in allowed.items()
        if (value := os.environ.get(name)) is not None and re.fullmatch(pattern, value)
    }


def collect(role: str, package: str | None, report: dict[str, Any]) -> None:
    deadline = time.monotonic() + WORK_SECONDS
    raw = query(["--version"], report, min(deadline, time.monotonic() + 4))
    report["queries"][-1]["operation"] = "nix_version"
    number = rb"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}"
    version = re.fullmatch(
        rb"nix \((Nix|Determinate Nix (" + number + rb"))\) (" + number + rb")\s*",
        raw or b"",
    )
    report["nix_version"] = version[3].decode("ascii") if version else None
    report["determinate_nix_version"] = (
        version[2].decode("ascii") if version and version[2] else None
    )
    for name in SETTINGS:
        raw = query(["config", "show", name], report, min(deadline, time.monotonic() + 4))
        report["queries"][-1]["operation"] = name
        try:
            report["settings"][name] = (
                setting(name, raw) if raw is not None else {"status": "unavailable"}
            )
        except (ValueError, UnicodeError):
            report["settings"][name] = {"status": "unsupported"}
    if role == "core":
        raw = query(
            [
                "--offline",
                "--option",
                "allow-import-from-derivation",
                "false",
                "eval",
                "--no-write-lock-file",
                "--raw",
                ".#packages.x86_64-linux.database-tests.outPath",
            ],
            report,
            min(deadline, time.monotonic() + 8),
        )
        report["queries"][-1]["operation"] = "pure_package_declaration"
        package = raw.decode("ascii").strip() if raw is not None and raw.isascii() else None
    if package is None or not PACKAGE_PATH.fullmatch(package):
        report["closure"] = {"status": "package_unavailable"}
        return
    report["package"] = package
    raw = query(
        ["--offline", "--store", "daemon", "path-info", "--json", "--recursive", package],
        report,
        min(deadline, time.monotonic() + 8),
        byte_limit=METADATA_BYTES,
    )
    report["queries"][-1]["operation"] = "local_closure_metadata"
    try:
        report["closure"] = closure(raw, package) if raw is not None else {"status": "unavailable"}
    except (ValueError, TypeError):
        report["closure"] = {"status": "unsupported"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("core", "database"), required=True)
    parser.add_argument("--package")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    report: dict[str, Any] = {
        "schema_version": 1,
        "role": args.role,
        "context": context(),
        "started_at": datetime.now(UTC).isoformat(),
        "queries": [],
        "settings": {},
        "settings_scope": "effective_client_config_only",
        "daemon_auth_trust": "not_observed",
        "status": "partial",
        "auth_validated": False,
        "remote_availability": "not_observed",
        "cache_transfer_performed": False,
        "limits": {
            "work_seconds": WORK_SECONDS,
            "query_output_bytes": METADATA_BYTES,
            "closure_paths": MAX_PATHS,
        },
    }
    status = 0
    try:
        with cancellation_scope():
            collect(args.role, args.package, report)
        if (
            report["closure"]["status"] == "observed"
            and all(row["status"] == "observed" for row in report["settings"].values())
            and all(row["status"] == "ok" for row in report["queries"])
        ):
            report["status"] = "observed"
    except BaseException as error:  # noqa: BLE001 - write only allowlisted diagnostic state, never exception output.
        status = error.code if isinstance(error, SystemExit) and isinstance(error.code, int) else 1
        report["status"] = "interrupted" if isinstance(error, SystemExit) else "observer_failed"
    report["finished_at"] = datetime.now(UTC).isoformat()
    report["collector_duration_seconds"] = time.monotonic() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
