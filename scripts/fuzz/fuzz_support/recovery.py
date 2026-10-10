"""Bind cleanup and recovery to the output identities saved with current evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from contextlib import ExitStack
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

from fuzz_support.archives import (
    archive_directory,
)
from fuzz_support.directories import bound_child_directory
from fuzz_support.execution import (
    collected_execution,
    execution_cache,
)
from fuzz_support.filesystem import (
    FUZZ_DIR,
    RECOVERY_EVIDENCE_NAMES,
    RECOVERY_RAW_NAMES,
    copy_evidence_file,
    digest,
    evidence_snapshot,
    evidence_text,
    invalid,
    overlaps,
    owned_raw_root,
    raw_inventory,
    validate_regular_destination,
    validate_restore_cargo_home,
    write_json,
)
from fuzz_support.source import (
    configured_cache,
    source_hashes,
)


def recovery_directory(directory: Path, run_id: str, *, create: bool = False) -> Path:
    if str(uuid.UUID(run_id)) != run_id:
        invalid("malformed fuzz recovery run ID")
    owned = directory.resolve()
    configured_cache(directory)
    if any(owned.is_relative_to(FUZZ_DIR / name) for name in (*RECOVERY_RAW_NAMES, "target")):
        invalid("fuzz recovery evidence must be outside transient output roots")
    container = owned / "cleanup-recovery"
    recovery = container / run_id
    if container.is_symlink() or recovery.is_symlink():
        invalid("fuzz recovery directory cannot be a symlink")
    if create:
        recovery.mkdir(parents=True, exist_ok=False)
    if not recovery.is_dir() or recovery.resolve() != recovery:
        invalid("fuzz recovery directory is unavailable or unsafe")
    return recovery


def cleanup_root_binding(path: Path) -> dict:
    """Bind the lexical parent route and an optional owned directory inode."""
    with archive_directory(path.parent) as (parent, identities):
        try:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            identity = None
        else:
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                invalid("fuzz cleanup root must be a producer-owned directory")
            identity = [info.st_dev, info.st_ino, info.st_uid]
        return {
            "path": str(path),
            "parents": [list(identity) for identity in identities],
            "root": identity,
        }


def require_cleanup_root(path: Path, expected: dict, *, allow_removed: bool = False) -> None:
    current = cleanup_root_binding(path)
    if current != expected and not (
        allow_removed and expected.get("root") is not None and current == {**expected, "root": None}
    ):
        invalid("fuzz cleanup root identity or presence changed")


def cleanup_paths(cache: Path) -> dict[str, Path]:
    return {"cache": cache, **{name: FUZZ_DIR / name for name in RECOVERY_RAW_NAMES}}


def validate_cleanup_roots(cache: Path, manifest: dict) -> dict[str, Path]:
    paths = cleanup_paths(cache)
    bindings = manifest.get("cleanup_roots")
    if not isinstance(bindings, dict) or set(bindings) != set(paths):
        invalid("fuzz cleanup recovery lacks root identity bindings")
    for name, path in paths.items():
        expected = bindings[name]
        if not isinstance(expected, dict) or set(expected) != {"path", "parents", "root"}:
            invalid("fuzz cleanup root binding is malformed")
        if (
            expected["path"] != str(path)
            or (name == "cache" and expected["root"] is None)
            or (
                name != "cache"
                and (expected["root"] is not None) != manifest["raw"][name]["present"]
            )
        ):
            invalid("fuzz cleanup root binding differs from current recovery")
        require_cleanup_root(path, expected)
    return paths


def cleanup_entry_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode)


def cleanup_entry_record(info: os.stat_result) -> dict:
    record = {"identity": list(cleanup_entry_identity(info)), "mode": stat.S_IMODE(info.st_mode)}
    if not stat.S_ISDIR(info.st_mode):
        record.update(size=info.st_size, mtime_ns=info.st_mtime_ns)
    return record


def walk_cleanup_snapshot(
    opened: int, device: int, check: Callable[[], None], prefix: str, result: dict
) -> None:
    check()
    names = sorted(os.listdir(opened))
    for name in names:
        check()
        info = os.stat(name, dir_fd=opened, follow_symlinks=False)
        if info.st_uid != os.geteuid() or info.st_dev != device:
            invalid("fuzz cleanup entry ownership or filesystem is unsupported")
        relative = prefix + name
        result[relative] = cleanup_entry_record(info)
        if stat.S_ISDIR(info.st_mode):
            with bound_child_directory(opened, name, check) as (child, check_child):
                if cleanup_entry_identity(os.fstat(child)) != cleanup_entry_identity(info):
                    invalid("fuzz cleanup directory changed before binding")
                walk_cleanup_snapshot(child, device, check_child, relative + "/", result)
        elif stat.S_ISLNK(info.st_mode):
            result[relative]["target"] = os.readlink(name, dir_fd=opened)
        elif not stat.S_ISREG(info.st_mode):
            invalid("fuzz cleanup refuses a special filesystem entry")
    check()
    if sorted(os.listdir(opened)) != names:
        invalid("fuzz cleanup tree membership changed while binding")


def cleanup_tree_snapshot(path: Path, binding: dict) -> dict:
    """Inventory output identities without following a single nested link."""
    require_cleanup_root(path, binding)
    if binding["root"] is None:
        return {}
    result = {}
    with archive_directory(path.parent) as (parent, _):
        descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:

            def check_root() -> None:
                require_cleanup_root(path, binding)
                if list(cleanup_entry_identity(os.fstat(descriptor)))[:3] != binding["root"]:
                    invalid("fuzz cleanup opened root differs from binding")

            walk_cleanup_snapshot(descriptor, binding["root"][0], check_root, "", result)
        finally:
            os.close(descriptor)
    return result


def remove_owned_cleanup_tree(  # noqa: PLR0912 - explicit filesystem type and identity checks
    descriptor: int,
    device: int,
    check_root: Callable[[], None],
    expected: dict,
    prefix: str = "",
) -> None:
    """Remove entries through pinned directory FDs, never by following links.

    Checks reject observed namespace changes. They are not a systemwide
    transaction against arbitrary same-UID mutation between filesystem calls.
    """
    for name in sorted(os.listdir(descriptor)):
        check_root()
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        relative = prefix + name
        saved = expected.get(relative)
        if saved is None or cleanup_entry_record(before) != {
            k: v for k, v in saved.items() if k != "target"
        }:
            invalid("fuzz cleanup entry differs from its backup identity")
        if before.st_uid != os.geteuid() or before.st_dev != device:
            invalid("fuzz cleanup entry ownership or filesystem is unsupported")
        if stat.S_ISDIR(before.st_mode):
            with bound_child_directory(descriptor, name, check_root) as (child, check_child):
                if cleanup_entry_identity(os.fstat(child)) != cleanup_entry_identity(before):
                    invalid("fuzz cleanup directory changed before traversal")
                remove_owned_cleanup_tree(child, device, check_child, expected, relative + "/")
            check_root()
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if cleanup_entry_identity(current) != cleanup_entry_identity(before):
                invalid("fuzz cleanup directory changed before removal")
            os.rmdir(name, dir_fd=descriptor)
        elif stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            check_root()
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if cleanup_entry_record(current) != cleanup_entry_record(before):
                invalid("fuzz cleanup entry changed before removal")
            if (
                stat.S_ISLNK(before.st_mode)
                and os.readlink(name, dir_fd=descriptor) != saved["target"]
            ):
                invalid("fuzz cleanup literal link changed before removal")
            os.unlink(name, dir_fd=descriptor)
        else:
            invalid("fuzz cleanup refuses a special filesystem entry")


def remove_cleanup(directory: Path, run_id: str) -> None:
    cache, manifest = cleanup_context(directory, run_id)
    paths = validate_cleanup_roots(cache, manifest)
    with ExitStack() as handles:
        opened = {}
        # Pin every root before the first deletion. A preexisting mismatch must
        # preserve every root, including roots later in the cleanup order.
        for name, path in paths.items():
            parent, _ = handles.enter_context(archive_directory(path.parent))
            expected = manifest["cleanup_roots"][name]
            require_cleanup_root(path, expected)
            if expected["root"] is None:
                continue
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            handles.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if [info.st_dev, info.st_ino, info.st_uid] != expected["root"]:
                invalid("fuzz cleanup root changed before opening")
            opened[name] = (parent, descriptor, info.st_dev)
        for name, (parent, descriptor, device) in opened.items():
            path = paths[name]
            expected = manifest["cleanup_roots"][name]

            def check_root(path: Path = path, expected: dict = expected) -> None:
                require_cleanup_root(path, expected)

            check_root()
            remove_owned_cleanup_tree(
                descriptor, device, check_root, manifest["cleanup_entries"][name]
            )
            check_root()
            os.rmdir(path.name, dir_fd=parent)
        for name, path in paths.items():
            require_cleanup_root(path, {**manifest["cleanup_roots"][name], "root": None})


def copy_raw_backups(recovery: Path) -> dict:
    raw = recovery / "raw"
    raw.mkdir()
    records = {}
    for name in RECOVERY_RAW_NAMES:
        source = owned_raw_root(name)
        present = source.exists()
        inventory = raw_inventory(source) if present else {}
        if present:
            shutil.copytree(source, raw / name, symlinks=True, copy_function=copy_evidence_file)
            if raw_inventory(raw / name) != inventory or raw_inventory(source) != inventory:
                invalid("fuzz raw evidence changed during recovery copy")
        records[name] = {"present": present, "inventory": inventory}
    return records


def backup_cleanup(directory: Path) -> str:  # noqa: PLR0912 - complete backup consistency checks
    data = collected_execution(directory)
    if data["status"] != "awaiting-cleanup":
        invalid("only successful current fuzz execution can prepare cleanup")
    if data["target_dir"] != str(configured_cache(directory)):
        invalid("fuzz cleanup cache differs from current execution")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = directory / name
        snapshots[name] = evidence_snapshot(path)
    recovery = recovery_directory(directory, data["run_id"], create=True)
    evidence = recovery / "evidence"
    evidence.mkdir()
    for name, content in snapshots.items():
        (evidence / name).write_bytes(content)
    cache = execution_cache(directory)
    bindings = {name: cleanup_root_binding(path) for name, path in cleanup_paths(cache).items()}
    if bindings["cache"]["root"] is None:
        invalid("fuzz current build cache is missing")
    entries = {
        name: cleanup_tree_snapshot(path, bindings[name])
        for name, path in cleanup_paths(cache).items()
    }
    records = copy_raw_backups(recovery)
    for name, path in cleanup_paths(cache).items():
        require_cleanup_root(path, bindings[name])
        if cleanup_tree_snapshot(path, bindings[name]) != entries[name]:
            invalid("fuzz cleanup output identities changed during backup")
    if any(evidence_snapshot(directory / name) != content for name, content in snapshots.items()):
        invalid("fuzz collection evidence changed during recovery copy")
    if source_hashes(data["selected_targets"]) != data["source"]["files"]:
        invalid("fuzz source identity changed before cleanup")
    write_json(
        recovery / "backup-ready.json",
        {
            "run_id": data["run_id"],
            "source": data["source"]["files"],
            "raw": records,
            "cleanup_roots": bindings,
            "cleanup_entries": entries,
            "evidence": {name: digest(evidence / name) for name in snapshots},
        },
    )
    return data["run_id"]


def validate_raw_backups(recovery: Path, manifest: dict) -> None:
    for name, record in manifest["raw"].items():
        source = recovery / "raw" / name
        if not isinstance(record["present"], bool) or source.is_symlink():
            invalid("fuzz recovery raw presence or root is unsafe")
        if source.exists() != record["present"]:
            invalid("fuzz recovery raw copy presence changed")
        if record["present"] and (
            not source.is_dir() or raw_inventory(source) != record["inventory"]
        ):
            invalid("fuzz recovery raw copy is missing or changed")


def load_cleanup_backup(directory: Path, run_id: str) -> tuple[Path, dict, dict]:
    recovery = recovery_directory(directory, run_id)
    manifest_path = recovery / "backup-ready.json"
    if manifest_path.is_symlink():
        invalid("fuzz recovery manifest cannot be a symlink")
    manifest = json.loads(evidence_text(manifest_path))
    if manifest["run_id"] != run_id or set(manifest["raw"]) != set(RECOVERY_RAW_NAMES):
        invalid("fuzz recovery manifest does not bind the current run")
    for name in ("raw", "evidence"):
        container = recovery / name
        if container.is_symlink() or not container.is_dir() or container.resolve() != container:
            invalid("fuzz recovery container is missing or unsafe")
    snapshots = {}
    for name in RECOVERY_EVIDENCE_NAMES:
        path = recovery / "evidence" / name
        snapshot = evidence_snapshot(path)
        if hashlib.sha256(snapshot).hexdigest() != manifest["evidence"][name]:
            invalid("fuzz recovery evidence is missing or changed")
        snapshots[name] = snapshot
    data = json.loads(snapshots["execution.json"])
    marker = json.loads(snapshots["collection.ok"])
    if (
        data["run_id"] != run_id
        or marker["run_id"] != run_id
        or data["source"]["files"] != manifest["source"]
        or marker["summary_sha256"] != manifest["evidence"]["collection-summary.json"]
    ):
        invalid("fuzz recovery identity or collection receipt is inconsistent")
    validate_raw_backups(recovery, manifest)
    return recovery, manifest, snapshots


def restore_missing_file(
    source: int, destination: int, name: str, expected: dict, check_destination: Callable[[], None]
) -> None:
    source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source)
    try:
        opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or cleanup_entry_record(opened)
            != cleanup_entry_record(os.stat(name, dir_fd=source, follow_symlinks=False))
            or opened.st_nlink != 1
        ):
            invalid("fuzz recovery source file changed before opening")
        check_destination()
        output = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IMODE(opened.st_mode),
            dir_fd=destination,
        )
        try:
            digest = hashlib.sha256()
            with (
                os.fdopen(source_fd, "rb", closefd=False) as content,
                os.fdopen(output, "wb", closefd=False) as sink,
            ):
                while block := content.read(1024 * 1024):
                    check_destination()
                    digest.update(block)
                    sink.write(block)
                sink.flush()
            if digest.hexdigest() != expected["sha256"] or cleanup_entry_record(
                os.fstat(source_fd)
            ) != cleanup_entry_record(opened):
                invalid("fuzz recovery source bytes changed while copying")
            os.fchmod(output, stat.S_IMODE(opened.st_mode))
            os.utime(output, ns=(opened.st_atime_ns, opened.st_mtime_ns))
            check_destination()
            if cleanup_entry_identity(
                os.stat(name, dir_fd=destination, follow_symlinks=False)
            ) != cleanup_entry_identity(os.fstat(output)):
                invalid("fuzz recovery output identity changed")
        finally:
            os.close(output)
    finally:
        os.close(source_fd)


def restore_missing_entries(  # noqa: C901, PLR0912, PLR0913, PLR0915 - explicit no-overwrite entry types
    source: int,
    destination: int,
    inventory: dict,
    remaining: dict,
    check_destination: Callable[[], None],
    *,
    prefix: str = "",
) -> None:
    """Reconstruct missing entries through pinned FDs; never overwrite an entry."""
    for name in sorted(os.listdir(source)):
        relative = prefix + name
        expected = inventory.get(relative)
        if expected is None:
            invalid("fuzz recovery source has an unexpected entry")
        check_destination()
        info = os.stat(name, dir_fd=source, follow_symlinks=False)
        try:
            existing = os.stat(name, dir_fd=destination, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and cleanup_entry_record(existing) != {
            k: v for k, v in remaining.get(relative, {}).items() if k != "target"
        }:
            invalid("fuzz recovery destination entry was substituted")
        if expected["type"] == "directory" and stat.S_ISDIR(info.st_mode):
            if existing is None:
                os.mkdir(name, mode=stat.S_IMODE(info.st_mode), dir_fd=destination)
            source_child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source
            )
            try:
                with bound_child_directory(destination, name, check_destination) as (
                    child,
                    check_child,
                ):
                    restore_missing_entries(
                        source_child,
                        child,
                        inventory,
                        remaining,
                        check_child,
                        prefix=relative + "/",
                    )
            finally:
                os.close(source_child)
        elif expected["type"] == "symlink" and stat.S_ISLNK(info.st_mode):
            target = os.readlink(name, dir_fd=source)
            if target != expected["target"]:
                invalid("fuzz recovery literal link changed")
            if existing is None:
                check_destination()
                os.symlink(target, name, dir_fd=destination)
            elif (
                not stat.S_ISLNK(existing.st_mode)
                or os.readlink(name, dir_fd=destination) != target
            ):
                invalid("fuzz recovery refuses an existing changed link")
        elif expected["type"] == "file" and stat.S_ISREG(info.st_mode):
            if existing is not None:
                continue  # All retained original bytes were checked before any write.
            restore_missing_file(source, destination, name, expected, check_destination)
        else:
            invalid("fuzz recovery entry type differs from its saved inventory")


def remaining_raw_entries(manifest: dict) -> dict:
    remaining = {}
    for name in RECOVERY_RAW_NAMES:
        path = FUZZ_DIR / name
        binding = manifest["cleanup_roots"][name]
        require_cleanup_root(path, binding, allow_removed=True)
        if path.exists():
            current = cleanup_tree_snapshot(path, binding)
            expected = manifest["cleanup_entries"][name]
            if any(expected.get(key) != value for key, value in current.items()):
                invalid("fuzz recovery remaining output identity changed")
            raw = raw_inventory(path)
            if any(
                manifest["raw"][name]["inventory"].get(key) != value for key, value in raw.items()
            ):
                invalid("fuzz recovery refuses changed or additional raw bytes")
            remaining[name] = current
        else:
            remaining[name] = {}
    return remaining


def restore_one_raw_root(  # noqa: PLR0915 - pin and validate an exclusively restored root
    name: str, recovery: Path, manifest: dict, remaining: dict
) -> None:
    record = manifest["raw"][name]
    path = FUZZ_DIR / name
    binding = manifest["cleanup_roots"][name]
    with archive_directory(path.parent) as (parent, _):
        require_cleanup_root(path, binding, allow_removed=True)
        created = not path.exists()
        if created:
            os.mkdir(path.name, dir_fd=parent)
        else:
            require_cleanup_root(path, binding)
        target = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            identity = cleanup_entry_identity(os.fstat(target))
            if not created and list(identity)[:3] != binding["root"]:
                invalid("fuzz recovery original root changed before opening")
            current_binding = {**binding, "root": list(identity)[:3]}

            def check_root(path: Path = path, binding: dict = current_binding) -> None:
                require_cleanup_root(path, binding)

            check_root()
            with archive_directory(recovery / "raw") as (raw_parent, _):
                source = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=raw_parent
                )
                try:
                    restore_missing_entries(
                        source, target, record["inventory"], remaining, check_root
                    )
                finally:
                    os.close(source)
            check_root()
        finally:
            os.close(target)
    if raw_inventory(path) != record["inventory"]:
        invalid("fuzz restored evidence differs from its recovery copy")


def restore_raw_copy(recovery: Path, manifest: dict) -> None:
    # Check every remaining destination before the first exclusive addition.
    remaining = remaining_raw_entries(manifest)
    for name, record in manifest["raw"].items():
        if not record["present"]:
            continue
        restore_one_raw_root(name, recovery, manifest, remaining[name])


def restore_cleanup(directory: Path, run_id: str, exit_code: int, reason: str) -> bool:
    if reason not in ("removal", "receipt"):
        invalid("unknown fuzz cleanup recovery reason")
    validate_restore_cargo_home(directory)
    recovery, manifest, snapshots = load_cleanup_backup(directory, run_id)
    report = {
        "run_id": run_id,
        "reason": reason,
        "status": "restored",
        "cleanup_exit_code": exit_code,
    }
    try:
        restore_raw_copy(recovery, manifest)
    except (OSError, ValueError) as error:
        report.update(status="failed", error=str(error))
        print(
            f"[security] fuzz raw restoration failed; recovery copies retained: {error}",
            file=sys.stderr,
        )
    data = json.loads(snapshots["execution.json"])
    summary = json.loads(snapshots["run_summary.json"])
    data.update(status="failed", cleanup_exit_code=exit_code, cleanup_recovery=report)
    summary.update(status="failed", execution=data)
    try:
        for name in RECOVERY_EVIDENCE_NAMES:
            if (directory / name).is_symlink():
                invalid("fuzz evidence restoration refuses existing symlink traversal")
        for name in ("collection.ok", "collection-summary.json"):
            validate_regular_destination(directory / name)
        for name in ("collection.ok", "collection-summary.json"):
            (directory / name).write_bytes(snapshots[name])
        write_json(directory / "execution.json", data)
        write_json(directory / "run_summary.json", summary)
    except (OSError, ValueError) as error:
        report.update(status="failed", evidence_error=str(error))
        print(
            f"[security] fuzz evidence restoration failed; original evidence retained: {error}",
            file=sys.stderr,
        )
    # Preserve the verified backup and append recovery disposition, even after failure.
    write_json(recovery / f"recovery-result-{uuid.uuid4()}.json", report)
    return report["status"] == "restored"


def cleanup_context(directory: Path, run_id: str) -> tuple[Path, dict]:
    data = collected_execution(directory)
    recovery, manifest, snapshots = load_cleanup_backup(directory, run_id)
    cache = execution_cache(directory)
    if not cache.is_dir():
        invalid("fuzz current build cache is missing")
    saved = json.loads(snapshots["execution.json"])
    if data != saved or source_hashes(data["selected_targets"]) != manifest["source"]:
        invalid("fuzz cleanup cache is not bound to current recovery evidence")
    if data["target_dir"] != str(cache) or overlaps(cache, recovery):
        invalid("fuzz cleanup cache differs from current execution or overlaps recovery")
    paths = validate_cleanup_roots(cache, manifest)
    entries = manifest.get("cleanup_entries")
    if not isinstance(entries, dict) or set(entries) != set(paths):
        invalid("fuzz recovery lacks complete output identity inventory")
    for name, path in paths.items():
        if cleanup_tree_snapshot(path, manifest["cleanup_roots"][name]) != entries[name]:
            invalid("fuzz cleanup output membership or identities changed after backup")
        if (
            name != "cache"
            and manifest["raw"][name]["present"]
            and raw_inventory(path) != manifest["raw"][name]["inventory"]
        ):
            invalid("fuzz cleanup raw bytes changed after backup")
    return cache, manifest


def cleanup_cache(directory: Path, run_id: str) -> Path:
    return cleanup_context(directory, run_id)[0]
