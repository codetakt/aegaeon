"""Construct and publish corpus, crash and upload archives through owned descriptors."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
import uuid
from contextlib import ExitStack, contextmanager, suppress
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

from fuzz_support.filesystem import (
    ROOT,
    UPLOAD_ROOTS,
    evidence_digest,
    invalid,
    lexical_directory,
    open_evidence_file,
    overlaps,
    raw_inventory,
    validate_cargo_home_paths,
)


class ArchiveContentWriter:
    """Hash the bytes produced by compression, independently of later FD reads."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.sha256 = hashlib.sha256()

    def write(self, block: bytes) -> int:
        written = self.stream.write(block)
        if written != len(block):
            invalid("archive construction encountered a short write")
        self.sha256.update(block)
        return written

    def tell(self) -> int:
        return self.stream.tell()

    def flush(self) -> None:
        self.stream.flush()

    def fileno(self) -> int:
        return self.stream.fileno()


def descriptor_content_digest(descriptor: int) -> bytes:
    with os.fdopen(descriptor, "rb", closefd=False) as stream:
        stream.seek(0)
        observed = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            observed.update(block)
        return observed.digest()


@contextmanager
def archive_directory(directory: Path) -> Iterator[tuple[int, tuple[tuple[int, int], ...]]]:
    route = lexical_directory(directory)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    identities = []
    with ExitStack() as handles:
        descriptor = os.open("/", flags)
        handles.callback(os.close, descriptor)
        for name in ("", *route.parts[1:]):
            if name:
                descriptor = os.open(name, flags, dir_fd=descriptor)
                handles.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            identities.append((info.st_dev, info.st_ino))
        if info.st_uid != os.geteuid():
            invalid("archive directory must belong to the producer")
        yield descriptor, tuple(identities)


def validate_archive_directory(directory: Path, identities: tuple[tuple[int, int], ...]) -> None:
    with archive_directory(directory) as (_, current):
        if current != identities:
            invalid("archive directory route changed during construction")


def owned_archive_entry(directory: int, name: str, descriptor: int) -> bool:
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    opened = os.fstat(descriptor)
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_uid == os.geteuid()
        and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
    )


def verify_archive_stream(stream: BinaryIO, path: Path) -> None:
    stream.seek(0)
    try:
        with tarfile.open(name=str(path), fileobj=stream, mode="r:gz") as archive:
            for member in archive:
                if member.isfile():
                    content = archive.extractfile(member)
                    if content is None:
                        invalid("completed archive has unavailable regular content")
                    with content:
                        while content.read(1024 * 1024):
                            pass
            # Reach gzip EOF as well as tar EOF so CRC/footer failures are blocking.
            while archive.fileobj.read(1024 * 1024):
                pass
    except (tarfile.TarError, EOFError):
        invalid("archive construction did not produce a complete archive")


def write_exclusive_archive(  # noqa: C901, PLR0912, PLR0915 - owned archive publication boundary
    path: Path, roots: list[tuple[Path, str]], keep_archives: int | None = None
) -> None:
    published_link_count = 2
    directory = lexical_directory(path.parent)
    with archive_directory(directory) as (directory_fd, identities):
        temporary = ".archive-" + uuid.uuid4().hex + ".tmp"
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o666,
            dir_fd=directory_fd,
        )
        published = False
        complete = False
        try:
            opened = os.fstat(descriptor)
            if (
                not owned_archive_entry(directory_fd, temporary, descriptor)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
            ):
                invalid("archive temporary must be exclusive and producer-owned before writing")
            with os.fdopen(descriptor, "w+b", closefd=False) as stream:
                constructed = ArchiveContentWriter(stream)
                with tarfile.open(
                    name=str(path), fileobj=constructed, mode="w:gz", dereference=False
                ) as tar:
                    for source, arcname in roots:
                        archive_raw_tree(tar, source, arcname)
                stream.flush()
                constructed_digest = constructed.sha256.digest()
                verify_archive_stream(stream, path)
                if descriptor_content_digest(descriptor) != constructed_digest:
                    invalid("archive content changed after construction readback")
            validate_archive_directory(directory, identities)
            opened = os.fstat(descriptor)
            if (
                not owned_archive_entry(directory_fd, temporary, descriptor)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
            ):
                invalid("archive temporary identity or ownership changed")
            # Atomic no-clobber publication. This does not claim a systemwide
            # namespace transaction against arbitrary same-UID interleavings.
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published = True
            if descriptor_content_digest(descriptor) != constructed_digest:
                invalid("archive content changed during publication")
            if (
                not owned_archive_entry(directory_fd, path.name, descriptor)
                or os.fstat(descriptor).st_nlink != published_link_count
            ):
                invalid("archive publication identity or alias count changed")
            validate_archive_directory(directory, identities)
            if keep_archives is not None:
                names = os.listdir(directory_fd)  # noqa: PTH208 - bound directory fd, no Path equivalent
                archives = sorted(name for name in names if name.endswith(".tar.gz"))
                for name in archives[:-keep_archives]:
                    validate_archive_directory(directory, identities)
                    os.unlink(name, dir_fd=directory_fd)
            if descriptor_content_digest(descriptor) != constructed_digest:
                invalid("archive content changed before completion")
            validate_archive_directory(directory, identities)
            if (
                not owned_archive_entry(directory_fd, temporary, descriptor)
                or not owned_archive_entry(directory_fd, path.name, descriptor)
                or os.fstat(descriptor).st_nlink != published_link_count
            ):
                invalid("archive publication identity or alias count changed before completion")
            complete = True
        finally:
            try:
                if (
                    published
                    and not complete
                    and owned_archive_entry(directory_fd, path.name, descriptor)
                ):
                    with suppress(FileNotFoundError):
                        os.unlink(path.name, dir_fd=directory_fd)
                if owned_archive_entry(directory_fd, temporary, descriptor):
                    with suppress(FileNotFoundError):
                        os.unlink(temporary, dir_fd=directory_fd)
            finally:
                os.close(descriptor)


def upload_inventory() -> dict:
    # Validate every root before any nested content hash/read.
    for name in UPLOAD_ROOTS:
        source = ROOT / name
        lexical_directory(source.parent)
        if source.is_symlink():
            invalid("upload evidence root cannot be a symlink")
        if source.exists() and not (
            source.is_dir()
            or (source.is_file() and name == "security-artifacts/security_status.jsonl")
        ):
            invalid("upload evidence root has an unsupported type")
    inventories = {}
    for name in UPLOAD_ROOTS:
        source = ROOT / name
        if not source.exists():
            inventories[name] = {"present": False}
        elif source.is_dir():
            inventories[name] = {
                "present": True,
                "type": "directory",
                "entries": raw_inventory(source),
            }
        else:
            inventories[name] = {"present": True, "type": "file", "sha256": evidence_digest(source)}
    return inventories


class ArchiveEvidenceReader:
    def __init__(self, content: BinaryIO) -> None:
        self.content = content
        self.sha256 = hashlib.sha256()
        self.size = 0

    def read(self, size: int) -> bytes:
        block = self.content.read(size)
        self.sha256.update(block)
        self.size += len(block)
        return block


def add_evidence_entry(tar: tarfile.TarFile, path: Path, arcname: str, expected: dict) -> None:
    before = path.lstat()
    if expected["type"] == "file" and stat.S_ISREG(before.st_mode):
        with open_evidence_file(path, before) as content:
            info = tar.gettarinfo(str(path), arcname=arcname, fileobj=content)
            if not info.isfile() or info.size != os.fstat(content.fileno()).st_size:
                invalid("upload entry changed before archiving")
            archived = ArchiveEvidenceReader(content)
            tar.addfile(info, archived)
            if archived.size != info.size or archived.sha256.hexdigest() != expected["sha256"]:
                invalid("archive entry content differs from expected inventory")
    else:
        info = tar.gettarinfo(str(path), arcname=arcname)
        if (expected["type"] == "directory" and stat.S_ISDIR(before.st_mode) and info.isdir()) or (
            expected["type"] == "symlink"
            and stat.S_ISLNK(before.st_mode)
            and info.issym()
            and info.linkname == expected["target"]
        ):
            tar.addfile(info)
        else:
            invalid("archive entry type or literal link differs from expected inventory")


def archive_raw_tree(tar: tarfile.TarFile, source: Path, arcname: str) -> None:
    inventory = raw_inventory(source)
    add_evidence_entry(tar, source, arcname, {"type": "directory"})
    for entry, expected in inventory.items():
        add_evidence_entry(tar, source / entry, arcname + "/" + entry, expected)
    if raw_inventory(source) != inventory:
        invalid("raw evidence changed during archiving")


def add_upload_entry(tar: tarfile.TarFile, path: Path, expected: dict) -> None:
    add_evidence_entry(tar, path, path.relative_to(ROOT).as_posix(), expected)


def write_upload_archive(stream: BinaryIO, inventories: dict) -> None:
    with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as tar:
        for name, record in inventories.items():
            if not record["present"]:
                continue
            source = ROOT / name
            add_upload_entry(tar, source, record)
            if record["type"] == "directory":
                for entry, expected in record["entries"].items():
                    add_upload_entry(tar, source / entry, expected)


def package_upload(directory: Path) -> None:  # noqa: C901, PLR0912, PLR0915 - owned upload publication boundary
    validate_cargo_home_paths([ROOT / name for name in UPLOAD_ROOTS], "upload", output=directory)
    output = lexical_directory(directory)
    protected = (*UPLOAD_ROOTS, "artifacts/ct", "artifacts/karamel")
    if any(overlaps(output, ROOT / name) for name in protected):
        invalid("upload output overlaps evidence source")
    if not output.is_relative_to(ROOT / "artifacts") or output == ROOT / "artifacts":
        invalid("upload output must be a dedicated repository artifacts directory")
    if output.exists() and (output.stat().st_uid != os.geteuid() or any(output.iterdir())):
        invalid("upload output must be empty and owned by the producer")
    inventories = upload_inventory()
    output.mkdir(parents=True, exist_ok=True)
    with archive_directory(output) as (directory_fd, identities):
        if os.listdir(directory_fd):  # noqa: PTH208 - bound directory fd, no Path equivalent
            invalid("upload output must be empty and owned by the producer")
        temporary = ".archive-" + uuid.uuid4().hex + ".tmp"
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        entries = [(temporary, "security-evidence.tar.gz", descriptor)]
        published = set()
        complete = False
        published_link_count = 2
        try:
            opened = os.fstat(descriptor)
            if (
                not owned_archive_entry(directory_fd, temporary, descriptor)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
            ):
                invalid("upload temporary must be exclusive and producer-owned before writing")
            with os.fdopen(descriptor, "w+b", closefd=False) as stream:
                writer = ArchiveContentWriter(stream)
                write_upload_archive(writer, inventories)
                stream.flush()
                constructed = writer.sha256
                if upload_inventory() != inventories:
                    invalid("upload evidence changed during packaging")
                verify_archive_stream(stream, output / "security-evidence.tar.gz")
                if descriptor_content_digest(descriptor) != constructed.digest():
                    invalid("upload archive content changed after construction")
            validate_archive_directory(output, identities)
            if (
                not owned_archive_entry(directory_fd, temporary, descriptor)
                or os.fstat(descriptor).st_nlink != 1
            ):
                invalid("upload temporary identity or ownership changed")
            # As with write_exclusive_archive, this is no-clobber publication,
            # not a systemwide namespace transaction against same-UID interleavings.
            os.link(
                temporary,
                "security-evidence.tar.gz",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published.add("security-evidence.tar.gz")
            validate_archive_directory(output, identities)
            if (
                not owned_archive_entry(directory_fd, "security-evidence.tar.gz", descriptor)
                or os.fstat(descriptor).st_nlink != published_link_count
            ):
                invalid("upload archive publication identity or alias count changed")
            manifest_temporary = ".manifest-" + uuid.uuid4().hex + ".tmp"
            manifest_descriptor = os.open(
                manifest_temporary,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            entries.append((manifest_temporary, "manifest.json", manifest_descriptor))
            manifest_payload = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "producer_uid": os.geteuid(),
                        "stage": os.environ.get("SECURITY_UPLOAD_STAGE", "unknown"),
                        "stage_outcome": os.environ.get("SECURITY_UPLOAD_OUTCOME", "unknown"),
                        "roots": inventories,
                        "archive": {
                            "path": "security-evidence.tar.gz",
                            "sha256": constructed.hexdigest(),
                        },
                    },
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            with os.fdopen(manifest_descriptor, "w+b", closefd=False) as stream:
                stream.write(manifest_payload)
                stream.flush()
            validate_archive_directory(output, identities)
            for temporary_name, final_name, opened_descriptor in entries:
                info = os.fstat(opened_descriptor)
                if (
                    not owned_archive_entry(directory_fd, temporary_name, opened_descriptor)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != (published_link_count if final_name in published else 1)
                    or (
                        final_name in published
                        and not owned_archive_entry(directory_fd, final_name, opened_descriptor)
                    )
                ):
                    invalid("upload publication identity or ownership changed")
            os.link(
                manifest_temporary,
                "manifest.json",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published.add("manifest.json")
            if descriptor_content_digest(descriptor) != constructed.digest():
                invalid("upload archive content changed during manifest publication")
            if (
                descriptor_content_digest(manifest_descriptor)
                != hashlib.sha256(manifest_payload).digest()
            ):
                invalid("upload manifest content differs from constructed payload")
            validate_archive_directory(output, identities)
            for temporary_name, final_name, opened_descriptor in entries:
                if (
                    not owned_archive_entry(directory_fd, temporary_name, opened_descriptor)
                    or not owned_archive_entry(directory_fd, final_name, opened_descriptor)
                    or os.fstat(opened_descriptor).st_nlink != published_link_count
                ):
                    invalid("upload publication identity or alias count changed")
            complete = True
        finally:
            for temporary_name, final_name, opened_descriptor in reversed(entries):
                try:
                    if (
                        not complete
                        and final_name in published
                        and owned_archive_entry(directory_fd, final_name, opened_descriptor)
                    ):
                        with suppress(FileNotFoundError):
                            os.unlink(final_name, dir_fd=directory_fd)
                    if owned_archive_entry(directory_fd, temporary_name, opened_descriptor):
                        with suppress(FileNotFoundError):
                            os.unlink(temporary_name, dir_fd=directory_fd)
                finally:
                    os.close(opened_descriptor)
