"""Bind corpus and crash archives to the bytes constructed in their retained FD."""

# ruff: noqa: PT009 - unittest controls remain effective under -O

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from test_security_fuzz import TARGETS, SecurityFuzzFixture

CONTROL = r"""import hashlib, io, json, os, pathlib, runpy, sys, tarfile
from datetime import UTC, datetime

h = runpy.run_path(sys.argv[1])
state = h["write_exclusive_archive"].__globals__
route, stage = sys.argv[2:4]
root = h["ROOT"]
target = h["REQUIRED_TARGETS"][0]


class FixedTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 4, 12, 34, 56, 123456, tzinfo=UTC)


h["create_archive"].__globals__["datetime"] = FixedTime
os.environ["CORPUS_ARCHIVE_KEEP"] = "2"
source = root / "fuzz" / ("artifacts" if route == "crash" else "corpus") / target
source.mkdir(parents=True)
original = b"A" * (2 * 1024 * 1024 + 17)
(source / "entry").write_bytes(original)
outside = root.parent / "outside"
outside.mkdir()
sentinel = outside / "sentinel"
sentinel.write_bytes(b"inert external sentinel")
(source / "literal-link").symlink_to(sentinel)
before = h["raw_inventory"](source)
output = h["ARCHIVE_DIR"] if route == "corpus" else root / "artifacts/archive-control"
output.mkdir(parents=True)
name = (
    ("crashes_" if route == "crash" else "")
    + FixedTime.now().strftime("%Y%m%dT%H%M%S%fZ")
    + ".tar.gz"
)
final = output / name
prior = output / "19990101T000000000000Z.tar.gz"
prior.write_bytes(b"preserve retained prior")
if stage == "supported":
    for number in range(2):
        (output / f"1998010{number}T000000000000Z.tar.gz").write_bytes(b"older archive")
unrelated = output / ".archive-unrelated.tmp"
unrelated.symlink_to(sentinel)
member = ("corpus/" if route == "corpus" else "") + target + "/entry"
foreign = io.BytesIO()
with tarfile.open(fileobj=foreign, mode="w:gz") as tar:
    info = tarfile.TarInfo(member)
    replacement = b"valid replacement B archive"
    info.size = len(replacement)
    tar.addfile(info, io.BytesIO(replacement))
replacement_bytes = foreign.getvalue()
attacks = []
identities = []
constructed = None
verify_completed = False
retention_scans = 0
actual_verify = state["verify_archive_stream"]
actual_link = os.link
actual_listdir = os.listdir
actual_close = tarfile.TarFile.close


def substitute(path, label):
    before_info = path.stat()
    path.write_bytes(replacement_bytes)
    after_info = path.stat()
    identities.append(
        {
            "before": [before_info.st_dev, before_info.st_ino, before_info.st_nlink],
            "after": [after_info.st_dev, after_info.st_ino, after_info.st_nlink],
        }
    )
    attacks.append(label)


def verify_control(stream, path):
    global constructed, verify_completed
    stream.seek(0)
    constructed = hashlib.sha256(stream.read()).hexdigest()
    temporary = next(
        p for p in output.iterdir() if p.name.startswith(".archive-") and p != unrelated
    )
    if stage == "before-readback":
        substitute(temporary, stage)
    actual_verify(stream, path)
    verify_completed = True
    if stage == "after-readback":
        substitute(temporary, stage)


state["verify_archive_stream"] = verify_control


def close_control(archive):
    constructing = archive.mode == "w" and not archive.closed
    writer = archive.fileobj.fileobj if constructing else None
    actual_close(archive)
    if constructing and stage == "construction-close":
        writer.flush()
        temporary = next(p for p in output.iterdir()
                         if p.name.startswith(".archive-") and p != unrelated)
        substitute(temporary, stage)


tarfile.TarFile.close = close_control


def link_control(src, dst, *args, **kwargs):
    if stage == "before-link":
        substitute(output / src, stage)
    actual_link(src, dst, *args, **kwargs)
    if stage == "after-link":
        substitute(final, stage)


state["os"].link = link_control


def listdir_control(path):
    global retention_scans
    names = actual_listdir(path)
    if isinstance(path, int):
        retention_scans += 1
        if stage == "retention-scan":
            substitute(final, stage)
    return names


state["os"].listdir = listdir_control
rejected = False
reason = ""
archive = None
try:
    archive = (
        h["create_archive"]()
        if route == "corpus"
        else h["archive_crashes"](h["gather_crash_stats"](), output)
    )
except ValueError as error:
    rejected = True
    reason = str(error)
record = {
    "route": route,
    "stage": stage,
    "rejected": rejected,
    "reason": reason,
    "attacks": attacks,
    "substitution_identities": identities,
    "verify_completed": verify_completed,
    "retention_scans": retention_scans,
    "raw_preserved": h["raw_inventory"](source) == before,
    "sentinel_preserved": sentinel.read_bytes() == b"inert external sentinel",
    "prior_preserved": prior.exists() and prior.read_bytes() == b"preserve retained prior",
    "unrelated_temp_preserved": unrelated.is_symlink() and os.readlink(unrelated) == str(sentinel),
    "published": final.exists(),
    "temps": [
        p.name for p in output.iterdir() if p.name.startswith(".archive-") and p != unrelated
    ],
    "optimize": sys.flags.optimize,
    "native_calls": 0,
}
if not rejected:
    record["content_matches_constructed"] = (
        hashlib.sha256(final.read_bytes()).hexdigest() == constructed
    )
    record["regular_unaliased"] = (
        final.is_file() and not final.is_symlink() and final.stat().st_nlink == 1
    )
    record["archive_name"] = archive.name
    record["retained_archives"] = sorted(p.name for p in output.glob("*.tar.gz"))
    with tarfile.open(archive) as tar:
        with tar.extractfile(member) as content:
            record["raw_bytes_match"] = content.read() == original
        if stage == "supported":
            link = tar.getmember(member.removesuffix("entry") + "literal-link")
            record["literal_link_preserved"] = link.issym() and link.linkname == str(sentinel)
print(json.dumps(record, sort_keys=True))
"""


class FuzzCorpusCrashBindingTests(SecurityFuzzFixture):
    def binding_control(self, route, stage):
        helper = self.root / "scripts/fuzz/manage_fuzz_corpus.py"
        result = subprocess.run(  # noqa: S603 - real writer with owned deterministic interleavings
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                CONTROL,
                str(helper),
                route,
                stage,
            ],
            cwd=self.root,
            env={**self.env, "FUZZ_TARGETS": TARGETS[0]},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(Path(self.env["CARGO_TARGET_DIR"]).exists())
        record = json.loads(result.stdout)
        for field in (
            "raw_preserved",
            "sentinel_preserved",
            "prior_preserved",
            "unrelated_temp_preserved",
        ):
            self.assertTrue(record[field], record)
        self.assertEqual(record["optimize"], sys.flags.optimize)
        return record

    def control_case(self, route, stage):
        fixture = FuzzCorpusCrashBindingTests()
        fixture.setUp()
        try:
            return fixture.binding_control(route, stage)
        finally:
            fixture.doCleanups()

    def test_same_inode_valid_archives_reject_before_and_after_readback(self):
        for route in ("corpus", "crash"):
            for stage in ("before-readback", "after-readback"):
                with self.subTest(route=route, stage=stage):
                    self.assert_rejected_substitution(self.control_case(route, stage), stage)

    def test_content_binding_starts_with_bytes_written_before_construction_closes(self):
        for route in ("corpus", "crash"):
            with self.subTest(route=route):
                self.assert_rejected_substitution(
                    self.control_case(route, "construction-close"), "construction-close"
                )

    def test_same_inode_valid_archives_reject_during_publication(self):
        for route in ("corpus", "crash"):
            for stage in ("before-link", "after-link"):
                with self.subTest(route=route, stage=stage):
                    self.assert_rejected_substitution(self.control_case(route, stage), stage)

    def test_corpus_same_inode_valid_archive_rejects_during_retention_scan(self):
        record = self.control_case("corpus", "retention-scan")
        self.assert_rejected_substitution(record, "retention-scan")
        self.assertEqual(record["retention_scans"], 1, record)

    def assert_rejected_substitution(self, record, stage):
        self.assertTrue(record["rejected"], record)
        self.assertEqual(record["attacks"], [stage], record)
        self.assertTrue(record["verify_completed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(record["temps"], [], record)
        self.assertEqual(len(record["substitution_identities"]), 1, record)
        identity = record["substitution_identities"][0]
        self.assertEqual(identity["before"], identity["after"], record)

    def test_supported_corpus_and_crash_bind_constructed_bytes_links_and_retention(self):
        for route in ("corpus", "crash"):
            with self.subTest(route=route):
                record = self.control_case(route, "supported")
                self.assertFalse(record["rejected"], record)
                for field in (
                    "content_matches_constructed",
                    "raw_bytes_match",
                    "regular_unaliased",
                    "literal_link_preserved",
                ):
                    self.assertTrue(record[field], record)
                self.assertEqual(
                    record["archive_name"],
                    ("crashes_" if route == "crash" else "") + "20261004T123456123456Z.tar.gz",
                )
                self.assertEqual(len(record["retained_archives"]), 2 if route == "corpus" else 4)
                self.assertEqual(record["retention_scans"], 1 if route == "corpus" else 0)
                self.assertEqual(record["temps"], [], record)
