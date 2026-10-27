"""Keep upload publication bound to its constructed archive and source boundary."""

# ruff: noqa: PT009 - unittest controls remain active under Python -O

from __future__ import annotations

import json
import subprocess
import sys

from test_security_fuzz import TARGETS, SecurityFuzzFixture

CONTROL = r"""import hashlib, io, json, os, pathlib, runpy, sys, tarfile

h = runpy.run_path(sys.argv[1])
state = h["package_upload"].__globals__
root = h["ROOT"]
case = sys.argv[2]
source = root / "artifacts/security/latest"
source.mkdir(parents=True)
(source / "input").write_bytes(b"constructed A evidence")
before = h["upload_inventory"]()
output = root / "artifacts/upload-binding"
protected = None
guard_before = None
if case.startswith("protected:"):
    _, name, presence, descendant = case.split(":")
    protected = root / "artifacts" / name
    if presence == "empty":
        protected.mkdir(parents=True)
    guard_before = (protected.exists(), list(protected.rglob("*")) if protected.exists() else [])
    output = protected / ("child/new-output" if descendant == "nested" else "")
outside = root.parent / "outside"
outside.mkdir()
foreign = outside / "foreign.tar.gz"
with tarfile.open(foreign, "w:gz") as tar:
    data = b"replacement B evidence"
    info = tarfile.TarInfo("replacement")
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
foreign_bytes = foreign.read_bytes()
attacks = []
calls = 0
swapped = None
held = None
replacement_temp = None
constructed = None
manifest_constructed = None
final = output / "security-evidence.tar.gz"
manifest = output / "manifest.json"
actual_inventory = state["upload_inventory"]


def swap_directory(ancestor=False):
    global swapped, held
    swapped = output.parent if ancestor else output
    held = swapped.with_name(swapped.name + ".held")
    swapped.rename(held)
    swapped.symlink_to(outside, target_is_directory=True)


def interleave():
    global calls, constructed, replacement_temp
    calls += 1
    result = actual_inventory()
    if calls != 2 or case.startswith("protected:"):
        return result
    entries = [p for p in output.iterdir() if p.name.startswith(".archive-")]
    if len(entries) != 1:
        raise RuntimeError("one owned archive temporary required")
    temporary = entries[0]
    constructed = hashlib.sha256(temporary.read_bytes()).hexdigest()
    if case.startswith("temp-"):
        temporary.rename(temporary.with_name(temporary.name + ".held"))
        replacement_temp = temporary
        if case == "temp-regular":
            temporary.write_bytes(foreign_bytes)
        elif case == "temp-symlink":
            temporary.symlink_to(foreign)
        elif case == "temp-hardlink":
            os.link(foreign, temporary)
        else:
            temporary.mkdir()
            (temporary / "sentinel").write_bytes(b"foreign directory")
        attacks.append(case)
    elif case == "inplace-content":
        temporary.write_bytes(foreign_bytes)
        attacks.append(case)
    elif case in ("directory-swap", "ancestor-swap"):
        swap_directory(case == "ancestor-swap")
        attacks.append(case)
    elif case.startswith("collision-"):
        destination = manifest if case.startswith("collision-manifest-") else final
        kind = case.rsplit("-", 1)[1]
        if kind == "regular":
            destination.write_bytes(foreign_bytes)
        elif kind == "symlink":
            destination.symlink_to(foreign)
        elif kind == "hardlink":
            os.link(foreign, destination)
        else:
            destination.mkdir()
            (destination / "sentinel").write_bytes(b"foreign directory")
        attacks.append(case)
    return result


state["upload_inventory"] = interleave
original_link = os.link
linked = []


def link_control(src, dst, *args, **kwargs):
    global manifest_constructed
    if str(dst) == "manifest.json":
        temporary_manifest = output / src
        manifest_constructed = hashlib.sha256(temporary_manifest.read_bytes()).hexdigest()
        if case == "manifest-write-content":
            data = json.loads(temporary_manifest.read_text())
            data["stage_outcome"] = "forged"
            temporary_manifest.write_text(json.dumps(data, indent=2) + "\n")
            attacks.append(case)
        elif case == "archive-manifest-preparation-content":
            final.write_bytes(foreign_bytes)
            attacks.append(case)
    original_link(src, dst, *args, **kwargs)
    linked.append(str(dst))
    if str(dst) == "security-evidence.tar.gz":
        if case == "postlink-directory-swap":
            swap_directory()
        elif case == "postlink-final-replacement":
            final.unlink()
            final.write_bytes(foreign_bytes)
        elif case == "late-hardlink":
            original_link(final, outside / "late-alias")
        if case.startswith("postlink-") or case == "late-hardlink":
            attacks.append(case)
    if str(dst) == "manifest.json":
        if case == "manifest-publication-content":
            data = json.loads(manifest.read_text())
            data["stage_outcome"] = "forged"
            manifest.write_text(json.dumps(data, indent=2) + "\n")
            attacks.append(case)
        elif case == "archive-manifest-publication-content":
            final.write_bytes(foreign_bytes)
            attacks.append(case)


state["os"].link = link_control
rejected = False
reason = ""
try:
    h["package_upload"](output)
except (ValueError, OSError) as error:
    rejected = True
    reason = str(error)
finally:
    if swapped is not None:
        swapped.unlink()
        held.rename(swapped)
if h["upload_inventory"]() != before:
    raise RuntimeError("upload source inventory changed")
if foreign.read_bytes() != foreign_bytes:
    raise RuntimeError("foreign bytes changed")
record = {
    "case": case,
    "rejected": rejected,
    "reason": reason,
    "attacks": attacks,
    "archive_present": final.exists() or final.is_symlink(),
    "manifest_present": manifest.exists() or manifest.is_symlink(),
    "source_preserved": True,
    "foreign_preserved": True,
    "optimize": sys.flags.optimize,
    "temp_names": sorted(p.name for p in output.iterdir() if p.name.startswith("."))
    if output.is_dir()
    else [],
    "linked": linked,
}
if protected is not None:
    record["guard_preserved"] = guard_before == (
        protected.exists(),
        list(protected.rglob("*")) if protected.exists() else [],
    )
if replacement_temp is not None:
    record["replacement_temp_preserved"] = (
        replacement_temp.exists() or replacement_temp.is_symlink()
    )
    if replacement_temp.is_file() and not replacement_temp.is_symlink():
        record["replacement_temp_preserved"] &= replacement_temp.read_bytes() == foreign_bytes
    elif replacement_temp.is_symlink():
        record["replacement_temp_preserved"] &= os.readlink(replacement_temp) == str(foreign)
    elif replacement_temp.is_dir():
        record["replacement_temp_preserved"] &= (
            replacement_temp / "sentinel"
        ).read_bytes() == b"foreign directory"
if case.startswith("collision-") or case == "postlink-final-replacement":
    destination = manifest if case.startswith("collision-manifest-") else final
    if destination.is_symlink():
        preserved = os.readlink(destination) == str(foreign)
    elif destination.is_dir():
        preserved = (destination / "sentinel").read_bytes() == b"foreign directory"
    else:
        preserved = destination.exists() and destination.read_bytes() == foreign_bytes
    record["replacement_final_preserved"] = preserved
if not rejected and not case.startswith("protected:"):
    receipt = json.loads(manifest.read_text())
    record["manifest_content_matches_constructed"] = (
        hashlib.sha256(manifest.read_bytes()).hexdigest() == manifest_constructed
    )
    final_digest = hashlib.sha256(final.read_bytes()).hexdigest()
    record["manifest_digest_matches_archive"] = receipt["archive"]["sha256"] == final_digest
    record["manifest_digest_matches_constructed"] = receipt["archive"]["sha256"] == constructed
    record["archive_unaliased"] = final.stat().st_nlink == 1
    with tarfile.open(final) as tar:
        member = (
            tar.extractfile("artifacts/security/latest/input")
            if "artifacts/security/latest/input" in tar.getnames()
            else None
        )
        record["archive_matches_inventory"] = (
            member is not None and member.read() == b"constructed A evidence"
        )
print(json.dumps(record, sort_keys=True))
"""


class FuzzUploadBindingTests(SecurityFuzzFixture):
    def upload_control(self, case):
        result = subprocess.run(  # noqa: S603 - actual helper and owned inert interleavings
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                CONTROL,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                case,
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
        record = json.loads(result.stdout)
        self.assertTrue(record["source_preserved"], record)
        self.assertTrue(record["foreign_preserved"], record)
        self.assertEqual(record["optimize"], sys.flags.optimize)
        return record

    def control_case(self, case):
        fixture = FuzzUploadBindingTests()
        fixture.setUp()
        try:
            return fixture.upload_control(case)
        finally:
            fixture.doCleanups()

    def test_protected_source_upload_destinations_reject_before_creation(self):
        for name in ("ct", "karamel"):
            for presence in ("absent", "empty"):
                for descendant in ("root", "nested"):
                    with self.subTest(name=name, presence=presence, descendant=descendant):
                        record = self.control_case(f"protected:{name}:{presence}:{descendant}")
                        self.assertTrue(record["rejected"], record)
                        self.assertTrue(record["guard_preserved"], record)
                        self.assertFalse(record["archive_present"], record)
                        self.assertFalse(record["manifest_present"], record)

    def test_upload_temporary_substitutions_preserve_foreign_entries(self):
        for case in ("temp-regular", "temp-symlink", "temp-hardlink", "temp-directory"):
            with self.subTest(case=case):
                record = self.control_case(case)
                self.assertTrue(record["rejected"], record)
                self.assertTrue(record["replacement_temp_preserved"], record)
                self.assertFalse(record["archive_present"], record)
                self.assertFalse(record["manifest_present"], record)

    def test_upload_constructed_descriptor_content_cannot_change_before_publication(self):
        record = self.control_case("inplace-content")
        self.assertTrue(record["rejected"], record)
        self.assertFalse(record["archive_present"], record)
        self.assertFalse(record["manifest_present"], record)
        self.assertEqual(record["temp_names"], [], record)

    def test_upload_directory_substitutions_preserve_external_outputs(self):
        for case in ("directory-swap", "ancestor-swap", "postlink-directory-swap"):
            with self.subTest(case=case):
                record = self.control_case(case)
                self.assertTrue(record["rejected"], record)
                self.assertFalse(record["archive_present"], record)
                self.assertFalse(record["manifest_present"], record)
                self.assertEqual(record["temp_names"], [], record)

    def test_upload_publication_never_clobbers_foreign_final_entries(self):
        for role in ("archive", "manifest"):
            for kind in ("regular", "symlink", "hardlink", "directory"):
                with self.subTest(role=role, kind=kind):
                    record = self.control_case(f"collision-{role}-{kind}")
                    self.assertTrue(record["rejected"], record)
                    self.assertTrue(record["replacement_final_preserved"], record)
                    if role == "archive":
                        self.assertFalse(record["manifest_present"], record)
                    else:
                        self.assertFalse(record["archive_present"], record)
                    self.assertEqual(record["temp_names"], [], record)

    def test_upload_postlink_identity_and_alias_failures_hold_foreign_replacements(self):
        for case in ("postlink-final-replacement", "late-hardlink"):
            with self.subTest(case=case):
                record = self.control_case(case)
                self.assertTrue(record["rejected"], record)
                self.assertFalse(record["manifest_present"], record)
                if case == "postlink-final-replacement":
                    self.assertTrue(record["replacement_final_preserved"], record)
                else:
                    self.assertFalse(record["archive_present"], record)
                self.assertEqual(record["temp_names"], [], record)

    def test_upload_same_inode_contents_bind_after_manifest_preparation_and_publication(self):
        for case in (
            "manifest-write-content",
            "manifest-publication-content",
            "archive-manifest-preparation-content",
            "archive-manifest-publication-content",
        ):
            with self.subTest(case=case):
                record = self.control_case(case)
                self.assertTrue(record["rejected"], record)
                self.assertEqual(record["attacks"], [case], record)
                self.assertFalse(record["archive_present"], record)
                self.assertFalse(record["manifest_present"], record)
                self.assertEqual(record["temp_names"], [], record)

    def test_upload_manifest_digest_binds_complete_constructed_descriptor(self):
        record = self.control_case("supported")
        self.assertFalse(record["rejected"], record)
        self.assertTrue(record["manifest_digest_matches_archive"], record)
        self.assertTrue(record["manifest_digest_matches_constructed"], record)
        self.assertTrue(record["manifest_content_matches_constructed"], record)
        self.assertTrue(record["archive_matches_inventory"], record)
        self.assertTrue(record["archive_unaliased"], record)
        self.assertEqual(record["temp_names"], [], record)
