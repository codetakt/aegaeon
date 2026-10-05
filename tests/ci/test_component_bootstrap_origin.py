"""Private protocol fixtures: no signatures, service, CA or production authority."""
# ruff: noqa: PT009, PT027
# These stdlib-only bootstrap controls run in an isolated interpreter without pytest.

from __future__ import annotations

import base64
import builtins
import copy
import dataclasses
import json
import os
import subprocess
import sys
import tempfile
import unittest
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    from collections.abc import Callable

# Only the new protected bootstrap modules enter this test process; remove the
# temporary path before constructing any fixture premises or loading candidates.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import component_bootstrap_origin as origin_module
from component_bootstrap_loader import authenticate_and_project, load_admitted_entry
from component_bootstrap_origin import (
    API_ROOT,
    CREDENTIAL_SCOPE,
    DESCRIPTOR_PATH,
    POLICY_PATH,
    REPOSITORY,
    BootstrapPremises,
    OriginalReply,
    OriginRejectedError,
    git_blob,
    require,
    sha256,
    verify_original_sources,
)

sys.path.pop(0)

BASE = "a" * 40
SOURCE = "b" * 40
BASE_TREE = "d" * 40
SOURCE_TREE = "e" * 40
PROBE = "scripts/ci/origin_probe.py"
SIBLING = "scripts/ci/origin_sibling.py"
PROBE_BYTES = (
    b"import builtins\nvars(builtins)['_aegaeon_origin_probe'] += 1\n"
    b"def installed_value():\n    from origin_sibling import VALUE\n    return VALUE\n"
)
SIBLING_BYTES = b"VALUE = 17\n"
JsonObject = dict[str, Any]


def isolated_test[TestCaseType: unittest.TestCase](
    method: Callable[[TestCaseType], None],
) -> Callable[[TestCaseType], None]:
    """Run the exact selected method in a clean -I child for ordinary discovery."""

    @wraps(method)
    def run(case: TestCaseType) -> None:
        if sys.flags.isolated == 1:
            method(case)
            return
        selected = method.__qualname__
        case.assertTrue(selected.startswith("BootstrapOriginTests.test_"))
        with tempfile.TemporaryDirectory(prefix="aegaeon-bootstrap-test-") as temporary:
            environment = {
                "HOME": temporary,
                "TMPDIR": temporary,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), selected]
            try:
                completed = subprocess.run(  # noqa: S603 - exact interpreter, own file and selected method
                    command,
                    cwd=temporary,
                    env=environment,
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                case.fail(f"isolated bootstrap child timed out: {selected}: {error}")
            case.assertLessEqual(len(completed.stdout) + len(completed.stderr), 1024 * 1024)
            sys.stderr.write(f"isolated bootstrap child: {selected}\n{completed.stderr}")
            case.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            case.assertIn("Ran 1 test", completed.stderr)
            case.assertNotIn("skipped=", completed.stderr)
            case.assertNotIn("(skipped", completed.stderr)

    return run


def encoded(value: JsonObject) -> bytes:
    return json.dumps(value, sort_keys=True).encode()


class PrivateOriginalFixture:
    """Synthetic replies and rechecks; never a production original-read adapter."""

    def __init__(self, probe_bytes: bytes = PROBE_BYTES) -> None:
        self.reads: list[str] = []
        self.rechecks = 0
        self.documents: dict[str, JsonObject] = {}
        self.reply_change: Callable[[OriginalReply], OriginalReply] = lambda reply: reply
        self.rows: list[JsonObject] = []
        for ordinal, (path, raw) in enumerate([(PROBE, probe_bytes), (SIBLING, SIBLING_BYTES)]):
            self.rows.append(
                {
                    "registry_id": "fixture-" + str(ordinal),
                    "relative_path": path,
                    "repository_or_supplier": REPOSITORY,
                    "commit_or_version": SOURCE,
                    "git_mode": "100644",
                    "bytes": len(raw),
                    "sha256": sha256(raw),
                    "tree_or_content_digest": sha256(raw),
                }
            )
        self.rebind_descriptor()
        self._commit(SOURCE, SOURCE_TREE, {PROBE: probe_bytes, SIBLING: SIBLING_BYTES})
        self.premises = BootstrapPremises(
            actual_base=BASE,
            source_inventory=tuple(sorted([PROBE, SIBLING])),
            interpreter=sys.executable,
            runtime_import_paths=tuple(sys.path),
            runtime_packages=(),
            module_map=(("origin_probe", PROBE), ("origin_sibling", SIBLING)),
            entrypoint="origin_probe",
            ca_file="/nix/store/private-fixture/public-ca",
            ca_sha256="c" * 64,
            credential_scope=CREDENTIAL_SCOPE,
            recheck=self.recheck,
        )

    def recheck(self, premises: BootstrapPremises) -> None:
        self.rechecks += 1
        require(premises == self.premises, "fixture independently fixed input changed")

    def _commit(self, commit: str, tree: str, sources: dict[str, bytes]) -> None:
        self.documents["commits/" + commit] = {
            "sha": commit,
            "commit": {
                "tree": {"sha": tree},
                "verification": {
                    "verified": True,
                    "reason": "valid",
                    "signature": "private noncryptographic fixture",
                    "payload": "tree " + tree + "\nauthor private fixture\n\nmessage\n",
                },
            },
        }
        entries = []
        for path, raw in sources.items():
            oid = git_blob(raw, "0" * 40)
            entries.append({"path": path, "type": "blob", "mode": "100644", "sha": oid})
            self.documents["git/blobs/" + oid] = {
                "sha": oid,
                "encoding": "base64",
                "size": len(raw),
                "content": base64.b64encode(raw).decode(),
            }
        self.documents["git/trees/" + tree + "?recursive=1"] = {
            "sha": tree,
            "truncated": False,
            "tree": entries,
        }

    def rebind_descriptor(self) -> None:
        self.descriptor = encoded({"source_registry": self.rows})
        self.policy = encoded(
            {
                "plan_envelope_version": 2,
                "supplemental_lanes": {"components": "pending"},
                "component_release": {
                    "version": 1,
                    "descriptor_path": DESCRIPTOR_PATH,
                    "descriptor_sha256": sha256(self.descriptor),
                },
            }
        )
        self._commit(BASE, BASE_TREE, {POLICY_PATH: self.policy, DESCRIPTOR_PATH: self.descriptor})

    def read(self, url: str, maximum_bytes: int, premises: BootstrapPremises) -> OriginalReply:
        require(
            url.startswith(API_ROOT) and premises is self.premises and maximum_bytes > 0,
            "fixture original read scope changed",
        )
        self.reads.append(url)
        route = url.removeprefix(API_ROOT)
        require(route in self.documents, "fixture missing original route")
        return self.reply_change(
            OriginalReply(url, url, "GET", 200, "application/json", encoded(self.documents[route]))
        )


class BootstrapOriginTests(unittest.TestCase):
    def setUp(self) -> None:
        vars(builtins)["_aegaeon_origin_probe"] = 0

    def tearDown(self) -> None:
        del vars(builtins)["_aegaeon_origin_probe"]

    @isolated_test
    def test_positive_originals_project_and_load_only_fixed_verified_bytes(self) -> None:
        large_probe = PROBE_BYTES + b"#" + b"x" * (3 * 1024 * 1024 // 2) + b"\n"
        self.assertGreater(len(large_probe), 1024 * 1024)
        for probe_bytes in (PROBE_BYTES, large_probe):
            with (
                self.subTest(source_bytes=len(probe_bytes)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                vars(builtins)["_aegaeon_origin_probe"] = 0
                fixture = PrivateOriginalFixture(probe_bytes)
                projection = authenticate_and_project(
                    fixture, fixture.premises, fixture.policy, Path(temporary)
                )
                try:
                    projection.recheck()
                    self.assertEqual(projection.source_bytes(PROBE), probe_bytes)
                    with load_admitted_entry(projection) as module:
                        self.assertEqual(module.installed_value(), 17)
                        self.assertIn("origin_sibling", sys.modules)
                    self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 1)
                    self.assertNotIn("origin_probe", sys.modules)
                    with self.assertRaises(OriginRejectedError):
                        module.installed_value()
                    self.assertGreater(fixture.rechecks, len(fixture.reads) * 2)
                    self.assertTrue(all(url.startswith(API_ROOT) for url in fixture.reads))
                    self.assertFalse(any("/contents/" in url for url in fixture.reads))
                    blob_url = API_ROOT + "git/blobs/" + git_blob(probe_bytes, "0" * 40)
                    self.assertIn(blob_url, fixture.reads)
                finally:
                    projection.close()

    @isolated_test
    def test_all_origin_failures_stop_before_projection_or_candidate_import(self) -> None:  # noqa: C901, PLR0915 - directed original-input matrix
        def change_bytes(fixture: PrivateOriginalFixture) -> None:
            fixture.rows[0]["sha256"] = "0" * 64
            fixture.rebind_descriptor()

        def change_rows(fixture: PrivateOriginalFixture, kind: str) -> None:
            if kind == "missing":
                fixture.rows.pop()
            elif kind == "extra":
                fixture.rows.append(copy.deepcopy(fixture.rows[0]))
            elif kind == "duplicate":
                fixture.rows[1] = copy.deepcopy(fixture.rows[0])
            else:
                fixture.rows[0][kind] = {
                    "git_mode": "100755",
                    "repository_or_supplier": "other/repo",
                    "commit_or_version": "0" * 40,
                    "bytes": 0,
                    "tree_or_content_digest": "0" * 64,
                }[kind]
            fixture.rebind_descriptor()

        def signature(fixture: PrivateOriginalFixture, field: str) -> None:
            fixture.documents["commits/" + SOURCE]["commit"]["verification"][field] = {
                "verified": False,
                "reason": "invalid",
                "signature": "",
                "payload": "tree wrong\n",
            }[field]

        def row_change(kind: str) -> Callable[[PrivateOriginalFixture], None]:
            def apply(fixture: PrivateOriginalFixture) -> None:
                change_rows(fixture, kind)

            return apply

        def signature_change(field: str) -> Callable[[PrivateOriginalFixture], None]:
            def apply(fixture: PrivateOriginalFixture) -> None:
                signature(fixture, field)

            return apply

        def original_descriptor_changed(fixture: PrivateOriginalFixture) -> None:
            raw = b"{}" + b" " * (len(fixture.descriptor) - 2)
            fixture._commit(BASE, BASE_TREE, {POLICY_PATH: fixture.policy, DESCRIPTOR_PATH: raw})

        def blob_change(field: str, value: object) -> Callable[[PrivateOriginalFixture], None]:
            def apply(fixture: PrivateOriginalFixture) -> None:
                fixture.documents["git/blobs/" + git_blob(PROBE_BYTES, "0" * 40)][field] = value

            return apply

        cases: dict[str, Callable[[PrivateOriginalFixture], None]] = {
            "changed-sha": change_bytes,
            **{
                kind: row_change(kind)
                for kind in [
                    "missing",
                    "extra",
                    "duplicate",
                    "git_mode",
                    "repository_or_supplier",
                    "bytes",
                    "tree_or_content_digest",
                    "commit_or_version",
                ]
            },
            **{
                field: signature_change(field)
                for field in ["verified", "reason", "signature", "payload"]
            },
            "truncated": lambda fixture: fixture.documents[
                "git/trees/" + SOURCE_TREE + "?recursive=1"
            ].update(truncated=True),
            "duplicate-tree": lambda fixture: fixture.documents[
                "git/trees/" + SOURCE_TREE + "?recursive=1"
            ]["tree"].append(
                copy.deepcopy(
                    fixture.documents["git/trees/" + SOURCE_TREE + "?recursive=1"]["tree"][0]
                )
            ),
            "blob-oid": blob_change("sha", "0" * 40),
            "actual-git-blob": blob_change(
                "content", base64.b64encode(b"X" * len(PROBE_BYTES)).decode()
            ),
            "blob-size": blob_change("size", len(PROBE_BYTES) + 1),
            "blob-size-bool": blob_change("size", True),
            "blob-encoding": blob_change("encoding", "none"),
            "blob-base64": blob_change("content", "not!base64"),
            "blob-content-type": blob_change("content", 17),
            "tree-source-path": lambda fixture: fixture.documents[
                "git/trees/" + SOURCE_TREE + "?recursive=1"
            ]["tree"][0].update(path="scripts/ci/unadopted.py"),
            "tree-blob-association": lambda fixture: fixture.documents[
                "git/trees/" + SOURCE_TREE + "?recursive=1"
            ]["tree"][0].update(sha=git_blob(SIBLING_BYTES, "0" * 40)),
            "tree-source-mode": lambda fixture: fixture.documents[
                "git/trees/" + SOURCE_TREE + "?recursive=1"
            ]["tree"][0].update(mode="100755"),
            "descriptor-digest": original_descriptor_changed,
            "protected-policy-origin": lambda fixture: setattr(
                fixture, "policy", fixture.policy + b" "
            ),
            "redirect-origin": lambda fixture: setattr(
                fixture,
                "reply_change",
                lambda reply: dataclasses.replace(reply, final_url="https://example.invalid/"),
            ),
            "wrong-method": lambda fixture: setattr(
                fixture, "reply_change", lambda reply: dataclasses.replace(reply, method="POST")
            ),
        }
        for label, change in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = PrivateOriginalFixture()
                change(fixture)
                with self.assertRaises(OriginRejectedError):
                    authenticate_and_project(
                        fixture, fixture.premises, fixture.policy, Path(temporary)
                    )
                self.assertEqual(list(Path(temporary).iterdir()), [])
                self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)

    @isolated_test
    def test_actual_base_signature_and_descriptor_origin_are_independent(self) -> None:
        changes: dict[str, JsonObject] = {
            "base-change": {"actual_base": "f" * 40},
            "credential-scope": {"credential_scope": "https://example.invalid/"},
            "inventory": {"source_inventory": (PROBE, PROBE)},
            "module-map": {"entrypoint": "unapproved"},
        }
        for kind in [
            "base-signature",
            "descriptor-mode",
            "base-change",
            "credential-scope",
            "inventory",
            "module-map",
        ]:
            with self.subTest(kind=kind):
                fixture = PrivateOriginalFixture()
                premises = fixture.premises
                if kind == "base-signature":
                    fixture.documents["commits/" + BASE]["commit"]["verification"]["verified"] = (
                        False
                    )
                elif kind == "descriptor-mode":
                    fixture.documents["git/trees/" + BASE_TREE + "?recursive=1"]["tree"][1][
                        "mode"
                    ] = "100755"
                else:
                    premises = dataclasses.replace(
                        premises,
                        **changes[kind],
                    )
                with self.assertRaises(OriginRejectedError):
                    verify_original_sources(fixture, premises, fixture.policy)
                self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)

    @isolated_test
    def test_retained_mutations_and_ambient_imports_reject_before_entry_exec(self) -> None:  # noqa: PLR0912, PLR0915 - retained filesystem fault matrix
        for kind in [
            "bytes",
            "mode",
            "replace",
            "extra",
            "missing",
            "hardlink",
            "ancestor",
            "ambient-path",
        ]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                fixture = PrivateOriginalFixture()
                projection = authenticate_and_project(
                    fixture, fixture.premises, fixture.policy, Path(temporary)
                )
                original_path = list(sys.path)
                try:
                    source = projection.root / "source" / PROBE
                    if kind == "bytes":
                        source.chmod(0o600)
                        source.write_bytes(PROBE_BYTES + b"\n")
                    elif kind == "mode":
                        source.chmod(0o555)
                    elif kind == "replace":
                        source.parent.chmod(0o700)
                        source.unlink()
                        source.write_bytes(PROBE_BYTES)
                    elif kind == "extra":
                        source.parent.chmod(0o700)
                        (source.parent / "extra.py").write_text("VALUE = 19\n")
                    elif kind == "missing":
                        source.parent.chmod(0o700)
                        source.unlink()
                    elif kind == "hardlink":
                        os.link(source, Path(temporary) / "unexpected-link")
                    elif kind == "ancestor":
                        renamed = Path(temporary + "-retained")
                        Path(temporary).rename(renamed)
                        Path(temporary).mkdir()
                    else:
                        sys.path.insert(0, temporary)
                    with self.assertRaises(OriginRejectedError), load_admitted_entry(projection):
                        self.fail("modified input reached candidate entry")
                    self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)
                finally:
                    sys.path[:] = original_path
                    projection.close()
                    if kind == "ancestor":
                        Path(temporary).rmdir()
                        Path(temporary + "-retained").rename(Path(temporary))

    @isolated_test
    def test_existing_destination_is_preserved_and_never_overwritten(self) -> None:
        fixture = PrivateOriginalFixture()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bootstrap-package"
            destination.mkdir()
            sentinel = destination / "original"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(FileExistsError):
                authenticate_and_project(fixture, fixture.premises, fixture.policy, Path(temporary))
            self.assertEqual(sentinel.read_bytes(), b"preserve")
            self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)

    @isolated_test
    def test_nonfinite_original_json_rejects_before_candidate_import(self) -> None:
        for value in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                fixture = PrivateOriginalFixture()
                fixture.documents["commits/" + BASE]["unrelated"] = value
                with self.assertRaises(OriginRejectedError):
                    authenticate_and_project(
                        fixture, fixture.premises, fixture.policy, Path(temporary)
                    )
                self.assertEqual(list(Path(temporary).iterdir()), [])
                self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)

    @isolated_test
    def test_aggregate_reply_budget_rejects_after_two_individually_bounded_replies(self) -> None:
        fixture = PrivateOriginalFixture()
        first = len(encoded(fixture.documents["commits/" + BASE]))
        second = len(encoded(fixture.documents["git/trees/" + BASE_TREE + "?recursive=1"]))
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(origin_module, "MAX_RETAINED_REPLIES", first + second - 1),
        ):
            with self.assertRaisesRegex(OriginRejectedError, "aggregate complete original reply"):
                authenticate_and_project(fixture, fixture.premises, fixture.policy, Path(temporary))
            self.assertEqual(len(fixture.reads), 2)
            self.assertEqual(list(Path(temporary).iterdir()), [])
            self.assertEqual(vars(builtins)["_aegaeon_origin_probe"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
