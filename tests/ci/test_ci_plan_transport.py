"""Protected CI artifact authority, complete literal Git inputs and projections."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions must remain active under Python -O.
import ast
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import validate_change
import verify_ci_plan as transport
import yaml

ROOT = Path(__file__).resolve().parents[2]
LEGACY_SOURCE = "856c1793bc74f218fd6dc55d3c8ea41024c3ef21"
RECORDS = transport.read_records(ROOT)
GRAPH = transport.validate_authority(RECORDS)
PRODUCER = {
    "repository": "codetakt/aegaeon",
    "run_id": "1",
    "run_attempt": 1,
    "job": "plan",
    "event_payload_sha256": "0" * 64,
}
BOUND = {
    "event": "pull_request",
    "event_base": "a" * 40,
    "base": "a" * 40,
    "source_head": "b" * 40,
    "test_sha": "c" * 40,
    "test_tree": "d" * 40,
}


class BatchFailingStream(io.BytesIO):
    def __init__(self, data, operation):
        super().__init__(data)
        self.operation = operation

    def read(self, size):
        if self.operation == "read":
            raise OSError
        return super().read(size)

    def readline(self, size):
        if self.operation == "header":
            raise OSError
        return super().readline(size)

    def write(self, data):
        if self.operation == "write":
            raise OSError
        return super().write(data)

    def flush(self):
        if self.operation == "flush":
            raise OSError
        return super().flush()

    def close(self):
        super().close()
        if self.operation == "close":
            raise OSError


class BatchFakeProcess:
    def __init__(self, data, status, failure):
        self.stdin = BatchFailingStream(
            b"", failure if failure in ("write", "close", "flush") else ""
        )
        self.stdout = BatchFailingStream(data, failure if failure in ("read", "header") else "")
        self.returncode = None
        self.status = status
        self.waited = False
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self):
        self.waited = True
        self.returncode = self.status
        return self.status

    def terminate(self):
        self.terminated = True


class CiPlanTransportTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(self.enterContext(tempfile.TemporaryDirectory()))
        subprocess.run(["git", "init", "--quiet", str(self.repo)], check=True, capture_output=True)  # noqa: S603,S607 - commitless Git fixture

    def blob(self, value):
        return (
            subprocess.check_output(  # noqa: S603 - fixed commitless Git object commands
                ["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],  # noqa: S607 - Git
                input=value,
            )
            .strip()
            .decode()
        )

    def tree(self, entries):
        rows = []
        for name, mode, content in sorted(entries):
            oid = "e" * 40 if mode == "160000" else self.blob(content)
            kind = "commit" if mode == "160000" else "blob"
            rows.append(f"{mode} {kind} {oid}\t".encode() + name + b"\0")
        return (
            subprocess.check_output(  # noqa: S603 - fixed commitless Git object commands
                ["git", "-C", str(self.repo), "mktree", "-z"],  # noqa: S607 - Git
                input=b"".join(rows),
            )
            .strip()
            .decode()
        )

    def snapshots(self):
        base = self.tree(
            [
                (b"same", "100644", b"unchanged"),
                (b"deleted", "100644", b"gone"),
                (b"old-name", "100644", b"rename"),
            ]
        )
        head = self.tree(
            [
                (b"same", "100755", b"unchanged"),
                (b"new-name", "100644", b"rename"),
                (b"link", "120000", b"/outside/unread-example"),
                (b"bad_\xff", "100644", b"raw"),
                (b"submodule", "160000", b""),
            ]
        )
        tested = self.tree(
            [(b"same", "100755", b"unchanged"), (b"tested-only", "100644", b"queue input")]
        )
        return {"base": base, "head": head, "tested": tested}

    def union(self):
        trees = self.snapshots()
        bound = {**BOUND, "test_tree": trees["tested"]}
        original = transport.git

        def objects(repo, *args):
            if args[0] == "merge-base":
                return (BOUND["base"] + "\n").encode()
            if args[0] == "diff":
                args = tuple(
                    trees["base"]
                    if arg == BOUND["base"]
                    else trees["head"]
                    if arg == BOUND["source_head"]
                    else arg
                    for arg in args
                )
            if args[0] == "rev-parse":
                return (
                    trees[
                        {
                            BOUND["base"]: "base",
                            BOUND["source_head"]: "head",
                            BOUND["test_sha"]: "tested",
                        }[args[1].split("^")[0]]
                    ]
                    + "\n"
                ).encode()
            return original(repo, *args)

        with patch.object(transport, "git", side_effect=objects):
            return bound, transport.build_union(self.repo, bound, RECORDS)

    def prepared(self):
        bound, union = self.union()
        changes = [{"path": "new-name", "status": "A", "old_mode": "000000", "new_mode": "100644"}]
        with (
            patch.object(transport, "check_protected_source"),
            patch.object(transport, "authoritative_changes", return_value=("a" * 40, changes, "")),
            patch.object(transport, "build_union", return_value=union),
            patch.object(transport, "git", return_value=b"protected classifier bytes"),
        ):
            plan, union_bytes = transport.prepare(self.repo, bound, RECORDS, PRODUCER)
        return bound, plan, union_bytes

    def outputs(self, plan_bytes):
        plan = transport.load(plan_bytes)
        return {
            "component_plan_sha256": transport.digest(plan_bytes),
            "component_targets": transport.projection(plan),
            "component_plan_provenance": plan["component_plan_provenance"],
        }

    def assert_metadata_only(self, cache):
        for metadata in cache.values():
            self.assertEqual(set(metadata), {"sha256", "symlink_target_base64"})
            self.assertIsInstance(metadata["sha256"], str)
            self.assertTrue(
                metadata["symlink_target_base64"] is None
                or isinstance(metadata["symlink_target_base64"], str)
            )

    def test_batch_large_unique_duplicate_and_shared_link_objects_keep_complete_metadata(self):  # noqa: PLR0915 - actual Git process, bounded reads and full three-snapshot identities
        large = b"owned large Git fixture\x00\n" * 150000
        shared = b"../unread-link-\xff\n"
        originals = [(f"input-{i:03}".encode(), "100644", str(i).encode()) for i in range(64)]
        base = self.tree([*originals, (b"large", "100644", large), (b"shared", "100644", shared)])
        head = self.tree(
            [(b"large-duplicate", "100755", large), (b"literal-link", "120000", shared)]
        )
        tested = self.tree(
            [
                (b"large", "100755", large),
                (b"literal-link", "120000", shared),
                (b"only-tested", "100644", b"tested"),
            ]
        )
        trees = {"base": base, "head": head, "tested": tested}
        commands, body_reads, cached = [], [], []
        real_popen = subprocess.Popen
        real_metadata = getattr(transport, "read_blob_metadata", None)

        class BoundedReads:
            def __init__(self, stream):
                self.stream = stream

            def read(self, size):
                body_reads.append(size)
                return self.stream.read(size)

            def readline(self, size):
                return self.stream.readline(size)

            def close(self):
                return self.stream.close()

        def counted(command, **kwargs):
            commands.append(command)
            process = real_popen(command, **kwargs)
            if command[-2:] == ["cat-file", "--batch"]:
                process.stdout = BoundedReads(process.stdout)
            return process

        def observed(*args):
            value = real_metadata(*args)
            cached.append(value)
            return value

        with (
            patch.object(transport.subprocess, "Popen", side_effect=counted),
            patch.object(transport, "read_blob_metadata", side_effect=observed, create=True),
        ):
            entries = transport.union_entries(self.repo, trees, GRAPH)
        self.assertEqual(len(commands), 4)
        self.assertEqual(sum(command[-2:] == ["cat-file", "--batch"] for command in commands), 1)
        self.assertTrue(all(command[1] == "--no-replace-objects" for command in commands))
        self.assertTrue(body_reads)
        self.assertLessEqual(max(body_reads), 65536)
        self.assertEqual(len(cached), 1)
        self.assertEqual(len(cached[0]), 67)
        self.assert_metadata_only(cached[0])
        by_path = {base64.b64decode(entry["raw_path_base64"]): entry for entry in entries}
        self.assertEqual(
            set(by_path),
            {name for name, _mode, _data in originals}
            | {b"large", b"shared", b"large-duplicate", b"literal-link", b"only-tested"},
        )
        self.assertEqual(by_path[b"large"]["base"]["sha256"], transport.digest(large))
        self.assertEqual(by_path[b"large-duplicate"]["head"]["sha256"], transport.digest(large))
        self.assertEqual(by_path[b"large"]["tested"]["mode"], "100755")
        self.assertFalse(by_path[b"large"]["head"]["present"])
        self.assertIsNone(by_path[b"shared"]["base"]["symlink_target_base64"])
        for side in ("head", "tested"):
            link = by_path[b"literal-link"][side]
            self.assertEqual(link["object_id"], by_path[b"shared"]["base"]["object_id"])
            self.assertEqual(link["sha256"], transport.digest(shared))
            self.assertEqual(base64.b64decode(link["symlink_target_base64"]), shared)
        for entry in entries:
            self.assertTrue(set(GRAPH["holds"]) <= set(entry["unresolved"]))

    def test_batch_metadata_retains_only_digests_for_large_regular_blobs(self):
        large = b"regular-body-fixture" * 200000
        oid = self.blob(large)
        metadata = transport.read_blob_metadata(self.repo, {oid: False})
        self.assertEqual(
            metadata, {oid: {"sha256": transport.digest(large), "symlink_target_base64": None}}
        )

    def test_batch_literal_base64_survives_chunk_edges_and_empty_objects(self):
        for size in (0, 1, 2, 65535, 65536, 65537, 131074):
            with self.subTest(size=size):
                body = (b"\xff\x00literal\n" * (size // 10 + 1))[:size]
                oid = self.blob(body)
                metadata = transport.read_blob_metadata(self.repo, {oid: True})[oid]
                self.assertEqual(metadata["sha256"], transport.digest(body))
                self.assertEqual(base64.b64decode(metadata["symlink_target_base64"]), body)

    def test_batch_missing_and_inherited_overrides_fail_before_partial_admission(self):
        with self.assertRaises(ValueError):
            transport.read_blob_metadata(self.repo, {"f" * 40: False})
        for variable in ("GIT_DIR", "GIT_CONFIG_KEY_0"):
            with (
                self.subTest(variable=variable),
                patch.dict(os.environ, {variable: "private-fixture"}),
                patch.object(transport.subprocess, "Popen") as process,
            ):
                with self.assertRaisesRegex(ValueError, "Git authority override"):
                    transport.read_blob_metadata(self.repo, {"a" * 40: False})
                process.assert_not_called()

    def test_batch_ignores_replacement_objects(self):
        original = self.blob(b"original object")
        replacement = self.blob(b"replacement object")
        subprocess.run(  # noqa: S603 - commitless local replacement fixture
            ["git", "-C", str(self.repo), "update-ref", "refs/replace/" + original, replacement],  # noqa: S607 - Git
            check=True,
            capture_output=True,
        )
        metadata = transport.read_blob_metadata(self.repo, {original: False})[original]
        self.assertEqual(metadata["sha256"], transport.digest(b"original object"))

    def test_batch_malformed_short_read_write_exit_and_cleanup_failures_reject(self):
        oid = self.blob(b"abc")
        frame = oid.encode() + b" blob 3\nabc\n"
        cases = [
            ("missing", oid.encode() + b" missing\n", 0),
            ("wrong-oid", b"f" * 40 + b" blob 3\nabc\n", 0),
            ("wrong-type", oid.encode() + b" tree 3\nabc\n", 0),
            ("negative-size", oid.encode() + b" blob -3\nabc\n", 0),
            ("noncanonical-size", oid.encode() + b" blob 03\nabc\n", 0),
            ("long-header", oid.encode() + b" blob " + b"9" * 256 + b"\n", 0),
            ("short-body", oid.encode() + b" blob 3\na", 0),
            ("bad-trailer", frame[:-1] + b"x", 0),
            ("trailing-output", frame + b"extra", 0),
            ("process-exit", frame, 7),
            ("read-error", frame, 0),
            ("header-error", frame, 0),
            ("write-error", frame, 0),
            ("flush-error", frame, 0),
            ("close-error", frame, 0),
            ("second-object-missing", frame + b"f" * 40 + b" missing\n", 0),
        ]

        for name, data, status in cases:
            process = BatchFakeProcess(data, status, name.removesuffix("-error"))
            objects = {oid: False}
            if name == "second-object-missing":
                objects["f" * 40] = False
            with (
                self.subTest(case=name),
                patch.object(transport.subprocess, "Popen", return_value=process),
                self.assertRaises((ValueError, OSError)),
            ):
                transport.read_blob_metadata(self.repo, objects)
            self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.waited)
        with (
            patch.object(
                transport.subprocess, "Popen", side_effect=OSError("controlled launch failure")
            ),
            self.assertRaises(OSError),
        ):
            transport.read_blob_metadata(self.repo, {oid: False})

    def test_actual_git_union_retains_modes_rename_deletion_links_raw_and_tested_inputs(self):
        bound, union = self.union()
        by_path = {base64.b64decode(x["raw_path_base64"]): x for x in union["entries"]}
        self.assertEqual(
            set(by_path),
            {
                b"same",
                b"deleted",
                b"old-name",
                b"new-name",
                b"link",
                b"bad_\xff",
                b"submodule",
                b"tested-only",
            },
        )
        self.assertEqual(
            [base64.b64decode(x["raw_path_base64"]) for x in union["entries"]], sorted(by_path)
        )
        self.assertEqual(by_path[b"same"]["base"]["sha256"], by_path[b"same"]["head"]["sha256"])
        self.assertEqual(by_path[b"same"]["base"]["mode"], "100644")
        self.assertEqual(by_path[b"same"]["head"]["mode"], "100755")
        for path in [b"deleted", b"old-name"]:
            self.assertEqual(by_path[path]["head"], transport.absent(by_path[path]["head"]["tree"]))
        self.assertEqual(
            by_path[b"old-name"]["base"]["sha256"], by_path[b"new-name"]["head"]["sha256"]
        )
        self.assertFalse(by_path[b"tested-only"]["base"]["present"])
        self.assertTrue(by_path[b"tested-only"]["tested"]["present"])
        link = by_path[b"link"]["head"]
        self.assertEqual(
            base64.b64decode(link["symlink_target_base64"]), b"/outside/unread-example"
        )
        self.assertEqual(link["sha256"], transport.digest(b"/outside/unread-example"))
        self.assertIsNone(by_path[b"bad_\xff"]["decoded_path"])
        self.assertIn("ambiguous-path", by_path[b"bad_\xff"]["unresolved"])
        self.assertEqual(by_path[b"submodule"]["head"]["type"], "gitlink")
        self.assertIsNone(by_path[b"submodule"]["head"]["sha256"])
        self.assertEqual(union["test_tree"], bound["test_tree"])
        for entry in union["entries"]:
            self.assertEqual(entry["protected_producers"], GRAPH["producers"])
            self.assertEqual(entry["protected_expected_ids"], GRAPH["inventory_families"])
            self.assertTrue(set(GRAPH["holds"]) <= set(entry["unresolved"]))
        self.assertEqual(len(union["external_inputs"]), 11)
        self.assertTrue(union["fallback"])

    def test_duplicate_nonfinite_nonobject_and_invalid_utf8_documents_reject(self):
        for invalid in [
            b'{"version":2,"version":2}',
            b'{"nested":{"x":1,"x":1}}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b"[]",
            b"\xff",
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                transport.load(invalid)

    def test_schema_rejects_unknown_versions_types_missing_extra_and_duplicate_targets(self):
        _, valid, _ = self.prepared()
        variants = [
            ("version", True),
            ("version", 1),
            ("version", 3),
            ("scope", None),
            ("selected", ["docs", "docs"]),
            ("extra", 1),
        ]
        for field, value in variants:
            mutated = {**valid, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                transport.validate_schema(
                    mutated, transport.load(RECORDS["ci/ci-plan.schema.json"])
                )
        for field in valid:
            mutated = deepcopy(valid)
            del mutated[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                transport.validate_schema(
                    mutated, transport.load(RECORDS["ci/ci-plan.schema.json"])
                )
        for key, value in [("version", True), ("components", ["unknown"]), ("changes", {})]:
            mutated = deepcopy(valid)
            mutated["component_plan"][key] = value
            with self.subTest(component_field=key), self.assertRaises(ValueError):
                transport.validate_schema(
                    mutated, transport.load(RECORDS["ci/ci-plan.schema.json"])
                )

    def test_protected_policy_cannot_reduce_original_or_component_inventories(self):
        policy = transport.load(RECORDS["ci/pr-policy.json"])
        for field, value in [
            ("version", True),
            ("plan_envelope_version", True),
            ("component_plan_version", True),
            ("components", []),
            ("infrastructure_modules", []),
            ("scopes", {"full": ["docs"]}),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                transport.validate_transport_policy({**policy, field: value})
        transport.validate_transport_policy(policy)

    def test_protected_registry_preserves_independent_exact_ids_and_all_holds(self):
        inventory = transport.load(RECORDS["ci/ci-expected-inventory.json"])["families"]
        self.assertEqual(len(GRAPH["producers"]), 47)
        self.assertEqual(len(GRAPH["holds"]), 11)
        self.assertEqual(len(inventory["python_component"]["tests"]), 17)
        self.assertEqual(
            inventory["python_component"]["supported_interpreters"], ["3.10.20", "3.13.15"]
        )
        self.assertEqual(len(inventory["conformance_component"]["expected_python_methods"]), 39)
        self.assertEqual(len(inventory["npm_component"]["expected_commands"]), 6)
        self.assertEqual(len(inventory["infrastructure_component"]["modules"]), 3)
        self.assertEqual(len(inventory["fuzz"]["declared_targets"]), 7)
        self.assertEqual(len(inventory["fstar"]["required_passes"]), 5)
        self.assertEqual(len(inventory["tamarin"]["selection"]), 53)
        self.assertEqual(sum(len(x["lemmas"]) for x in inventory["tamarin"]["selection"]), 296)
        self.assertEqual(sum(len(x.get("harnesses", [])) for x in inventory["kani"]["groups"]), 31)
        self.assertFalse(GRAPH["narrowing_adopted"])
        expected = transport.load(RECORDS["ci/ci-expected-inventory.json"])
        self.assertEqual(len(expected["nix_static_checks"]), 20)
        self.assertEqual(len(expected["source_candidates"]["python_test_methods"]), 755)
        self.assertEqual(len(expected["source_candidates"]["rust_test_harness_candidates"]), 2841)

    def test_inherited_git_authority_overrides_reject_without_exposing_values(self):
        for key in [*sorted(transport.GIT_OVERRIDES), "GIT_CONFIG_KEY_0"]:
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: "private-placeholder"}),
                self.assertRaisesRegex(ValueError, "authority override"),
            ):
                transport.git(self.repo, "rev-parse", "HEAD")

    def test_unintegrated_or_candidate_transport_records_cannot_become_authority(self):
        sha = LEGACY_SOURCE
        tree = transport.git(ROOT, "rev-parse", f"{sha}^{{tree}}").decode().strip()
        bound = {
            **BOUND,
            "base": sha,
            "event_base": sha,
            "source_head": sha,
            "test_sha": sha,
            "test_tree": tree,
        }
        original = transport.git

        def historical_checkout(repo, *args):
            if args == ("rev-parse", "HEAD"):
                return sha.encode()
            return original(repo, *args)

        with (
            patch.object(transport, "git", side_effect=historical_checkout),
            self.assertRaisesRegex(ValueError, "protected base"),
        ):
            transport.check_protected_source(ROOT, bound, RECORDS)
        with self.assertRaisesRegex(ValueError, "event context"):
            transport.check_protected_source(ROOT, {**bound, "unexpected": "x"}, RECORDS)

    def test_preparation_is_full_with_complete_changes_and_protected_commitments(self):
        bound, plan, union = self.prepared()
        self.assertEqual(plan["scope"], "full")
        self.assertEqual(plan["selected"], transport.LANES)
        self.assertEqual(plan["component_plan"]["components"], transport.COMPONENTS)
        self.assertEqual(plan["component_plan"]["infrastructure_modules"], transport.MODULES)
        self.assertEqual(
            [tuple(x[k] for k in transport.IDENTITY) for x in plan["changes"]],
            [tuple(x[k] for k in transport.IDENTITY) for x in plan["component_plan"]["changes"]],
        )
        self.assertEqual(plan["input_union"]["sha256"], transport.digest(union))
        self.assertEqual(
            plan["expected_inventory"]["sha256"],
            transport.digest(RECORDS["ci/ci-expected-inventory.json"]),
        )
        self.assertEqual(plan["result_contract"]["authority_commit"], bound["base"])
        self.assertEqual(
            plan["component_plan_provenance"],
            {
                **bound,
                "classifier_sha256": plan["classifier_sha256"],
                "policy_sha256": plan["policy_sha256"],
            },
        )

    def test_exact_full_artifact_and_compact_provenance_admission(self):
        bound, plan, union = self.prepared()
        data = transport.encoded(plan)
        outputs = self.outputs(data)
        with patch.object(transport, "prepare", return_value=(plan, union)):
            receipt = transport.verify(self.repo, bound, RECORDS, PRODUCER, data, union, outputs)
            self.assertEqual(receipt["admission"], "protected-v2-conservative-full")
            for mutated_data in [
                data + b" ",
                data.replace(b'"version": 2', b'"version": 2,"version": 2', 1),
            ]:
                with self.subTest(artifact="exact bytes"), self.assertRaises(ValueError):
                    transport.verify(
                        self.repo, bound, RECORDS, PRODUCER, mutated_data, union, outputs
                    )
            for key in ["component_plan_sha256", "component_targets", "component_plan_provenance"]:
                missing = deepcopy(outputs)
                del missing[key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    transport.verify(self.repo, bound, RECORDS, PRODUCER, data, union, missing)
            for key in ["component_targets", "component_plan_provenance"]:
                wrong = deepcopy(outputs)
                wrong[key] = {}
                with self.subTest(wrong=key), self.assertRaises(ValueError):
                    transport.verify(self.repo, bound, RECORDS, PRODUCER, data, union, wrong)

    def test_alternate_plan_bytes_reject_even_with_recomputed_digest(self):
        bound, plan, union = self.prepared()
        canonical = transport.encoded(plan)
        alternatives = [
            canonical + b" ",
            canonical.rstrip(b"\n"),
            json.dumps(plan, separators=(",", ":")).encode(),
            json.dumps(plan, sort_keys=True, indent=4).encode() + b"\n",
        ]
        with patch.object(transport, "prepare", return_value=(plan, union)):
            receipt = transport.verify(
                self.repo, bound, RECORDS, PRODUCER, canonical, union, self.outputs(canonical)
            )
            self.assertEqual(receipt["component_plan_sha256"], transport.digest(canonical))
            for data in alternatives:
                with self.subTest(serialization=data[:40]):
                    self.assertNotEqual(data, canonical)
                    self.assertEqual(transport.load(data), plan)
                    outputs = self.outputs(data)
                    self.assertEqual(outputs["component_plan_sha256"], transport.digest(data))
                    with self.assertRaisesRegex(ValueError, "protected Git-object authority"):
                        transport.verify(self.repo, bound, RECORDS, PRODUCER, data, union, outputs)

    def test_full_plan_mutations_reject_even_with_recomputed_digest(self):
        bound, valid, union = self.prepared()
        for field, value in [
            ("scope", "docs"),
            ("selected", ["docs"]),
            ("source_head", "e" * 40),
            ("schema_sha256", "e" * 64),
            ("producer", {**PRODUCER, "run_attempt": 2}),
        ]:
            plan = {**valid, field: value}
            data = transport.encoded(plan)
            with (
                self.subTest(field=field),
                patch.object(transport, "prepare", return_value=(valid, union)),
                self.assertRaisesRegex(ValueError, "protected Git-object"),
            ):
                transport.verify(
                    self.repo, bound, RECORDS, PRODUCER, data, union, self.outputs(data)
                )

    def test_union_removed_reordered_mode_or_commitment_changes_reject(self):
        bound, plan, valid = self.prepared()
        original = transport.load(valid)
        mutations = []
        missing = deepcopy(original)
        missing["entries"].pop()
        mutations.append(missing)
        reordered = deepcopy(original)
        reordered["entries"].reverse()
        mutations.append(reordered)
        mode = deepcopy(original)
        mode["entries"][0]["base"]["mode"] = "100755"
        mutations.append(mode)
        graph = deepcopy(original)
        graph["protected_graph_sha256"] = "e" * 64
        mutations.append(graph)
        for mutated in [transport.encoded(x) for x in mutations] + [valid + b" "]:
            data = transport.encoded(plan)
            with (
                self.subTest(union="identity or bytes"),
                patch.object(transport, "prepare", return_value=(plan, valid)),
                self.assertRaises(ValueError),
            ):
                transport.verify(
                    self.repo, bound, RECORDS, PRODUCER, data, mutated, self.outputs(data)
                )

    def test_raw_changes_keep_rename_sides_and_fail_on_incomplete_or_nonutf8(self):
        raw = (
            b":100644 000000 " + b"1" * 40 + b" " + b"0" * 40 + b" D\0old\0"
            b":000000 100644 " + b"0" * 40 + b" " + b"1" * 40 + b" A\0new\0"
        )
        with patch.object(transport, "git", side_effect=[b"a" * 40, raw]) as git:
            _, changes, error = transport.authoritative_changes(ROOT, BOUND)
        self.assertEqual([x["status"] for x in changes], ["A", "D"])
        self.assertFalse(error)
        self.assertIn("--no-renames", git.call_args.args)
        self.assertIn("--no-abbrev", git.call_args.args)
        self.assertIn("--ignore-submodules=none", git.call_args.args)
        for invalid in [raw[:-1], raw + b"truncated"]:
            with (
                self.subTest(raw="truncated"),
                patch.object(transport, "git", side_effect=[b"a" * 40, invalid]),
                self.assertRaisesRegex(ValueError, "incomplete"),
            ):
                transport.authoritative_changes(ROOT, BOUND)
        with patch.object(
            transport, "git", side_effect=[b"a" * 40, raw.replace(b"old", b"bad_\xff")]
        ):
            _, changes, error = transport.authoritative_changes(ROOT, BOUND)
        self.assertEqual(changes, [])
        self.assertIn("literal identity", error)

    def raw_diff_fixture(self):
        merge_base = "9" * 40
        old_tree = self.tree(
            [
                (b"gone_\xff", "100644", b"merge-base-only deletion"),
                (b"old-submodule", "160000", b""),
                (b"old-name", "100644", b"rename"),
                (b"modified", "100644", b"old bytes"),
                (b"mode", "100644", b"same bytes"),
                (b"kind", "100644", b"regular"),
            ]
        )
        trees = {
            "base": self.tree([(b"base-only", "100644", b"base input")]),
            "head": self.tree(
                [
                    (b"new-name", "100644", b"rename"),
                    (b"modified", "100644", b"new bytes"),
                    (b"mode", "100755", b"same bytes"),
                    (b"kind", "120000", b"literal-target"),
                ]
            ),
            "tested": self.tree([(b"tested-only", "100644", b"queue input")]),
        }
        bound = {**BOUND, "test_tree": trees["tested"]}
        original = transport.git

        def objects(repo, *args):  # noqa: PLR0911 - modeled commit context, literal Git objects
            if args[0] == "merge-base":
                return (merge_base + "\n").encode()
            if args[0] == "show":
                return b"protected classifier bytes"
            if args[0] == "rev-parse":
                return (
                    trees[
                        {
                            BOUND["base"]: "base",
                            BOUND["source_head"]: "head",
                            BOUND["test_sha"]: "tested",
                        }[args[1].split("^")[0]]
                    ]
                    + "\n"
                ).encode()
            if args[0] == "diff":
                args = tuple(
                    old_tree
                    if arg == merge_base
                    else trees["head"]
                    if arg == BOUND["source_head"]
                    else arg
                    for arg in args
                )
            return original(repo, *args)

        return bound, merge_base, old_tree, trees, objects

    def test_raw_diff_retains_nonutf8_merge_base_only_deletion_and_full_fallback(self):  # noqa: PLR0915 - complete raw/endpoint identity and fallback fixture
        bound, merge_base, old_tree, trees, objects = self.raw_diff_fixture()
        subprocess.run(  # noqa: S603 - fixed literal Git setting in commitless fixture
            ["git", "-C", str(self.repo), "config", "diff.ignoreSubmodules", "all"],  # noqa: S607 - Git
            check=True,
            capture_output=True,
        )
        with (
            patch.object(transport, "git", side_effect=objects),
            patch.object(transport, "check_protected_source"),
        ):
            plan, union_bytes = transport.prepare(self.repo, bound, RECORDS, PRODUCER)
            receipt = transport.verify(
                self.repo,
                bound,
                RECORDS,
                PRODUCER,
                transport.encoded(plan),
                union_bytes,
                self.outputs(transport.encoded(plan)),
            )
        union = transport.load(union_bytes)
        record = union["raw_diff"]
        raw = transport.git(
            self.repo,
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-renames",
            "--ignore-submodules=none",
            "--no-ext-diff",
            "--no-textconv",
            old_tree,
            trees["head"],
            "--",
        )
        self.assertEqual(transport.checked_raw_diff(record), raw)
        self.assertEqual(record["sha256"], transport.digest(raw))
        self.assertEqual(record["merge_base"], merge_base)
        self.assertEqual(plan["merge_base"], merge_base)
        self.assertIn(b"gone_\xff\0", raw)
        endpoints = {base64.b64decode(entry["raw_path_base64"]) for entry in union["entries"]}
        self.assertNotIn(b"gone_\xff", endpoints)
        self.assertNotIn(b"old-submodule", endpoints)
        fields = raw.split(b"\0")
        by_path = dict(zip(fields[1::2], fields[:-1:2], strict=True))
        self.assertTrue(by_path[b"gone_\xff"].endswith(b" D"))
        self.assertTrue(by_path[b"old-name"].endswith(b" D"))
        self.assertTrue(by_path[b"old-submodule"].startswith(b":160000 000000 "))
        self.assertTrue(by_path[b"old-submodule"].endswith(b" D"))
        self.assertTrue(by_path[b"new-name"].endswith(b" A"))
        self.assertTrue(by_path[b"modified"].endswith(b" M"))
        self.assertTrue(by_path[b"kind"].endswith(b" T"))
        self.assertTrue(by_path[b"mode"].startswith(b":100644 100755 "))
        for header in by_path.values():
            self.assertEqual([len(oid) for oid in header.split()[2:4]], [40, 40])
        self.assertEqual(plan["scope"], "full")
        self.assertEqual(plan["selected"], transport.LANES)
        self.assertEqual(plan["changes"], [])
        self.assertEqual(plan["component_plan"]["version"], 1)
        self.assertEqual(plan["component_plan"]["components"], transport.COMPONENTS)
        self.assertEqual(plan["component_plan"]["infrastructure_modules"], transport.MODULES)
        self.assertIn("nonUTF8", plan["fallback"])
        for hold in GRAPH["holds"]:
            self.assertIn(hold, plan["fallback"])
        self.assertEqual(receipt["admission"], "protected-v2-conservative-full")

    def verify_mutated_raw_union(self, bound, plan, union):
        union_bytes = transport.encoded(union)
        mutated = deepcopy(plan)
        mutated["input_union"]["sha256"] = transport.digest(union_bytes)
        data = transport.encoded(mutated)
        return transport.verify(
            self.repo,
            bound,
            RECORDS,
            PRODUCER,
            data,
            union_bytes,
            self.outputs(data),
        )

    def test_raw_diff_identity_tampering_rejects_recomputed_commitments(self):
        bound, _, _, _, objects = self.raw_diff_fixture()
        with (
            patch.object(transport, "git", side_effect=objects),
            patch.object(transport, "check_protected_source"),
        ):
            plan, valid = transport.prepare(self.repo, bound, RECORDS, PRODUCER)
            original = transport.load(valid)
            raw = transport.checked_raw_diff(original["raw_diff"])
            for field, changed in (
                ("deleted path", raw.replace(b"gone_\xff", b"other_\xff")),
                ("old object", raw.replace(raw.split(b" ")[2], b"f" * 40, 1)),
                ("status", raw.replace(b" D\0old-name", b" M\0old-name")),
                ("mode", raw.replace(b":100644 100755", b":100755 100755")),
            ):
                union = deepcopy(original)
                union["raw_diff"]["raw_base64"] = base64.b64encode(changed).decode("ascii")
                union["raw_diff"]["sha256"] = transport.digest(changed)
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(ValueError, "protected Git-object"),
                ):
                    self.verify_mutated_raw_union(bound, plan, union)
            union = deepcopy(original)
            union["raw_diff"]["merge_base"] = "f" * 40
            with self.assertRaisesRegex(ValueError, "merge base differ"):
                self.verify_mutated_raw_union(bound, plan, union)
            changed_plan = deepcopy(plan)
            changed_plan["merge_base"] = "f" * 40
            with self.assertRaisesRegex(ValueError, "protected Git-object"):
                self.verify_mutated_raw_union(bound, changed_plan, union)

    def test_raw_diff_strict_schema_encoding_hash_and_commit_rejection(self):
        bound, _, _, _, objects = self.raw_diff_fixture()
        with (
            patch.object(transport, "git", side_effect=objects),
            patch.object(transport, "check_protected_source"),
        ):
            plan, valid = transport.prepare(self.repo, bound, RECORDS, PRODUCER)
            original = transport.load(valid)
            cases = [
                ("version", True),
                ("version", 2),
                ("version", "1"),
                ("merge_base", "a" * 39),
                ("merge_base", "g" * 40),
                ("merge_base", None),
                ("sha256", "a" * 63),
                ("sha256", "g" * 64),
                ("sha256", 1),
                ("sha256", "0" * 64),
                ("raw_base64", None),
                ("raw_base64", "%%%"),
                ("raw_base64", "é"),
                ("raw_base64", original["raw_diff"]["raw_base64"] + "\n"),
                ("raw_base64", original["raw_diff"]["raw_base64"] + "="),
            ]
            for key, value in cases:
                union = deepcopy(original)
                union["raw_diff"][key] = value
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    self.verify_mutated_raw_union(bound, plan, union)
            for key in original["raw_diff"]:
                union = deepcopy(original)
                del union["raw_diff"][key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    self.verify_mutated_raw_union(bound, plan, union)
            for field in ("unknown",):
                union = deepcopy(original)
                union["raw_diff"][field] = 1
                with self.assertRaises(ValueError):
                    self.verify_mutated_raw_union(bound, plan, union)
            for replacement in (None, [], True):
                union = deepcopy(original)
                union["raw_diff"] = replacement
                with self.subTest(raw_diff=replacement), self.assertRaises(ValueError):
                    self.verify_mutated_raw_union(bound, plan, union)
            del original["raw_diff"]
            with self.assertRaises(ValueError):
                self.verify_mutated_raw_union(bound, plan, original)

    def test_raw_diff_noncanonical_padding_and_malformed_headers_reject(self):
        raw = b":000000 100644 " + b"0" * 40 + b" " + b"1" * 40 + b" A\0path\0"
        while len(raw) % 3 == 0:
            raw = raw[:-1] + b"p\0"
        encoded = base64.b64encode(raw).decode("ascii")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        index = len(encoded.rstrip("=")) - 1
        noncanonical = (
            encoded[:index] + alphabet[alphabet.index(encoded[index]) + 1] + encoded[index + 1 :]
        )
        self.assertEqual(base64.b64decode(noncanonical), raw)
        record = {
            "version": 1,
            "merge_base": "9" * 40,
            "raw_base64": noncanonical,
            "sha256": transport.digest(raw),
        }
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            transport.checked_raw_diff(record)
        self.assertEqual(transport.parse_raw_changes(b""), ([], ""))
        for malformed in (
            raw[:-1],
            raw + b"truncated",
            raw.replace(b"1" * 40, b"1" * 7),
            raw.replace(b" A\0", b" R100\0"),
            raw.replace(b":000000", b"000000"),
            raw.replace(b"100644", b"100600"),
            raw.replace(b"path", b""),
            raw.replace(b"path", b"bad_\xff") + b":malformed\0later\0",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                transport.parse_raw_changes(malformed)
        with (
            patch.object(transport, "git", return_value=b"1234567"),
            self.assertRaisesRegex(ValueError, "full commit"),
        ):
            transport.authoritative_raw_diff(self.repo, BOUND)

    def test_workflow_preparation_preserves_all_jobs_conditions_and_publication(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        parent_bytes = transport.git(
            ROOT, "show", "856c1793bc74f218fd6dc55d3c8ea41024c3ef21:.github/workflows/pr.yml"
        )
        parent = yaml.safe_load(parent_bytes)
        self.assertEqual(set(workflow["jobs"]), set(parent["jobs"]))
        for key in [True, "permissions", "concurrency"]:
            self.assertEqual(workflow[key], parent[key])
        for job in [*transport.LANES, "required"]:
            self.assertEqual(workflow["jobs"][job], parent["jobs"][job])
        outputs = workflow["jobs"]["plan"]["outputs"]
        self.assertEqual(outputs["plan_artifact_id"], "${{ steps.evidence.outputs.artifact-id }}")
        run = next(
            step["run"]
            for step in workflow["jobs"]["plan"]["steps"]
            if step.get("id") == "transport"
        )
        body = run.split("python3 -I - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        ast.parse(body)
        self.assertIn("legacy-full-installation", body)
        self.assertIn("plan.get('scope') != 'full'", body)
        self.assertNotIn("import pr_plan", body)
        self.assertIn("--records", body)

    def test_legacy_installation_retains_exact_artifact_and_never_admits_missing_as_empty(self):  # noqa: PLR0915 - complete protected-v1 installation fixture
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        run = next(
            step["run"]
            for step in workflow["jobs"]["plan"]["steps"]
            if step.get("id") == "transport"
        )
        body = run.split("python3 -I - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        head = LEGACY_SOURCE
        base = transport.git(ROOT, "rev-parse", f"{head}^1").decode().strip()
        tree = transport.git(ROOT, "rev-parse", f"{head}^{{tree}}").decode().strip()
        policy = transport.git(ROOT, "show", f"{base}:ci/pr-policy.json")
        source = transport.git(ROOT, "show", f"{base}:scripts/ci/pr_plan.py")
        script, config, output = (
            self.repo / "trusted.py",
            self.repo / "policy.json",
            self.repo / "ci-plan.json",
        )
        script.write_bytes(source)
        config.write_bytes(policy)
        subprocess.run(  # noqa: S603 - exact protected Git source, offline only
            [
                sys.executable,
                str(script),
                "--repo",
                str(ROOT),
                "--base",
                base,
                "--head",
                head,
                "--policy",
                str(config),
                "--output",
                str(output),
            ],
            check=True,
            capture_output=True,
            env={key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"},
        )
        bound = {
            "event": "merge_group",
            "event_base": base,
            "base": base,
            "source_head": head,
            "test_sha": head,
            "test_tree": tree,
        }
        plan = {**transport.load(output.read_bytes()), **bound}
        self.assertEqual(plan["scope"], "full")
        commits = (
            transport.git(ROOT, "rev-list", "--reverse", f"{base}..{head}").decode().splitlines()
        )
        validation = {
            **bound,
            "signatures_valid": True,
            "signatures": [{"sha": sha, "verified": True, "reason": "valid"} for sha in commits],
            "verifier_sha256": transport.digest(
                transport.git(ROOT, "show", f"{base}:scripts/ci/validate_change.py")
            ),
        }
        env = {
            "VALIDATED_BASE": base,
            "VALIDATED_HEAD": head,
            "VALIDATED_TEST": head,
            "GITHUB_OUTPUT": str(self.repo / "outputs"),
        }
        original_check_output = subprocess.check_output

        def protected_objects(*args, **kwargs):
            self.assertEqual(args[0][0], "git", "legacy candidate execution")
            return original_check_output(["git", "-C", str(ROOT), *args[0][1:]], **kwargs)

        previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, previous)
        Path("ci-plan.json").write_bytes(transport.encoded(plan))
        Path("ci-validation.json").write_bytes(transport.encoded(validation))
        original = Path("ci-plan.json").read_bytes()
        with (
            patch.dict(os.environ, env),
            patch("subprocess.check_output", side_effect=protected_objects),
        ):
            # Git-only reads use the bound actual repository; no fixture commits.
            exec(compile(body, "protected-transport-inline", "exec"), {})  # noqa: S102 - reviewed fixed workflow body
        outputs = dict(line.split("=", 1) for line in Path("outputs").read_text().splitlines())
        self.assertEqual(
            transport.load(outputs["component_targets"].encode())["components"],
            transport.COMPONENTS,
        )
        self.assertEqual(outputs["component_plan_sha256"], transport.digest(original))
        self.assertEqual(outputs["transport_version"], "1")
        self.assertEqual(Path("ci-plan.json").read_bytes(), original)
        for field, value in [
            ("version", True),
            ("scope", "docs"),
            ("changes", []),
            ("classifier_sha256", "0" * 64),
            ("unexpected", "x"),
        ]:
            Path("ci-plan.json").write_bytes(transport.encoded({**plan, field: value}))
            Path("outputs").unlink(missing_ok=True)
            with (
                self.subTest(field=field),
                patch.dict(os.environ, env),
                patch("subprocess.check_output", side_effect=protected_objects),
                self.assertRaises(ValueError),
            ):
                exec(compile(body, "legacy-rejection-control", "exec"), {})  # noqa: S102 - fixed reviewed workflow body
            self.assertFalse(Path("outputs").exists())

    def protected_v2_case(self):
        bound, plan, union = self.prepared()
        source = (ROOT / "scripts/ci/pr_plan.py").read_bytes()
        protected = {
            **RECORDS,
            "scripts/ci/pr_plan.py": source,
            "scripts/ci/verify_ci_plan.py": (ROOT / "scripts/ci/verify_ci_plan.py").read_bytes(),
        }
        plan["classifier_sha256"] = transport.digest(source)
        plan["component_plan_provenance"]["classifier_sha256"] = transport.digest(source)
        event = self.repo / "event.json"
        event.write_text("{}")
        plan["producer"]["event_payload_sha256"] = transport.digest(event.read_bytes())
        for path in ["scripts/ci/pr_plan.py", "scripts/ci/verify_ci_plan.py", "ci/pr-policy.json"]:
            candidate = self.repo / path
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text('raise RuntimeError("candidate authority executed")')
        env = {
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "codetakt/aegaeon",
            "GITHUB_OUTPUT": str(self.repo / "outputs"),
        }

        def read(argv, **_kwargs):
            self.assertEqual(argv[:2], ["git", "show"])
            self.assertTrue(argv[2].startswith(bound["base"] + ":"))
            return protected[argv[2].split(":", 1)[1]]

        def execute(argv, **kwargs):
            self.assertNotIn("GITHUB_OUTPUT", kwargs["env"])
            records = Path(argv[argv.index("--records") + 1])
            for path, data in protected.items():
                if path == "scripts/ci/pr_plan.py":
                    continue
                self.assertEqual((records / path).read_bytes(), data)
            self.assertEqual(
                transport.load(Path(argv[argv.index("--context") + 1]).read_bytes()), bound
            )
            Path(argv[argv.index("--plan") + 1]).write_bytes(transport.encoded(plan))
            Path(argv[argv.index("--union") + 1]).write_bytes(union)

        previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, previous)
        return bound, env, read, execute

    def test_v2_selection_extracts_only_protected_complete_transport(self):
        bound, env, read, execute = self.protected_v2_case()
        with (
            patch.dict(os.environ, env),
            patch("validate_change.subprocess.check_output", side_effect=read),
            patch("validate_change.subprocess.run", side_effect=execute),
        ):
            selected = validate_change.classify(bound, self.repo / "selected.json")
        self.assertEqual(selected["version"], 2)
        self.assertEqual(selected["component_plan"]["components"], transport.COMPONENTS)
        self.assertFalse(Path("outputs").exists())

    def test_v2_missing_protected_record_fails_without_empty_success(self):
        bound, env, read, _execute = self.protected_v2_case()

        def missing(argv, **kwargs):
            if argv[2].endswith(":ci/ci-plan.schema.json"):
                raise subprocess.CalledProcessError(128, "git")
            return read(argv, **kwargs)

        with (
            patch.dict(os.environ, env),
            patch("validate_change.subprocess.check_output", side_effect=missing),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            validate_change.classify(bound, self.repo / "rejected.json")
        self.assertFalse(Path("rejected.json").exists())

    def test_reserved_artifact_preflight_rejects_regular_directory_symlink_and_hardlink(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        run = next(
            step["run"] for step in workflow["jobs"]["plan"]["steps"] if step.get("id") == "plan"
        )
        preflight = run.split("python3 -I - <<'PY'\n", 1)[1].split("\nPY", 1)[0]

        def invoke(directory):
            return subprocess.run(
                [sys.executable, "-I", "-"],
                input=preflight.encode(),
                cwd=directory,
                capture_output=True,
                check=False,
            )

        self.assertEqual(invoke(self.repo).returncode, 0)
        for kind in ["regular", "directory", "symlink", "hardlink"]:
            directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
            reserved = directory / "ci-plan.json"
            if kind == "regular":
                reserved.write_text("original")
            elif kind == "directory":
                reserved.mkdir()
            elif kind == "symlink":
                reserved.symlink_to(directory / "absent-target")
            else:
                source = directory / "source"
                source.write_text("original")
                reserved.hardlink_to(source)
            with self.subTest(kind=kind):
                result = invoke(directory)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"reserved CI artifact already exists", result.stderr)
                if kind in {"regular", "hardlink"}:
                    self.assertEqual(reserved.read_text(), "original")

    def test_isolated_python_does_not_import_candidate_shadow_module(self):
        (self.repo / "json.py").write_text('raise RuntimeError("candidate shadow module")')
        code = 'import json; print(json.dumps({"isolated": True}))'
        safe = subprocess.run(  # noqa: S603 - isolated standard-library import
            [sys.executable, "-I", "-c", code], cwd=self.repo, capture_output=True, check=False
        )
        unsafe = subprocess.run(  # noqa: S603 - bounded shadow-module negative control
            [sys.executable, "-c", code], cwd=self.repo, capture_output=True, check=False
        )
        self.assertEqual(safe.returncode, 0)
        self.assertEqual(transport.load(safe.stdout), {"isolated": True})
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertIn(b"candidate shadow module", unsafe.stderr)
