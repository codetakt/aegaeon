"""Regressions for false acceptance reproduced during the non-author review."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from test_assumption_graph import Fixture, ag, rewrap, summary, write_json


class ReviewedGraphRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))
        self.fixture.install()
        self.register_path = self.fixture.src / "spec/assumption-register.json"

    def accept(self, register):
        for entry in register["entries"]:
            entry["status"] = "accepted"
            entry["review"] = {
                "reviewer_id": "synthetic-test-reviewer",
                "reviewer_role": "test control only",
                "date": "2026-09-12",
                "record": "synthetic control; not a real premise acceptance",
                "subject_sha256": ag.review_subject_digest(entry),
            }
        return register

    def rebuilt(self, register=None):
        if register is not None:
            write_json(self.register_path, register)
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout
        return graph

    def external_register(self):
        self.fixture.sources["fstar/Alpha.fst"] += (
            "\nlet collision_event (a b:nat) : Type0 = a = b\n"
        )
        self.fixture.install()
        register = json.loads(self.register_path.read_text())
        for kind in ["computational", "symbolic-abstraction"]:
            register["entries"].append(
                {
                    "id": f"test-{kind}",
                    "kind": kind,
                    "title": "Synthetic external premise",
                    "statement": "External interpretation only; no mathematical axiom",
                    "status": "specified-not-attested",
                    "events": ["Alpha.collision_event"],
                }
            )
        return register

    def test_each_tool_and_external_premise_blocks_qualification(self):
        register = self.accept(self.external_register())
        graph = self.rebuilt(register)
        assert self.fixture.qualify(graph).returncode == 0
        ids = [
            e["id"]
            for e in register["entries"]
            if e["kind"] in ("tool", "computational", "symbolic-abstraction")
        ]
        for entry_id in ids:
            with self.subTest(entry=entry_id):
                changed = copy.deepcopy(register)
                next(e for e in changed["entries"] if e["id"] == entry_id)["status"] = "rejected"
                graph = self.rebuilt(changed)
                result = self.fixture.qualify(graph)
                assert result.returncode == 2, result.stdout
                assert any("not accepted" in r for r in summary(result)["reasons"])

    def test_implicit_external_justification_cycle_is_rejected(self):
        register = self.external_register()
        register["entries"][-1]["justified_by"] = ["property:Alpha#alpha_prop"]
        graph = self.rebuilt(register)
        assert self.fixture.check(graph).returncode == 1

    def test_unresolved_event_is_fatal(self):
        register = self.external_register()
        register["entries"][-1]["events"] = ["Alpha.missing_event"]
        write_json(self.register_path, register)
        result, _ = self.fixture.build()
        assert result.returncode == 3
        assert "no declaration" in result.stdout

    def test_missing_malformed_and_stale_review_records_are_rejected(self):
        baseline = self.accept(json.loads(self.register_path.read_text()))
        changes = [
            ("review", None),
            ("reviewer_id", ""),
            ("reviewer_role", " "),
            ("date", "2026-02-30"),
            ("record", "\n"),
            ("subject_sha256", "0" * 64),
        ]
        for key, value in changes:
            with self.subTest(field=key):
                register = copy.deepcopy(baseline)
                if key == "review":
                    register["entries"][0].pop(key)
                else:
                    register["entries"][0]["review"][key] = value
                write_json(self.register_path, register)
                result, _ = self.fixture.build()
                assert result.returncode == 3, result.stdout
                assert "register" in result.stdout

    def test_actual_probe_command_return_codes_and_record_hash_are_bound(self):
        graph = self.rebuilt()
        path = self.fixture.evidence / "dependencies/1/record.json"
        record = json.loads(path.read_text())
        for key, value in [
            ("dependency_argv", ["/bin/false"]),
            ("load_argv", ["/bin/false"]),
            ("dependency_returncode", 1),
            ("load_returncode", 1),
            ("load_returncode", False),
            ("unexpected_field", "tamper"),
        ]:
            with self.subTest(field=key, value=value):
                changed = {**record, key: value}
                write_json(path, changed)
                assert self.fixture.check(graph).returncode == 1
        write_json(path, record)
        assert self.fixture.check(graph).returncode == 0

    def test_failed_proof_and_corrupt_output_are_rejected_even_after_rehash(self):
        graph = self.rebuilt()
        directory = self.fixture.evidence / "invocations/1"
        path = directory / "result.json"
        result = json.loads(path.read_text())
        write_json(path, {**result, "returncode": 1, "status": "failed"})
        assert self.fixture.check(graph).returncode == 1
        write_json(path, result)
        output = directory / "output.log"
        original = output.read_text()
        output.write_text(original + "* Error 19 at Alpha.fst(1,0-1,10): assertion failed\n")
        assert self.fixture.check(graph).returncode == 1
        # A coordinated record rehash must still fail admission, not just byte checks.
        changed = {**result, "output_sha256": ag.digest_file(output)}
        write_json(path, changed)
        modules = json.loads((directory / "modules.json").read_text())
        modules["output_sha256"] = changed["output_sha256"]
        write_json(directory / "modules.json", modules)
        admission = json.loads((self.fixture.evidence / "admission.json").read_text())
        admission["passes"]["1"].update(
            output_sha256=changed["output_sha256"],
            modules_sha256=ag.digest_file(directory / "modules.json"),
        )
        write_json(self.fixture.evidence / "admission.json", admission)
        result, _ = self.fixture.build()
        assert result.returncode == 3, result.stdout
        assert "replay rejected" in result.stdout

    def test_malformed_load_family_is_fatal_and_absent_event_stays_blocking(self):
        directory = self.fixture.evidence / "dependencies/1"
        path = directory / "load.log"
        original = path.read_text()
        record_path = directory / "record.json"
        record = json.loads(record_path.read_text())
        event = "Now lax-checking interface of Spec.X"
        path.write_text(original.replace(event, "Now lax-checking interface Spec.X"))
        write_json(record_path, {**record, "load_sha256": ag.digest_file(path)})
        result, _ = self.fixture.build()
        assert result.returncode == 3, result.stdout
        assert "malformed load-mode" in result.stdout
        # Removing the entire event cannot establish non-use, even with accepted entries.
        path.write_text(original.replace(event, ""))
        write_json(record_path, {**record, "load_sha256": ag.digest_file(path)})
        graph = self.rebuilt(self.accept(json.loads(self.register_path.read_text())))
        assert self.fixture.check(graph).returncode == 0
        result = self.fixture.qualify(graph)
        assert result.returncode == 2, result.stdout
        assert any("does not establish non-use" in r for r in summary(result)["reasons"])

    def test_proof_returncode_type_cannot_be_rebuilt_into_accepted_evidence(self):
        path = self.fixture.evidence / "invocations/1/result.json"
        original = json.loads(path.read_text())
        for value in (False, 0.0, "0", None):
            with self.subTest(value=repr(value)):
                write_json(path, {**original, "returncode": value})
                result, _ = self.fixture.build()
                assert result.returncode == 3, result.stdout
                assert "replay rejected" in result.stdout
                assert "return code" in result.stdout
        write_json(path, original)
        graph = self.rebuilt()
        assert self.fixture.check(graph).returncode == 0

    def test_duplicate_logical_edges_rejected_with_identical_or_conflicting_attributes(self):
        graph = self.rebuilt()
        body = json.loads(graph.read_text())["body"]
        for conflict in [False, True]:
            with self.subTest(conflict=conflict):
                changed = copy.deepcopy(body)
                edge = copy.deepcopy(body["edges"][0])
                if conflict:
                    edge["evidence"] = ["contradiction"]
                changed["edges"].append(edge)
                rewrap(graph, changed)
                assert self.fixture.check(graph).returncode == 1

    def test_tool_digest_mismatch_is_rejected_after_reconstruction(self):
        register = json.loads(self.register_path.read_text())
        for tool in ["tool:fstar", "tool:solver"]:
            with self.subTest(tool=tool):
                changed = copy.deepcopy(register)
                next(e for e in changed["entries"] if e["id"] == tool)["tool_sha256"] = "0" * 64
                graph = self.rebuilt(changed)
                result = self.fixture.check(graph)
                assert result.returncode == 1, result.stdout
                assert any("registered tool digest" in r for r in summary(result)["reasons"])

    def test_tool_nodes_cannot_be_accepted_through_non_tool_registrations(self):
        baseline = self.accept(json.loads(self.register_path.read_text()))
        assert self.fixture.qualify(self.rebuilt(baseline)).returncode == 0
        for tool in ("fstar", "solver"):
            for selector in ("premise_ids", "covers", "existing-provider"):
                for digest in ("matching", "wrong", "missing"):
                    with self.subTest(tool=tool, selector=selector, digest=digest):
                        register = copy.deepcopy(baseline)
                        entry = next(e for e in register["entries"] if e["id"] == f"tool:{tool}")
                        if selector == "existing-provider":
                            register["entries"].remove(entry)
                            entry = next(
                                e for e in register["entries"] if e["kind"] == "provider-lax-source"
                            )
                            entry["premise_ids"] = [f"premise:tool:{tool}"]
                        else:
                            entry["kind"] = "dependency-source"
                            if selector == "covers":
                                entry.pop("premise_ids")
                                entry["covers"] = [{"kind": "tool"}]
                        if digest == "wrong":
                            entry["tool_sha256"] = "0" * 64
                        elif digest == "missing":
                            entry.pop("tool_sha256", None)
                        self.accept(register)  # Bind every synthetic review to the mutated entry.
                        graph = self.rebuilt(register)
                        result = self.fixture.check(graph)
                        assert result.returncode == 1, result.stdout
                        assert any("non-tool register" in r for r in summary(result)["reasons"])
                        assert self.fixture.qualify(graph).returncode != 0


class ComposedCollisionRegistrations(unittest.TestCase):
    def test_composed_events_have_direct_full_hash_and_encoding_premises(self):
        root = Path(__file__).resolve().parents[2]
        register = json.loads((root / "spec/assumption-register.json").read_text())
        events = {entry["id"]: set(entry.get("events", [])) for entry in register["entries"]}
        expected = {
            "A-SHA256-CR": {
                "Verified.Crypto.Bridge.sha256_of_string_collision",
                "Pkce.s256_collision",
                "HashComputation.oidc_hash_collision",
                "Jose.SdJwt.disclosure_digest_collision",
            },
            "A-SHA384-CR": {"HashComputation.oidc_hash_collision"},
            "A-SHA512-CR": {"HashComputation.oidc_hash_collision"},
            "string_encoding_collision": {"Pkce.s256_collision"},
        }
        for premise, required in expected.items():
            with self.subTest(premise=premise):
                assert required <= events[premise]
                # Full hash resistance must not stand in for the separate
                # leftmost-half truncation premise.
                assert "HashComputation.truncation_collision" not in events[premise]


if __name__ == "__main__":
    unittest.main()
