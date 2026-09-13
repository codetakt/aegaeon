"""Batch provenance controls: incomplete or contradictory traces cannot qualify."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pytest
from test_assumption_graph import CWD, Fixture, ag, sha256, summary, write_json


def refresh_result_lines(record: dict, output: str) -> None:
    """Trace mutations move result lines; keep the synthetic admission record exact."""
    lines = output.splitlines()
    for entry in record["requested"]:
        if entry["disposition"] == "paired-interface":
            entry["line"] = None
            continue
        prefix = (
            "Verified module: "
            if entry["role"] == "implementation"
            else "Verified i'face (or impl+i'face): "
        )
        result = prefix + entry["module"]
        assert lines.count(result) == 1
        entry["line"] = lines.index(result) + 1


class TracedFixture(Fixture):
    def argv(self, pass_id: str) -> list[str]:
        argv = super().argv(pass_id)
        return [argv[0], *ag.TRACE_OPTIONS, *argv[1:]]

    def write_pass(self, pass_id: str) -> None:
        super().write_pass(pass_id)
        directory = self.evidence / "invocations" / pass_id
        probe = self.evidence / "dependencies" / pass_id
        # Spec.X stays in the conservative closure, with a parsing attempt but
        # without a type-checker load. No premise or dependency edge is removed.
        processing = [
            f"{CWD}/C.Loops.fst" if s == "krml:C.Loops.fst" else self.recorded(s)
            for s in self.dependencies[pass_id]
            if s != "hacl:Spec.X.fsti"
        ]
        trace = (
            ag.PROCESS_FILES
            + " ".join(processing)
            + "\n"
            + ag.VERIFY_FILES
            + " ".join(self.recorded(s) for s in self.requested[pass_id])
            + "\n"
            + (probe / "load.log").read_text().replace("Now lax-checking interface of Spec.X\n", "")
        )
        output = (directory / "output.log").read_text()
        (directory / "output.log").write_text(trace + output)
        (probe / "load.log").write_text(trace)
        for name in ("result.json", "modules.json"):
            data = ag.load_object(directory / name)
            data["output_sha256"] = ag.digest_file(directory / "output.log")
            if name == "modules.json":
                refresh_result_lines(data, trace + output)
            write_json(directory / name, data)
        record = ag.load_object(probe / "record.json")
        record["load_contract"] = ag.TRACE_CONTRACT
        record["load_argv"][3:5] = ag.TRACE_OPTIONS
        record["load_sha256"] = ag.digest_file(probe / "load.log")
        write_json(probe / "record.json", record)

    def register(self) -> dict:
        register = super().register()
        register["entries"].append(
            {
                "id": "provider-scan",
                "kind": "dependency-source",
                "title": "Unaccepted external source contracts",
                "status": "specified-not-attested",
                "statement": "A batch schedule does not prove these contracts sound or irrelevant.",
                "covers": [{"kind": "dependency-source", "origin": "provider:hacl"}],
            }
        )
        return register


class BatchTraceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = TracedFixture(self.root)
        self.fixture.install()

    def replace_trace(self, before: str, after: str, *, proof: bool = True, probe: bool = True):
        """Recompute all envelope digests: rejection must come from content checks."""
        directory = self.fixture.evidence / "invocations/1"
        if proof:
            path = directory / "output.log"
            path.write_text(path.read_text().replace(before, after))
            for name in ("result.json", "modules.json"):
                data = ag.load_object(directory / name)
                data["output_sha256"] = ag.digest_file(path)
                if name == "modules.json":
                    refresh_result_lines(data, path.read_text())
                write_json(directory / name, data)
            admission_path = self.fixture.evidence / "admission.json"
            admission = ag.load_object(admission_path)
            admission["passes"]["1"]["output_sha256"] = ag.digest_file(path)
            admission["passes"]["1"]["modules_sha256"] = ag.digest_file(directory / "modules.json")
            write_json(admission_path, admission)
        if probe:
            directory = self.fixture.evidence / "dependencies/1"
            path = directory / "load.log"
            path.write_text(path.read_text().replace(before, after))
            record = ag.load_object(directory / "record.json")
            record["load_sha256"] = ag.digest_file(path)
            write_json(directory / "record.json", record)

    def rejected(self, message: str):
        result, _ = self.fixture.build()
        assert result.returncode != 0, result.stdout
        assert message in result.stdout, result.stdout + result.stderr

    def test_scan_only_source_remains_a_reachable_unaccepted_premise(self):
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout + result.stderr
        assert self.fixture.check(graph).returncode == 0
        body = json.loads(graph.read_text())["body"]
        premise = "premise:dependency-source:Spec.X#interface"
        assert body["nodes"][premise]["premise_kind"] == "dependency-source"
        assert any(
            e["from"] == "property:Alpha#alpha_prop" and e["to"] == premise
            for e in body["edges"]
            if e["kind"] == "depends-on"
        )
        source = body["nodes"][f"source:{self.fixture.recorded('hacl:Spec.X.fsti')}"]
        assert source["sha256"] == sha256(b"module Spec.X\nval x : nat\n")
        result = self.fixture.qualify(graph)
        assert result.returncode == 2
        assert any(premise in r and "not accepted" in r for r in summary(result)["reasons"])

    def test_missing_scheduled_event_is_fatal_even_when_all_digests_match(self):
        self.replace_trace("Now verifying implementation of Alpha\n", "")
        self.rejected("scheduled source has no positive")

    def test_already_loaded_is_not_positive_type_check_evidence(self):
        self.replace_trace(
            "Now verifying implementation of Alpha\n",
            f"Already loaded checked file {CWD}/Alpha.fst.checked\n",
        )
        self.rejected("scheduled source has no positive")

    def test_proof_and_probe_schedule_must_match(self):
        self.replace_trace(f"{CWD}/Beta.fsti ", "", proof=False)
        self.rejected("proof and probe batch schedules differ")

    def test_complete_proof_trace_is_required_even_with_complete_probe(self):
        self.replace_trace(ag.PROCESS_FILES, "Discarded schedule: ", probe=False)
        self.rejected("missing complete batch schedule")

    def test_loaded_source_cannot_be_hidden_outside_the_schedule(self):
        self.replace_trace(f"{CWD}/Alpha.fst ", "")
        self.rejected("requested source absent")

    def test_interface_is_interleaved_with_its_adjacent_implementation(self):
        self.replace_trace("Now verifying interface of Beta\n", "")
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout
        node = ag.load_object(graph)["body"]["nodes"][f"source:{CWD}/Beta.fsti"]
        assert node["load_modes"]["1"]["interleaved_with"] == f"{CWD}/Beta.fst"

    def test_interleaving_rechecks_interface_after_its_cache_was_read(self):
        # Upstream can read the interface cache for dependency bookkeeping,
        # then fall back to source for the implementation and interleave both.
        # The independent real-F* control exercises this with an unrequested
        # provider so no requested .checked file violates admission preconditions.
        provider = "/provider/ReviewProvider"
        client = f"{CWD}/Alpha.fst"
        schedule = {
            "process": [provider + ".fsti", provider + ".fst", client],
            "verify": [client],
        }
        lines = [
            f"Trying to load checked file result {provider}.fsti.checked",
            f"Successfully loaded module from checked file {provider}.fsti.checked",
            f"Trying to load checked file with tc result {provider}.fst.checked",
            "Now lax-checking implementation of ReviewProvider",
            f"Trying to load checked file result {client}.checked",
            "Now verifying implementation of Alpha",
        ]
        modes = ag.traced_load_modes(
            schedule,
            ag.normalize_load_paths(ag.parse_load_log("\n".join(lines)), CWD),
            {s + ".checked": s for s in schedule["process"]},
            {client},
        )
        assert modes[provider + ".fsti"] == {
            "mode": "lax-source",
            "interleaved_with": provider + ".fst",
        }

    def test_interface_cannot_use_a_nonadjacent_implementation_event(self):
        self.replace_trace("Now verifying interface of Beta\n", "")
        self.replace_trace(
            f"{CWD}/Alpha.fst {CWD}/Beta.fsti {CWD}/Beta.fst",
            f"{CWD}/Beta.fsti {CWD}/Alpha.fst {CWD}/Beta.fst",
        )
        self.rejected("scheduled source has no positive")

    def test_external_load_event_outside_schedule_is_fatal(self):
        self.replace_trace(
            f"Trying to load checked file result {self.fixture.checked_path('hacl:Spec.X.fsti')}\n",
            f"Trying to load checked file result {self.fixture.checked_path('hacl:Spec.X.fsti')}\n"
            "Now lax-checking interface of Spec.X\n",
        )
        self.rejected("load/check event outside batch schedule")

    def test_conflicting_source_check_modes_are_fatal(self):
        self.replace_trace(
            "Now verifying implementation of Alpha\n",
            "Now lax-checking implementation of Alpha\nNow verifying implementation of Alpha\n",
        )
        self.rejected("contradictory source-check events")

    def test_traced_proof_cannot_downgrade_the_probe_contract(self):
        self.replace_trace("Now verifying implementation of Alpha\n", "", probe=False)
        path = self.fixture.evidence / "dependencies/1/record.json"
        record = ag.load_object(path)
        record["load_contract"] = ag.LOAD_CONTRACT
        record["load_argv"][3:7] = ["--debug", "CheckedFiles"]
        write_json(path, record)
        self.rejected("proof and probe trace contracts differ")

    def test_verification_schedule_cannot_accept_lax_source_check(self):
        self.replace_trace(
            "Now verifying implementation of Alpha\n",
            "Now lax-checking implementation of Alpha\n",
        )
        self.rejected("verification-scheduled source was lax-checked")

    def test_verification_schedule_cannot_accept_cache_reuse_only(self):
        self.replace_trace(
            "Now verifying implementation of Alpha\n",
            f"Successfully loaded module from checked file {CWD}/Alpha.fst.checked\n",
        )
        self.rejected("verification-scheduled source only reused a checked artifact")

    def test_source_check_cannot_claim_verification_outside_verify_schedule(self):
        path = self.fixture.checked_path("ulib:FStar.Pervasives.fsti")
        self.replace_trace(
            f"Successfully loaded module from checked file {path}\n",
            "Now verifying interface of FStar.Pervasives\n",
        )
        self.rejected("source verification event outside verification schedule")

    def test_type_checker_attempt_is_not_a_parsing_only_scan(self):
        path = self.fixture.checked_path("hacl:Spec.X.fsti")
        self.replace_trace(
            f"Trying to load checked file result {path}\n",
            f"Trying to load checked file with tc result {path}\n",
        )
        self.rejected("unresolved type-checker load attempt")

    def test_verification_schedule_cannot_add_an_unrequested_module(self):
        self.replace_trace(
            ag.VERIFY_FILES + f"{CWD}/Alpha.fst",
            ag.VERIFY_FILES
            + self.fixture.recorded("ulib:FStar.Pervasives.fsti")
            + f" {CWD}/Alpha.fst",
        )
        self.rejected("batch verification schedule differs")

    def test_source_check_overrides_a_cache_read_that_was_not_used(self):
        self.replace_trace(
            "Now verifying implementation of Alpha\n",
            f"Successfully loaded module from checked file {CWD}/Alpha.fst.checked\n"
            "Now verifying implementation of Alpha\n",
        )
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout
        node = ag.load_object(graph)["body"]["nodes"][f"source:{CWD}/Alpha.fst"]
        assert node["load_modes"]["1"]["mode"] == "requested-verified"

    def test_duplicate_malformed_or_truncated_schedules_are_rejected(self):
        good = ag.PROCESS_FILES + "A.fst\n" + ag.VERIFY_FILES + "A.fst\n"
        for trace in (
            good + good,
            good.replace("A.fst", "A.fst A.fst"),
            good.replace(ag.PROCESS_FILES, ag.PROCESS_FILES.rstrip()),
            good.replace("A.fst\n", "\n", 1),
            good.splitlines()[0],
        ):
            with self.subTest(trace=trace), pytest.raises(ag.GraphError):
                ag.parse_batch_schedule(trace, CWD)


if __name__ == "__main__":
    unittest.main()
