"""Retained proof records must reject changed dependencies and legacy cache-only evidence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from test_assumption_graph import CWD, Fixture, ag, write_json


class RetainedInputsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = Fixture(self.root)
        self.fixture.install()

    def build_ok(self):
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout + result.stderr
        assert self.fixture.check(graph).returncode == 0
        return graph

    def rejected(self, expected):
        result, _ = self.fixture.build()
        assert result.returncode != 0, result.stdout + result.stderr
        assert expected in result.stdout, result.stdout + result.stderr

    def test_mutable_provider_and_ulib_source_changes_reject_new_graphs(self):
        self.build_ok()
        for spec in ("hacl:Spec.X.fsti", "ulib:FStar.Pervasives.fsti"):
            with self.subTest(spec=spec):
                path = Path(self.fixture.recorded(spec))
                original = path.read_bytes()
                path.write_bytes(original + b"\nassume val inserted: unit\n")
                self.rejected("differs from its recorded digest")
                path.write_bytes(original)
        self.build_ok()

    def test_loaded_mutable_cache_changes_reject_new_graphs(self):
        graph = self.build_ok()
        path = Path(self.fixture.checked_path("ulib:FStar.Pervasives.fsti"))
        node = json.loads(graph.read_text())["body"]["nodes"][f"checked:{path}"]
        assert node["sha256"] == ag.digest_file(path)
        path.write_bytes(b"different checked declarations\n")
        self.rejected("differs from its recorded digest")
        assert self.fixture.check(graph).returncode == 1

    def test_unrequested_identity_is_bound_by_search_snapshot_without_broad_context_entry(self):
        directory = self.fixture.evidence / "invocations/1"
        source = Path(self.fixture.recorded("hacl:Spec.X.fsti"))
        inputs = ag.load_object(directory / "inputs.json")
        inputs["dependency_context"] = [{"path": str(source), "sha256": ag.digest_file(source)}]
        inputs["local_context"] = [m for m in inputs["local_context"] if m["path"] != str(source)]
        write_json(directory / "inputs.json", inputs)
        output_path = directory / "output.log"
        output = output_path.read_text().replace(
            "All verification conditions",
            "Verified i'face (or impl+i'face): Spec.X\nAll verification conditions",
        )
        output_path.write_text(output)
        result = ag.load_object(directory / "result.json")
        result.update(
            pass_id="1",  # noqa: S106 - verification pass identifier
            inputs_sha256=ag.digest_file(directory / "inputs.json"),
            output_sha256=ag.digest_file(output_path),
        )
        write_json(directory / "result.json", result)
        modules = ag.admission.reconcile("1", inputs, result, output, self.fixture.src / "fstar")
        assert modules["status"] == "accepted", modules
        assert modules["unrequested"][0]["sha256"] == ag.digest_file(source)
        write_json(directory / "modules.json", modules)
        self.rehash_inputs(directory)
        path = self.fixture.evidence / "admission.json"
        admission = ag.load_object(path)
        admission["passes"]["1"]["output_sha256"] = ag.digest_file(output_path)
        write_json(path, admission)
        self.build_ok()
        source.write_bytes(source.read_bytes() + b"\nassume val substituted: unit\n")
        self.rejected("differs from its recorded digest")

    def test_mutable_cache_missing_from_retained_inputs_is_rejected(self):
        self.build_ok()
        directory = self.fixture.evidence / "invocations/1"
        inputs = ag.load_object(directory / "inputs.json")
        checked = self.fixture.checked_path("ulib:FStar.Pervasives.fsti")
        inputs["local_context"] = [m for m in inputs["local_context"] if m["path"] != checked]
        write_json(directory / "inputs.json", inputs)
        self.rehash_inputs(directory)
        self.rejected("mutable dependency has no recorded digest")

    def rehash_inputs(self, directory):
        for name in ("result.json", "modules.json"):
            data = ag.load_object(directory / name)
            data["inputs_sha256"] = ag.digest_file(directory / "inputs.json")
            write_json(directory / name, data)
        path = self.fixture.evidence / "admission.json"
        admission = ag.load_object(path)
        admission["passes"]["1"].update(
            inputs_sha256=ag.digest_file(directory / "inputs.json"),
            modules_sha256=ag.digest_file(directory / "modules.json"),
        )
        write_json(path, admission)

    def test_legacy_requested_sources_require_positive_non_lax_checks(self):
        self.build_ok()
        directory = self.fixture.evidence / "dependencies/1"
        path = directory / "load.log"
        original = path.read_text()
        event = "Now verifying implementation of Alpha"
        for replacement in (
            "",
            "Now lax-checking implementation of Alpha",
            f"Successfully loaded module from checked file {CWD}/Alpha.fst.checked",
            event + "\nNow lax-checking implementation of Alpha",
            event + "\nSuccessfully loaded module from checked file Alpha.fst.checked",
        ):
            with self.subTest(replacement=replacement):
                path.write_text(original.replace(event, replacement))
                record = ag.load_object(directory / "record.json")
                record["load_sha256"] = ag.digest_file(path)
                write_json(directory / "record.json", record)
                self.rejected("no positive non-lax source verification")
        path.write_text(original)
        record = ag.load_object(directory / "record.json")
        record["load_sha256"] = ag.digest_file(path)
        write_json(directory / "record.json", record)
        self.build_ok()

    def test_legacy_cache_read_must_precede_positive_source_recheck(self):
        directory = self.fixture.evidence / "dependencies/1"
        path = directory / "load.log"
        original = path.read_text()
        for source, module in (("Alpha.fst", "Alpha"), ("Beta.fsti", "Beta")):
            # Paired interfaces are checked with their implementation; they need
            # not produce a separate interface source-check event.
            baseline = original.replace("Now verifying interface of Beta\n", "")
            event = f"Now verifying implementation of {module}"
            for cache in (source + ".checked", f"{CWD}/{source}.checked"):
                read = f"Successfully loaded module from checked file {cache}"
                for before in (True, False):
                    with self.subTest(source=source, cache=cache, cache_before_source=before):
                        sequence = read + "\n" + event if before else event + "\n" + read
                        path.write_text(baseline.replace(event, sequence))
                        record = ag.load_object(directory / "record.json")
                        record["load_sha256"] = ag.digest_file(path)
                        write_json(directory / "record.json", record)
                        if before:
                            graph = json.loads(self.build_ok().read_text())["body"]
                            mode = graph["nodes"][f"source:{CWD}/{source}"]["load_modes"]["1"]
                            assert mode == {"mode": "requested-verified", "checked": "loaded"}
                        else:
                            self.rejected("no positive non-lax source verification")


if __name__ == "__main__":
    unittest.main()
