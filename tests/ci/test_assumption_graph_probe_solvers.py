"""Bind dependency/load probe starts and both output streams to the proof's pin."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_assumption_graph import SCRIPT, Fixture, ag, write_json


class ProbeSolverTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = Fixture(self.root)
        self.fixture.install()
        self.proof = self.fixture.evidence / "invocations/1"
        self.probe = self.fixture.evidence / "dependencies/1"
        inputs = ag.load_object(self.proof / "inputs.json")
        self.pin = inputs["solver"]
        self.tool = Path(inputs["tool"]["path"])
        for key in ("argv", "executed_argv"):
            inputs[key].extend(["--smt", self.pin["path"]])
        write_json(self.proof / "inputs.json", inputs)
        inputs_digest = ag.digest_file(self.proof / "inputs.json")
        result = ag.load_object(self.proof / "result.json")
        result.update(
            argv=inputs["argv"],
            inputs_sha256=inputs_digest,
            solver_effective=ag.effective_solver(
                (self.proof / "output.log").read_text(), self.tool
            ),
        )
        write_json(self.proof / "result.json", result)
        modules = ag.load_object(self.proof / "modules.json")
        modules["inputs_sha256"] = inputs_digest
        write_json(self.proof / "modules.json", modules)
        summary_path = self.fixture.evidence / "admission.json"
        summary = ag.load_object(summary_path)
        summary["passes"]["1"].update(
            inputs_sha256=inputs_digest,
            modules_sha256=ag.digest_file(self.proof / "modules.json"),
        )
        write_json(summary_path, summary)
        self.fixture.write_dependencies("1", inputs)

    def replay(self):
        return ag.Inputs(
            self.fixture.evidence,
            self.fixture.src,
            self.fixture.src / "spec/assumption-register.json",
        ).pass_records("1")

    def rejected(self, message):
        received = None
        try:
            self.replay()
        except ag.GraphError as error:
            received = str(error)
        assert received is not None, "Invalid probe was accepted"
        assert message in received, received

    def start(self, path=None, version="4.13.3", arguments='["-smt2", "-in"]'):
        path = path or self.pin["path"]
        return f'Creating new z3proc (cmd=[("{path}", {arguments})], version=["{version}"])\n'

    def append(self, name, text, *, bind_digest=True, bind_summary=True):
        path = self.probe / name
        path.write_text(path.read_text() + text)
        record = ag.load_object(self.probe / "record.json")
        if bind_digest:
            record[ag.PROBE_OUTPUTS[name]] = ag.digest_file(path)
        if bind_summary:
            kind, names = (
                ("dependency", ("depend.txt", "depend.stderr"))
                if name.startswith("depend")
                else ("load", ("load.log", "load.stderr"))
            )
            text = "\n".join((self.probe / p).read_text() for p in names)
            record[f"{kind}_solver"] = ag.effective_solver(text, self.tool)
        write_json(self.probe / "record.json", record)

    def test_no_probe_start_is_recorded_as_unobserved(self):
        records = self.replay()
        for kind in ("dependency", "load"):
            assert records["record"][f"{kind}_solver"]["observed"] is False
        result, _ = self.fixture.build()
        assert result.returncode == 0, result.stdout

    def test_matching_restarts_across_all_streams_are_accepted(self):
        for name in ag.PROBE_OUTPUTS:
            self.append(name, self.start())
        records = self.replay()
        for kind in ("dependency", "load"):
            assert records["record"][f"{kind}_solver"]["process_count"] == 2

    def test_wrong_solver_is_rejected_even_with_recomputed_digests_and_summary(self):
        for name in ag.PROBE_OUTPUTS:
            with self.subTest(stream=name):
                before = (self.probe / name).read_bytes()
                record = (self.probe / "record.json").read_bytes()
                self.append(name, self.start(str(self.fixture.outer_z3 / "z3")))
                self.rejected("does not match the explicit pin")
                (self.probe / name).write_bytes(before)
                (self.probe / "record.json").write_bytes(record)

    def test_malformed_or_changed_arguments_are_rejected_in_each_stream(self):
        for name in ag.PROBE_OUTPUTS:
            for arguments in ("[]", '["-in", "-smt2"]', '["-smt2", "-in", "-v:0"]'):
                with self.subTest(stream=name, arguments=arguments):
                    before = (self.probe / name).read_bytes()
                    record = (self.probe / "record.json").read_bytes()
                    self.append(name, self.start(arguments=arguments), bind_summary=False)
                    self.rejected("malformed solver process")
                    (self.probe / name).write_bytes(before)
                    (self.probe / "record.json").write_bytes(record)

    def test_restart_to_different_version_across_stdout_stderr_is_rejected(self):
        self.append("load.log", self.start())
        self.append("load.stderr", self.start(version="4.99"), bind_summary=False)
        self.rejected("mixed solver process identities")

    def test_probe_version_must_match_proof_version(self):
        self.append("load.stderr", self.start(version="4.99"))
        self.rejected("solver differs from the proof")

    def test_stderr_missing_or_modified_without_its_digest_is_rejected(self):
        for name in ("depend.stderr", "load.stderr"):
            with self.subTest(stream=name):
                self.append(name, self.start(), bind_digest=False, bind_summary=False)
                self.rejected("does not match its record digest")
                (self.probe / name).unlink()
                self.rejected("missing for pass")
                (self.probe / name).write_text("")

    def test_summary_cannot_hide_observed_starts(self):
        self.append("load.stderr", self.start(), bind_summary=False)
        self.rejected("summary differs from probe output")

    def test_probe_pin_cannot_be_changed_independently(self):
        record = ag.load_object(self.probe / "record.json")
        record["solver"] = None
        write_json(self.probe / "record.json", record)
        self.rejected("pin differs from the proof")

    def test_old_probe_contract_requires_recollection(self):
        record = ag.load_object(self.probe / "record.json")
        record["contract"] = "fstar-2025.10.06-dep-v1"
        write_json(self.probe / "record.json", record)
        self.rejected("unsupported contract")

    def test_probe_process_records_failure_despite_zero_child_exit(self):
        # A real child emits the controlled start only during the load probe.
        # This tests orchestration and retention, not real F* or Z3 verification.
        self.tool.write_text(
            f"#!{sys.executable}\nimport sys\n"
            "if '--admit_smt_queries' in sys.argv:\n"
            f"    print({self.start(str(self.fixture.outer_z3 / 'z3'))!r}, file=sys.stderr)\n"
        )
        output = self.root / "live-probe"
        result = subprocess.run(  # noqa: S603 - fixed script and locally authored test tool
            [
                sys.executable,
                str(SCRIPT),
                "probe",
                "--out-dir",
                str(output),
                "--pass-id",
                "1",
                "--",
                str(self.tool),
                "--smt",
                self.pin["path"],
                "Alpha.fst",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        record = json.loads((output / "dependencies/1/record.json").read_text())
        assert (record["dependency_returncode"], record["load_returncode"]) == (0, 0)
        assert record["status"] == "failed"
        assert "does not match the explicit pin" in record["error"]
        for name, key in ag.PROBE_OUTPUTS.items():
            assert record[key] == ag.digest_file(output / "dependencies/1" / name)


if __name__ == "__main__":
    unittest.main()
