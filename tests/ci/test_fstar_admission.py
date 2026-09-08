"""Per-module F* admission: real tool evidence plus controlled mutations."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADMIT = ROOT / "scripts/validation/admit_fstar_modules.py"
FIXTURES = ROOT / "tests/fixtures/fstar_admission"
HOSTED = FIXTURES / "hosted-34200194649"
PROBES = FIXTURES / "tool-probes"
NIX_TOOL = "/nix/store/g60d57ag3i8gf6g104xw5lafk0xymk1f-ocaml5.3.0-fstar-2025.10.06/bin/fstar.exe"
COMPLETE = (
    "Verified module: Alpha\n"
    "Verified module: Beta\n"
    "All verification conditions discharged successfully\n"
    "TOTAL TIME 5 ms: <ECHO>\n"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Case:
    """Build one invocation record set the way run_fstar_invocation.py writes it."""

    def __init__(
        self,
        root: Path,
        pass_id: str = "1",  # noqa: S107 - a pass identifier, not a secret
        tool: str = "/opt/fstar/bin/fstar.exe",
    ):
        self.root = root
        self.pass_id = pass_id
        self.tool = tool
        self.src = root / "src"
        self.out = root / "out"
        self.directory = self.out / "invocations" / pass_id
        self.directory.mkdir(parents=True)
        self.src.mkdir(exist_ok=True)

    def source(self, relative: str, text: str | None = None) -> Path:
        path = self.src / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        stem = Path(relative).name.rsplit(".", 1)[0]
        path.write_text(text if text is not None else f"(* fixture *)\nmodule {stem}\nlet x = 1\n")
        return path

    def record(  # noqa: PLR0913 - one builder for every recorded invocation field
        self,
        modules: list[str],
        output: str,
        returncode: int = 0,
        *,
        options: tuple[str, ...] = ("--query_stats",),
        local_context: list[dict[str, str]] | None = None,
        status: str | None = None,
        echo: str | None = None,
        include_paths: list[str] | None = None,
    ) -> Path:
        argv = ["fstar.exe", *options, *modules]
        executed = [self.tool, *argv[1:]]
        if local_context is None:
            local_context = [
                {"path": str(self.src / m), "sha256": sha256(self.src / m)} for m in modules
            ]
        inputs = {
            "argv": argv,
            "executed_argv": executed,
            "cwd": str(self.src),
            "modules": [{"path": m, "sha256": sha256(self.src / m)} for m in modules],
            "include_paths": include_paths or [],
            "providers": {},
            "local_context": local_context,
            "tool": {"path": self.tool, "sha256": "00" * 32},
            "solver": None,
            "recorder": {"path": "recorder", "sha256": "00" * 32},
            "loops_origin": "pre-existing",
        }
        (self.directory / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
        (self.directory / "output.log").write_text(
            output.replace("<ECHO>", " ".join(executed) if echo is None else echo)
        )
        result = {
            "schema_version": 1,
            "pass_id": self.pass_id,
            "argv": argv,
            "cwd": str(self.src),
            "status": status or ("succeeded" if returncode == 0 else "failed"),
            "returncode": returncode,
            "inputs_sha256": sha256(self.directory / "inputs.json"),
            "output_sha256": sha256(self.directory / "output.log"),
        }
        (self.directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return self.directory

    def admit(self, passes: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture directories
            [
                sys.executable,
                str(ADMIT),
                "--out-dir",
                str(self.out),
                "--passes",
                *(passes or [self.pass_id]),
                "--source-root",
                str(self.src),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture directories
            [
                sys.executable,
                str(ADMIT),
                "--verify-records",
                str(self.out),
                "--passes",
                self.pass_id,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def modules(self) -> dict:
        return json.loads((self.directory / "modules.json").read_text())

    def dispositions(self) -> list[str]:
        return [entry["disposition"] for entry in self.modules()["requested"]]

    def reasons(self) -> str:
        return "\n".join(self.modules()["reasons"])


def copy_records(source: Path, directory: Path) -> None:
    """Copy one recorded invocation; outputs are stored as output.txt (*.log is ignored)."""
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(source / "inputs.json", directory / "inputs.json")
    shutil.copy(source / "result.json", directory / "result.json")
    shutil.copy(source / "output.txt", directory / "output.log")


def summary_events(stdout: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("FSTAR-ADMISSION "))
        for line in stdout.splitlines()
        if line.startswith("FSTAR-ADMISSION ")
    ]


class FixtureIntegrityTests(unittest.TestCase):
    def test_fixture_manifest_matches_files(self) -> None:
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text())
        for relative, expected in manifest["files"].items():
            assert sha256(FIXTURES / relative) == expected, relative
        assert manifest["tool"].startswith("F* 2025.10.06")


class RealEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def hosted_case(self) -> Case:
        case = Case(self.root, "1", NIX_TOOL)
        shutil.rmtree(case.directory)
        copy_records(HOSTED / "pass-1", case.directory)
        shutil.rmtree(case.src)
        shutil.copytree(HOSTED / "sources", case.src)
        return case

    def test_hosted_pass_is_admitted_and_records_are_bound(self) -> None:
        case = self.hosted_case()
        completed = case.admit()
        assert completed.returncode == 0, completed.stdout + completed.stderr
        record = case.modules()
        assert record["status"] == "accepted"
        assert case.dispositions() == ["verified"] * 4
        assert [e["module"] for e in record["requested"]] == [
            "Jose.Federation.Policy.Types",
            "Jose.Federation.Policy.Merge",
            "Jose.Federation.Policy.Order",
            "Jose.Federation.Policy.Lemmas",
        ]
        lines = [e["line"] for e in record["requested"]]
        assert lines == sorted(lines)
        assert record["unrequested"] == []
        assert record["diagnostics"]["total_time_argv_matches"] is True
        assert record["tool"]["path"] == NIX_TOOL
        result = json.loads((case.directory / "result.json").read_text())
        assert record["inputs_sha256"] == result["inputs_sha256"]
        assert record["output_sha256"] == result["output_sha256"]
        admission = json.loads((case.out / "admission.json").read_text())
        assert admission["status"] == "accepted"
        assert admission["passes"]["1"]["modules_sha256"] == sha256(case.directory / "modules.json")
        events = summary_events(completed.stdout)
        assert events[0]["dispositions"] == {"verified": 4}
        assert events[-1] == {"event": "summary", "status": "accepted", "passes": {"1": "accepted"}}
        assert case.verify().returncode == 0

    def test_hosted_records_cannot_be_tampered_after_admission(self) -> None:
        case = self.hosted_case()
        assert case.admit().returncode == 0
        output = case.directory / "output.log"
        original = output.read_bytes()
        output.write_bytes(original + b"\nVerified module: Jose.Federation.Policy.Extra\n")
        assert case.verify().returncode != 0
        output.write_bytes(original)
        assert case.verify().returncode == 0
        record = case.directory / "modules.json"
        record.write_text(record.read_text().replace('"verified"', '"missing"', 1))
        assert case.verify().returncode != 0

    def test_hosted_sources_must_match_recorded_digests(self) -> None:
        case = self.hosted_case()
        target = case.src / "jose/Jose.Federation.Policy.Order.fst"
        target.write_text(target.read_text() + "\n(* changed after the run *)\n")
        completed = case.admit()
        assert completed.returncode == 1
        assert "source digest differs" in case.reasons()
        assert not (case.out / "admission.json").exists()

    def test_impossible_lemma_probe_is_rejected_despite_verified_line(self) -> None:
        case = Case(self.root, "injected")
        shutil.rmtree(case.directory)
        copy_records(FIXTURES / "injected-lemma", case.directory)
        shutil.copy(
            FIXTURES / "injected-lemma/InjectedFailure.fst", case.src / "InjectedFailure.fst"
        )
        completed = case.admit()
        assert completed.returncode == 1
        record = case.modules()
        assert "Verified module: InjectedFailure" in (case.directory / "output.log").read_text()
        assert record["status"] == "rejected"
        assert record["diagnostics"]["errors"] >= 3
        assert "return code 1" in case.reasons()
        assert "error line(s)" in case.reasons()
        assert not (case.out / "admission.json").exists()


class ToolProbeTests(unittest.TestCase):
    """Outputs recorded from the pinned fstar.exe with synthetic sources of the same names."""

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.case = Case(self.root, "probe", NIX_TOOL)

    def probe(self, name: str) -> str:
        return (PROBES / f"{name}.out").read_text()

    def test_success_then_failure_is_rejected_even_with_forged_status(self) -> None:
        self.case.source("Probe.fst")
        self.case.source("Bad.fst")
        self.case.record(["Probe.fst", "Bad.fst"], self.probe("ok_then_bad"), 1, options=())
        assert self.case.admit().returncode == 1
        assert self.case.dispositions() == ["verified", "verified"]
        assert "return code 1" in self.case.reasons()
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        self.case.record(["Probe.fst", "Bad.fst"], self.probe("ok_then_bad"), 0, options=())
        assert self.case.admit().returncode == 1
        reasons = self.case.reasons()
        assert "error line(s)" in reasons
        assert "completion marker occurs 0" in reasons

    def test_failure_stops_processing_so_later_module_is_missing(self) -> None:
        self.case.source("Bad.fst")
        self.case.source("Second.fst")
        self.case.record(["Bad.fst", "Second.fst"], self.probe("bad_then_ok"), 1, options=())
        assert self.case.admit().returncode == 1
        assert self.case.dispositions() == ["missing", "missing"]

    def test_interface_only_and_paired_interface(self) -> None:
        self.case.source("Iface.fsti", "module Iface\nval f : nat -> nat\n")
        self.case.record(["Iface.fsti"], self.probe("iface_only"), options=())
        assert self.case.admit().returncode == 0, self.case.reasons()
        assert self.case.dispositions() == ["interface-verified"]
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        (self.case.out / "admission.json").unlink()
        self.case.source("Iface.fst", "module Iface\nlet f x = x + 1\n")
        self.case.record(["Iface.fsti", "Iface.fst"], self.probe("iface_pair"), options=())
        assert self.case.admit().returncode == 0, self.case.reasons()
        assert self.case.dispositions() == ["paired-interface", "verified"]

    def test_checked_reuse_options_are_not_fresh_evidence(self) -> None:
        self.case.source("Probe.fst")
        self.case.record(["Probe.fst"], self.probe("cache_reuse"), options=("--cache_dir", "cache"))
        assert self.case.admit().returncode == 1
        assert "denied options in argv: --cache_dir" in self.case.reasons()
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        self.case.source("Second.fst")
        self.case.record(
            ["Second.fst"],
            self.probe("already_cached"),
            options=("--cache_dir", "cache", "--already_cached", "Probe"),
        )
        assert self.case.admit().returncode == 1
        assert "--already_cached" in self.case.reasons()

    def test_silent_and_mismatch_outputs_are_rejected(self) -> None:
        self.case.source("Probe.fst")
        self.case.record(["Probe.fst"], self.probe("silent"), options=("--silent",))
        assert self.case.admit().returncode == 1
        assert "completion marker occurs 0" in self.case.reasons()
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        self.case.source("Mismatch.fst", "module Other\nlet x = 1\n")
        self.case.record(["Mismatch.fst"], self.probe("mismatch"), 1, options=())
        assert self.case.admit().returncode == 1
        assert "does not match the file name" in self.case.reasons()

    def test_query_stats_echo_is_checked_against_executed_argv(self) -> None:
        self.case.source("Probe.fst")
        self.case.record(["Probe.fst"], self.probe("probe_querystats"))
        assert self.case.admit().returncode == 0, self.case.reasons()
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        (self.case.out / "admission.json").unlink()
        self.case.record(
            ["Probe.fst"],
            self.probe("probe_querystats"),
            options=("--query_stats", "--z3rlimit", "5"),
        )
        assert self.case.admit().returncode == 1
        assert "does not echo the executed argv" in self.case.reasons()


class ControlledMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.case = Case(self.root, "2b")
        self.case.source("Alpha.fst")
        self.case.source("Beta.fst")

    def admit(self, output: str, **kwargs) -> subprocess.CompletedProcess[str]:
        self.case.record(["Alpha.fst", "Beta.fst"], output, **kwargs)
        return self.case.admit()

    def test_complete_mapping_is_accepted(self) -> None:
        completed = self.admit(COMPLETE)
        assert completed.returncode == 0, completed.stderr
        assert self.case.dispositions() == ["verified", "verified"]
        assert self.case.modules()["contract"] == "fstar-2025.10.06-text-v1"

    def test_omitted_module_with_zero_status_is_rejected(self) -> None:
        assert self.admit(COMPLETE.replace("Verified module: Beta\n", "")).returncode == 1
        assert self.case.dispositions() == ["verified", "missing"]
        assert "no result line for implementation Beta" in self.case.reasons()

    def test_equal_total_substitution_is_rejected(self) -> None:
        output = COMPLETE.replace("Verified module: Beta\n", "Verified module: Alpha\n")
        assert self.admit(output).returncode == 1
        assert self.case.dispositions() == ["duplicate", "missing"]

    def test_wrong_module_result_cannot_satisfy_a_request(self) -> None:
        output = COMPLETE.replace("Verified module: Beta\n", "Verified module: Gamma\n")
        assert self.admit(output).returncode == 1
        record = self.case.modules()
        assert record["requested"][1]["disposition"] == "missing"
        assert record["unrequested"][0]["classification"] == "unclassified"
        assert "no known source" in self.case.reasons()

    def test_resolvable_dependency_result_is_recorded_but_not_credited(self) -> None:
        dep = self.case.source("deps/Gamma.fst")
        output = COMPLETE.replace(
            "Verified module: Beta\n", "Verified module: Gamma\nVerified module: Beta\n"
        )
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            output,
            local_context=[
                {"path": str(self.case.src / m), "sha256": sha256(self.case.src / m)}
                for m in ("Alpha.fst", "Beta.fst", "deps/Gamma.fst")
            ],
        )
        assert self.case.admit().returncode == 0, self.case.reasons()
        assert self.case.modules()["unrequested"] == [
            {
                "module": "Gamma",
                "kind": "implementation",
                "lines": [2],
                "classification": "dependency",
                "source": str(dep),
            }
        ]

    def test_contradictory_interface_line_for_paired_interface(self) -> None:
        self.case.source("Alpha.fsti", "module Alpha\nval x : int\n")
        output = COMPLETE.replace(
            "Verified module: Alpha\n",
            "Verified module: Alpha\nVerified i'face (or impl+i'face): Alpha\n",
        )
        self.case.record(["Alpha.fsti", "Alpha.fst", "Beta.fst"], output)
        assert self.case.admit().returncode == 1
        assert self.case.dispositions() == ["contradictory", "verified", "verified"]

    def test_identity_ambiguity_and_declaration_defects(self) -> None:
        self.case.source("other/Alpha.fst")
        self.case.record(["Alpha.fst", "other/Alpha.fst", "Beta.fst"], COMPLETE)
        assert self.case.admit().returncode == 1
        assert self.case.dispositions()[:2] == ["ambiguous", "ambiguous"]
        for text, reason in (
            ("(* comment only *)\nlet x = 1\n", "does not begin with a module declaration"),
            ("module Alpha\nlet x = 1\nmodule Alpha\n", "more than one module declaration"),
            ("(* nested (* comment *) still *)\nmodule Beta\n", "does not match the file name"),
        ):
            with self.subTest(reason=reason):
                shutil.rmtree(self.case.directory)
                self.case.directory.mkdir()
                self.case.source("Alpha.fst", text)
                self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE)
                assert self.case.admit().returncode == 1
                assert reason in self.case.reasons()

    def test_module_abbreviations_are_not_second_declarations(self) -> None:
        # Real first-party sources alias modules, e.g. FStar.Base64.fst.
        self.case.source(
            "Alpha.fst",
            "module Alpha\n\nmodule Str = FStar.String\nmodule U8 = FStar.UInt8\n"
            "module U32=FStar.UInt32\nlet x = U8.uint_to_t 1\n",
        )
        assert self.admit(COMPLETE).returncode == 0, self.case.reasons()
        assert self.case.dispositions() == ["verified", "verified"]

    def test_comment_and_directive_prefixes_are_tolerated(self) -> None:
        self.case.source(
            "Alpha.fst",
            "(* Copyright (* nested *) header *)\n// line comment mentioning module Nope\n"
            '#light "off"\nmodule Alpha\nlet s = "module inside a string"\n',
        )
        assert self.admit(COMPLETE).returncode == 0, self.case.reasons()

    def test_truncated_output_and_incomplete_status(self) -> None:
        truncated = COMPLETE.split("All verification", 1)[0]
        assert self.admit(truncated).returncode == 1
        assert "completion marker occurs 0" in self.case.reasons()
        shutil.rmtree(self.case.directory)
        self.case.directory.mkdir()
        assert self.admit(COMPLETE, status="incomplete", returncode=0).returncode == 1
        assert "invocation status 'incomplete'" in self.case.reasons()

    def test_signal_and_nonzero_exit_reject_despite_complete_output(self) -> None:
        assert self.admit(COMPLETE, returncode=-15).returncode == 1
        assert "return code -15" in self.case.reasons()

    def test_checked_file_for_requested_module_rejects(self) -> None:
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            COMPLETE,
            local_context=[
                {
                    "path": str(self.case.src / "Alpha.fst"),
                    "sha256": sha256(self.case.src / "Alpha.fst"),
                },
                {
                    "path": str(self.case.src / "Beta.fst"),
                    "sha256": sha256(self.case.src / "Beta.fst"),
                },
                {"path": str(self.case.src / "Alpha.fst.checked"), "sha256": "11" * 32},
            ],
        )
        assert self.case.admit().returncode == 1
        assert "checked file for requested module Alpha" in self.case.reasons()

    def test_hints_are_allowed(self) -> None:
        assert (
            self.admit(
                COMPLETE, options=("--query_stats", "--use_hints", "--hint_dir", ".")
            ).returncode
            == 0
        )

    def test_tampered_invocation_records_are_rejected(self) -> None:
        self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE)
        (self.case.directory / "output.log").write_text(COMPLETE.replace("<ECHO>", "x"))
        assert self.case.admit().returncode == 1
        assert "output.log digest differs" in self.case.reasons()

    def test_missing_pass_and_stale_records_are_rejected(self) -> None:
        self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE)
        completed = self.case.admit(["2b", "9"])
        assert completed.returncode == 1
        events = summary_events(completed.stdout)
        assert events[-1]["passes"] == {"2b": "accepted", "9": "rejected"}
        assert not (self.case.out / "admission.json").exists()
        # A second admission over the same records must not reuse the earlier modules.json.
        shutil.rmtree(self.case.out / "invocations" / "9", ignore_errors=True)
        completed = self.case.admit()
        assert completed.returncode == 1
        assert "already exists" in summary_events(completed.stdout)[0]["reasons"][0]
        assert self.case.modules()["status"] == "accepted"  # the earlier record is untouched
        assert not (self.case.out / "admission.json").exists()


if __name__ == "__main__":
    unittest.main()
