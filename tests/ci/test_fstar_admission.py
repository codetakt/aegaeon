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
sys.path.insert(0, str(ADMIT.parent))
from admit_fstar_modules import (  # noqa: E402 - path set above
    DENIED_OPTIONS,
    reconcile,
    resolve_unrequested,
)

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


class ExplicitSolverEvidenceTests(unittest.TestCase):
    def case(self) -> Case:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        case = Case(root)
        case.source("Alpha.fst")
        case.source("Beta.fst")
        start = (
            'Creating new z3proc (cmd=[("/missing/selected-z3", ["-smt2", "-in"])], '
            'version=["4.13.3"])\n'
        )
        case.record(
            ["Alpha.fst", "Beta.fst"],
            start + COMPLETE,
            options=("--query_stats", "--smt", "/missing/selected-z3"),
        )
        inputs = json.loads((case.directory / "inputs.json").read_text())
        inputs["solver"] = {"path": "/missing/canonical-z3", "sha256": "12" * 32}
        (case.directory / "inputs.json").write_text(json.dumps(inputs))
        result = json.loads((case.directory / "result.json").read_text())
        identity = {
            "observed": True,
            "name": "/missing/selected-z3",
            "version": "4.13.3",
            **inputs["solver"],
        }
        result["solver_effective"] = {
            **identity,
            "arguments": ["-smt2", "-in"],
            "process_count": 1,
            "processes": [identity],
        }
        self.rebind(case, result)
        return case

    @staticmethod
    def rebind(case: Case, result: dict) -> None:
        for field, filename in (("inputs_sha256", "inputs.json"), ("output_sha256", "output.log")):
            result[field] = sha256(case.directory / filename)
        (case.directory / "result.json").write_text(json.dumps(result))
        # Model consistent copied/reconstructed summaries, so rejection must come
        # from the solver contract rather than a stale file digest.
        if (case.directory / "modules.json").exists():
            record = case.modules()
            for field in ("inputs_sha256", "output_sha256"):
                record[field] = result[field]
            (case.directory / "modules.json").write_text(json.dumps(record))
            summary = json.loads((case.out / "admission.json").read_text())
            summary["passes"][case.pass_id].update(
                inputs_sha256=result["inputs_sha256"],
                output_sha256=result["output_sha256"],
                modules_sha256=sha256(case.directory / "modules.json"),
            )
            (case.out / "admission.json").write_text(json.dumps(summary))

    def test_pinned_alias_replay_needs_no_source_or_executable(self) -> None:
        case = self.case()
        assert case.admit().returncode == 0
        shutil.rmtree(case.src)
        assert case.verify().returncode == 0

    def test_command_mutations_reject_even_with_rebound_envelopes(self) -> None:
        for mutation in ("operand", "operand-and-echo", "executed", "executed-lax"):
            with self.subTest(mutation=mutation):
                case = self.case()
                assert case.admit().returncode == 0
                inputs = json.loads((case.directory / "inputs.json").read_text())
                result = json.loads((case.directory / "result.json").read_text())
                original = " ".join(inputs["executed_argv"])
                if mutation.startswith("operand"):
                    inputs["argv"][3] = "/missing/unobserved-z3"
                    result["argv"] = inputs["argv"]
                if mutation == "operand-and-echo":
                    inputs["executed_argv"][3] = "/missing/unobserved-z3"
                elif mutation == "executed":
                    inputs["executed_argv"][0] = "/missing/different-fstar"
                elif mutation == "executed-lax":
                    inputs["executed_argv"].insert(1, "--lax")
                log = case.directory / "output.log"
                log.write_text(log.read_text().replace(original, " ".join(inputs["executed_argv"])))
                (case.directory / "inputs.json").write_text(json.dumps(inputs))
                self.rebind(case, result)
                assert case.verify().returncode == 1
                (case.directory / "modules.json").unlink()
                (case.out / "admission.json").unlink()
                assert case.admit().returncode == 1
                assert "solver operand" in case.reasons() or "executed argv" in case.reasons()

    @staticmethod
    def mutate_solver(case: Case, result: dict, mutation: str) -> None:
        observed = result["solver_effective"]
        log = case.directory / "output.log"
        original = log.read_text()
        first = original.splitlines(keepends=True)[0]
        if mutation == "no-start":
            log.write_text(original.removeprefix(first))
        elif mutation == "missing-pin":
            inputs = json.loads((case.directory / "inputs.json").read_text())
            inputs["solver"] = None
            (case.directory / "inputs.json").write_text(json.dumps(inputs))
        elif mutation == "missing-summary":
            del result["solver_effective"]
        elif mutation == "changed-hash":
            observed["processes"][0]["sha256"] = "ff" * 32
        elif mutation == "malformed-start":
            log.write_text(original.replace('["-smt2", "-in"]', "[]"))
        elif mutation in ("changed-later-name", "mixed-version"):
            later = (
                first.replace("selected-z3", "different-z3")
                if mutation == "changed-later-name"
                else first.replace("4.13.3", "9.9.9")
            )
            log.write_text(first + later + original.removeprefix(first))
            observed["process_count"] = 2
            observed["processes"].append(observed["processes"][0].copy())
        else:
            key, value = {
                "unobserved": ("observed", False),
                "bad-count": ("process_count", 2),
                "boolean-count": ("process_count", True),
                "bad-arguments": ("arguments", ["-in", "-smt2"]),
                "missing-process": ("processes", []),
            }[mutation]
            observed[key] = value

    def test_constructed_bad_solver_records_reject_admission_and_replay(self) -> None:
        for mutation in (
            "no-start",
            "missing-pin",
            "unobserved",
            "missing-summary",
            "bad-count",
            "boolean-count",
            "bad-arguments",
            "changed-later-name",
            "changed-hash",
            "malformed-start",
            "missing-process",
            "mixed-version",
        ):
            with self.subTest(mutation=mutation):
                case = self.case()
                assert case.admit().returncode == 0
                result = json.loads((case.directory / "result.json").read_text())
                self.mutate_solver(case, result, mutation)
                self.rebind(case, result)
                completed = case.verify()
                assert completed.returncode == 1, completed.stdout + completed.stderr
                assert "solver" in completed.stderr
                (case.directory / "modules.json").unlink()
                (case.out / "admission.json").unlink()
                completed = case.admit()
                assert completed.returncode == 1, completed.stdout + completed.stderr
                assert "solver" in case.reasons()

    def test_repeated_names_support_legacy_aggregates_but_aliases_need_identities(self) -> None:
        for alias in (False, True):
            for retained in (False, True):
                with self.subTest(alias=alias, retained=retained):
                    case = self.case()
                    log = case.directory / "output.log"
                    first = log.read_text().splitlines(keepends=True)[0]
                    later = first.replace("selected-z3", "alias-z3") if alias else first
                    log.write_text(later + log.read_text())
                    result = json.loads((case.directory / "result.json").read_text())
                    observed = result["solver_effective"]
                    observed["name"] = "/missing/alias-z3" if alias else observed["name"]
                    observed["process_count"] = 2
                    observed["processes"].insert(
                        0, {**observed["processes"][0], "name": observed["name"]}
                    )
                    if not retained:
                        del observed["processes"]
                    self.rebind(case, result)
                    accepted = not alias or retained
                    assert (case.admit().returncode == 0) == accepted
                    if accepted:
                        shutil.rmtree(case.src)
                        assert case.verify().returncode == 0


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

    def test_replay_rejects_changed_or_missing_admission_summary_digests(self) -> None:
        case = self.hosted_case()
        assert case.admit().returncode == 0
        path = case.out / "admission.json"
        original = path.read_text()
        for field in ("inputs_sha256", "output_sha256"):
            for value in (None, "", "ff" * 32):
                with self.subTest(field=field, value=value):
                    summary = json.loads(original)
                    if value is None:
                        del summary["passes"]["1"][field]
                    else:
                        summary["passes"]["1"][field] = value
                    path.write_text(json.dumps(summary))
                    completed = case.verify()
                    assert completed.returncode == 1
                    assert f"admission.json {field} differs" in completed.stderr
        path.write_text(original)
        shutil.rmtree(case.src)
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

    def test_hosted_replay_requires_an_integer_zero_returncode(self) -> None:
        case = self.hosted_case()
        assert case.admit().returncode == 0
        path = case.directory / "result.json"
        original = json.loads(path.read_text())
        for value in (False, 0.0, "0", None):
            with self.subTest(value=repr(value)):
                path.write_text(json.dumps({**original, "returncode": value}) + "\n")
                result = case.verify()
                assert result.returncode == 1
                assert "replay rejected" in result.stderr
                assert "return code" in result.stderr
        path.write_text(json.dumps(original) + "\n")
        assert case.verify().returncode == 0

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
        dep = self.case.source("Gamma.fst")
        output = COMPLETE.replace(
            "Verified module: Beta\n", "Verified module: Gamma\nVerified module: Beta\n"
        )
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            output,
            local_context=[
                {"path": str(self.case.src / m), "sha256": sha256(self.case.src / m)}
                for m in ("Alpha.fst", "Beta.fst", "Gamma.fst")
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
                "sha256": sha256(dep),
            }
        ]

    def test_dependency_in_an_unsearched_subdirectory_is_not_a_known_source(self) -> None:
        # F* does not search subdirectories of the working directory (search-scope probe d).
        self.case.source("deps/Gamma.fst")
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
        assert self.case.admit().returncode != 0
        assert "no Gamma.fst in the searched directories" in self.case.reasons()
        assert self.case.modules()["unrequested"][0]["classification"] == "unclassified"

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

    def test_equals_form_denied_options_reject_complete_success_logs(self) -> None:
        for option in sorted(DENIED_OPTIONS):
            with self.subTest(option=option):
                shutil.rmtree(self.case.out)
                self.case.directory.mkdir(parents=True)
                assert (
                    self.admit(COMPLETE, options=("--query_stats", option + "=true")).returncode
                    == 1
                )
                assert f"denied options in argv: {option}=true" in self.case.reasons()

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


class ReviewFollowUpTests(unittest.TestCase):
    """PR #18 review: cache candidates in include directories, pass identity, dependency replay."""

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.case = Case(self.root, "2b")
        self.case.source("Alpha.fst")
        self.case.source("Beta.fst")
        self.provider = self.root / "provider"
        self.provider.mkdir()

    def test_checked_candidate_for_a_requested_module_rejects_wherever_fstar_searches(self) -> None:
        cases = {
            "absolute include": (self.provider / "Alpha.fst.checked", [str(self.provider)]),
            "relative include": (self.case.src / "inc" / "Beta.fsti.checked", ["inc"]),
            "source directory": (self.case.src / "Alpha.fst.checked", []),
        }
        for name, (cache, includes) in cases.items():
            with self.subTest(case=name):
                shutil.rmtree(self.case.directory, ignore_errors=True)
                self.case.directory.mkdir()
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_bytes(b"stale checked module")
                self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE, include_paths=includes)
                assert self.case.admit().returncode == 1
                assert f"checked file for requested module found: {cache}" in self.case.reasons()
                cache.unlink()

    def test_checked_scan_is_recorded_and_replays_without_the_provider(self) -> None:
        self.case.record(
            ["Alpha.fst", "Beta.fst"], COMPLETE, include_paths=[str(self.provider), "inc"]
        )
        assert self.case.admit().returncode == 0, self.case.reasons()
        scan = self.case.modules()["checked_scan"]
        assert scan["candidates"] == []
        assert str(self.provider) in scan["directories"]
        assert str(self.case.src / "inc") in scan["directories"]
        assert str(self.case.src) in scan["directories"]
        shutil.rmtree(self.provider)
        assert self.case.verify().returncode == 0

    def test_records_of_another_pass_are_not_this_pass(self) -> None:
        self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE)
        other = self.case.out / "invocations" / "1"
        shutil.copytree(self.case.directory, other)
        completed = self.case.admit(["2b", "1"])
        assert completed.returncode == 1
        relabelled = json.loads((other / "modules.json").read_text())
        assert "records pass '2b', not '1'" in "\n".join(relabelled["reasons"])
        # Re-labelling result.json is not enough: the evidence is still the same invocation.
        shutil.rmtree(self.case.out)
        self.case.directory.mkdir(parents=True)
        self.case.record(["Alpha.fst", "Beta.fst"], COMPLETE)
        shutil.copytree(self.case.directory, other)
        result = other / "result.json"
        result.write_text(result.read_text().replace('"pass_id": "2b"', '"pass_id": "1"'))
        completed = self.case.admit(["2b", "1"])
        assert completed.returncode == 1
        events = summary_events(completed.stdout)
        assert any(e.get("event") == "cross-pass" for e in events)
        assert any(
            "share the same inputs_sha256" in r for e in events for r in e.get("reasons", [])
        )
        assert not (self.case.out / "admission.json").exists()

    def dependency_output(self) -> str:
        return COMPLETE.replace(
            "Verified module: Beta\n", "Verified module: Dpop\nVerified module: Beta\n"
        )

    def context(self, *paths: Path) -> list[dict[str, str]]:
        return [{"path": str(p), "sha256": sha256(p)} for p in paths]

    def test_dependency_outside_the_searched_directories_is_rejected(self) -> None:
        # R18-04: a same-named module in the recorded local context but outside
        # cwd and the include directories is not a source F* could have used.
        outside = self.case.source("not-in-search-path/Dpop.fst", "module Dpop\nlet o = 11\n")
        included = self.case.src / "included"
        included.mkdir()
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            options=("--query_stats", "--include", str(included)),
            include_paths=[str(included)],
            local_context=self.context(outside, alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "no Dpop.fst in the searched directories" in self.case.reasons()
        entry = self.case.modules()["unrequested"][0]
        assert entry["classification"] == "unclassified"
        assert entry["source"] is None

    def test_dependency_binding_does_not_depend_on_context_order(self) -> None:
        # R18-04: with an outside file and an included file of the same name,
        # the included one is bound whichever is listed first.
        outside = self.case.source("not-in-search-path/Dpop.fst", "module Dpop\nlet o = 11\n")
        included = self.case.src / "included"
        included.mkdir()
        allowed = included / "Dpop.fst"
        allowed.write_text("module Dpop\nlet o = 22\n")
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        for order in ((outside, allowed), (allowed, outside)):
            with self.subTest(first=order[0].parent.name):
                shutil.rmtree(self.case.out)
                self.case.directory.mkdir(parents=True)
                self.case.record(
                    ["Alpha.fst", "Beta.fst"],
                    self.dependency_output(),
                    options=("--query_stats", "--include", str(included)),
                    include_paths=[str(included)],
                    local_context=self.context(*order, alpha, beta),
                )
                assert self.case.admit().returncode == 0, self.case.reasons()
                entry = self.case.modules()["unrequested"][0]
                assert entry["source"] == str(allowed)
                assert entry["sha256"] == sha256(allowed)
                assert self.case.verify().returncode == 0

    def test_same_named_sources_in_two_searched_directories_are_ambiguous(self) -> None:
        # Precedence between cwd and include directories is the verifier's
        # business (search-scope probes a, b, b'); the gate does not guess.
        included = self.case.src / "included"
        included.mkdir()
        (included / "Dpop.fst").write_text("module Dpop\nlet o = 22\n")
        local = self.case.source("Dpop.fst", "module Dpop\nlet o = 11\n")
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            options=("--query_stats", "--include", str(included)),
            include_paths=[str(included)],
            local_context=self.context(local, included / "Dpop.fst", alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "Dpop.fst is ambiguous across" in self.case.reasons()

    def test_result_kind_must_match_the_source_kind(self) -> None:
        # An implementation line is bound to <name>.fst only, an interface
        # line to <name>.fsti only.
        iface = self.case.source("Dpop.fsti", "module Dpop\nval o : int\n")
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            local_context=self.context(iface, alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "no Dpop.fst in the searched directories" in self.case.reasons()
        shutil.rmtree(self.case.out)
        self.case.directory.mkdir(parents=True)
        output = COMPLETE.replace(
            "Verified module: Beta\n",
            "Verified i'face (or impl+i'face): Dpop\nVerified module: Beta\n",
        )
        self.case.record(
            ["Alpha.fst", "Beta.fst"], output, local_context=self.context(iface, alpha, beta)
        )
        assert self.case.admit().returncode == 0, self.case.reasons()
        entry = self.case.modules()["unrequested"][0]
        assert (entry["kind"], entry["source"]) == ("interface", str(iface))

    def test_candidate_must_declare_the_module_and_match_the_recorded_context(self) -> None:
        wrong = self.case.source("Dpop.fst", "module Other\nlet o = 1\n")
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            local_context=self.context(wrong, alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "declares module Other, not Dpop" in self.case.reasons()
        shutil.rmtree(self.case.out)
        self.case.directory.mkdir(parents=True)
        wrong.write_text("module Dpop\nlet o = 1\n")
        stale = [{"path": str(wrong), "sha256": "ab" * 32}]
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            local_context=stale + self.context(alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "differs from the recorded local context" in self.case.reasons()
        shutil.rmtree(self.case.out)
        self.case.directory.mkdir(parents=True)
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            local_context=self.context(alpha, beta),
        )
        assert self.case.admit().returncode != 0
        assert "is not in the recorded local context" in self.case.reasons()

    def test_replay_rejects_a_recorded_source_outside_the_search_scope(self) -> None:
        # admission.json binds every modules.json digest, so a tampered record
        # already fails --verify-records; the replay rule itself is checked by
        # replaying a record whose resolution points outside the search scope.
        dep = self.case.source("Dpop.fst", "module Dpop\nlet o = 1\n")
        alpha, beta = self.case.src / "Alpha.fst", self.case.src / "Beta.fst"
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            self.dependency_output(),
            local_context=self.context(dep, alpha, beta),
        )
        assert self.case.admit().returncode == 0, self.case.reasons()
        assert self.case.verify().returncode == 0
        inputs = json.loads((self.case.directory / "inputs.json").read_text())
        result = json.loads((self.case.directory / "result.json").read_text())
        output = (self.case.directory / "output.log").read_text()
        recorded = self.case.modules()
        replay = reconcile("2b", inputs, result, output, None, recorded=recorded)
        assert replay["status"] == "accepted", replay["reasons"]
        for source, needle in (
            (str(self.case.src / "elsewhere" / "Dpop.fst"), "outside the searched directories"),
            (str(self.case.src / "Dpop.fsti"), "is not Dpop.fst"),
        ):
            with self.subTest(source=source):
                tampered = json.loads(json.dumps(recorded))
                tampered["unrequested"][0]["source"] = source
                replay = reconcile("2b", inputs, result, output, None, recorded=tampered)
                assert replay["status"] == "rejected"
                assert any(needle in r for r in replay["reasons"]), replay["reasons"]
                assert replay["unrequested"][0]["classification"] == "unclassified"
        record = self.case.directory / "modules.json"
        text = record.read_text()
        record.write_text(
            text.replace(json.dumps(str(dep)), json.dumps(str(self.case.src / "x" / "Dpop.fst")))
        )
        assert self.case.verify().returncode != 0

    def test_hosted_fixture_resolution_is_order_independent(self) -> None:
        # Reviewer's case 3: reversing the recorded local context of the real
        # hosted pass must not change how an unrequested Dpop would resolve.
        fixture = json.loads((HOSTED / "pass-1" / "inputs.json").read_text())
        root = self.root / "no-such-tree"
        first = resolve_unrequested("Dpop", "implementation", fixture, root)
        fixture["local_context"] = list(reversed(fixture["local_context"]))
        second = resolve_unrequested("Dpop", "implementation", fixture, root)
        assert first == second == (None, "no Dpop.fst in the searched directories")

    def test_dependency_from_absolute_include_replays_without_the_provider(self) -> None:
        dependency = self.provider / "Gamma.fst"
        dependency.write_text("module Gamma\nlet x = 1\n")
        output = COMPLETE.replace(
            "Verified module: Beta\n", "Verified module: Gamma\nVerified module: Beta\n"
        )
        self.case.record(
            ["Alpha.fst", "Beta.fst"],
            output,
            include_paths=[str(self.provider)],
            local_context=self.context(
                self.case.src / "Alpha.fst", self.case.src / "Beta.fst", dependency
            ),
        )
        assert self.case.admit().returncode == 0, self.case.reasons()
        entry = self.case.modules()["unrequested"][0]
        assert entry["classification"] == "dependency"
        assert entry["source"] == str(dependency)
        assert entry["sha256"] == sha256(dependency)
        shutil.rmtree(self.provider)
        assert self.case.verify().returncode == 0
        record = self.case.directory / "modules.json"
        record.write_text(record.read_text().replace('"dependency"', '"unclassified"'))
        assert self.case.verify().returncode != 0


class DependencyIdentityRegressions(unittest.TestCase):
    def case(self) -> Case:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        case = Case(root)
        paths = [case.source(name + ".fst") for name in ("Alpha", "Beta", "Gamma")]
        case.record(
            ["Alpha.fst", "Beta.fst"],
            COMPLETE.replace(
                "Verified module: Beta", "Verified module: Gamma\nVerified module: Beta"
            ),
            local_context=[{"path": str(path), "sha256": sha256(path)} for path in paths],
            include_paths=[str(root / "empty-provider")],
        )
        assert case.admit().returncode == 0
        assert case.verify().returncode == 0
        return case

    def test_fully_rebound_dependency_and_requested_identity_mutations_reject(self) -> None:
        for mutation in (
            "digest",
            "malformed",
            "source",
            "provider",
            "requested-line",
            "duplicate",
        ):
            with self.subTest(mutation=mutation):
                case = self.case()
                record = case.modules()
                dependency = record["unrequested"][0]
                if mutation in ("digest", "malformed"):
                    dependency["sha256"] = "ff" * 32 if mutation == "digest" else "not-a-digest"
                elif mutation == "source":
                    dependency["source"] = str(case.src / "other" / "Gamma.fst")
                elif mutation == "provider":
                    dependency["source"] = str(case.root / "empty-provider" / "Gamma.fst")
                elif mutation == "requested-line":
                    record["requested"][0]["line"] = 9000
                else:
                    record["unrequested"].append(dependency.copy())
                (case.directory / "modules.json").write_text(json.dumps(record))
                result = json.loads((case.directory / "result.json").read_text())
                ExplicitSolverEvidenceTests.rebind(case, result)
                shutil.rmtree(case.src)
                assert case.verify().returncode == 1

    def test_snapshot_ambiguity_or_missing_identity_rejects_source_free_replay(self) -> None:
        for mutation in ("missing", "malformed", "conflicting", "ambiguous", "duplicate-identical"):
            with self.subTest(mutation=mutation):
                case = self.case()
                inputs = json.loads((case.directory / "inputs.json").read_text())
                context = inputs["local_context"]
                dependency = next(item for item in context if item["path"].endswith("Gamma.fst"))
                if mutation == "missing":
                    context.remove(dependency)
                elif mutation == "malformed":
                    dependency["sha256"] = "bad"
                else:
                    added = dependency.copy()
                    if mutation == "conflicting":
                        added["sha256"] = "ff" * 32
                    elif mutation == "ambiguous":
                        added["path"] = str(case.root / "empty-provider" / "Gamma.fst")
                    context.append(added)
                (case.directory / "inputs.json").write_text(json.dumps(inputs))
                result = json.loads((case.directory / "result.json").read_text())
                ExplicitSolverEvidenceTests.rebind(case, result)
                shutil.rmtree(case.src)
                assert case.verify().returncode == (0 if mutation == "duplicate-identical" else 1)

    def linked_case(self, layout: str) -> tuple[Case, str, Path]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        case = Case(root)
        case.source("Alpha.fst")
        case.source("Beta.fst")
        provider = root / "physical/provider"
        provider.mkdir(parents=True)
        dependency = provider / "Gamma.fst"
        dependency.write_text("module Gamma\nlet x = 1\n")
        link = case.src / "alias"
        if layout == "directory-link":
            link.symlink_to(provider, target_is_directory=True)
            include = str(link)
        elif layout == "file-link":
            link.mkdir()
            (link / "Gamma.fst").symlink_to(dependency)
            include = str(link)
        else:
            (root / "physical/child").mkdir()
            link.symlink_to(root / "physical/child", target_is_directory=True)
            include = "alias/../provider"
        return case, include, dependency

    def test_recorder_preserves_searched_symlinks_for_relocated_replay(self) -> None:
        recorder = ROOT / "scripts/validation/run_fstar_invocation.py"
        for layout in ("directory-link", "file-link", "relative-parent"):
            with self.subTest(layout=layout):
                case, include, dependency = self.linked_case(layout)
                root = case.root
                tool = root / "fstar.exe"
                tool.write_text(
                    f"#!{sys.executable}\nimport sys\n"
                    "print('Verified module: Alpha')\nprint('Verified module: Gamma')\n"
                    "print('Verified module: Beta')\n"
                    "print('All verification conditions discharged successfully')\n"
                    "print('TOTAL TIME 5 ms: ' + ' '.join(sys.argv))\n"
                )
                tool.chmod(0o755)
                case.directory.rmdir()  # The real recorder requires a fresh invocation directory.
                completed = subprocess.run(  # noqa: S603 - controlled recorder and fixture tool
                    [
                        sys.executable,
                        str(recorder),
                        "--out-dir",
                        str(case.out),
                        "--pass-id",
                        "1",
                        "--",
                        str(tool),
                        "--include",
                        include,
                        "Alpha.fst",
                        "Beta.fst",
                    ],
                    cwd=case.src,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert completed.returncode == 0, completed.stderr
                inputs = json.loads((case.directory / "inputs.json").read_text())
                searched = (
                    Path(include) if Path(include).is_absolute() else case.src / include
                ) / "Gamma.fst"
                assert {"path": str(searched), "sha256": sha256(dependency)} in inputs[
                    "dependency_context"
                ]
                assert case.admit().returncode == 0, case.reasons()
                relocated = root / "relocated"
                case.out.rename(relocated)
                case.out = relocated
                case.directory = relocated / "invocations/1"
                shutil.rmtree(case.src)
                shutil.rmtree(root / "physical")
                tool.unlink()
                assert case.verify().returncode == 0


if __name__ == "__main__":
    unittest.main()
