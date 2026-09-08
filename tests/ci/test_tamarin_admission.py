"""Tamarin requested-property admission: real tool evidence plus controlled mutations."""

# The docs lane runs these with unittest; assertRaises is the supported form here.
# ruff: noqa: PT027

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))

from admit_tamarin_lemmas import (  # noqa: E402 - path set above for the docs lane
    CONTRACT,
    AdmissionError,
    build_requests,
    declared_lemmas,
    reconcile,
    warning_sections,
)

ADMIT = ROOT / "scripts/validation/admit_tamarin_lemmas.py"
FIXTURES = ROOT / "tests/fixtures/tamarin_admission"
PROBES = FIXTURES / "tool-probes"
REGISTRY = ROOT / "spec/tamarin-evidence.json"
SEPARATOR = "=" * 78
ALPHA_THEORY = """theory alpha
begin

// lemma commented_out: "All #i. A()@i ==> F"
/* lemma also_commented: exists-trace "Ex #i. A()@i" */

lemma alpha_one:
  "All x #i. A(x)@i ==> Ex #j. B(x)@j"

lemma alpha_two [reuse]:
  "All x #i. B(x)@i ==> Ex #j. A(x)@j"

lemma alpha_reach:
  exists-trace
  "Ex x #i. A(x)@i"

end
"""
MOCK_TOOL = """
import os, pathlib, re, sys, time
args = sys.argv[1:]
if "--version" in args:
    print("maude tool: 'maude'")
    version = os.environ.get("MOCK_VERSION", "1.12.0")
    print(" checking version: tamarin-prover " + version + ", (C) mock")
    sys.exit(0)
theory = [a for a in args if a.endswith(".spthy")][0]
prove = [a.split("=", 1)[1] for a in args if a.startswith("--prove=")]
if os.environ.get("MOCK_SLEEP"):
    time.sleep(float(os.environ["MOCK_SLEEP"]))
text = pathlib.Path(theory).read_text()
text = re.sub(r"/\\*.*?\\*/", "", text, flags=re.S)
text = re.sub(r"//[^\\n]*", "", text)
pattern = r"^\\s*lemma\\s+(\\w+)\\s*(?:\\[[^\\]]*\\])?"
pattern += r"\\s*:\\s*(exists-trace|all-traces)?"
lemmas = re.findall(pattern, text, re.M)
lines = []
warn = os.environ.get("MOCK_WARN")
if warn:
    lines += ["/*", "WARNING: the following wellformedness checks failed!", "", "Formula terms"]
    lines += ["=============", "", "  Lemma `x' uses terms of the wrong form:"]
    lines += ["    `Free y'", "*/"]
else:
    lines.append("/* All wellformedness checks were successful. */")
mock_version = os.environ.get("MOCK_VERSION", "1.12.0")
tool_version = "Tamarin version " + mock_version
lines += ["", "/*", "Generated from:", tool_version, "Maude version 3.5.1", "*/", "", "end", ""]
lines += ["=" * 78, "summary of summaries:", "", "analyzed: " + theory, ""]
lines += ["  processing time: 0.10s", ""]
if warn:
    lines += ["  WARNING: 1 wellformedness check failed!"]
    lines += ["           The analysis results might be wrong!", ""]
for name, quantifier in lemmas:
    quantifier = quantifier or "all-traces"
    if name == os.environ.get("MOCK_OMIT_LEMMA"):
        continue
    if name in prove:
        failed = name == os.environ.get("MOCK_FAIL_LEMMA")
        status = "falsified - found trace" if failed else "verified"
    else:
        status = "analysis incomplete"
    lines.append(f"  {name} ({quantifier}): {status} (2 steps)")
if os.environ.get("MOCK_TRUNCATE"):
    sys.stdout.write("\\n".join(lines) + "\\n")
    sys.exit(0)
lines += ["", "=" * 78]
print("\\n".join(lines))
sys.exit(int(os.environ.get("MOCK_EXIT", "0")))
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registry(exceptions: list | None = None) -> dict:
    return {
        "contract": CONTRACT,
        "schema_version": 1,
        "tamarin_version": "1.12.0",
        "maude_version": "3.5.1",
        "timeout_seconds": 600,
        "derivcheck_timeout_seconds": 180,
        "wellformedness_exceptions": exceptions or [],
    }


def make_log(  # noqa: PLR0913 - composes every field of the pinned grammar
    theory: str,
    lemmas: list[tuple[str, str, str]],
    *,
    wellformed: bool = True,
    warning_block: str | None = None,
    closed: bool = True,
    versions: tuple[str, str] = ("1.12.0", "3.5.1"),
    summary_blocks: int = 1,
    extra_summary: list[str] | None = None,
) -> str:
    """Compose a log in the pinned grammar (line forms copied from real probes)."""
    head = ["/* All wellformedness checks were successful. */"] if wellformed else []
    if warning_block is not None:
        head = [
            "/*",
            "WARNING: the following wellformedness checks failed!",
            "",
            *warning_block.splitlines(),
            "*/",
        ]
    head += [
        "",
        "/*",
        "Generated from:",
        f"Tamarin version {versions[0]}",
        f"Maude version {versions[1]}",
        "*/",
        "end",
    ]
    summary = [
        SEPARATOR,
        "summary of summaries:",
        "",
        f"analyzed: {theory}",
        "",
        "  processing time: 0.14s",
        "",
    ]
    if warning_block is not None:
        summary += [
            "  WARNING: 1 wellformedness check failed!",
            "           The analysis results might be wrong!",
            "",
        ]
    summary += extra_summary or []
    summary += [
        f"  {name} ({quantifier}): {status} (3 steps)" for name, quantifier, status in lemmas
    ]
    if closed:
        summary += ["", SEPARATOR]
    return "\n".join(head + summary * summary_blocks) + "\n"


def request(
    theory: str = "models/code_replay.spthy",
    lemma: str = "code_single_use",
    quantifier: str = "all-traces",
    sha: str = "ab" * 32,
) -> dict:
    return {
        "id": f"{theory}__{lemma}",
        "theory": theory,
        "theory_sha256": sha,
        "lemma": lemma,
        "quantifier": quantifier,
    }


def invocation(returncode: int = 0, timed_out: bool = False, sha: str = "ab" * 32) -> dict:
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "timeout_seconds": 600,
        "theory_sha256_after": sha,
    }


class FixtureIntegrityTests(unittest.TestCase):
    def test_fixture_manifest_matches_files(self) -> None:
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text())
        for relative, expected in manifest["files"].items():
            assert sha256(FIXTURES / relative) == expected, relative
        assert any("tamarin-prover 1.12.0" in line for line in manifest["tool"])

    def test_registry_exceptions_match_current_theories(self) -> None:
        reg = json.loads(REGISTRY.read_text())
        assert reg["contract"] == CONTRACT
        for entry in reg["wellformedness_exceptions"]:
            path = ROOT / "proofs/tamarin" / entry["theory"]
            assert sha256(path) == entry["sha256"], (
                f"{entry['theory']} changed; re-review its exception"
            )
            assert entry["sections"], entry["theory"]
            assert entry["reason"]
            assert entry["handoff"]
            for section in entry["sections"]:
                assert "prove" not in section["title"].lower()
            fixture = (
                FIXTURES
                / "wellformedness"
                / (entry["theory"].replace("/", "_").removesuffix(".spthy") + ".txt")
            )
            recorded = {s["sha256"] for s in warning_sections(fixture.read_text(errors="replace"))}
            assert {s["sha256"] for s in entry["sections"]} == recorded, entry["theory"]


class RealOutputTests(unittest.TestCase):
    def probe(self, name: str) -> str:
        return (PROBES / f"{name}.txt").read_text(errors="replace")

    def test_exact_request_is_admitted(self) -> None:
        result = reconcile(request(), invocation(), self.probe("p1_exact"), registry())
        assert result["status"] == "accepted", result["reasons"]
        names = [e["name"] for e in result["parsed"]["summary"]["lemmas"]]
        assert names == ["code_single_use", "code_freshness", "code_redemption_reachable"]
        assert result["parsed"]["summary"]["lemmas"][1]["status"] == "analysis incomplete"

    def test_malformed_refresh_theory_is_rejected_despite_verified_line(self) -> None:
        text = self.probe("p4_malformed_refresh")
        assert "rotation_reachable (exists-trace): verified" in text
        req = request("models/refresh_token_rotation.spthy", "rotation_reachable", "exists-trace")
        result = reconcile(req, invocation(), text, registry())
        assert result["status"] == "rejected"
        assert any(
            "unregistered wellformedness warning" in r and "Formula terms" in r
            for r in result["reasons"]
        )
        text = self.probe("p11_malformed_ntar")
        assert "no_token_after_revocation (all-traces): verified (28 steps)" in text
        req = request("models/refresh_token_rotation.spthy", "no_token_after_revocation")
        assert reconcile(req, invocation(), text, registry())["status"] == "rejected"

    def test_quantified_refresh_theory_is_admitted(self) -> None:
        req = request("models/refresh_token_rotation_fixed.spthy", "no_token_after_revocation")
        result = reconcile(req, invocation(), self.probe("p12_fixed_ntar"), registry())
        assert result["status"] == "accepted", result["reasons"]
        assert result["parsed"]["summary"]["lemmas"][5]["steps"] == 28
        for name, quantifier in (
            ("rotation_reachable", "exists-trace"),
            ("cross_client_isolation", "all-traces"),
        ):
            req = request("models/refresh_token_rotation_fixed.spthy", name, quantifier)
            assert (
                reconcile(req, invocation(), self.probe("p13_fixed_all"), registry())["status"]
                == "accepted"
            )

    def test_falsified_and_prove_argument_warning_are_rejected(self) -> None:
        req = request("models/code_replay_persistent_without_unique.spthy")
        result = reconcile(req, invocation(), self.probe("p6_falsified"), registry())
        assert result["status"] == "rejected"
        assert any("falsified" in r for r in result["reasons"])
        result = reconcile(
            request(lemma="code_single"), invocation(), self.probe("p2_prefix_nostar"), registry()
        )
        assert result["status"] == "rejected"
        assert any("--prove/--lemma" in r for r in result["reasons"])

    def test_missing_file_output_and_two_requests(self) -> None:
        result = reconcile(
            request(), invocation(returncode=1), self.probe("p8_missing_file"), registry()
        )
        assert result["status"] == "rejected"
        assert any("exited with 1" in r for r in result["reasons"])
        assert any("summary block" in r for r in result["reasons"])
        result = reconcile(
            request(lemma="code_freshness"), invocation(), self.probe("p10_two_exact"), registry()
        )
        assert result["status"] == "accepted"


class ControlledMutationTests(unittest.TestCase):
    THEORY = "authcode/code_replay.spthy"
    LEMMAS: ClassVar[list[tuple[str, str, str]]] = [
        ("code_single_use", "all-traces", "verified"),
        ("code_freshness", "all-traces", "analysis incomplete"),
        ("code_redemption_reachable", "exists-trace", "analysis incomplete"),
    ]

    def decide(
        self, text: str, req: dict | None = None, inv: dict | None = None, reg: dict | None = None
    ) -> dict:
        return reconcile(req or request(self.THEORY), inv or invocation(), text, reg or registry())

    def test_complete_positive(self) -> None:
        assert self.decide(make_log(self.THEORY, self.LEMMAS))["status"] == "accepted"

    def test_helper_verified_with_requested_falsified(self) -> None:
        lemmas = [
            ("code_freshness", "all-traces", "verified"),
            ("code_single_use", "all-traces", "falsified - found trace"),
        ]
        result = self.decide(make_log(self.THEORY, lemmas))
        assert result["status"] == "rejected"
        assert any("requested lemma is falsified" in r for r in result["reasons"])

    def test_requested_incomplete_omitted_duplicated_or_wrong_quantifier(self) -> None:
        cases = {
            "incomplete": [("code_single_use", "all-traces", "analysis incomplete")],
            "omitted": [("code_freshness", "all-traces", "verified")],
            "duplicated": [
                ("code_single_use", "all-traces", "verified"),
                ("code_single_use", "all-traces", "verified"),
            ],
            "quantifier": [("code_single_use", "exists-trace", "verified")],
        }
        for name, lemmas in cases.items():
            with self.subTest(case=name):
                assert self.decide(make_log(self.THEORY, lemmas))["status"] == "rejected"

    def test_equal_count_substitution_and_other_theory(self) -> None:
        lemmas = [
            ("code_freshness", "all-traces", "verified"),
            ("code_redemption_reachable", "exists-trace", "analysis incomplete"),
        ]
        assert self.decide(make_log(self.THEORY, lemmas))["status"] == "rejected"
        result = self.decide(make_log("authcode/other.spthy", self.LEMMAS))
        assert any("summary analysed" in r for r in result["reasons"])

    def test_truncated_empty_body_only_and_double_summary(self) -> None:
        assert self.decide(make_log(self.THEORY, self.LEMMAS, closed=False))["status"] == "rejected"
        assert self.decide("")["status"] == "rejected"
        body_only = (
            "/* All wellformedness checks were successful. */\nlemma code_single_use: verified\n"
        )
        assert self.decide(body_only)["status"] == "rejected"
        assert (
            self.decide(make_log(self.THEORY, self.LEMMAS, summary_blocks=2))["status"]
            == "rejected"
        )

    def test_nonzero_exit_signal_and_timeout_override_verified_lines(self) -> None:
        text = make_log(self.THEORY, self.LEMMAS)
        for inv, needle in (
            (invocation(returncode=1), "exited with 1"),
            (invocation(returncode=-9), "exited with -9"),
            (invocation(returncode=124, timed_out=True), "budget"),
        ):
            with self.subTest(needle=needle):
                result = self.decide(text, inv=inv)
                assert result["status"] == "rejected"
                assert any(needle in r for r in result["reasons"])

    def test_changed_theory_digest_and_tool_version(self) -> None:
        text = make_log(self.THEORY, self.LEMMAS)
        assert any(
            "digest changed" in r
            for r in self.decide(text, inv=invocation(sha="cd" * 32))["reasons"]
        )
        text = make_log(self.THEORY, self.LEMMAS, versions=("1.8.0", "3.5.1"))
        assert any("contract" in r for r in self.decide(text)["reasons"])

    def test_registered_exception_is_labelled_and_bound_to_digest(self) -> None:
        block = "\n".join(
            [
                "Message Derivation Checks",
                "=" * 25,
                "",
                "  Rule X:",
                "  Failed to derive Variable(s): sk",
            ]
        )
        text = make_log(self.THEORY, self.LEMMAS, wellformed=False, warning_block=block)
        digests = [s["sha256"] for s in warning_sections(text)]
        assert len(digests) == 1
        entry = {
            "theory": self.THEORY,
            "sha256": "ab" * 32,
            "sections": [{"title": "Message Derivation Checks", "sha256": digests[0]}],
        }
        result = self.decide(text, reg=registry([entry]))
        assert result["status"] == "accepted-with-registered-exception", result["reasons"]
        assert self.decide(text)["status"] == "rejected"
        other_digest = {**entry, "sha256": "cd" * 32}
        assert self.decide(text, reg=registry([other_digest]))["status"] == "rejected"
        changed = text.replace("Variable(s): sk", "Variable(s): nonce")
        assert self.decide(changed, reg=registry([entry]))["status"] == "rejected"
        # Tamarin counts failed checks, not sections (id_token_chain reports 3 for 2 sections);
        # the summary must still acknowledge the block it printed.
        counted = text.replace(
            "WARNING: 1 wellformedness check failed!", "WARNING: 3 wellformedness checks failed!"
        )
        assert (
            self.decide(counted, reg=registry([entry]))["status"]
            == "accepted-with-registered-exception"
        )
        silent = text.replace("  WARNING: 1 wellformedness check failed!\n", "")
        assert self.decide(silent, reg=registry([entry]))["status"] == "rejected"


class RequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "x").mkdir()
        (self.root / "x/alpha.spthy").write_text(ALPHA_THEORY)

    def test_declared_lemmas_ignore_comments_and_read_quantifiers(self) -> None:
        assert declared_lemmas(ALPHA_THEORY) == {
            "alpha_one": "all-traces",
            "alpha_two": "all-traces",
            "alpha_reach": "exists-trace",
        }
        with self.assertRaises(AdmissionError):
            declared_lemmas(ALPHA_THEORY + '\nlemma alpha_one:\n  "F"\n')

    def test_valid_selection(self) -> None:
        requests = build_requests(self.root, ["x/alpha.spthy:alpha_one,alpha_reach"])
        assert [(r["lemma"], r["quantifier"]) for r in requests] == [
            ("alpha_one", "all-traces"),
            ("alpha_reach", "exists-trace"),
        ]
        assert requests[0]["theory_sha256"] == sha256(self.root / "x/alpha.spthy")
        assert requests[0]["id"] == "x_alpha__alpha_one"

    def test_invalid_selections_are_rejected_before_execution(self) -> None:
        for spec, needle in (
            ("x/alpha.spthy:", "malformed"),
            ("x/alpha.spthy:alpha_one,", "empty lemma"),
            ("x/alpha.spthy:alpha_one,alpha_one", "duplicate"),
            ("x/missing.spthy:alpha_one", "not a .spthy"),
            ("x/alpha.spthy:commented_out", "not declared"),
            ("x/alpha.spthy:also_commented", "not declared"),
            ("x/alpha.spthy:alpha", "not declared"),
        ):
            with self.subTest(spec=spec), self.assertRaises(AdmissionError) as raised:
                build_requests(self.root, [spec])
            assert needle in str(raised.exception)
        with self.assertRaises(AdmissionError):
            build_requests(self.root, [])


class ControlledToolTests(unittest.TestCase):
    """Drive the production wrappers with a mock prover that reproduces the grammar."""

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for path in (
            "scripts/flake/verify_tamarin.sh",
            "scripts/verify/verify_tamarin_ci.sh",
            "scripts/validation/admit_tamarin_lemmas.py",
        ):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        (self.root / "spec").mkdir()
        (self.root / "spec/tamarin-evidence.json").write_text(
            json.dumps(registry(), indent=2) + "\n"
        )
        (self.root / "proofs/tamarin/x").mkdir(parents=True)
        (self.root / "proofs/tamarin/x/alpha.spthy").write_text(ALPHA_THEORY)
        normalize = (
            (ROOT / "ci/tamarin_proofs.sh").read_text().split("normalize_tamarin_proofs() {", 1)[1]
        )
        (self.root / "ci").mkdir()
        (self.root / "ci/small.sh").write_text(
            'PROOFS=("x/alpha.spthy:alpha_one,alpha_reach")\nnormalize_tamarin_proofs() {'
            + normalize
        )
        (self.root / "ci/empty.sh").write_text(
            "PROOFS=()\nnormalize_tamarin_proofs() {" + normalize
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        tool = self.bin / "tamarin-prover"
        tool.write_text(f"#!{sys.executable}\n" + MOCK_TOOL)
        tool.chmod(0o755)
        self.output = self.root / "output"
        self.environment = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "OUT_DIR": str(self.output),
            "TAMARIN_PROOFS_FILE": str(self.root / "ci/small.sh"),
            "AEG_TAMARIN_SELFTEST": "0",
        }

    def invoke(
        self, script: str = "scripts/flake/verify_tamarin.sh", **environment: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture environment
            ["bash", script],  # noqa: S607 - supported shell
            cwd=self.root,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    def events(self, stdout: str) -> list[dict]:
        return [
            json.loads(line.removeprefix("TAMARIN-ADMISSION "))
            for line in stdout.splitlines()
            if line.startswith("TAMARIN-ADMISSION ")
        ]

    def test_small_selection_is_admitted_with_records(self) -> None:
        result = self.invoke()
        assert result.returncode == 0, result.stdout + result.stderr
        admission = json.loads((self.output / "admission.json").read_text())
        assert admission["status"] == "accepted"
        assert admission["counts"] == {
            "accepted": 2,
            "accepted-with-registered-exception": 0,
            "rejected": 0,
        }
        requests = json.loads((self.output / "requests.json").read_text())["requests"]
        assert [r["lemma"] for r in requests] == ["alpha_one", "alpha_reach"]
        for req in requests:
            directory = self.output / "invocations" / req["id"]
            command = json.loads((directory / "command.json").read_text())
            assert command["argv"][3:5] == ["tamarin-prover", f"--prove={req['lemma']}"]
            assert command["theory_sha256_after"] == req["theory_sha256"]
            assert sha256(directory / "output.log") == command["output_sha256"]
            assert json.loads((directory / "result.json").read_text())["status"] == "accepted"
        log = (self.output / "verify-tamarin.log").read_text()
        assert "[OK] x/alpha.spthy:alpha_one" in log
        assert "Lemmas failed: 0/2" in log
        assert self.events(result.stdout)[-1]["status"] == "accepted"
        verify = subprocess.run(  # noqa: S603 - fixed script
            [
                sys.executable,
                str(self.root / "scripts/validation/admit_tamarin_lemmas.py"),
                "verify-records",
                str(self.output),
                "--registry",
                str(self.root / "spec/tamarin-evidence.json"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert verify.returncode == 0, verify.stderr
        # A second run over the same directory must not reuse earlier records.
        assert self.invoke().returncode != 0

    def test_injected_failures_are_fatal_with_reasons(self) -> None:
        for environment, needle in (
            ({"MOCK_FAIL_LEMMA": "alpha_reach"}, "falsified"),
            ({"MOCK_OMIT_LEMMA": "alpha_one"}, "0 summary lines"),
            ({"MOCK_EXIT": "3"}, "exited with 3"),
            ({"MOCK_TRUNCATE": "1"}, "not closed"),
            ({"MOCK_WARN": "1"}, "unregistered wellformedness"),
            ({"MOCK_SLEEP": "3", "TAMARIN_TIMEOUT": "1"}, "budget"),
            ({"MOCK_VERSION": "1.8.0"}, "contract requires"),
        ):
            with self.subTest(environment=environment):
                shutil.rmtree(self.output, ignore_errors=True)
                result = self.invoke(**environment)
                assert result.returncode != 0
                assert not (self.output / "admission.json").exists()
                assert needle in result.stdout + result.stderr + (
                    (self.output / "verify-tamarin.log").read_text()
                    if (self.output / "verify-tamarin.log").exists()
                    else ""
                )

    def test_rejection_reports_the_prover_output_tail(self) -> None:
        result = self.invoke(MOCK_EXIT="3")
        assert result.returncode != 0
        log = (self.output / "verify-tamarin.log").read_text()
        events = [
            json.loads(line.split(" ", 1)[1])
            for line in log.splitlines()
            if line.startswith("TAMARIN-ADMISSION ")
        ]
        rejected = [e for e in events if e.get("event") == "request" and e["status"] == "rejected"]
        assert rejected
        for payload in rejected:
            assert payload["returncode"] == 3
            assert isinstance(payload["wall_seconds"], float)
            assert any(line.startswith("analyzed: ") for line in payload["output_tail"])
            assert payload["output_tail"][-1] == "=" * 78
        assert "    returncode=3 wall_seconds=" in log
        assert "    | analyzed: " in log
        assert "output_tail" in result.stdout
        accepted = [e for e in events if e.get("event") == "request" and e["status"] != "rejected"]
        assert all("output_tail" not in e for e in accepted)

    def test_empty_selection_and_missing_inputs_fail_before_running(self) -> None:
        result = self.invoke(TAMARIN_PROOFS_FILE=str(self.root / "ci/empty.sh"))
        assert result.returncode != 0
        assert "selection is empty" in result.stderr
        assert not self.output.exists()
        (self.root / "spec/tamarin-evidence.json").unlink()
        assert "required input not found" in self.invoke().stderr

    def test_real_selection_normalises_and_runs_through_the_wrapper(self) -> None:
        shutil.copytree(ROOT / "proofs/tamarin", self.root / "proofs/tamarin", dirs_exist_ok=True)
        shutil.copyfile(ROOT / "ci/tamarin_proofs.sh", self.root / "ci/tamarin_proofs.sh")
        environment = {k: v for k, v in self.environment.items() if k != "TAMARIN_PROOFS_FILE"}
        result = subprocess.run(
            ["bash", "scripts/flake/verify_tamarin.sh"],  # noqa: S607
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        expected = subprocess.run(  # noqa: S603 - fixed shell snippet
            [  # noqa: S607 - supported shell
                "bash",
                "-c",
                (
                    f'source "{ROOT}/ci/tamarin_proofs.sh"; normalize_tamarin_proofs; '
                    'for s in "${TAMARIN_PROOF_SPECS[@]}"; do echo "$s"; done'
                ),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        total = sum(len(spec.split(":", 1)[1].split(",")) for spec in expected)
        admission = json.loads((self.output / "admission.json").read_text())
        assert admission["counts"]["accepted"] == total
        assert len(admission["results"]) == total

    def setup_nix(self) -> dict[str, str]:
        nix = self.bin / "nix"
        nix.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, sys\n"
            "print('nix build diagnostic retained')\n"
            "status = int(os.environ.get('NIX_EXIT', '0'))\n"
            "if status == 0:\n"
            "    link = pathlib.Path(sys.argv[sys.argv.index('--out-link') + 1])\n"
            "    link.symlink_to(os.environ['NIX_OUTPUT'])\n"
            "sys.exit(status)\n"
        )
        nix.chmod(0o755)
        store = self.root / "store"
        assert self.invoke(OUT_DIR=str(store)).returncode == 0
        return {"TAMARIN_CI_ARTIFACT_DIR": str(self.root / "hosted"), "NIX_OUTPUT": str(store)}

    def test_hosted_wrapper_replays_records_and_rejects_tampering(self) -> None:
        environment = self.setup_nix()
        result = self.invoke("scripts/verify/verify_tamarin_ci.sh", **environment)
        assert result.returncode == 0, result.stderr
        run = next((self.root / "hosted").iterdir())
        assert json.loads((run / "build-result.json").read_text()) == {
            "build_status": 0,
            "log_status": 0,
        }
        assert (run / "verified-output/admission.json").exists()
        assert "requests replay as admitted" in result.stdout
        output = self.root / "store/invocations/x_alpha__alpha_one/output.log"
        output.write_text(
            output.read_text().replace(
                "alpha_one (all-traces): verified",
                "alpha_one (all-traces): falsified - found trace",
            )
        )
        result = self.invoke("scripts/verify/verify_tamarin_ci.sh", **environment)
        assert result.returncode != 0
        assert "digest differs" in result.stderr

    def test_hosted_wrapper_retains_failed_build_diagnostics(self) -> None:
        environment = self.setup_nix()
        result = self.invoke("scripts/verify/verify_tamarin_ci.sh", **environment, NIX_EXIT="42")
        assert result.returncode != 0
        run = next((self.root / "hosted").iterdir())
        assert "diagnostic retained" in (run / "build.log").read_text()
        assert json.loads((run / "build-result.json").read_text())["build_status"] == 42
        assert not (run / "verified-output").exists()


if __name__ == "__main__":
    unittest.main()
