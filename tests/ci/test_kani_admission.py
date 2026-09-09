# ruff: noqa: PT027 - unittest-style assertRaises is the house style for these suites
"""Regressions for the Kani evidence runner (registry v2, contract kani-0.66.0-text-v1).

Real fixtures come from recorded cargo-kani 0.66.0 invocations (tests/fixtures/kani_admission,
MANIFEST.json); controlled mutations are synthetic and say so. The wrapper tests drive the runner
end to end with a controlled fake toolchain that reproduces the tool's output grammar.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))

import run_kani_evidence as kani  # noqa: E402 - path set above for the docs lane

FIXTURES = ROOT / "tests/fixtures/kani_admission"
RUNNER = ROOT / "scripts/validation/run_kani_evidence.py"
CHECKER = ROOT / "scripts/validation/check_kani_citations.py"
SCHEMA = ROOT / "spec/kani-evidence.schema.json"
BUDGET = 600


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(case: str, name: str = "run.txt") -> str:
    path = FIXTURES / "real" / case / name
    if path.exists():
        return path.read_text(errors="replace")
    # Recordings above the repository's added-file limit are stored gzip-compressed
    # (gzip -n, byte-exact after decompression; both digests are in MANIFEST.json).
    return gzip.decompress(path.with_name(name + ".gz").read_bytes()).decode(errors="replace")


def fixture_metadata(case: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "real" / case / "kani-metadata.json").read_text())


JOSE = "kani_tests::verification::verify_jose_context_bounds"
CANONICALISATION_HARNESS = (
    "id_token::kani_verification::oidc_id_token_jwt_canonicalisation_no_panic"
)
ID_TOKEN_GUARD = {
    f"{CANONICALISATION_HARNESS}.assertion.2": "unexpected canonicalisation error",
}


class FixtureIntegrityTests(unittest.TestCase):
    def test_manifest_matches_files(self) -> None:
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text())
        for relative, entry in manifest.get("compressed", {}).items():
            content = gzip.decompress((FIXTURES / relative).read_bytes())
            assert hashlib.sha256(content).hexdigest() == entry["content_sha256"], relative
        assert manifest["files"], "fixture manifest is empty"
        for relative, expected in manifest["files"].items():
            assert sha256(FIXTURES / relative) == expected, relative
        assert "0.66.0" in manifest["tool"]
        for path in (FIXTURES / "real").rglob("*"):
            if path.is_file():
                assert str(path.relative_to(FIXTURES)) in manifest["files"], path


class AcceptReportTests(unittest.TestCase):
    """Structural acceptance of one exact harness (R4: property status, not words)."""

    def test_real_success_is_accepted_with_callee_notes(self) -> None:
        report = kani.accept_report(
            fixture("success_jose_context_bounds"), JOSE, 0, None, "0.66.0", BUDGET
        )
        assert len(report["properties"]) >= 1
        assert all(p["status"] in {"SUCCESS", "UNREACHABLE"} for p in report["properties"])
        assert isinstance(report["callee_unreachable"], list)

    def test_real_success_with_reviewed_guard(self) -> None:
        report = kani.accept_report(
            fixture("success_id_token_canonicalisation"),
            CANONICALISATION_HARNESS,
            0,
            ID_TOKEN_GUARD,
            "0.66.0",
            BUDGET,
        )
        guarded = [p for p in report["properties"] if p["id"] in ID_TOKEN_GUARD]
        assert guarded
        assert guarded[0]["status"] == "UNREACHABLE"
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(
                fixture("success_id_token_canonicalisation"),
                CANONICALISATION_HARNESS,
                0,
                None,
                "0.66.0",
                BUDGET,
            )

    def test_successful_unwind_property_is_accepted(self) -> None:
        # Synthetic: a successful unwinding check must not be rejected by its wording (R4).
        text = fixture("success_jose_context_bounds")
        count = len(kani.accept_report(text, JOSE, 0, None, "0.66.0", BUDGET)["properties"])
        extra = (
            f"Check {count + 1}: {JOSE}.unwind.0\n\t - Status: SUCCESS\n"
            '\t - Description: "unwinding assertion loop 0"\n\n'
        )
        summary_at = text.index("\nSUMMARY:\n")
        mutated = (
            text[:summary_at]
            + "\n"
            + extra
            + text[summary_at + 1 :].replace(
                f" ** 0 of {count} failed", f" ** 0 of {count + 1} failed", 1
            )
        )
        report = kani.accept_report(mutated, JOSE, 0, None, "0.66.0", BUDGET)
        unwind = [p for p in report["properties"] if p["id"].endswith(".unwind.0")]
        assert unwind
        assert unwind[0]["status"] == "SUCCESS"
        failed = mutated.replace(
            'Status: SUCCESS\n\t - Description: "unwinding',
            'Status: FAILURE\n\t - Description: "unwinding',
            1,
        )
        with self.assertRaises(kani.AdmissionError) as ctx:
            kani.accept_report(failed, JOSE, 0, None, "0.66.0", BUDGET)
        assert "FAILURE" in str(ctx.exception)

    def test_real_failed_undetermined_and_oom_are_rejected_structurally(self) -> None:
        cases = (
            (
                "failed_parse_json_null",
                "kani_tests::verification::verify_parse_json_entries_null_pointer",
                1,
                "exit",
            ),
            (
                "undetermined_sd_jwt_roundtrip",
                "harnesses::proof_sd_jwt_disclosure_roundtrip",
                1,
                "exit",
            ),
            (
                "oom_driver_panic_utf8_valid",
                "kani_tests::verification::verify_utf8_decode_valid_input",
                101,
                "panic",
            ),
        )
        for case, harness, exit_code, needle in cases:
            with self.subTest(case=case):
                with self.assertRaises(kani.AdmissionError) as ctx:
                    kani.accept_report(fixture(case), harness, exit_code, None, "0.66.0", BUDGET)
                assert needle in str(ctx.exception)
                # Even with a forged zero exit the property statuses reject the run.
                with self.assertRaises(kani.AdmissionError) as ctx2:
                    kani.accept_report(fixture(case), harness, 0, None, "0.66.0", BUDGET)
                reason = str(ctx2.exception)
                assert (
                    "FAILURE" in reason
                    or "UNDETERMINED" in reason
                    or "report" in reason
                    or "summary" in reason
                ), reason

    def test_wrong_missing_and_duplicate_harness_are_rejected(self) -> None:
        text = fixture("success_jose_context_bounds")
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(
                text,
                "kani_tests::verification::verify_free_string_null_safety",
                0,
                None,
                "0.66.0",
                BUDGET,
            )
        duplicated = text.replace(
            f"Checking harness {JOSE}...",
            f"Checking harness {JOSE}...\nChecking harness {JOSE}...",
            1,
        )
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(duplicated, JOSE, 0, None, "0.66.0", BUDGET)
        truncated = text[: text.index("\nSUMMARY:\n")]
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(truncated, JOSE, 0, None, "0.66.0", BUDGET)
        success_then_nonzero = text
        with self.assertRaises(kani.AdmissionError) as ctx:
            kani.accept_report(success_then_nonzero, JOSE, 3, None, "0.66.0", BUDGET)
        assert "unknown nonzero exit 3" in str(ctx.exception)

    def test_count_mismatch_and_banner_are_rejected(self) -> None:
        text = fixture("success_jose_context_bounds")
        count = len(kani.accept_report(text, JOSE, 0, None, "0.66.0", BUDGET)["properties"])
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(
                text.replace(f" ** 0 of {count} failed", f" ** 0 of {count + 1} failed"),
                JOSE,
                0,
                None,
                "0.66.0",
                BUDGET,
            )
        with self.assertRaises(kani.AdmissionError):
            kani.accept_report(text, JOSE, 0, None, "0.65.0", BUDGET)

    def test_exit_classification(self) -> None:
        assert "budget" in kani.classify_exit(124, "", 600)
        assert "signal 9" in kani.classify_exit(-9, "", 600)
        assert "signal 9" in kani.classify_exit(137, "", 600)
        assert kani.classify_exit(101, "thread panicked at x", 600) == "process panic (exit 101)"
        assert "unknown nonzero" in kani.classify_exit(101, "", 600)
        assert "unknown nonzero exit 2" in kani.classify_exit(2, "", 600)


class EnvironmentTests(unittest.TestCase):
    """The build environment is controlled, not inherited."""

    def test_forbidden_wrappers_and_flags_are_rejected_by_name(self) -> None:
        for name in (
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
        ):
            with self.subTest(name=name), self.assertRaises(kani.AdmissionError) as ctx:
                kani.controlled_environment({"PATH": "/bin", name: "x"})
            assert name in str(ctx.exception)
        with self.assertRaises(kani.AdmissionError):
            kani.controlled_environment({"PATH": "/bin", "RUSTFLAGS": "--cfg other"})

    def test_allowlist_and_policy_flags(self) -> None:
        env, record = kani.controlled_environment(
            {
                "PATH": "/bin",
                "HOME": "/h",
                "FOO": "bar",
                "RUSTFLAGS": kani.POLICY_RUSTFLAGS,
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/nix/store/x/bin/clang",
            }
        )
        assert env["RUSTFLAGS"] == kani.POLICY_RUSTFLAGS
        assert "FOO" not in env
        assert "FOO" in record["dropped"]
        assert env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"].endswith("clang")
        assert env["CARGO_INCREMENTAL"] == "0"


class MetadataBindingTests(unittest.TestCase):
    def group(self) -> dict[str, Any]:
        return {
            "id": "ffi-evidence",
            "class": "required",
            "gating": "evidence",
            "package": {"name": "ffi", "manifest": "crates/ffi/Cargo.toml"},
            "crate": "ffi",
            "features": ["kani"],
            "no_default_features": True,
            "cfg": ["kani"],
            "default_unwind": 16,
            "harnesses": [],
        }

    def test_real_metadata_binds_and_mutations_reject(self) -> None:
        registry = {"solver": "cadical"}
        harness = {"name": JOSE, "file": "crates/ffi/src/kani_tests.rs", "domain": "x"}
        meta = fixture_metadata("success_jose_context_bounds")
        bound = kani.bind_metadata(meta, self.group(), harness, registry, ".")
        assert bound["effective"]["unwind"] == 16
        assert bound["effective"]["solver"] == "cadical"
        for mutate, needle in (
            (lambda m: m.__setitem__("crate_name", "other"), "compiled crate"),
            (
                lambda m: m["proof_harnesses"][0].__setitem__("pretty_name", "x::y"),
                "exactly the requested",
            ),
            (
                lambda m: m["proof_harnesses"][0].__setitem__(
                    "original_file", "crates/ffi/src/lib.rs"
                ),
                "compiled source",
            ),
            (
                lambda m: m["proof_harnesses"][0]["attributes"].__setitem__("should_panic", True),
                "panic expectation",
            ),
            (
                lambda m: m["proof_harnesses"][0]["attributes"].__setitem__(
                    "stubs", [{"original": "a", "replacement": "b"}]
                ),
                "substitution",
            ),
            (
                lambda m: m["proof_harnesses"].append(dict(m["proof_harnesses"][0])),
                "exactly the requested",
            ),
        ):
            with self.subTest(needle=needle):
                mutated = json.loads(json.dumps(meta))
                mutate(mutated)
                with self.assertRaises(kani.AdmissionError) as ctx:
                    kani.bind_metadata(mutated, self.group(), harness, registry, ".")
                assert needle in str(ctx.exception)

    def test_workspace_relative_sources_join_the_workspace_root(self) -> None:
        # Kani records original_file relative to the compiled crate's workspace root: for
        # an excluded crate such as crates/kani-harness that is "src/lib.rs", not the
        # repository-relative path the registry names.
        registry = {"solver": "cadical"}
        harness = {"name": JOSE, "file": "crates/ffi/src/kani_tests.rs", "domain": "x"}
        meta = fixture_metadata("success_jose_context_bounds")
        meta["proof_harnesses"][0]["original_file"] = "src/kani_tests.rs"
        bound = kani.bind_metadata(meta, self.group(), harness, registry, "crates/ffi")
        assert bound["source"] == {
            "original_file": "src/kani_tests.rs",
            "source_base": "crates/ffi",
            "file": harness["file"],
        }
        for base, original, needle in (
            (".", "src/kani_tests.rs", "compiled source"),
            ("crates/ffi", "/abs/src/kani_tests.rs", "not workspace-relative"),
            ("crates/ffi", "", "original_file"),
            ("crates/ffi", "../../../etc/kani_tests.rs", "escapes the repository"),
            ("crates/ffi", "../jose/src/kani_tests.rs", "compiled source"),
        ):
            with self.subTest(base=base, original=original):
                mutated = json.loads(json.dumps(meta))
                mutated["proof_harnesses"][0]["original_file"] = original
                with self.assertRaises(kani.AdmissionError) as ctx:
                    kani.bind_metadata(mutated, self.group(), harness, registry, base)
                assert needle in str(ctx.exception)

    def test_metadata_must_exist_and_be_structurally_complete(self) -> None:
        # one new file is not evidence by itself; the retained metadata must
        # be an object with the proof identity and explicit attributes.
        registry = {"solver": "cadical", "kani_version": "0.66.0"}
        harness = {"name": JOSE, "file": "crates/ffi/src/kani_tests.rs", "domain": "x"}
        text = fixture("success_jose_context_bounds")
        invocation = {"exit_code": 0, "budget_seconds": BUDGET}
        discovery = {"file": harness["file"], "attributes": {}}
        result = kani.decide_request(
            harness, self.group(), registry, text, invocation, None, 1, discovery, "."
        )
        assert result["status"] == "rejected"
        assert any("compiled metadata" in r for r in result["reasons"]), result["reasons"]
        meta = fixture_metadata("success_jose_context_bounds")
        for label, mutate in (
            (
                "no should_panic",
                lambda m: m["proof_harnesses"][0]["attributes"].pop("should_panic"),
            ),
            ("no stubs", lambda m: m["proof_harnesses"][0]["attributes"].pop("stubs")),
            (
                "no verified_stubs",
                lambda m: m["proof_harnesses"][0]["attributes"].pop("verified_stubs"),
            ),
            ("no attributes", lambda m: m["proof_harnesses"][0].pop("attributes")),
            ("no mangled_name", lambda m: m["proof_harnesses"][0].pop("mangled_name")),
            ("no original_file", lambda m: m["proof_harnesses"][0].pop("original_file")),
            ("no crate_name", lambda m: m.pop("crate_name")),
            ("proofs not a list", lambda m: m.__setitem__("proof_harnesses", {})),
            (
                "line not int",
                lambda m: m["proof_harnesses"][0].__setitem__("original_start_line", "1"),
            ),
            (
                "should_panic not bool",
                lambda m: m["proof_harnesses"][0]["attributes"].__setitem__("should_panic", "no"),
            ),
        ):
            with self.subTest(label=label):
                mutated = json.loads(json.dumps(meta))
                mutate(mutated)
                with self.assertRaises(kani.AdmissionError) as ctx:
                    kani.bind_metadata(mutated, self.group(), harness, registry, ".")
                assert "compiled metadata" in str(ctx.exception)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "kani-metadata.json"
            for content in ("null", "[]", "{not json", ""):
                path.write_text(content)
                assert kani.read_metadata(path) is None, content
            path.write_text(json.dumps(meta))
            assert kani.read_metadata(path) == meta

    def test_attribute_types_follow_kani_0_66_0(self) -> None:
        # HarnessKind, Option<CbmcSolver> and Option<u32> as serialised by
        # kani_metadata 0.66.0; the selected harnesses must be #[kani::proof] sites.
        registry = {"solver": "cadical"}
        harness = {"name": JOSE, "file": "crates/ffi/src/kani_tests.rs", "domain": "x"}
        meta = fixture_metadata("success_jose_context_bounds")

        def attributes(**values: Any) -> dict[str, Any]:
            mutated = json.loads(json.dumps(meta))
            mutated["proof_harnesses"][0]["attributes"].update(values)
            return mutated

        def proof(**values: Any) -> dict[str, Any]:
            mutated = json.loads(json.dumps(meta))
            mutated["proof_harnesses"][0].update(values)
            return mutated

        rejected = (
            ("kind null", attributes(kind=None)),
            ("kind number", attributes(kind=123)),
            ("kind unknown", attributes(kind="Fuzz")),
            ("kind Test (not a selected proof)", attributes(kind="Test")),
            (
                "kind contract (not a selected proof)",
                attributes(kind={"ProofForContract": {"target_fn": "f"}}),
            ),
            ("kind malformed contract", attributes(kind={"ProofForContract": 1})),
            ("solver number", attributes(solver=123)),
            ("solver unknown", attributes(solver="Nope")),
            ("solver malformed binary", attributes(solver={"Binary": 5})),
            ("unwind string", attributes(unwind_value="invalid")),
            ("unwind bool", attributes(unwind_value=False)),
            ("unwind negative", attributes(unwind_value=-1)),
            ("unwind above u32", attributes(unwind_value=1 << 32)),
            ("stub entry malformed", attributes(stubs=["x"])),
            ("verified stub malformed", attributes(verified_stubs=[1])),
            ("mangled empty", proof(mangled_name="")),
            ("pretty empty", proof(pretty_name="")),
            ("file empty", proof(original_file="")),
            ("line zero", proof(original_start_line=0)),
            ("line negative", proof(original_start_line=-1)),
            ("line bool", proof(original_start_line=True)),
            ("lines inverted", proof(original_start_line=50, original_end_line=10)),
        )
        for label, mutated in rejected:
            with self.subTest(label=label), self.assertRaises(kani.AdmissionError):
                kani.bind_metadata(mutated, self.group(), harness, registry, ".")
        # Valid Option values are preserved, including unwind 0 (Kani keeps 0 as well).
        for label, mutated, unwind in (
            ("unwind none -> group default", attributes(unwind_value=None), 16),
            ("unwind zero", attributes(unwind_value=0), 0),
            ("unwind five", attributes(unwind_value=5), 5),
            ("solver variant", attributes(solver="Cadical"), 16),
            ("solver binary", attributes(solver={"Binary": "/usr/bin/kissat"}), 16),
        ):
            with self.subTest(label=label):
                bound = kani.bind_metadata(mutated, self.group(), harness, registry, ".")
                assert bound["effective"]["unwind"] == unwind
        # The general validator accepts other kinds structurally (discovery lists them);
        # only the selection binding restricts the kind.
        for kind in ("Test", {"ProofForContract": {"target_fn": "f"}}):
            assert kani.validate_metadata(attributes(kind=kind))

    def test_decide_request_requires_one_new_metadata_and_discovery(self) -> None:
        registry = {"solver": "cadical", "kani_version": "0.66.0"}
        harness = {"name": JOSE, "file": "crates/ffi/src/kani_tests.rs", "domain": "x"}
        text = fixture("success_jose_context_bounds")
        invocation = {"exit_code": 0, "budget_seconds": BUDGET}
        meta = fixture_metadata("success_jose_context_bounds")
        discovery = {"file": harness["file"], "attributes": {}}
        ok = kani.decide_request(
            harness, self.group(), registry, text, invocation, meta, 1, discovery, "."
        )
        assert ok["status"] == "accepted", ok["reasons"]
        for count, discovery_entry, needle in (
            (0, discovery, "exactly one new"),
            (2, discovery, "exactly one new"),
            (1, None, "missing from compiled discovery"),
            (1, {"file": "crates/ffi/src/lib.rs"}, "discovery file differs"),
        ):
            with self.subTest(needle=needle):
                result = kani.decide_request(
                    harness,
                    self.group(),
                    registry,
                    text,
                    invocation,
                    meta,
                    count,
                    discovery_entry,
                    ".",
                )
                assert result["status"] == "rejected"
                assert any(needle in r for r in result["reasons"]), result["reasons"]


class RegistryTests(unittest.TestCase):
    def test_checked_in_registry_loads(self) -> None:
        registry = kani.load_registry(ROOT, ROOT / kani.REGISTRY, SCHEMA)
        required = [
            h
            for g in kani.executable_groups(registry)
            if g["class"] == "required"
            for h in g["harnesses"]
        ]
        diagnostic = [
            h
            for g in kani.executable_groups(registry)
            if g["class"] == "diagnostic"
            for h in g["harnesses"]
        ]
        assert len(required) == 26
        assert len(diagnostic) == 2
        assert (
            sum(1 for g in kani.executable_groups(registry) if g.get("gating") == "evidence") == 2
        )
        sites = kani.source_sites(ROOT)
        assert len(sites) == len(required) + len(diagnostic) + len(kani.excluded_sites(registry))

    def test_registry_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / "crates/demo/src").mkdir(parents=True)
            (root / "crates/demo/Cargo.toml").write_text('[package]\nname = "demo"\n')
            (root / "crates/demo/src/lib.rs").write_text(
                "#[kani::proof]\nfn alpha() {}\n#[kani::proof]\nfn beta() {}\n"
            )
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text("[build]\n")
            base = {
                "version": 2,
                "contract": kani.CONTRACT,
                "kani_version": "0.66.0",
                "target": "x86_64-unknown-linux-gnu",
                "solver": "cadical",
                "budgets": {
                    "timeout_seconds": 600,
                    "list_timeout_seconds": 600,
                    "memory_limit_bytes": 1 << 30,
                },
                "toolchain": {"rust_toolchain_toml_sha256": "0" * 64},
                "cargo_config": {
                    "registered_files": [
                        {
                            "path": ".cargo/config.toml",
                            "sha256": sha256(root / ".cargo/config.toml"),
                        }
                    ]
                },
                "groups": [
                    {
                        "id": "demo",
                        "class": "required",
                        "gating": "regression",
                        "package": {"name": "demo", "manifest": "crates/demo/Cargo.toml"},
                        "crate": "demo",
                        "features": [],
                        "no_default_features": False,
                        "cfg": ["kani"],
                        "default_unwind": 16,
                        "harnesses": [
                            {"name": "alpha", "file": "crates/demo/src/lib.rs", "domain": "d"}
                        ],
                    },
                    {
                        "id": "excluded",
                        "class": "excluded",
                        "sites": [
                            {
                                "name": "beta",
                                "file": "crates/demo/src/lib.rs",
                                "kind": "compiled",
                                "reason": "not selected",
                            }
                        ],
                    },
                ],
            }
            path = root / "registry.json"
            path.write_text(json.dumps(base))
            kani.load_registry(root, path, SCHEMA)
            for mutate, needle in (
                (lambda r: r["groups"][1]["sites"].clear(), "schema"),
                (
                    lambda r: r["groups"][0]["harnesses"].append(
                        {"name": "x::alpha", "file": "crates/demo/src/lib.rs", "domain": "d"}
                    ),
                    "ambiguous short name",
                ),
                (lambda r: r["groups"].pop(1), "neither selected nor excluded"),
                (lambda r: r["groups"][0].__setitem__("unknown", 1), "schema"),
                (lambda r: r["groups"][0].pop("gating"), "schema"),
                (
                    lambda r: r["cargo_config"]["registered_files"][0].__setitem__(
                        "sha256", "1" * 64
                    ),
                    "missing or changed",
                ),
                (
                    lambda r: r["groups"][0]["harnesses"][0].__setitem__(
                        "file", "crates/demo/src/none.rs"
                    ),
                    "does not exist",
                ),
                # Path traversal and absolute paths are rejected by the schema itself.
                (
                    lambda r: r["groups"][0]["harnesses"][0].__setitem__(
                        "file", "../demo/src/lib.rs"
                    ),
                    "schema",
                ),
                (
                    lambda r: r["groups"][0]["harnesses"][0].__setitem__(
                        "file", "crates/demo/../demo/src/lib.rs"
                    ),
                    "schema",
                ),
                (
                    lambda r: r["groups"][1]["sites"][0].__setitem__(
                        "file", "/crates/demo/src/lib.rs"
                    ),
                    "schema",
                ),
            ):
                with self.subTest(needle=needle):
                    mutated = json.loads(json.dumps(base))
                    mutate(mutated)
                    path.write_text(json.dumps(mutated))
                    with self.assertRaises(kani.AdmissionError) as ctx:
                        kani.load_registry(root, path, SCHEMA)
                    assert needle in str(ctx.exception), str(ctx.exception)


FAKE_KANI = r'''#!/usr/bin/env python3
"""Controlled fake cargo-kani: reproduces the 0.66.0 output grammar for the wrapper tests."""
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
knobs_path = pathlib.Path(__file__).resolve().parents[3] / "fake-mode.json"
knobs = json.loads(knobs_path.read_text()) if knobs_path.exists() else {}
mode = knobs.get("mode", "ok")
if args[:2] == ["kani", "--version"]:
    print("cargo-kani " + knobs.get("version", "0.66.0")); sys.exit(0)
if args and args[0] == "kani":
    manifest = pathlib.Path(args[args.index("--manifest-path") + 1])
    package = args[args.index("-p") + 1]
    crate = package.replace("-", "_")
    harnesses = json.loads((manifest.parent / "harnesses.json").read_text())
    target_root = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    target = target_root / "kani/x86_64-unknown-linux-gnu/debug/deps"
    target.mkdir(parents=True, exist_ok=True)
    def write_metadata(selected):
        attributes = {"kind": "Proof", "should_panic": False, "solver": None,
                      "unwind_value": None, "stubs": [], "verified_stubs": []}
        proofs = [{"pretty_name": n, "mangled_name": "_R" + n, "crate_name": crate,
                   "original_file": f, "original_start_line": 1, "original_end_line": 2,
                   "goto_file": None, "attributes": dict(attributes), "contract": None,
                   "has_loop_contracts": False, "is_automatically_generated": False}
                  for n, f in harnesses.items() if n in selected]
        section = "discovery_overrides" if "--only-codegen" in args else "overrides"
        overrides = knobs.get(section, {})
        for proof in proofs:
            proof.update(overrides.get("proof", {}))
            proof["attributes"].update(overrides.get("attributes", {}))
        blob = json.dumps({"crate_name": crate, "proof_harnesses": proofs,
                           "unsupported_features": [], "test_harnesses": [],
                           "contracted_functions": [], "autoharness_md": None})
        digest = hashlib.sha256((blob + str(sorted(selected))).encode()).hexdigest()[:16]
        name = f"{crate}-{digest}.kani-metadata.json"
        content = blob
        if mode == "null-metadata" and "--only-codegen" not in args:
            content = "null"
        if mode == "incomplete-metadata" and "--only-codegen" not in args:
            for proof in proofs:
                proof["attributes"] = {"kind": "Proof"}
            content = json.dumps({"crate_name": crate, "proof_harnesses": proofs,
                                  "unsupported_features": [], "test_harnesses": [],
                                  "contracted_functions": [], "autoharness_md": None})
        if mode != "no-metadata" or "--only-codegen" in args:
            (target / name).write_text(content)
    print("Kani Rust Verifier 0.66.0 (cargo plugin)")
    crash = mode == "crash-discovery" and package == knobs.get("crash_package")
    if "--only-codegen" in args and crash:
        print("synthetic discovery crash"); sys.exit(13)
    if "--only-codegen" in args:
        write_metadata(set(harnesses)); sys.exit(0)
    harness = args[args.index("--harness") + 1]
    if mode == "mutate-source" and harness.endswith("two"):
        with (manifest.parent / "src/lib.rs").open("a") as handle:
            handle.write("// mutated during the run\n")
    if harness not in harnesses:
        print(f"error: no harness matched the filter `{harness}`"); sys.exit(1)
    if mode == "stale-metadata":
        write_metadata({harness}); write_metadata(set(harnesses))
    else:
        write_metadata({harness})
    print(f"Checking harness {harness}...")
    failing = mode == "fail" and harness.endswith(knobs.get("fail_suffix", "beta"))
    status = "FAILURE" if failing else "SUCCESS"
    print("\nRESULTS:")
    print(f"Check 1: {harness}.assertion.1\n\t - Status: {status}\n\t - Description: \"asserted\"\n"
          f"\t - Location: src/lib.rs:1:1 in function {harness}\n")
    print(f"Check 2: {harness}.unwind.0\n\t - Status: SUCCESS\n"
          "\t - Description: \"unwinding assertion loop 0\"\n")
    print("\nSUMMARY:")
    if status == "FAILURE":
        print(" ** 1 of 2 failed\nFailed Checks: asserted\n\nVERIFICATION:- FAILED\n"
              "Verification Time: 0.1s\n\nManual Harness Summary:\n"
              "Verification failed for - " + harness + "\n"
              "Complete - 0 successfully verified harnesses, 1 failures, 1 total.")
        sys.exit(1)
    print(" ** 0 of 2 failed\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: 0.1s\n\n"
          "Manual Harness Summary:\n"
          "Complete - 1 successfully verified harnesses, 0 failures, 1 total.")
    sys.exit(0 if mode != "nonzero-after-success" else 3)
if args[:1] == ["metadata"]:
    manifest = pathlib.Path(args[args.index("--manifest-path") + 1])
    package = manifest.parent.name
    crate = package.replace("-", "_")
    pid = f"path+file://{manifest.parent}#{package}@0.1.0"
    package_record = {"id": pid, "name": package, "version": "0.1.0", "source": None,
                      "manifest_path": str(manifest), "features": {},
                      "targets": [{"name": crate, "kind": ["lib"], "crate_types": ["lib"]}]}
    print(json.dumps({"workspace_root": str(manifest.parent), "packages": [package_record],
                      "resolve": {"nodes": [{"id": pid, "dependencies": [], "features": []}]}}))
    sys.exit(0)
if args[:2] == ["config", "get"]:
    print(json.dumps(knobs.get("cargo_config", {}))); sys.exit(0)
print("fake cargo: unsupported", args, file=sys.stderr); sys.exit(2)
'''
FAKE_RUSTC = (
    "#!/usr/bin/env python3\n"
    "print('rustc 1.93.0-nightly (fake)\\nbinary: rustc\\n"
    "host: x86_64-unknown-linux-gnu\\nrelease: 1.93.0-nightly')\n"
)


class WrapperTests(unittest.TestCase):
    """The runner end to end with a controlled fake toolchain."""

    def setUp(self) -> None:
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.write_repository()
        store = self.write_toolchain()
        self.write_policy(store)

    def write_repository(self) -> None:
        # Repository skeleton with two packages and their proof sites.
        for pkg, names in (("alpha-pkg", ["one", "two"]), ("beta-pkg", ["beta"])):
            src = self.root / "crates" / pkg / "src"
            src.mkdir(parents=True)
            (src.parent / "Cargo.toml").write_text(f'[package]\nname = "{pkg}"\n')
            (src / "lib.rs").write_text("".join(f"#[kani::proof]\nfn {n}() {{}}\n" for n in names))
            (src.parent / "harnesses.json").write_text(
                json.dumps({f"proofs::{n}": "src/lib.rs" for n in names})
            )
        (self.root / ".cargo").mkdir()
        (self.root / ".cargo/config.toml").write_text("[build]\n")
        (self.root / "spec").mkdir()
        shutil.copy(SCHEMA, self.root / "spec/kani-evidence.schema.json")
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "flake.lock"):
            (self.root / name).write_text(f"# {name}\n")

    def write_toolchain(self) -> pathlib.Path:
        # Fake Nix-like toolchain layout.
        store = self.root / "store" / "kani-verifier-0.66.0"
        (store / "bin").mkdir(parents=True)
        for rel in ("kani-0.66.0/bin/kani-driver", "kani-0.66.0/bin/kani-compiler"):
            path = store / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        toolchain = store / "kani-0.66.0/toolchain/bin"
        toolchain.mkdir(parents=True)
        # The fake tools name the running interpreter explicitly: /usr/bin/env does not
        # exist inside a Nix build sandbox, where the docs lane runs this suite.
        shebang = f"#!{sys.executable}"
        (toolchain / "rustc").write_text(FAKE_RUSTC.replace("#!/usr/bin/env python3", shebang, 1))
        (toolchain / "rustc").chmod(0o755)
        (toolchain / "cargo").write_text(FAKE_KANI.replace("#!/usr/bin/env python3", shebang, 1))
        (toolchain / "cargo").chmod(0o755)
        solver_dir = self.root / "store" / "fake-cadical-1.0" / "bin"
        cbmc_dir = self.root / "store" / "fake-cbmc-6.10.0" / "bin"
        for directory, tool in ((solver_dir, "cadical"), (cbmc_dir, "cbmc")):
            directory.mkdir(parents=True)
            (directory / tool).write_text("#!/bin/sh\necho '6.10.0 (fake)'\n")
            (directory / tool).chmod(0o755)
        wrapper = store / "bin" / "cargo-kani"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"PATH='{solver_dir}':\"$PATH\"\nPATH='{cbmc_dir}':\"$PATH\"\nexport PATH\n"
            f'exec {toolchain / "cargo"} "$@"\n'
        )
        wrapper.chmod(0o755)
        return store

    def write_policy(self, store: pathlib.Path) -> None:
        self.registry = {
            "version": 2,
            "contract": kani.CONTRACT,
            "kani_version": "0.66.0",
            "target": "x86_64-unknown-linux-gnu",
            "solver": "cadical",
            "budgets": {
                "timeout_seconds": 60,
                "list_timeout_seconds": 60,
                "memory_limit_bytes": 1 << 33,
            },
            "toolchain": {"rust_toolchain_toml_sha256": sha256(self.root / "rust-toolchain.toml")},
            "cargo_config": {
                "registered_files": [
                    {
                        "path": ".cargo/config.toml",
                        "sha256": sha256(self.root / ".cargo/config.toml"),
                    }
                ]
            },
            "groups": [
                {
                    "id": "alpha",
                    "class": "required",
                    "gating": "evidence",
                    "package": {"name": "alpha-pkg", "manifest": "crates/alpha-pkg/Cargo.toml"},
                    "crate": "alpha_pkg",
                    "features": [],
                    "no_default_features": False,
                    "cfg": ["kani"],
                    "default_unwind": 16,
                    "harnesses": [
                        {
                            "name": "proofs::one",
                            "file": "crates/alpha-pkg/src/lib.rs",
                            "domain": "d",
                            "rows": ["ROW-1"],
                        },
                        {
                            "name": "proofs::two",
                            "file": "crates/alpha-pkg/src/lib.rs",
                            "domain": "d",
                        },
                    ],
                },
                {
                    "id": "beta",
                    "class": "diagnostic",
                    "package": {"name": "beta-pkg", "manifest": "crates/beta-pkg/Cargo.toml"},
                    "crate": "beta_pkg",
                    "features": [],
                    "no_default_features": False,
                    "cfg": ["kani"],
                    "default_unwind": 16,
                    "harnesses": [
                        {
                            "name": "proofs::beta",
                            "file": "crates/beta-pkg/src/lib.rs",
                            "domain": "d",
                            "rows": ["ROW-2"],
                        }
                    ],
                },
            ],
        }
        self.registry_path = self.root / "spec/kani-evidence.json"
        self.write_registry(self.registry)
        self.fake()
        self.output = self.root / "out"
        # The runner controls the *cargo* environment itself; the test only prepends the
        # fake toolchain and removes inherited compiler overrides from its own process.
        self.env = {
            k: v
            for k, v in os.environ.items()
            if k not in kani.FORBIDDEN_ENVIRONMENT and not k.startswith("CARGO_TARGET_")
        }
        self.env.update(
            {
                "PATH": f"{store / 'bin'}:{os.environ['PATH']}",
                "HOME": str(self.root),
                "TMPDIR": str(self.root),
            }
        )
        self.env.pop("RUSTFLAGS", None)

    def fake(self, **knobs: Any) -> None:
        (self.root / "store" / "kani-verifier-0.66.0" / "fake-mode.json").write_text(
            json.dumps(knobs)
        )

    def write_registry(self, registry: dict[str, Any]) -> None:
        self.registry_path.write_text(json.dumps(registry, indent=2) + "\n")

    def invoke(self, *extra: str, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture paths
            [
                sys.executable,
                str(RUNNER),
                "--root",
                str(self.root),
                "--output",
                str(self.output),
                *extra,
            ],
            env={**self.env, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    def replay(self) -> subprocess.CompletedProcess[str]:
        run_dir = max(self.output.glob("run-*"))
        return subprocess.run(  # noqa: S603 - fixed script and fixture paths
            [
                sys.executable,
                str(RUNNER),
                "--root",
                str(self.root),
                "--verify-records",
                str(run_dir),
            ],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def admissions(self, stdout: str) -> list[dict[str, Any]]:
        return [
            json.loads(line.split(" ", 1)[1])
            for line in stdout.splitlines()
            if line.startswith("KANI-ADMISSION ")
        ]

    def test_full_scope_accepts_and_replays(self) -> None:
        result = self.invoke()
        assert result.returncode == 0, result.stdout + result.stderr
        summary = self.admissions(result.stdout)[-1]
        assert summary["gate"] is True
        assert summary["counts"] == {
            "required_accepted": 2,
            "required_rejected": 0,
            "diagnostic_accepted": 1,
            "diagnostic_rejected": 0,
            "faults": 0,
        }
        gate = json.loads((self.output / "gate.json").read_text())
        run_dir = self.output / gate["run"]
        evaluation = json.loads((run_dir / "evaluation.json").read_text())
        assert evaluation["registry_sha256"] == sha256(self.registry_path)
        assert {r["harness"]["name"] for r in evaluation["results"]} == {
            "proofs::one",
            "proofs::two",
            "proofs::beta",
        }
        assert (run_dir / "groups/alpha/discovery.kani-metadata.json").is_file()
        assert (run_dir / "environment.json").is_file()
        assert (run_dir / "tools.json").is_file()
        replay = self.replay()
        assert replay.returncode == 0, replay.stdout + replay.stderr

    def test_diagnostic_failure_does_not_block_but_required_failure_does(self) -> None:
        result = (self.fake(mode="fail"), self.invoke())[1]  # only harness 'beta' fails
        assert result.returncode == 0, result.stdout + result.stderr
        summary = self.admissions(result.stdout)[-1]
        assert summary["gate"] is True
        assert summary["counts"]["diagnostic_rejected"] == 1
        # Promote beta to required: the same failure now blocks and no gate is written.
        registry = json.loads(json.dumps(self.registry))
        registry["groups"][1]["class"] = "required"
        registry["groups"][1]["gating"] = "regression"
        self.write_registry(registry)
        shutil.rmtree(self.output)
        result = (self.fake(mode="fail"), self.invoke())[1]
        assert result.returncode != 0
        assert not (self.output / "gate.json").exists()
        assert self.admissions(result.stdout)[-1]["gate"] is False

    def test_scopes_never_write_gate(self) -> None:
        for extra in (("--scope", "diagnostic"), ("--scope", "partial", "--groups", "alpha")):
            with self.subTest(extra=extra):
                shutil.rmtree(self.output, ignore_errors=True)
                result = self.invoke(*extra)
                assert result.returncode == 0, result.stdout + result.stderr
                assert not (self.output / "gate.json").exists()
                assert self.admissions(result.stdout)[-1]["gate"] is False
                assert self.replay().returncode == 0
        result = self.invoke("--scope", "partial")
        assert result.returncode != 0

    def test_inherited_wrapper_is_rejected_before_running(self) -> None:
        for name in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            with self.subTest(name=name):
                shutil.rmtree(self.output, ignore_errors=True)
                result = self.invoke(**{name: "/usr/bin/env"})
                assert result.returncode != 0
                assert name in result.stdout + result.stderr
                assert not list(self.output.glob("run-*/requests"))

    def test_cargo_config_override_is_rejected(self) -> None:
        result = (self.fake(cargo_config={"build": {"rustc-wrapper": "sccache"}}), self.invoke())[1]
        assert result.returncode != 0
        assert "cargo configuration overrides the build" in result.stdout + result.stderr
        assert not (self.output / "gate.json").exists()

    def test_stale_or_missing_metadata_rejects(self) -> None:
        for mode in ("stale-metadata", "no-metadata"):
            with self.subTest(mode=mode):
                shutil.rmtree(self.output, ignore_errors=True)
                self.fake(mode=mode)
                result = self.invoke()
                assert result.returncode != 0
                assert "exactly one new compiled metadata" in result.stdout

    def test_success_output_then_nonzero_exit_rejects(self) -> None:
        result = (self.fake(mode="nonzero-after-success"), self.invoke())[1]
        assert result.returncode != 0
        assert "unknown nonzero exit 3" in result.stdout

    def test_unsupported_tool_version_and_missing_harness_reject(self) -> None:
        result = (self.fake(version="0.65.0"), self.invoke())[1]
        assert result.returncode != 0
        assert "unsupported Kani" in result.stdout + result.stderr
        registry = json.loads(json.dumps(self.registry))
        registry["groups"][0]["harnesses"].append(
            {"name": "proofs::ghost", "file": "crates/alpha-pkg/src/lib.rs", "domain": "d"}
        )
        (self.root / "crates/alpha-pkg/src/lib.rs").write_text(
            (self.root / "crates/alpha-pkg/src/lib.rs").read_text()
            + "#[kani::proof]\nfn ghost() {}\n"
        )
        self.write_registry(registry)
        self.fake()
        shutil.rmtree(self.output, ignore_errors=True)
        result = self.invoke()
        assert result.returncode != 0
        assert "missing from compiled discovery" in result.stdout

    def test_replay_rejects_tampering_and_class_swaps(self) -> None:
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        original = (run_dir / "requests/01/output.log").read_bytes()
        (run_dir / "requests/01/output.log").write_bytes(original + b"\n")
        assert self.replay().returncode != 0
        (run_dir / "requests/01/output.log").write_bytes(original)
        assert self.replay().returncode == 0
        # Group records (cargo metadata, discovery) are digest-bound to every result.
        discovery = run_dir / "groups" / self.registry["groups"][0]["id"] / "discovery.json"
        kept = discovery.read_bytes()
        discovery.write_bytes(kept.replace(b"src/lib.rs", b"src/other.rs"))
        tampered = self.replay()
        assert tampered.returncode != 0
        assert "discovery.json" in tampered.stdout + tampered.stderr
        discovery.write_bytes(kept)
        assert self.replay().returncode == 0
        registry = json.loads(json.dumps(self.registry))
        registry["groups"][0]["class"] = "diagnostic"
        registry["groups"][0].pop("gating")
        self.write_registry(registry)
        replay = self.replay()
        assert replay.returncode != 0
        assert "different registry" in replay.stdout + replay.stderr

    def test_citation_checker_structural_and_evidential(self) -> None:
        matrix = self.root / "spec/compliance-matrix.yaml"

        def row(row_id: str, status: str, file: str, harness: str, ci_check: str = "") -> str:
            check = f"  ci_check: {ci_check}\n" if ci_check else ""
            return (
                f"- id: {row_id}\n  status: {status}\n{check}  proof:\n"
                f"  - type: kani\n    file: {file}\n    harness: {harness}\n"
            )

        matrix.write_text(
            "rows:\n"
            + row("ROW-1", "verified", "crates/alpha-pkg/src/lib.rs", "one", "kani-evidence")
            + row("ROW-2", "partial", "crates/beta-pkg/src/lib.rs", "beta")
            + row("ROW-3", "planned", "crates/beta-pkg/src/lib.rs", "nothing")
        )

        def check(*extra: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(  # noqa: S603 - fixed script and fixture paths
                [
                    sys.executable,
                    str(CHECKER),
                    "--root",
                    str(self.root),
                    "--registry",
                    str(self.registry_path),
                    "--schema",
                    str(self.root / "spec/kani-evidence.schema.json"),
                    "--matrix",
                    str(matrix),
                    *extra,
                ],
                env=self.env,
                capture_output=True,
                text=True,
                check=False,
            )

        structural = check()
        assert structural.returncode != 0
        assert "ROW-3: unbound" in structural.stdout
        matrix.write_text(matrix.read_text().split("- id: ROW-3")[0])
        assert check().returncode == 0
        assert (self.fake(mode="fail"), self.invoke())[
            1
        ].returncode == 0  # beta (diagnostic) fails, gate still written
        evidential = check("--gate", str(self.output / "gate.json"))
        assert evidential.returncode == 0, evidential.stdout
        assert "accepted-evidence" in evidential.stdout
        assert "diagnostic-rejected" in evidential.stdout
        # A verified row citing the diagnostic harness is a structural failure.
        matrix.write_text(matrix.read_text().replace("status: partial", "status: verified"))
        result = check()
        assert result.returncode != 0
        assert "verified-row-cites-non-evidence" in result.stdout

    def check_citations(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture paths
            [
                sys.executable,
                str(CHECKER),
                "--root",
                str(self.root),
                "--registry",
                str(self.registry_path),
                "--schema",
                str(self.root / "spec/kani-evidence.schema.json"),
                "--matrix",
                str(self.root / "spec/compliance-matrix.yaml"),
                *extra,
            ],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def rebind(self, run_dir: pathlib.Path) -> None:
        # Re-declare the records and re-bind the gate to the rewritten evaluation, as an
        # adversary with write access to the artifact would.
        evaluation_path = run_dir / "evaluation.json"
        evaluation = json.loads(evaluation_path.read_text())
        evaluation["records"] = {
            p.relative_to(run_dir).as_posix(): sha256(p)
            for p in sorted(run_dir.rglob("*"))
            if p.is_file() and p.relative_to(run_dir).as_posix() != "evaluation.json"
        }
        evaluation_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n")
        gate_path = self.output / "gate.json"
        gate = json.loads(gate_path.read_text())
        gate["evaluation_sha256"] = sha256(evaluation_path)
        gate_path.write_text(json.dumps(gate, indent=2) + "\n")

    def write_matrix(self) -> None:
        (self.root / "spec/compliance-matrix.yaml").write_text(
            "rows:\n"
            "- id: ROW-1\n  status: verified\n  proof:\n"
            "  - type: kani\n    file: crates/alpha-pkg/src/lib.rs\n    harness: one\n"
            "- id: ROW-2\n  status: partial\n  proof:\n"
            "  - type: kani\n    file: crates/beta-pkg/src/lib.rs\n    harness: beta\n"
        )

    def test_replay_reconstructs_every_result_from_its_raw_records(self) -> None:
        # a stored status must never stand in for the reconstruction, and the
        # gate-bound summary must agree with every individual record.
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        result_path = run_dir / "requests/01/result.json"
        stored_bytes = result_path.read_bytes()
        stored = json.loads(stored_bytes)
        log = run_dir / "requests/01/output.log"
        original_log = log.read_bytes()
        result_path.write_text(
            json.dumps({**stored, "status": "rejected", "reasons": ["synthetic"]}, indent=2)
        )
        log.write_bytes(b"SYNTHETIC CORRUPTED LOG\n")
        replay = self.replay()
        assert replay.returncode != 0, replay.stdout
        assert "requests/01" in replay.stdout + replay.stderr
        log.write_bytes(original_log)
        replay = self.replay()  # status flipped alone, raw log intact
        assert replay.returncode != 0, replay.stdout
        result_path.write_bytes(stored_bytes)
        assert self.replay().returncode == 0

    def test_replay_rejects_a_consistently_rewritten_summary_and_gate(self) -> None:
        # rewriting the summary and re-binding the gate to it does not help;
        # the summary must agree with what the raw records reconstruct to.
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        evaluation_path = run_dir / "evaluation.json"
        evaluation_bytes = evaluation_path.read_bytes()
        evaluation = json.loads(evaluation_bytes)
        evaluation["results"][0]["status"] = "rejected"
        evaluation["results"][0]["reasons"] = ["synthetic"]
        evaluation_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n")
        gate_path = self.output / "gate.json"
        gate_bytes = gate_path.read_bytes()
        gate = json.loads(gate_bytes)
        gate["evaluation_sha256"] = sha256(evaluation_path)
        gate_path.write_text(json.dumps(gate, indent=2) + "\n")
        replay = self.replay()
        assert replay.returncode != 0, replay.stdout
        assert "disagree" in replay.stdout + replay.stderr
        evaluation_path.write_bytes(evaluation_bytes)
        gate_path.write_bytes(gate_bytes)
        assert self.replay().returncode == 0

    def test_replay_binds_sources_schema_and_provenance_records(self) -> None:
        # the caller's source snapshot, schema and every provenance record are
        # part of the evidence; a change or an omission rejects the run.
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        source = self.root / "crates/alpha-pkg/src/lib.rs"
        kept = source.read_bytes()
        source.write_bytes(kept.replace(b"fn one() {}", b"fn one() { assert!(false); }"))
        replay = self.replay()
        assert replay.returncode != 0, replay.stdout
        assert "source inputs" in replay.stdout + replay.stderr
        source.write_bytes(kept)
        assert self.replay().returncode == 0
        schema = self.root / "spec/kani-evidence.schema.json"
        kept_schema = schema.read_bytes()
        schema.write_bytes(kept_schema + b"\n")
        replay = self.replay()
        assert replay.returncode != 0
        assert "schema" in replay.stdout + replay.stderr
        schema.write_bytes(kept_schema)
        for relative in (
            "policy.json",
            "schema.json",
            "tools.json",
            "environment.json",
            "groups/alpha/discovery.kani-metadata.json",
            "groups/alpha/discovery.log",
            "groups/alpha/cargo-metadata.json",
            "requests/02/kani-metadata.json",
            "requests/02/command.json",
        ):
            with self.subTest(record=relative):
                path = run_dir / relative
                data = path.read_bytes()
                path.unlink()
                replay = self.replay()
                assert replay.returncode != 0, relative
                assert relative.split("/")[-1] in replay.stdout + replay.stderr
                assert "Traceback" not in replay.stderr, replay.stderr
                path.write_bytes(data)
        assert self.replay().returncode == 0

    def test_malformed_record_is_a_clean_rejection(self) -> None:
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        discovery = run_dir / "groups/alpha/discovery.json"
        kept_discovery = discovery.read_bytes()
        discovery.write_bytes(b"{}")
        evaluation_path = run_dir / "evaluation.json"
        evaluation = json.loads(evaluation_path.read_text())
        evaluation["records"]["groups/alpha/discovery.json"] = sha256(discovery)
        evaluation_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n")
        malformed = self.replay()
        assert malformed.returncode != 0
        assert "Traceback" not in malformed.stderr, malformed.stderr
        discovery.write_bytes(kept_discovery)

    def test_source_change_during_the_run_is_a_fault(self) -> None:
        self.fake(mode="mutate-source")
        result = self.invoke()
        assert result.returncode != 0
        assert "inputs changed during the run" in result.stdout + result.stderr
        assert not (self.output / "gate.json").exists()
        assert self.admissions(result.stdout)[-1]["status"] == "fault"
        assert self.replay().returncode != 0

    def test_citation_checker_reconstructs_the_gate_run(self) -> None:
        # the evidential mode reconstructs the run itself from the caller's
        # trust inputs; missing, duplicated or foreign records are rejected here.
        self.write_matrix()
        assert self.invoke().returncode == 0, "fixture run"
        run_dir = max(self.output.glob("run-*"))
        gate = str(self.output / "gate.json")
        good = self.check_citations("--gate", gate)
        assert good.returncode == 0, good.stdout + good.stderr
        assert "accepted-evidence" in good.stdout
        requests_backup = self.root / "requests-backup"
        shutil.copytree(run_dir / "requests", requests_backup)
        shutil.rmtree(run_dir / "requests")
        missing = self.check_citations("--gate", gate)
        assert missing.returncode != 0, missing.stdout
        shutil.copytree(requests_backup, run_dir / "requests")
        assert self.check_citations("--gate", gate).returncode == 0
        foreign = json.loads(json.dumps(self.registry))
        foreign["groups"][0]["harnesses"][0]["domain"] += " CHANGE"
        (self.root / "changed-registry.json").write_text(json.dumps(foreign, indent=2) + "\n")
        result = self.check_citations(
            "--registry", str(self.root / "changed-registry.json"), "--gate", gate
        )
        assert result.returncode != 0
        assert "registry" in result.stdout + result.stderr
        shutil.copytree(run_dir / "requests/03", run_dir / "requests/04")
        extra = self.check_citations("--gate", gate)
        assert extra.returncode != 0
        assert "requests/04" in extra.stdout + extra.stderr
        shutil.rmtree(run_dir / "requests/04")
        assert self.check_citations("--gate", gate).returncode == 0

    def test_citation_checker_binds_the_matrix_and_needs_an_admitted_gate(self) -> None:
        self.write_matrix()
        assert self.invoke().returncode == 0, "fixture run"
        gate = str(self.output / "gate.json")
        matrix = self.root / "spec/compliance-matrix.yaml"
        kept_matrix = matrix.read_bytes()
        matrix.write_bytes(kept_matrix + b"# edited after the run\n")
        edited = self.check_citations("--gate", gate)
        assert edited.returncode != 0
        assert "matrix" in edited.stdout + edited.stderr
        matrix.write_bytes(kept_matrix)
        assert self.check_citations("--gate", gate).returncode == 0
        # An uncited required failure leaves no gate; the checker cannot admit anything.
        shutil.rmtree(self.output)
        self.fake(mode="fail", fail_suffix="two")
        assert self.invoke().returncode != 0
        failed = self.check_citations("--gate", gate)
        assert failed.returncode != 0

    def test_metadata_without_substance_is_never_accepted(self) -> None:
        # a single new metadata file whose content is JSON null or lacks the
        # proof attributes is not compiled identity; runner, replay and checker reject.
        self.write_matrix()
        for mode in ("null-metadata", "incomplete-metadata"):
            with self.subTest(mode=mode):
                shutil.rmtree(self.output, ignore_errors=True)
                self.fake(mode=mode)
                result = self.invoke()
                assert result.returncode != 0, result.stdout
                assert "compiled metadata" in result.stdout
                assert "Traceback" not in result.stderr, result.stderr
                assert not (self.output / "gate.json").exists()
                assert self.replay().returncode != 0
                gate = str(self.output / "gate.json")
                assert self.check_citations("--gate", gate).returncode != 0

    def test_rebinding_records_after_deleting_metadata_is_rejected(self) -> None:
        # an accurate manifest of the remaining files is not enough.
        self.write_matrix()
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        (run_dir / "requests/01/kani-metadata.json").unlink()
        self.rebind(run_dir)
        replay = self.replay()
        assert replay.returncode != 0
        assert "kani-metadata.json" in replay.stdout + replay.stderr
        assert self.check_citations("--gate", str(self.output / "gate.json")).returncode != 0

    def test_altered_proof_details_are_rejected(self) -> None:
        # the retained report must equal the reconstruction in every detail,
        # not only in status and reasons.
        self.write_matrix()
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        result_path = run_dir / "requests/01/result.json"
        evaluation_path = run_dir / "evaluation.json"
        gate_path = self.output / "gate.json"
        kept = {p: p.read_bytes() for p in (result_path, evaluation_path, gate_path)}
        for label, mutate in (
            ("property status", lambda r: r["properties"][0].__setitem__("status", "FAILURE")),
            (
                "effective unwind",
                lambda r: r["compiled"]["effective"].__setitem__("unwind", 999999),
            ),
            ("metadata digest", lambda r: r.__setitem__("metadata_sha256", "0" * 64)),
            (
                "callee notes",
                lambda r: r.__setitem__("callee_unreachable", [{"id": "x", "description": "y"}]),
            ),
            ("extra field", lambda r: r.__setitem__("audited", True)),
        ):
            with self.subTest(label=label):
                record = json.loads(kept[result_path])
                mutate(record)
                result_path.write_text(json.dumps(record, indent=2) + "\n")
                evaluation = json.loads(kept[evaluation_path])
                evaluation["results"][0] = {**record, "request_dir": "requests/01"}
                evaluation_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n")
                self.rebind(run_dir)
                replay = self.replay()
                assert replay.returncode != 0, label
                assert "disagrees" in replay.stdout + replay.stderr, replay.stdout
                assert self.check_citations("--gate", str(gate_path)).returncode != 0
                for path, data in kept.items():
                    path.write_bytes(data)
        assert self.replay().returncode == 0

    def test_attribute_mutations_are_rejected_at_every_entry_point(self) -> None:
        # the runner, the replay and the checker reject metadata whose
        # attributes do not have Kani's types, without any post-hoc record edit.
        self.write_matrix()
        gate = str(self.output / "gate.json")
        for label, overrides in (
            ("kind null", {"attributes": {"kind": None}}),
            ("kind number", {"attributes": {"kind": 123}}),
            ("kind Test", {"attributes": {"kind": "Test"}}),
            ("solver number", {"attributes": {"solver": 123}}),
            ("unwind string", {"attributes": {"unwind_value": "invalid"}}),
            ("unwind bool", {"attributes": {"unwind_value": False}}),
            ("unwind negative", {"attributes": {"unwind_value": -1}}),
            ("mangled empty", {"proof": {"mangled_name": ""}}),
            ("line negative", {"proof": {"original_start_line": -1}}),
        ):
            with self.subTest(label=label):
                shutil.rmtree(self.output, ignore_errors=True)
                self.fake(overrides=overrides)
                result = self.invoke()
                assert result.returncode != 0, label
                assert not (self.output / "gate.json").exists()
                assert "Traceback" not in result.stderr, result.stderr
                assert self.replay().returncode != 0
                assert self.check_citations("--gate", gate).returncode != 0
        shutil.rmtree(self.output, ignore_errors=True)
        self.fake(discovery_overrides={"attributes": {"kind": None}})
        result = self.invoke()
        assert result.returncode != 0
        assert self.admissions(result.stdout)[-1]["status"] == "fault"
        assert not (self.output / "gate.json").exists()
        # unwind 0 is a valid attribute and is preserved as the effective value.
        shutil.rmtree(self.output, ignore_errors=True)
        self.fake(overrides={"attributes": {"unwind_value": 0}})
        result = self.invoke()
        assert result.returncode == 0, result.stdout
        run_dir = max(self.output.glob("run-*"))
        record = json.loads((run_dir / "requests/01/result.json").read_text())
        assert record["compiled"]["effective"]["unwind"] == 0
        assert self.replay().returncode == 0

    def test_discovery_records_are_reconstructed_on_replay(self) -> None:
        # the raw discovery metadata and the discovery summary are part of
        # the reconstruction, not only present-and-hashed.
        self.write_matrix()
        assert self.invoke().returncode == 0
        run_dir = max(self.output.glob("run-*"))
        gate = str(self.output / "gate.json")
        raw = run_dir / "groups/alpha/discovery.kani-metadata.json"
        summary = run_dir / "groups/alpha/discovery.json"
        kept = {
            p: p.read_bytes()
            for p in (raw, summary, run_dir / "evaluation.json", self.output / "gate.json")
        }

        def mutate_raw(text: str) -> None:
            raw.write_text(text)

        def mutate_summary(**values: Any) -> None:
            record = json.loads(kept[summary])
            record.update(values)
            summary.write_text(json.dumps(record, indent=2) + "\n")

        emptied = json.loads(kept[raw])
        emptied["proof_harnesses"] = []
        rekinded = json.loads(kept[raw])
        rekinded["proof_harnesses"][0]["attributes"]["kind"] = "Test"
        altered_map = json.loads(kept[summary])["harnesses"]
        for label, action in (
            ("raw null", lambda: mutate_raw("null\n")),
            ("raw invalid json", lambda: mutate_raw("{broken\n")),
            ("raw empty proofs", lambda: mutate_raw(json.dumps(emptied))),
            ("raw kind changed", lambda: mutate_raw(json.dumps(rekinded))),
            ("summary exit 13", lambda: mutate_summary(exit_code=13)),
            ("summary digest", lambda: mutate_summary(metadata_sha256="0" * 64)),
            (
                "summary harness file",
                lambda: mutate_summary(
                    harnesses={
                        **altered_map,
                        "proofs::one": {
                            **altered_map["proofs::one"],
                            "file": "crates/alpha-pkg/src/other.rs",
                        },
                    }
                ),
            ),
        ):
            with self.subTest(label=label):
                action()
                self.rebind(run_dir)
                replay = self.replay()
                assert replay.returncode != 0, label
                assert "Traceback" not in replay.stderr, replay.stderr
                assert "discovery" in replay.stdout + replay.stderr, replay.stdout
                assert self.check_citations("--gate", gate).returncode != 0
                for path, data in kept.items():
                    path.write_bytes(data)
        assert self.replay().returncode == 0

    def test_discovery_fault_of_a_diagnostic_group_blocks_every_scope(self) -> None:
        # a runner fault is not a mathematical diagnostic failure.
        self.fake(mode="crash-discovery", crash_package="beta-pkg")
        result = self.invoke()
        assert result.returncode != 0, result.stdout
        assert not (self.output / "gate.json").exists()
        summary = self.admissions(result.stdout)[-1]
        assert summary["gate"] is False
        assert summary["status"] == "fault"
        assert summary["counts"]["faults"] == 1
        assert "discovery compilation failed with exit 13" in result.stdout
        replay = self.replay()
        assert replay.returncode != 0
        assert "fault" in replay.stdout + replay.stderr
        shutil.rmtree(self.output)
        assert self.invoke("--scope", "diagnostic").returncode != 0
        shutil.rmtree(self.output)
        self.fake(mode="fail")  # a mathematical diagnostic failure stays non-blocking
        result = self.invoke()
        assert result.returncode == 0, result.stdout
        assert (self.output / "gate.json").exists()

    def test_baseline_comparison_is_report_only(self) -> None:
        assert self.invoke().returncode == 0
        first = max(self.output.glob("run-*")) / "evaluation.json"
        assert json.loads(first.read_text())["baseline"] == "none"
        baseline = self.root / "baseline.json"
        shutil.copy(first, baseline)
        shutil.rmtree(self.output)
        result = self.invoke("--baseline", str(baseline))
        assert result.returncode == 0, result.stdout
        run_dir = max(self.output.glob("run-*"))
        evaluation = json.loads((run_dir / "evaluation.json").read_text())
        assert evaluation["baseline"]["sha256"] == sha256(baseline)
        diff = json.loads((run_dir / "unreachable_diff.json").read_text())
        assert diff["baseline_sha256"] == sha256(baseline)
        assert all(entry["changes"] == [] for entry in diff["requests"]), diff

    def test_baseline_differences_and_new_context_are_reported(self) -> None:
        assert self.invoke().returncode == 0
        baseline = self.root / "baseline.json"
        shutil.copy(max(self.output.glob("run-*")) / "evaluation.json", baseline)
        record = json.loads(baseline.read_text())
        record["results"][0]["properties"][0]["status"] = "UNREACHABLE"
        record["results"][1]["properties"].append(
            {"id": "proofs::two.assertion.9", "status": "SUCCESS", "description": "x"}
        )
        baseline.write_text(json.dumps(record, indent=2) + "\n")
        shutil.rmtree(self.output)
        result = self.invoke("--baseline", str(baseline))
        assert result.returncode == 0, result.stdout  # report-only: the gate is unchanged
        assert (self.output / "gate.json").exists()
        run_dir = max(self.output.glob("run-*"))
        diff = json.loads((run_dir / "unreachable_diff.json").read_text())
        kinds = {c["kind"] for entry in diff["requests"] for c in entry["changes"]}
        assert {"status", "removed"} <= kinds, diff
        record["tools"]["reported_version"] = "cargo-kani 0.65.0"
        baseline.write_text(json.dumps(record, indent=2) + "\n")
        shutil.rmtree(self.output)
        assert self.invoke("--baseline", str(baseline)).returncode == 0
        run_dir = max(self.output.glob("run-*"))
        diff = json.loads((run_dir / "unreachable_diff.json").read_text())
        assert all(entry["context"] == "new context" for entry in diff["requests"]), diff

    def test_summary_prefers_the_gate_run_then_the_latest_start(self) -> None:
        assert self.invoke().returncode == 0
        gate_run = json.loads((self.output / "gate.json").read_text())["run"]
        older = self.output / "run-zzzzzzzz"  # lexically last, but older and without a gate
        shutil.copytree(self.output / gate_run, older)
        evaluation = json.loads((older / "evaluation.json").read_text())
        evaluation.update(
            {"scope": "partial", "status": "recorded", "started_at": "2000-01-01T00:00:00Z"}
        )
        (older / "evaluation.json").write_text(json.dumps(evaluation, indent=2) + "\n")

        def summary() -> str:
            return subprocess.run(  # noqa: S603 - fixed script and fixture paths
                [
                    sys.executable,
                    str(ROOT / "scripts/validation/summarize_kani_evidence.py"),
                    str(self.output),
                ],
                env=self.env,
                capture_output=True,
                text=True,
                check=False,
            ).stdout

        assert f"run: {gate_run}" in summary()
        (self.output / "gate.json").unlink()
        assert f"run: {gate_run}" in summary()  # latest started_at wins without a gate
        (older / "evaluation.json").write_text(
            json.dumps({**evaluation, "started_at": "2999-01-01T00:00:00Z"}, indent=2) + "\n"
        )
        assert "run: run-zzzzzzzz" in summary()


if __name__ == "__main__":
    unittest.main()
