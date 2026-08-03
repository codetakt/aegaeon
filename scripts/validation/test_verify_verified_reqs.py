"""Regression tests for grounded VerifiedReqs proof references."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import verify_verified_reqs

if TYPE_CHECKING:
    import pathlib
    from typing import Any


def _write(root: pathlib.Path, relative: str, content: str = "") -> pathlib.Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _entry(
    proof: list[dict[str, Any]],
    module: str = "crates/example/src/lib.rs",
    runtime_link: str = "crates/example/src/runtime.rs",
    trace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "fixture-001",
        "requirement": "MUST",
        "module": module,
        "proof": proof,
        "runtime_link": runtime_link,
        "status": "verified",
    }
    if trace is not None:
        entry["trace"] = trace
    return entry


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    _write(tmp_path, "crates/example/src/runtime.rs", "pub fn runtime() {}\n")
    return tmp_path


def _validate(
    repo: pathlib.Path,
    entry: dict[str, Any],
    model_fidelity: dict[str, str] | None = None,
    require_trace_must: bool = False,
) -> tuple[verify_verified_reqs.Stats, dict[str, Any]]:
    stats = verify_verified_reqs.Stats()
    validator = verify_verified_reqs.GroundingValidator(repo, model_fidelity)
    verify_verified_reqs.check_entry(
        "draft_fixture",
        entry,
        stats,
        validator,
        verbose=False,
        require_trace_must=require_trace_must,
    )
    return stats, stats.entries[0]


def test_fstar_missing_invariant_fails(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet present = true\n")
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "missing"}],
            module="fstar/Fixture.fst",
        ),
    )

    assert result["verdict"] == "fail"
    assert result["blocks"][0]["result"] == "ungrounded"
    assert "'missing' not defined" in result["blocks"][0]["reason"]


def test_fstar_existing_let_passes(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    _, result = _validate(
        repo,
        _entry([{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "grounded"}]),
    )

    assert result["verdict"] == "pass"
    assert result["blocks"][0]["result"] == "grounded"


def test_fstar_noeq_type_declaration_grounds(repo: pathlib.Path) -> None:
    _write(
        repo,
        "fstar/Fixture.fst",
        "module Fixture\nnoeq type revocation_request = {\n  token: nat;\n}\n",
    )
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "revocation_request"}],
        ),
    )

    assert result["verdict"] == "pass"
    assert result["blocks"][0]["result"] == "grounded"


def test_tamarin_all_comma_separated_lemmas_must_exist(repo: pathlib.Path) -> None:
    _write(repo, "proofs/tamarin/fixture.spthy", "theory Fixture\nlemma a:\n  exists-trace\nend\n")
    _, result = _validate(
        repo,
        _entry(
            [
                {
                    "type": "tamarin",
                    "file": "proofs/tamarin/fixture.spthy",
                    "lemma": "a, b",
                }
            ]
        ),
    )

    assert result["verdict"] == "fail"
    assert "'b' not defined" in result["blocks"][0]["reason"]


@pytest.mark.parametrize(
    ("attribute", "verdict"),
    [
        ("#[kani::proof]", "pass"),
        ("#[proof]", "pass"),
        ("#[cfg_attr(kani, kani::proof)]", "pass"),
        ("#[test]", "fail"),
    ],
)
def test_kani_harness_requires_proof_attribute(
    repo: pathlib.Path,
    attribute: str,
    verdict: str,
) -> None:
    _write(
        repo,
        "crates/example/src/kani.rs",
        f"{attribute}\n#[kani::unwind(4)]\nfn proof_fixture() {{}}\n",
    )
    _, result = _validate(repo, _entry([{"type": "kani", "harness": "proof_fixture"}]))

    assert result["verdict"] == verdict


def test_non_formal_evidence_cannot_verify_entry(repo: pathlib.Path) -> None:
    _, result = _validate(repo, _entry([{"type": "policy", "rule": "fixture_policy"}]))

    assert result["verdict"] == "fail"
    assert result["blocks"] == []
    assert result["reasons"] == ["no formal proof type (found: policy)"]


def test_fstar_qualified_comma_separated_identifiers_pass(repo: pathlib.Path) -> None:
    _write(
        repo,
        "fstar/Fixture.fst",
        "module Fixture\n"
        "[@ inline] irreducible val first: unit\n"
        "noextract let rec second () = ()\n",
    )
    _, result = _validate(
        repo,
        _entry(
            [
                {
                    "type": "fstar",
                    "file": "fstar/Fixture.fst",
                    "lemma": "Fixture.first, Other.Module.second",
                }
            ]
        ),
    )

    assert result["verdict"] == "pass"
    assert "first, second" in result["blocks"][0]["reason"]


def test_all_formal_blocks_must_be_grounded(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    _, result = _validate(
        repo,
        _entry(
            [
                {
                    "type": "fstar",
                    "file": "fstar/Fixture.fst",
                    "invariant": "grounded",
                },
                {
                    "type": "fstar",
                    "file": "fstar/Fixture.fst",
                    "invariant": "floating_label",
                },
            ],
        ),
    )

    assert result["verdict"] == "fail"
    assert result["blocks"][0]["result"] == "grounded"
    assert result["blocks"][1]["result"] == "ungrounded"
    assert result["reasons"][0].startswith("ungrounded formal proof block")


def test_all_grounded_formal_blocks_pass(repo: pathlib.Path) -> None:
    _write(
        repo,
        "fstar/Fixture.fst",
        "module Fixture\nlet first = true\nlet second = true\n",
    )
    _write(
        repo,
        "proofs/tamarin/fixture.spthy",
        "theory Fixture\nlemma linked:\n  exists-trace\nend\n",
    )
    _, result = _validate(
        repo,
        _entry(
            [
                {
                    "type": "fstar",
                    "file": "fstar/Fixture.fst",
                    "invariant": "first, second",
                },
                {
                    "type": "tamarin",
                    "file": "proofs/tamarin/fixture.spthy",
                    "lemma": "linked",
                },
            ],
        ),
    )

    assert result["verdict"] == "pass"
    assert all(block["result"] == "grounded" for block in result["blocks"])


def test_runtime_link_symbol_definition_passes(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    _write(repo, "crates/example/src/runtime.rs", "pub(crate) async fn runtime_symbol() {}\n")
    stats, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "grounded"}],
            runtime_link="crates/example/src/runtime.rs#runtime_symbol",
        ),
    )

    assert result["verdict"] == "pass"
    assert stats.runtime_linked == 1
    assert stats.runtime_symbol_linked == 1


def test_runtime_link_missing_symbol_fails(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    stats, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "grounded"}],
            runtime_link="crates/example/src/runtime.rs#missing_symbol",
        ),
    )

    assert result["verdict"] == "fail"
    assert stats.runtime_linked == 0
    assert stats.runtime_symbol_linked == 0
    assert result["reasons"] == [
        "runtime_link symbol not found: crates/example/src/runtime.rs#missing_symbol"
    ]


def test_runtime_link_file_only_form_remains_compatible(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    stats, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "grounded"}],
            runtime_link="crates/example/src/runtime.rs",
        ),
    )

    assert result["verdict"] == "pass"
    assert stats.runtime_linked == 1
    assert stats.runtime_symbol_linked == 0


def test_oracle_refinement_trace_passes(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet spec_fn = true\n")
    _write(repo, "crates/example/src/runtime.rs", "pub fn runtime_symbol() {}\n")
    _write(repo, "tests/spec_oracle_test.rs", "#[test]\nfn oracle() {}\n")
    stats, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "spec_fn"}],
            trace={
                "kind": "oracle",
                "fstar": "fstar/Fixture.fst#spec_fn",
                "rust": "crates/example/src/runtime.rs#runtime_symbol",
                "test": "tests/spec_oracle_test.rs",
            },
        ),
    )

    assert result["verdict"] == "pass"
    assert result["trace"]["result"] == "grounded"
    assert stats.trace_counts["oracle"] == 1
    assert stats.must_verified_total == 1


def test_refinement_trace_missing_rust_symbol_fails(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet spec_fn = true\n")
    _write(repo, "tests/spec_oracle_test.rs", "#[test]\nfn oracle() {}\n")
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "spec_fn"}],
            trace={
                "kind": "oracle",
                "fstar": "fstar/Fixture.fst#spec_fn",
                "rust": "crates/example/src/runtime.rs#missing_symbol",
                "test": "tests/spec_oracle_test.rs",
            },
        ),
    )

    assert result["verdict"] == "fail"
    assert result["trace"]["result"] == "invalid"
    assert "trace rust symbol not found" in result["reasons"][0]


def test_refinement_trace_missing_fstar_identifier_fails(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet spec_fn = true\n")
    _write(repo, "tests/spec_oracle_test.rs", "#[test]\nfn oracle() {}\n")
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "spec_fn"}],
            trace={
                "kind": "oracle",
                "fstar": "fstar/Fixture.fst#missing_spec",
                "rust": "crates/example/src/runtime.rs#runtime",
                "test": "tests/spec_oracle_test.rs",
            },
        ),
    )

    assert result["verdict"] == "fail"
    assert result["trace"]["result"] == "invalid"
    assert "trace fstar identifier not found" in result["reasons"][0]


def test_exempt_refinement_trace_requires_note(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet spec_fn = true\n")
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "spec_fn"}],
            trace={"kind": "exempt"},
        ),
    )

    assert result["verdict"] == "fail"
    assert result["trace"]["result"] == "invalid"
    assert result["reasons"] == ["trace exempt requires non-empty note"]


def test_require_trace_must_detects_missing_trace(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet spec_fn = true\n")
    _, result = _validate(
        repo,
        _entry([{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "spec_fn"}]),
        require_trace_must=True,
    )

    assert result["verdict"] == "fail"
    assert result["trace"]["result"] == "missing"
    assert result["reasons"] == ["missing refinement trace for MUST-level verified entry"]


def test_toy_stub_fstar_module_cannot_ground_verified_entry(repo: pathlib.Path) -> None:
    _write(repo, "fstar/Fixture.fst", "module Fixture\nlet grounded = true\n")
    _, result = _validate(
        repo,
        _entry(
            [{"type": "fstar", "file": "fstar/Fixture.fst", "invariant": "grounded"}],
        ),
        model_fidelity={"fstar/Fixture.fst": "toy-stub"},
    )

    assert result["verdict"] == "fail"
    assert result["blocks"][0]["result"] == "ungrounded"
    assert "classified toy-stub" in result["blocks"][0]["reason"]
