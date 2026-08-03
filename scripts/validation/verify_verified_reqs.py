#!/usr/bin/env python3
"""Verify that every ``status: verified`` row has grounded formal evidence.

A verified requirement must have a runtime link and at least one formal proof
block that resolves to a concrete, type-appropriate verification artefact. Every
formal block must be grounded; an ungrounded sibling block fails the entry.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from proof_classification import compute_proof_quality, compute_strength

MATRIX_FILE = pathlib.Path("spec/compliance-matrix.yaml")
MODEL_FIDELITY_FILE = pathlib.Path("docs/verification/claims/model-fidelity.yaml")
FORMAL_TYPES = {"fstar", "tamarin", "kani", "everparse", "lowstar", "hacl"}
MODEL_FIDELITY_CLASSES = {"faithful", "simplified", "toy-stub"}
FSTAR_TYPES = {"fstar", "lowstar"}
TRACE_KINDS = ("oracle", "structural", "guard", "exempt")
TRACE_TEST_REQUIRED_KINDS = {"oracle", "guard"}
MUST_REQUIREMENTS = {"MUST", "MUST NOT"}
LABEL_FIELDS = (
    "invariant",
    "refinement",
    "lemma",
    "harness",
    "primitive",
    "schema",
    "constant_time",
    "computation",
    "policy",
    "property",
    "parser",
    "entropy",
    "exhaustiveness",
    "exhaustive",
    "welltyped",
    "capability",
)
FSTAR_IDENTIFIER_FIELDS = tuple(
    field for field in LABEL_FIELDS if field not in {"harness", "primitive", "constant_time"}
)
HACL_INTEGRATION_FILES = (
    pathlib.Path("fstar/crypto/Verified.Crypto.Bridge.fst"),
    pathlib.Path("fstar/verifiedcore/api/VerifiedCore.Crypto.Hacl.fst"),
    pathlib.Path("c/verified-core/hacl_bridge.c"),
    pathlib.Path("c/jws.c"),
)

FSTAR_DEFINITION_TEMPLATE = (
    r"^\s*(?:\[@.*\]\s*)?"
    r"(?:(?:irreducible|noextract|inline_for_extraction|noeq|unopteq|private|unfold)\s+)*"
    r"(?:let(?:\s+rec)?|val|type|assume\s+val)\s+{name}\b"
)
TAMARIN_LEMMA_TEMPLATE = r"^\s*lemma\s+{name}\b"
# Accepts `#[kani::proof]`, the imported form `#[proof]` (via `use kani::proof`),
# and `#[cfg_attr(kani, kani::proof)]`.
KANI_HARNESS_TEMPLATE = (
    r"#\[(?:kani::proof|proof|cfg_attr\(kani,\s*kani::proof\))\]"
    r"(?:\s*#\[[^\]]+\])*\s*"
    r"(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+{name}\b"
)
RUST_SYMBOL_TEMPLATE = (
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?"
    r"(?:fn|struct|enum|trait|type|static|const)\s+{name}\b"
)


def _split_identifiers(raw: str) -> list[str]:
    """Split comma-separated identifiers and remove module qualification."""
    identifiers = []
    for raw_value in raw.split(","):
        value = raw_value.strip()
        if value:
            identifiers.append(value.rsplit(".", 1)[-1].rsplit("::", 1)[-1])
    return identifiers


def _labels(proof: dict[str, Any]) -> dict[str, str]:
    return {key: value for key in LABEL_FIELDS if isinstance((value := proof.get(key)), str)}


class GroundingValidator:
    """Resolve formal proof blocks relative to one repository root."""

    def __init__(
        self,
        repo_root: pathlib.Path,
        model_fidelity: dict[str, str] | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.model_fidelity = model_fidelity or {}
        self._file_cache: dict[pathlib.Path, str | None] = {}

    def resolve_path(self, raw: str) -> pathlib.Path:
        path = pathlib.Path(raw)
        if not path.is_absolute():
            path = self.repo_root / path
        return path.resolve()

    def _relative(self, path: pathlib.Path) -> str:
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)

    def _read(self, path: pathlib.Path) -> str | None:
        if path not in self._file_cache:
            try:
                self._file_cache[path] = path.read_text(errors="replace")
            except OSError:
                self._file_cache[path] = None
        return self._file_cache[path]

    def _under(self, path: pathlib.Path, directory: str) -> bool:
        try:
            path.relative_to(self.repo_root / directory)
        except ValueError:
            return False
        return True

    def _rust_symbol_link_result(
        self,
        raw: str,
        *,
        field_name: str,
    ) -> tuple[bool, bool, str | None]:
        if raw.count("#") != 1:
            return False, False, f"{field_name} must use <path>#<symbol>: {raw}"
        path_raw, _, symbol = raw.partition("#")
        path = self.resolve_path(path_raw)
        if not path.is_file():
            return False, False, f"{field_name} file not found: {raw}"
        if not symbol:
            return False, False, f"{field_name} symbol missing: {raw}"

        text = self._read(path)
        if text is None:
            return False, False, f"{field_name} file not readable: {path_raw}"
        pattern = RUST_SYMBOL_TEMPLATE.format(name=re.escape(symbol))
        if re.search(pattern, text, flags=re.MULTILINE) is None:
            return False, False, f"{field_name} symbol not found: {raw}"
        return True, True, None

    def runtime_link_result(self, raw: str) -> tuple[bool, bool, str | None]:
        if "#" not in raw:
            path = self.resolve_path(raw)
            if not path.is_file():
                return False, False, f"runtime_link file not found: {raw}"
            return True, False, None
        return self._rust_symbol_link_result(raw, field_name="runtime_link")

    def _fstar_symbol_link_result(self, raw: str) -> tuple[bool, str | None]:
        if raw.count("#") != 1:
            return False, f"trace fstar must use <file>#<identifier>: {raw}"
        raw_file, _, identifier = raw.partition("#")
        if not raw_file or not identifier:
            return False, f"trace fstar must use <file>#<identifier>: {raw}"
        path = self.resolve_path(raw_file)
        if path.suffix not in {".fst", ".fsti"}:
            return False, f"trace fstar file must be .fst/.fsti: {raw}"
        text = self._read(path)
        if text is None:
            return False, f"trace fstar file not found: {raw_file}"
        pattern = FSTAR_DEFINITION_TEMPLATE.format(name=re.escape(identifier))
        if re.search(pattern, text, flags=re.MULTILINE) is None:
            return False, f"trace fstar identifier not found: {raw}"
        return True, None

    def trace_result(self, trace: Any) -> tuple[dict[str, Any], list[str]]:
        if trace is None:
            return {"present": False, "result": "missing"}, []
        if not isinstance(trace, dict):
            return {"present": True, "result": "invalid", "reason": "trace must be a mapping"}, [
                "trace must be a mapping"
            ]

        kind = trace.get("kind")
        result: dict[str, Any] = {
            "present": True,
            "kind": kind,
            "result": "grounded",
        }
        errors: list[str] = []
        if kind not in TRACE_KINDS:
            errors.append(f"trace kind must be one of {', '.join(TRACE_KINDS)}")
            result["result"] = "invalid"
            result["reason"] = "; ".join(errors)
            return result, errors

        if kind == "exempt":
            note = trace.get("note")
            if not isinstance(note, str) or not note.strip():
                errors.append("trace exempt requires non-empty note")
            result["note"] = note
            if errors:
                result["result"] = "invalid"
                result["reason"] = "; ".join(errors)
            return result, errors

        fstar = trace.get("fstar")
        if not isinstance(fstar, str):
            errors.append("trace fstar is required")
        else:
            fstar_ok, fstar_error = self._fstar_symbol_link_result(fstar)
            if fstar_ok:
                result["fstar"] = fstar
            elif fstar_error is not None:
                errors.append(fstar_error)

        rust = trace.get("rust")
        if not isinstance(rust, str):
            errors.append("trace rust is required")
        else:
            rust_ok, _, rust_error = self._rust_symbol_link_result(rust, field_name="trace rust")
            if rust_ok:
                result["rust"] = rust
            elif rust_error is not None:
                errors.append(rust_error)

        test = trace.get("test")
        if not isinstance(test, str):
            if kind in TRACE_TEST_REQUIRED_KINDS:
                errors.append(f"trace {kind} requires test")
        else:
            test_path = self.resolve_path(test)
            if test_path.is_file():
                result["test"] = test
            else:
                errors.append(f"trace test file not found: {test}")

        if errors:
            result["result"] = "invalid"
            result["reason"] = "; ".join(errors)
        return result, errors

    def _result(
        self,
        proof: dict[str, Any],
        grounded: bool,
        reason: str,
        resolved_file: pathlib.Path | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": proof.get("type"),
            "labels": _labels(proof),
            "file": proof.get("file"),
            "result": "grounded" if grounded else "ungrounded",
            "reason": reason,
        }
        if resolved_file is not None:
            result["resolved_file"] = self._relative(resolved_file)
        return result

    def ground(self, entry: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
        proof_type = proof.get("type")
        if proof_type in FSTAR_TYPES:
            return self._ground_fstar(entry, proof)
        if proof_type == "tamarin":
            return self._ground_tamarin(proof)
        if proof_type == "kani":
            return self._ground_kani(proof)
        if proof_type == "everparse":
            return self._ground_everparse(proof)
        if proof_type == "hacl":
            return self._ground_hacl(proof)
        return self._result(proof, False, f"unsupported formal proof type: {proof_type!r}")

    def _ground_fstar(
        self,
        entry: dict[str, Any],
        proof: dict[str, Any],
    ) -> dict[str, Any]:
        raw_file = proof.get("file")
        used_module = False
        if not isinstance(raw_file, str):
            module = entry.get("module")
            if isinstance(module, str) and pathlib.Path(module).suffix in {".fst", ".fsti"}:
                raw_file = module
                used_module = True
            else:
                return self._result(
                    proof,
                    False,
                    "file is required; entry module is not an F* file",
                )

        path = self.resolve_path(raw_file)
        allowed = self._under(path, "fstar") or self._under(path, "generated/lowstar")
        if path.suffix not in {".fst", ".fsti"} or not allowed:
            return self._result(
                proof,
                False,
                "F* evidence must be an .fst/.fsti file under fstar/ or generated/lowstar/",
                path,
            )
        text = self._read(path)
        if text is None:
            return self._result(proof, False, f"F* file not found: {raw_file}", path)
        rel_path = self._relative(path)
        if self.model_fidelity.get(rel_path) == "toy-stub":
            return self._result(
                proof,
                False,
                f"F* model is classified toy-stub in {MODEL_FIDELITY_FILE}",
                path,
            )

        missing: list[str] = []
        specified: list[str] = []
        for field in FSTAR_IDENTIFIER_FIELDS:
            raw = proof.get(field)
            if not isinstance(raw, str):
                continue
            for identifier in _split_identifiers(raw):
                specified.append(identifier)
                pattern = FSTAR_DEFINITION_TEMPLATE.format(name=re.escape(identifier))
                if re.search(pattern, text, flags=re.MULTILINE) is None:
                    missing.append(identifier)

        if missing:
            names = ", ".join(repr(name) for name in missing)
            return self._result(
                proof,
                False,
                f"identifier(s) {names} not defined in {raw_file}",
                path,
            )
        source = "entry module" if used_module else "file"
        detail = f"; identifiers grounded: {', '.join(specified)}" if specified else ""
        return self._result(proof, True, f"grounded by {source} {raw_file}{detail}", path)

    def _ground_tamarin(self, proof: dict[str, Any]) -> dict[str, Any]:
        raw_file = proof.get("file")
        raw_lemma = proof.get("lemma")
        if not isinstance(raw_file, str):
            return self._result(proof, False, "file is required for Tamarin evidence")
        path = self.resolve_path(raw_file)
        if path.suffix != ".spthy":
            return self._result(proof, False, "Tamarin file must use the .spthy suffix", path)
        text = self._read(path)
        if text is None:
            return self._result(proof, False, f"Tamarin file not found: {raw_file}", path)
        if not isinstance(raw_lemma, str) or not _split_identifiers(raw_lemma):
            return self._result(proof, False, "lemma is required for Tamarin evidence", path)

        missing = []
        for lemma in _split_identifiers(raw_lemma):
            pattern = TAMARIN_LEMMA_TEMPLATE.format(name=re.escape(lemma))
            if re.search(pattern, text, flags=re.MULTILINE) is None:
                missing.append(lemma)
        if missing:
            names = ", ".join(repr(name) for name in missing)
            return self._result(
                proof,
                False,
                f"Tamarin lemma(s) {names} not defined in {raw_file}",
                path,
            )
        return self._result(proof, True, f"all Tamarin lemmas grounded in {raw_file}", path)

    def _kani_candidates(self, raw_file: str | None) -> tuple[list[pathlib.Path], str | None]:
        if raw_file is not None:
            path = self.resolve_path(raw_file)
            if self._read(path) is None:
                return [], f"Kani file not found: {raw_file}"
            if path.suffix != ".rs":
                return [], "Kani evidence file must use the .rs suffix"
            return [path], None

        candidates = list((self.repo_root / "crates/kani-harness").glob("**/*.rs"))
        candidates.extend((self.repo_root / "crates").glob("*/src/**/*.rs"))
        return sorted({path.resolve() for path in candidates}), None

    def _ground_kani(self, proof: dict[str, Any]) -> dict[str, Any]:
        raw_file = proof.get("file") if isinstance(proof.get("file"), str) else None
        raw_harness = proof.get("harness")
        if raw_file is None and not isinstance(raw_harness, str):
            return self._result(proof, False, "file or harness is required for Kani evidence")

        candidates, error = self._kani_candidates(raw_file)
        resolved = candidates[0] if raw_file is not None and candidates else None
        if error is not None:
            return self._result(proof, False, error, resolved)
        if not isinstance(raw_harness, str):
            return self._result(proof, True, f"Kani evidence file exists: {raw_file}", resolved)

        missing = []
        found_paths: set[pathlib.Path] = set()
        for harness in _split_identifiers(raw_harness):
            pattern = KANI_HARNESS_TEMPLATE.format(name=re.escape(harness))
            matches = [
                path
                for path in candidates
                if (text := self._read(path)) is not None
                and re.search(pattern, text, flags=re.MULTILINE) is not None
            ]
            if matches:
                found_paths.update(matches)
            else:
                missing.append(harness)
        if missing:
            names = ", ".join(repr(name) for name in missing)
            scope = raw_file or "crates/kani-harness/ and crates/*/src/"
            return self._result(
                proof,
                False,
                f"#[kani::proof] harness(es) {names} not defined in {scope}",
                resolved,
            )
        locations = ", ".join(sorted(self._relative(path) for path in found_paths))
        return self._result(proof, True, f"Kani harness grounded in {locations}", resolved)

    def _ground_everparse(self, proof: dict[str, Any]) -> dict[str, Any]:
        candidates = [
            value for key in ("spec", "file") if isinstance((value := proof.get(key)), str)
        ]
        failures = []
        for raw_file in candidates:
            path = self.resolve_path(raw_file)
            if self._read(path) is None:
                failures.append(f"not found: {raw_file}")
                continue
            if path.suffix == ".3d":
                base = path.stem
                generated = self.repo_root / "generated/everparse"
                outputs = (generated / f"{base}.c", generated / f"{base}Wrapper.c")
                existing = next((output for output in outputs if output.is_file()), None)
                if existing is None:
                    failures.append(f"no generated {base}.c or {base}Wrapper.c for {raw_file}")
                    continue
                return self._result(
                    proof,
                    True,
                    f"EverParse schema and generated validator exist: {raw_file}, "
                    f"{self._relative(existing)}",
                    path,
                )
            if path.suffix == ".c" and self._under(path, "generated/everparse"):
                return self._result(
                    proof,
                    True,
                    f"generated EverParse validator exists: {raw_file}",
                    path,
                )
            failures.append(f"not an EverParse .3d or generated validator C file: {raw_file}")
        reason = "; ".join(failures) if failures else "spec or file is required"
        return self._result(proof, False, f"EverParse evidence ungrounded: {reason}")

    def _ground_hacl(self, proof: dict[str, Any]) -> dict[str, Any]:
        raw_file = proof.get("file")
        if isinstance(raw_file, str):
            path = self.resolve_path(raw_file)
            if self._read(path) is None:
                return self._result(
                    proof,
                    False,
                    f"HACL integration file not found: {raw_file}",
                    path,
                )
            return self._result(proof, True, f"HACL integration file exists: {raw_file}", path)

        primitive = proof.get("primitive")
        if not isinstance(primitive, str) or not _split_identifiers(primitive):
            return self._result(proof, False, "file or primitive is required for HACL evidence")
        integration_texts = {
            path: text
            for relative in HACL_INTEGRATION_FILES
            if (text := self._read(path := self.resolve_path(str(relative)))) is not None
        }
        missing = []
        locations: set[pathlib.Path] = set()
        for name in _split_identifiers(primitive):
            matches = [
                path
                for path, text in integration_texts.items()
                if re.search(rf"\b{re.escape(name)}\b", text) is not None
            ]
            if matches:
                locations.update(matches)
            else:
                missing.append(name)
        if missing:
            names = ", ".join(repr(name) for name in missing)
            return self._result(
                proof,
                False,
                f"HACL primitive(s) {names} not found in integration modules",
            )
        files = ", ".join(sorted(self._relative(path) for path in locations))
        return self._result(proof, True, f"HACL primitive grounded in {files}")


class Stats:
    def __init__(self) -> None:
        self.checked = 0
        self.passed = 0
        self.errors: list[str] = []
        self.quality_counts: dict[str, int] = {"formal": 0, "empirical": 0, "unknown": 0}
        self.strength_counts: dict[str, int] = {"lemma": 0, "refinement": 0, "semantic": 0}
        self.runtime_linked = 0
        self.runtime_symbol_linked = 0
        self.trace_counts: dict[str, int] = dict.fromkeys(TRACE_KINDS, 0)
        self.must_verified_total = 0
        self.entries: list[dict[str, Any]] = []


def load_model_fidelity_registry(repo_root: pathlib.Path) -> tuple[dict[str, str], list[str]]:
    path = repo_root / MODEL_FIDELITY_FILE
    if not path.exists():
        return {}, [f"{MODEL_FIDELITY_FILE}: missing model fidelity registry"]

    data = yaml.safe_load(path.read_text()) or {}
    modules = data.get("modules") if isinstance(data, dict) else None
    if not isinstance(modules, dict):
        return {}, [f"{MODEL_FIDELITY_FILE}: top-level `modules` mapping is required"]

    registry: dict[str, str] = {}
    errors: list[str] = []
    for raw_path, raw_value in modules.items():
        rel_path = str(raw_path)
        classification: str | None
        if isinstance(raw_value, str):
            classification = raw_value
        elif isinstance(raw_value, dict):
            raw_classification = raw_value.get("classification")
            classification = raw_classification if isinstance(raw_classification, str) else None
        else:
            classification = None
        if classification not in MODEL_FIDELITY_CLASSES:
            allowed = ", ".join(sorted(MODEL_FIDELITY_CLASSES))
            errors.append(
                f"{MODEL_FIDELITY_FILE}: {rel_path}: classification must be one of: {allowed}"
            )
            continue
        registry[rel_path] = str(classification)

    actual = {
        path.relative_to(repo_root).as_posix() for path in (repo_root / "fstar").glob("**/*.fst")
    }
    registered = set(registry)
    missing = sorted(actual - registered)
    extra = sorted(registered - actual)
    if missing:
        errors.append(f"{MODEL_FIDELITY_FILE}: missing F* module entries: {', '.join(missing)}")
    if extra:
        errors.append(
            f"{MODEL_FIDELITY_FILE}: entries reference missing F* modules: {', '.join(extra)}"
        )
    return registry, errors


def check_entry(
    section: str,
    entry: dict[str, Any],
    stats: Stats,
    validator: GroundingValidator,
    *,
    verbose: bool,
    require_trace_must: bool = False,
) -> None:
    entry_id = str(entry.get("id", "<unknown>"))
    raw_proofs = entry.get("proof", [])
    proofs = (
        [proof for proof in raw_proofs if isinstance(proof, dict)]
        if isinstance(raw_proofs, list)
        else []
    )
    formal_proofs = [proof for proof in proofs if proof.get("type") in FORMAL_TYPES]
    blocks = [validator.ground(entry, proof) for proof in formal_proofs]
    stats.checked += 1
    is_must_verified = str(entry.get("requirement")) in MUST_REQUIREMENTS
    if is_must_verified:
        stats.must_verified_total += 1

    entry_errors = []
    runtime_link = entry.get("runtime_link")
    if not isinstance(runtime_link, str):
        entry_errors.append("missing runtime_link")
    else:
        runtime_ok, symbol_linked, runtime_error = validator.runtime_link_result(runtime_link)
        if runtime_ok:
            stats.runtime_linked += 1
            if symbol_linked:
                stats.runtime_symbol_linked += 1
        elif runtime_error is not None:
            entry_errors.append(runtime_error)

    trace_result, trace_errors = validator.trace_result(entry.get("trace"))
    entry_errors.extend(trace_errors)
    trace_kind = trace_result.get("kind")
    if (
        is_must_verified
        and trace_result.get("result") == "grounded"
        and trace_kind in stats.trace_counts
    ):
        stats.trace_counts[str(trace_kind)] += 1
    if require_trace_must and is_must_verified and trace_result.get("result") == "missing":
        entry_errors.append("missing refinement trace for MUST-level verified entry")

    if not formal_proofs:
        types = [str(proof.get("type", "(none)")) for proof in proofs]
        entry_errors.append(f"no formal proof type (found: {', '.join(types)})")
    else:
        ungrounded_blocks = [block for block in blocks if block["result"] != "grounded"]
        if ungrounded_blocks:
            reasons = "; ".join(
                f"{block.get('type')} {block.get('file')}: {block.get('reason')}"
                for block in ungrounded_blocks
            )
            entry_errors.append(f"ungrounded formal proof block(s): {reasons}")

    for proof in proofs:
        stats.quality_counts[compute_proof_quality(str(proof.get("type", "")))] += 1
        stats.strength_counts[compute_strength(proof)] += 1

    verdict = "fail" if entry_errors else "pass"
    if entry_errors:
        stats.errors.extend(f"{entry_id}: {error}" for error in entry_errors)
    else:
        stats.passed += 1
        if verbose:
            print(f"  PASS  {entry_id}")

    stats.entries.append(
        {
            "id": entry_id,
            "section": section,
            "requirement": entry.get("requirement"),
            "module": entry.get("module"),
            "verdict": verdict,
            "reasons": entry_errors,
            "blocks": blocks,
            "trace": trace_result,
        }
    )


def _write_report(path: pathlib.Path, stats: Stats) -> None:
    report = {
        "checked": stats.checked,
        "passed": stats.passed,
        "failed": stats.checked - stats.passed,
        "entries": stats.entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 on any error (retained for compatibility; validation is always strict)",
    )
    parser.add_argument("--verbose", action="store_true", help="print each passing entry")
    parser.add_argument("--report", type=pathlib.Path, help="write per-entry results as JSON")
    parser.add_argument(
        "--require-trace-must",
        action="store_true",
        help="fail if any MUST/MUST NOT verified entry lacks a refinement trace",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path.cwd()
    matrix_file = repo_root / MATRIX_FILE
    if not matrix_file.exists():
        print(f"ERROR: {MATRIX_FILE} not found", file=sys.stderr)
        return 1

    data = yaml.safe_load(matrix_file.read_text())
    stats = Stats()
    model_fidelity, registry_errors = load_model_fidelity_registry(repo_root)
    stats.errors.extend(registry_errors)
    validator = GroundingValidator(repo_root, model_fidelity)

    for section, entries in data.items():
        if section == "metadata" or not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("status") == "verified":
                check_entry(
                    section,
                    entry,
                    stats,
                    validator,
                    verbose=args.verbose,
                    require_trace_must=args.require_trace_must,
                )

    if args.report is not None:
        _write_report(args.report, stats)

    print()
    print("=" * 60)
    print("VerifiedReqs Grounded Proof-Reference Check")
    print("=" * 60)
    print(f"  Checked : {stats.checked}")
    print(f"  Passed  : {stats.passed}")
    print(f"  Failed  : {stats.checked - stats.passed}")
    print(f"  Errors  : {len(stats.errors)}")
    quality = stats.quality_counts
    strength = stats.strength_counts
    print(
        f"  Proof Quality : formal={quality['formal']},"
        f" empirical={quality['empirical']}, unknown={quality['unknown']}"
    )
    print(
        f"  Proof Strength: lemma={strength['lemma']},"
        f" refinement={strength['refinement']}, semantic={strength['semantic']}"
    )
    print(
        f"  Runtime Link  : {stats.runtime_linked}/{stats.checked}"
        f" (symbol-level: {stats.runtime_symbol_linked}/{stats.checked})"
    )
    traced = sum(stats.trace_counts.values())
    print(
        f"  Refinement Trace: {traced}/{stats.must_verified_total} MUST-level verified "
        f"(oracle={stats.trace_counts['oracle']}, structural={stats.trace_counts['structural']}, "
        f"guard={stats.trace_counts['guard']}, exempt={stats.trace_counts['exempt']})"
    )
    if args.report is not None:
        print(f"  JSON Report   : {args.report}")
    print("=" * 60)

    if stats.errors:
        print()
        for error in stats.errors:
            print(f"  ERROR  {error}", file=sys.stderr)
        print()
        return 1

    print("  All verified entries have grounded formal proof references.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
