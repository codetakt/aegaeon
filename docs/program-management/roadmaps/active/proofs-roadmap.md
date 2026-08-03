# Proofs Roadmap

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This note consolidates the verification work that spans the TLV decoder and
the JOSE header parser. Use it as a jumping-off point before diving into the
more detailed plans under `docs/program-management/initiatives/jose/`.

## Status Snapshot

| Area | Current State | Notes |
|------|---------------|-------|
| TLV decoder (`Jose.HeaderParser`) | Implementation + parity tests are present; the last recorded green run is 2025-10-16. Re-run verification to confirm stability in the current tree. | See `docs/program-management/initiatives/jose/parser/header-parser-plan.md`. |
| JOSE header logic | TLV-first implementation is active. JSON normalisation uses the Low*/C bridge via `json_lowstar` (serde_json front-end). EverParse integration and a TLV-only JSON path remain pending. | See `docs/program-management/initiatives/jose/parser/header-parser-plan.md` and `docs/program-management/initiatives/jose/json-tlv/json-tlv-proof-plan.md`. |
| Full-refresh baseline | The claim-supporting baseline was re-run fresh on 2026-03-10: `verify-fstar`, `verify-jose`, `verify-dudect`, `verify-tamarin`, `verify-kani`, `security-suite`, and compliance-matrix validation all returned green in the pinned Nix lane. | Treat this as the fixed full-refresh baseline for the current released server claim. |
| Tamarin regression status | `proofs/tamarin/` currently contains **54 total `.spthy` files**. The blocking claim-supporting baseline remains **50 models / 215 lemmas**, all green; two extended models remain outside that CI baseline and two theory files are shared libraries. | See `proofs/tamarin/PROOF_STATUS.md` for the canonical split between claim-supporting and extended models. |
| Low*/C extraction (JOSE) | `scripts/extraction/run_jose_lowstar.sh` completed on 2026-02-06; remaining warnings are upstream LowParse/KaRaMeL (274 namespace shadowing; 241/247 cache priming; 337 multiple decreases clauses; 361/331/328/271 LowParse internals). EverParse Low* generation remains opt-in. | Treat the remaining warnings as the next extraction-hardening targets. |
| `assume val` inventory | 80 `assume val` declarations across 27 F\* files (measured at HEAD). Top contributors: Jose.Federation (10), AuthCode.Store (9), Jose.SdJwt (6), VerifiedCore.Api.Claims.Runtime (5), Jose.LowStar.Json.Spec (5), AuthCode.Flow (5), Jose.HeaderKeyLemmas (4). Categories: FFI/runtime host callbacks, crypto primitives (sha256, jws_verify), serialization axioms, and list operation lemmas. | Tracked as a reduction target. Contrast with `admit()` (now 0). `assume val` declarations are intentional axioms (e.g. FFI bridges, crypto primitives) or proof obligations queued for future phases. |
| OIDC `RS256` verification boundary | The mandatory OIDC Core `RS256 Required Slice` and the narrow `RS256 Interop Slice` are now closed as promoted boundary exceptions for the current server claim. | The remaining work is evidence maintenance, proof hygiene, and keeping broader RSA / JOSE interoperability explicitly in compat unless separately promoted. See `docs/verification/oidc/rs256-required-slice.md`, `docs/verification/oidc/rs256-interop-slice.md`, `docs/verification/claims/crypto-allowlist.md`, and `docs/verification/workplans/verification-boundary-roadmap.md`. |
| Documentation | Core tracking documents have been consolidated (legacy `tlv-*` TODO notes merged/removed). Remaining plans/summaries must be kept in sync periodically. | This roadmap plus [structure-guidelines.md](../../../verification/workplans/structure-guidelines.md) are the primary coordination points. |

## Active Workstreams

### 1. TLV Decoder Proofs

- ✅ Bounds / progress / duplicate-key invariants (e.g. `lemma_decode_entry_raw_bounds`,
  `lemma_decode_all_unique`, etc.) are present (last recorded green run: 2025-10-16).
- ✅ UTF-8 lemmas (canonical checks, scalar round-trips, `lemma_decode_utf8_roundtrip`) are
  present (last recorded green run: 2025-10-16).
- ✅ Rust implementation, fuzz corpus, and integration tests are aligned with the new decoder,
  but require a fresh re-run to confirm current status. See
  `docs/program-management/initiatives/jose/parser/header-parser-plan.md`.
- 🔄 Next: advance FFI/Low* extraction and share the TLV implementation with the extraction pipeline
  (see `../../initiatives/jose/lowstar/lowstar-extraction-plan.md`).
- Reference: `docs/program-management/initiatives/jose/parser/header-parser-plan.md`.

### 2. JOSE Header Parser Proofs

- ✅ TLV-first execution logic under `parse_with_tlv` and friends.
- ✅ Low*/C JSON bridge is in place (`json_lowstar` -> `parse_json_entries_safe`), but JSON is
  still decoded via serde_json before crossing the FFI boundary.
- 🚧 JOSE-specific invariants (canonical header parsing, UTF-8 semantics) remain partially
  `assume`/sketch-level. Strengthen lemmas such as `lemma_parse_with_tlv_preserves`.
- 🚧 Extraction-friendly refactor: utilities, TLV logic, and JOSE logic are co-located in a single
  module. See [structure-guidelines.md](../../../verification/workplans/structure-guidelines.md) for split
  options.
- 🚧 `parse_jwe_buffer` / `parse_jws_buffer` TLV replacement and EverParse-generated helper
  integration are not complete.
- 🚧 Hardening backlog: plan a “formal parser” replacement by wiring EverParse helpers into
  `Jose.HeaderParser`, aligning Rust error mapping, keeping existing tests/conformance green, and
  treating stable EverParse extraction in CI as the exit criterion.
- Tracking docs: `../../initiatives/jose/parser/header-parser-plan.md`,
  `../../initiatives/jose/jose-implementation-plan.md`,
  `../../initiatives/jose/json-tlv/json-tlv-proof-plan.md`.

#### EverParse/Low* extraction hardening (out of DoD scope; follow-on phase)
- BitFields/EverParse3d dependency handling: mitigate ErrorCode fall-through caused by unresolved
  `LowParse.BitFields.uint_t` (e.g., add `.checked`, include in krml inputs, or avoid via
  `noextract`/bundling).
- Warning 26 mitigation: locate Top casts (e.g. via `-dast`) and eliminate them via monomorphisation
  or source annotations.
- Current warnings (2026-02-06): Warning 274 (namespace shadowing), Warning 241/247 (cache
  priming), Warning 337 (multiple decreases clauses), Warning 361/331/328/271 (LowParse internal
  warnings).
- Script posture: before enabling `GENERATE_EVERPARSE_LOWSTAR` by default, establish a locally-green
  configuration and keep actionable diagnostics on failure.
- CI posture: decide whether extraction runs unconditionally or remains opt-in (env/feature), and
  document reproduction steps accordingly.

### 3. Work Tracking & Tooling

- ✅ Primary TODOs are consolidated into
  `../../initiatives/jose/parser/header-parser-plan.md`,
  `../../initiatives/jose/jose-implementation-plan.md`, and
  `../../initiatives/jose/json-tlv/json-tlv-proof-plan.md`.
- 🚧 Promote remaining ad-hoc `assert` statements into named lemmas and track them in
  `../future/future-projects.md`.
- 🚧 Maintain a stable CI recipe (e.g. `nix build .#verify-fstar -L`) and ensure failures point back
  to the relevant triage document.
- ℹ️ EverCrypt.Helpers name-resolution drift is not reproducible today. Repro steps are documented in
  `docs/verification/fstar/troubleshooting.md#6-evercrypthelpers-name-resolution-monitoring` (non-blocker; monitoring only).

### 4. OIDC `RS256` Slice Evidence Maintenance

- ✅ **Required slice**: OP ID Token `RS256` issuance / validation, PKCS#1 v1.5 + SHA-256
  binding, and OIDC metadata / DCR consistency are already inside the promoted server boundary.
- ✅ **Interop slice**: signed Request Objects, `request_uri`, and `private_key_jwt` when they use
  `RS256` are also already inside the promoted server boundary.
- 🔄 **Current maintenance target**: keep matrix wording, assurance wording, dudect evidence, and
  runtime behaviour aligned so the closed slices remain narrow, explicit, and defensible.
- ℹ️ **Non-goal**: do not expand this workstream into general-purpose RSA verification unless the
  product position changes. `RS384/512`, `PS*`, and `RSA-OAEP` remain compat by default.
- Tracking docs: `docs/verification/claims/crypto-allowlist.md`,
  `docs/verification/workplans/verification-boundary-roadmap.md`,
  `docs/program-management/roadmaps/active/oidc-spec-coverage-roadmap.md`.

## Next Actions

1. **Keep the full-refresh baseline green** – rerun the claim-supporting lanes after material proof,
   crypto, or policy changes and update this roadmap when the fixed baseline moves.
2. **Keep the OIDC `RS256` slice evidence current** – both promoted slices are closed; preserve
   the narrow boundary wording and refresh the supporting evidence when the verifier path changes.
3. **Close the remaining lemma gaps** – refer to
   `../../initiatives/jose/parser/header-parser-plan.md` and
   `../future/future-projects.md`, and prioritise removing remaining `assume`
   and `assert false` fragments.
4. **Re-organise the F\* sources** – adopt the layout in [structure-guidelines.md](../../../verification/workplans/structure-guidelines.md). This simplifies cross-module reuse and keeps UTF-8 helpers in a shared library.
5. **Advance extraction & integration** – integrate the TLV implementation with the EverParse/Low*
   pipeline (see `../../initiatives/jose/lowstar/lowstar-extraction-plan.md`).
6. **Update execution plans** – keep
   `../../initiatives/jose/parser/header-parser-plan.md` checkpoints
   up to date and aligned with CI status.

## References

- TLV artefacts: `docs/program-management/initiatives/jose/parser/header-parser-plan.md`.
- JOSE artefacts: `jose-*` documents in this folder.
- Gap tracker: `../future/future-projects.md`.
- Structure guidance: [structure-guidelines.md](../../../verification/workplans/structure-guidelines.md).
