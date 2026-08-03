# CLAUDE Agent Guide (≤40 k)

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

This brief condenses the operational rules from `AGENTS.md` so it fits within Claude Code’s context window. Follow it as the day-to-day reference; open the full document whenever deeper context is needed.

---
## 1. Collaboration & Communication
- Work as a concise, evidence-driven teammate. Surface findings first, then options; clearly mark any assumptions.
- Responses must be self-contained, parallel in structure, and use inline code references (`path:line`).
- Run relevant commands/tests when possible, but never undo user changes or run destructive git commands unless instructed.
- Planning tool usage:
  - Skip for trivial tasks.
  - Plans need ≥2 steps; update the plan after completing a step.
- Editing:
  - Prefer `apply_patch` for small targeted changes; avoid for generated files.
  - Default to ASCII; only introduce Unicode if already present and necessary.
- Testing: execute the project’s normal checks when practical; include rerun instructions if you cannot.

## 2. Standards & Policy Stance
- Enforce strict OAuth 2.0/JOSE compliance (RFC 6749/6750/7636/7009/7662/8414/9126/9449/9700). ROPC/implicit flows remain disabled.
- PKCE S256 is mandatory; sender-constrained tokens (DPoP or mTLS) are encouraged.
- mTLS metadata (`mtls_endpoint_aliases`, `tls_client_certificate_bound_access_tokens`) is emitted only when the active database-backed mTLS policy is enabled; PAR aliasing is also policy-controlled.
- Non-standard metadata keys must carry the `aeg_*` prefix and be guarded by explicit toggles.
- Any change to metadata, policy toggles, or extensions must update docs, compliance artefacts, and CI checks together.

## 3. Current References
- Full contributor and agent rules: `AGENTS.md`.
- Verification entrypoints and evidence map: `docs/verification/README.md`.
- CI and automation expectations: `docs/automation/ci-cd-guide.md`.
- Documentation validation tools: `docs/development/validation-tools.md`.

## 4. Dependency Governance
- `cargo deny` is a release blocker (run via `nix run .#security-suite` and flake checks).
- `cargo vet` adoption:
  - **Bootstrap** – keep `supply-chain/` tracked; make `cargo-vet` available in dev shells.
  - **Phase 1** – run `cargo vet check` (warning mode) for risky crates; record unaudited entries with owners.
  - **Phase 2** – require audits or documented unaudited entries before merge; include `cargo vet diff` in PR review.
- Document all exceptions in `docs/policies/dependency-policy.md` and revisit each release.

## 5. Security, Fuzzing, Sanitizers
- Fuzz targets: `fuzz_bearer_token`, `fuzz_dpop_proof`, `fuzz_pkce_verifier`, `fuzz_par`, `fuzz_introspection`, `fuzz_jose_parsing`.
  - Default smoke run: ~30 s/target (`FUZZ_TIMEOUT=1m`, `FUZZ_MAX_TOTAL=30`).
  - For longer runs, set `FUZZ_TIMEOUT`, `FUZZ_MAX_TOTAL`, `FUZZ_TOTAL_TIMEOUT` explicitly.
- Security suite (`nix run .#security-suite`) enforces tool presence: `cargo-fuzz`, `cargo audit`, `cargo-deny`, `cargo-geiger`, `cargo-udeps`, `cargo-vet`, sanitizers, SBOM scan.
- Sanitizers:
  - AddressSanitizer runs through `scripts/run_sanitizers.sh` inside `nix develop .#asan`.
  - Link shared compiler-rt (`SANITIZER_RUNTIME_DIR`), avoid global `LD_PRELOAD` (already removed).
  - LeakSanitizer is suppressed unless a dedicated runner is available.
- SBOM scanning: `scripts/security/run_sbom_scan.sh` (CycloneDX + grype; optional Trivy via `RUN_TRIVY=1`). Wrapped by `just security-sbom`.

## 6. Formal Verification Roadmap
### F* (Phase 1 focus)
- Modules: `pkce.fst`, `par.fst`, `dpop.fst`, `token.fst`, `jose.fst` (determinism), `pkjwt.fst` (validator).
- Requirements: proofs pass with pinned toolchain; KaRaMeL extraction succeeds; dudect shows no leakage; Rust harnesses exercise extracted code.
- Phase 2 extends to store composition, lifetimes, and deterministic serialization proofs.

### Kani
- Phase 1 harnesses: JWKS circuit breaker, JTI stores, JWKS cache GC, parsing guards.
- Known issue: HashMap-heavy harnesses trigger Kani 0.65.0 ICE. Retain failing harnesses, log them, and upstream minimal repros.
- Scripts should keep logs even on failure.

### Tamarin
- Phase 1: authorization code, PAR, mix-up, bearer BCP lemmas.
- Phase 2: private_key_jwt, mTLS sender constraints, DCR policies, introspection/revocation properties.
- Always refresh proof artefacts under `proofs/tamarin/artifacts/` when rerunning.

## 7. CI & Tooling Expectations
- Core gates to keep green: `nix flake check`, `nix run .#security-suite`, F* proofs, Kani harnesses, dudect, Tamarin, fuzz suite, JOSE conformance, compliance matrix validation.
- Dev shell tooling must expose: `nix`, `just`, EverParse, KaRaMeL, F*, Z3, Tamarin, Kani, dudect, cargo utilities listed above.
- Treat `cargo deny` and `nix flake check` failures as release blockers; verify locally before pushing.

## 8. Compliance & Documentation Discipline
- `spec/compliance-matrix.yaml` is authoritative; validate with `scripts/validation/validate_compliance_matrix.py`.
- Whenever toggles/metadata/verification scope changes, update docs, compliance matrix, and CI scripts together.
- Upload verification artefacts (proof logs, fuzz results, sanitizer logs) under `artifacts/`.
- Document unaudited dependencies, sanitizer quirks, and verification gaps in the corresponding policy docs.

## 9. Repository Interaction Quick Rules
- Never revert or discard user changes without explicit instruction.
- Use numeric option lists when proposing multiple paths forward.
- Provide reproducible command snippets (`nix run …`, `just …`) and note expected runtimes.
- For large edits, follow TDD/Red‑Green‑Refactor: add failing test, implement minimal fix, refactor.
- When editing JSON/TLV formalization, keep metadata standard-first, prefer derived proofs over ad-hoc reasoning.

## 10. Low*/JSON Integration (current focus)
- Expose JSON normalization through Low*/C wrappers (`Jose.LowStar.Json`, KaRaMeL extraction) before replacing Rust serde fallback.
- Ensure FFI modules map decode errors correctly (decode_error → Rust `JwsError` etc.).
- Maintain parity tests (`cargo test -p aegaeon-jose --test json_tlv_parity`) once Low* path is wired up; integrate into CI.

## 11. Quick Checklist Before Merging
- [ ] `nix flake check` + `nix run .#security-suite` pass locally.
- [ ] Compliance matrix updated/validated with matching artefacts.
- [ ] Formal verification artefacts (F*, Kani, Tamarin, dudect) regenerated when code paths change.
- [ ] Fuzzing + sanitizer runs executed recently; SBOM refreshed if dependencies moved.
- [ ] Documentation (policies, runbooks, roadmap) reflects any new toggles or behaviours.

---
Stay within this summary for routine work. When uncertain, open `AGENTS.md` for the full context.
