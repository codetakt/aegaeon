# Unsafe Code Policy

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

## Scope
- All Rust crates must declare `#![forbid(unsafe_code)]` unless explicitly exempt.
- The only current exemption is `crates/ffi`, which owns the FFI boundary and raw-pointer glue.
- Build scripts (`build.rs`) are separate crates; avoid `unsafe` there unless strictly required.

## Allowed Unsafe Areas
- `crates/ffi`: FFI bindings, raw pointer conversion, allocation/free, and low-level adapters.
- Any additional `unsafe` usage requires an explicit policy update before landing.

## Requirements
1. Prefer safe wrappers; keep `unsafe` blocks minimal and localized.
2. Every `unsafe` block must include a brief safety comment describing invariants.
3. Add tests and fuzz coverage for inputs crossing the unsafe boundary.
4. Ensure review sign-off for any new unsafe usage.

## Enforcement
- `#![forbid(unsafe_code)]` is enforced at crate roots.
- `cargo geiger` is used to monitor unsafe usage; findings are triaged rather than ignored.

## cargo geiger Policy
- **Gate**: run `cargo geiger --no-deps` on first-party crates to fail on new unsafe usage.
- **Report**: run a full dependency scan only for visibility; do not fail the
  build on third-party `unsafe`.
- **Rationale**: core dependencies (crypto, runtimes, FFI glue) legitimately use `unsafe`, and
  blocking on those creates false negatives while `cargo vet`/`cargo deny`/SBOM already govern
  supply-chain risk.
- **Exception**: `crates/ffi` remains allowed to use `unsafe` and is excluded from the gate.

## Exceptions Process
- Propose a new exception with rationale, affected crate/module, and risk assessment.
- Update this policy and obtain reviewer approval before merging.
