# Dependency Policy & Supply-Chain Checks

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Platform/CI

## Current Gates
- `cargo deny`: enforced via `nix run .#security-suite` (first stage) and `nix flake check` (`verify-cargo-deny`).
  - Blocks releases when RustSec advisories, disallowed licenses, banned crates, or untrusted sources are present.
- `cargo audit`: bundled with `nix run .#security-suite` for advisory sanity alongside `cargo deny`.
- `cargo vet`: initialized (current exempt count ~391) and available via `nix run .#security-suite` (soft gate) or `nix develop -c cargo vet check`; cache pinned to workspace-local `.cargo-vet-cache` for sandbox compatibility.
- `cargo geiger`: executed from `scripts/security/run_security_suite.sh` (non-blocking). Per-crate results are written to `artifacts/security/latest/geiger/<crate>.txt` so we can diff unsafe usage over time. When running inside a restricted network, ensure the crate indices/artifacts are already fetched (`cargo fetch` or vendoring) or set `CARGO_NET_OFFLINE=false` temporarily; missing registries will otherwise surface as warnings in the log instead of metrics.

The aggregated helper `nix run .#security-suite` captures combined logs under `artifacts/security/latest/summary/security.log` while preserving individual error codes for deny/audit.

### Geiger Log Normalization
- Source of truth: gate results plus filtered report outputs (`*.gate.*`, `*.report.raw.txt`, `*.report.txt`).
- Debug-only: unfiltered outputs (`*.gate.full.txt`, `*.report.full.txt`) are kept for triage and should not be treated as gate failures.
- Noise filtering is controlled by:
  - `GEIGER_FILTER_RAW=1` (default) to filter known non-actionable warnings from raw logs.
  - `GEIGER_KEEP_FULL=1` (default) to retain the unfiltered logs for diagnostics.
- `scripts/security/run_geiger.sh` uses a dedicated `CARGO_HOME` and writes a `config.toml` that pins the crates.io index/protocol to reduce registry source mismatches.

## Planned `cargo vet` Rollout
1. **Bootstrap**
   - Keep `cargo-vet` available in the flake dev shell (`cargo-vet` binary).
   - Run `cargo vet init` to generate `supply-chain/` manifests (config, audits, imports) and commit them.
   - Trust upstream review sources (e.g., `rust-secure-code/cargo-vet`).
2. **Phase 1 – Warning Mode**
   - Execute `cargo vet check` in CI (non-blocking) focusing on high-risk crates (crypto, HTTP, FFI).
   - Track unaudited dependencies using `cargo vet suggest`; document owners and mitigation deadlines here.
3. **Phase 2 – Enforcement**
   - Turn the warning into a hard gate: `cargo vet check` must pass before merge/release.
   - Use `cargo vet diff` during PRs to surface new dependency additions and require audit entries.
   - Update `supply-chain/audits.toml` with internal or trusted third-party reviews.

## Imported Audit Compatibility (bytecode-alliance)
Some upstream audit files (notably `bytecode-alliance`) use newer cargo-vet schema features
such as `[[wildcard-audits]]`. When our cargo-vet binary is too old, the import yields
`Ignored invalid audits` warnings. To keep imports compatible:

1. Pin a newer cargo-vet in the flake dev shell (currently `0.10.2-git-e496a28`).
2. Keep `supply-chain/config.toml` at the supported major/minor (currently `version = "0.10"`).
3. Run `nix develop .#default --command cargo vet regenerate imports` and then
   `nix develop .#default --command cargo vet check` to refresh `imports.lock`.

If the warning reappears, confirm the flake is providing the newer cargo-vet and re-run step 3.
If warnings persist after a regeneration with the pinned cargo-vet, record the status here and
treat the warning as informational (do not block) while `cargo vet check` remains otherwise clean.
Re-evaluate once cargo-vet is upgraded or the upstream audit schema stabilizes.
As of 2026-02-06, the dev shell pin above clears the invalid-audit warnings after regeneration.
If they reappear, record the new upstream revision and keep the gate non-blocking until resolved.

## Operational Checklist
- Update this file whenever new unaudited dependencies or exceptions are introduced.
- Review outstanding unaudited entries on every release candidate.
- Ensure CI workflows (`security.yml`, `compliance.yml`) execute the final `cargo vet` gate once enforcement is enabled.
- After adding or removing audits, run `cargo vet prune` to keep `imports.lock` minimal.

## Phase 1 Tracking: High-Risk Audit Completion (2026-01-27)
The initial high-risk backlog is now audited and recorded in `supply-chain/audits.toml`.
Keep these helpers up to date when reviewing new high-risk crates:

- Inspection links (diff.rs): `artifacts/security/latest/vet/inspect/summary.md`.
  - Generate with `scripts/security/vet_inspect_links.sh` (non-interactive).
- Source triage (unsafe/build.rs/proc-macro counts): `artifacts/security/latest/vet/inspect/source_triage.md`.
  - Generate with `scripts/security/vet_source_triage.sh`.

## Current cargo-vet Findings (Triage Log, 2026-02-13)
This list captures the non-blocking `cargo vet check` findings from `security-suite`.
We keep the triage here until the corresponding audits or trust entries are recorded.

Notes:
- Recorded run: `cargo vet check` passes (335 fully audited, 5 partially audited, 116 exempted).
- Phase 2 dependency additions (AWS SDK, platform crates, loadtest deps) introduced 66 unvetted
  dependencies on 2026-02-13. Resolved via publisher trust entries + exemptions (see below).
- `cargo vet prune` run to remove unnecessary imports.
- `cargo vet check (dev-tools/sanitizer-smoke)` succeeded; it only warned about running
  `cargo vet prune`.
- Recorded fuzz run: `cargo vet check (fuzz)` is clean after Action C audits (2026-02-06).

### Publisher Trust Entries Added (2026-02-13)
The following publishers are now trusted for all their crates (already trusted by isrg, mozilla,
bytecode-alliance, and/or zcash):
- `kennykerr` — Windows platform crates (windows, windows-sys, windows-targets, windows_* arch)
- `seanmonstar` — HTTP networking (hyper, h2, reqwest, tower, http-body, http-body-util, hyper-util)
- `dtolnay` — Rust core (syn, quote, proc-macro2, serde_json, serde_path_to_error, semver, thiserror)
- `Darksonn` (Alice Ryhl) — Async runtime (tokio, bytes, slab, tokio-util, tokio-macros)
- `alexcrichton` — WASM/system (openssl-probe, wasm-bindgen-*, web-sys)
- `rust-lang-owner` — Rust project (libc, cc, cmake)
- `cuviper` (Josh Stone) — num-bigint
- `aws-sdk-rust-ci` — AWS SDK crates (aws-config, aws-sdk-*, aws-smithy-*, aws-runtime, aws-sigv4, aws-types)
- `djc` — TLS (rustls-native-certs, hyper-rustls, tokio-rustls, quinn, rcgen)
- `cpu` — TLS (rustls, rustls-webpki, rustls-pemfile)
- `ctz` — TLS (rustls, sct, webpki-roots)

### Exemptions Added (2026-02-13)
28 remaining unvetted dependencies exempted (pending deeper review):
- Platform: schannel, security-framework (2 versions), security-framework-sys, winapi, winapi-*-gnu, ntapi
- SIMD: base64-simd, vsimd, outref
- Concurrency: crossbeam-channel, crossbeam-deque, crossbeam-epoch
- Loadtest/bench: hdrhistogram, sysinfo, criterion, criterion-plot, plotters, plotters-backend, plotters-svg, half, hermit-abi
- Misc: bytes-utils, crc32fast, getrandom 0.3.4, xmlparser, yasna

### Unvetted (safe-to-deploy)
- (none; cleared via trust entries + exemptions on 2026-02-13)

### Unvetted (safe-to-run)
- (none)

### Phase 1 Trust Entries — Deeper Review Pending
The following trusted publishers were added as Phase 1 trust entries to reduce the audit
backlog. They require deeper review before the trust expiry date:
- `stringprep` (user-id 5) — expires **2027-01-27**
- `unicode-properties` (user-id 1139) — expires **2027-01-27**

Both entries have `notes = "Phase 1 trust to reduce audit backlog; pending deeper review"`.
Schedule deeper review before 2027-01-01.

### Proposed Actions
- Action C completed on 2026-02-06; audits recorded in `supply-chain/audits.toml`.
- Action D completed on 2026-02-13; trust entries + exemptions for Phase 2 additions.
- Diff/inspect artefacts are retained under `artifacts/security/latest/vet/`.
- Next: audit exempted platform/SIMD crates (28 remaining) for Phase 2 enforcement.

Owner: Security
Target: 2026-03-01

## Exceptions & Allowances
- RustSec `ignore` list (2026-02-13):
  - `RUSTSEC-2025-0134` (rustls-pemfile deprecated) — thin wrapper; no upgrade path available.
  - `RUSTSEC-2023-0071` (rsa Marvin Attack) — transitive via sqlx-mysql; Aegaeon uses PostgreSQL only, vulnerable code path never compiled or executed.
- `CDLA-Permissive-2.0` allowed for `webpki-roots` transitive dependency (via `reqwest`/`hyper-rustls`). The license grants permissive use of certificate data and does not impose copyleft obligations; reviewed 2025-09-29.
- base64 0.21.7 retained alongside 0.22.x until warp/headers update; tracked via cargo-deny skip entry.
- getrandom 0.2.16 retained alongside 0.3.x due to ring/rand_core; revisit once upstream supports 0.3.
- rand 0.8.5 retained alongside 0.9.x for quickcheck/tungstenite compatibility until upstream upgrades.
- rand_chacha 0.3.1 retained alongside 0.9.x for backward-compat rand usage.
- rand_core 0.6.4 retained alongside 0.9.x because crypto crates still depend on 0.6.
- socket2 0.5.10 retained alongside 0.6.x because warp/hyper 0.14 chain still requires it.
- thiserror 1.0.69 retained alongside 2.x; all direct deps migrated to 2.0 (2026-02-13), transitive via protobuf/protobuf-support (prometheus).
- thiserror-impl 1.0.69 retained alongside 2.x; transitive via protobuf until upstream migrates.
- tower 0.4.13 retained alongside 0.5.x due to warp server stack.
- untrusted 0.7.1 retained alongside 0.9.x because aws-lc-rs still requires it.
- wasi 0.11.1+wasi-snapshot-preview1 retained alongside 0.14.x because getrandom 0.2 still depends on preview1 shim.
- windows-link 0.1.3 retained alongside 0.2.x via windows-targets 0.53.x.
- windows-sys 0.52.0/0.59.0/0.60.2 retained until upstreams converge on 0.61.x.
- windows-targets 0.52.6 retained alongside 0.53.x for backtrace/tokio.
- windows_* architecture crates at 0.52.6 retained with windows-targets 0.52.x until upstream convergence.
