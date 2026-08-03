# Trusted Computing Base (TCB) Inventory

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Security

Audience: security reviewers, maintainers

> **Status note (2026-03-08):** This document describes the broader system/security TCB. It must not be read as redefining the formal verification boundary, which is owned by `docs/verification/claims/assurance-case/claim-definition.md` and `docs/verification/claims/assumptions/current-register.md`.

## Document Version
- Version: 1.1.1
- Date: 2026-07-24
- Changes: completed component enumeration (Kani, EverParse, C toolchain,
  service dependencies), corrected crypto-library roles, replaced stale
  verification metrics with pointers to the maintained snapshot, and recorded
  the RS256 verifier move from project-local bigint arithmetic to `aws-lc-rs`
- Prior: 1.0.0 (2025-09-02, Sprint 8 - External Conformance & Beta)

## Executive Summary

This document identifies and catalogs all components within Aegaeon's Trusted Computing Base (TCB) - the minimal set of components whose correct operation is necessary for the system's security guarantees.

## TCB Boundary Definition

### Core TCB Components

#### 1. Formal Verification Toolchain
- **F* Compiler**: v2025.01.21 (pinned)
  - Role: Type checking and verification of protocol core
  - Trust Assumption: F* type system soundness
  - Mitigation: Version pinning, reproducible builds

- **Z3 Theorem Prover**: v4.13.3 (pinned)
  - Role: SMT solving for F* verification
  - Trust Assumption: Z3 correctness
  - Mitigation: Cross-validation with alt-ergo when critical

- **KaRaMeL**: v1.5.0 (pinned)
  - Role: F* to C extraction
  - Trust Assumption: Semantics-preserving translation
  - Mitigation: Extracted code review, CT validation

- **Tamarin Prover**: v1.8+ (pinned)
  - Role: Symbolic protocol verification
  - Trust Assumption: Dolev-Yao model adequacy
  - Mitigation: Computational soundness proofs for critical paths

- **Kani / CBMC**: v0.66.0 (pinned via `nix/kani/package.nix`)
  - Role: Bounded model checking for Rust code
  - Trust Assumption: CBMC soundness within stated bounds
  - Mitigation: Version pinning; bounds documented per harness

- **EverParse**: v2025.10 (pinned)
  - Role: Verified parser generation from `.3d` schemas
  - Trust Assumption: Generator produces code matching the schema semantics
  - Mitigation: Generated C reviewed and committed; F*-verified schemas

- **C toolchain (gcc/clang, linker, libc)**
  - Role: Compiles and links KaRaMeL/EverParse output and the C ABI shim
  - Trust Assumption: No miscompilation of extracted verified code; correct
    linkage and libc behaviour
  - Mitigation: Pinned via Nix; sanitizer smoke suite over the FFI surface

#### 2. Cryptographic Libraries
- **HACL*/EverCrypt**: v0.7.1
  - Role: Verified primitives on the verified-profile paths (SHA-2, HMAC,
    Ed25519 verification, ChaCha20-Poly1305)
  - Trust Assumption: Computational hardness assumptions; correct linkage of
    the extracted C (see the Assumption Register, categories A and B')
  - Mitigation: Machine-checked spec/implementation correspondence,
    constant-time guarantees

- **aws-lc-rs / ring** (Rust)
  - Role: Primary compat-profile crypto (RSA, ECDSA, AES-GCM, HKDF, CSPRNG,
    signing-key generation), including the runtime crypto behind the promoted
    RS256 verifier slices (RC-7) through `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256
    verification; outside the formal claim but on mandatory OIDC paths
  - Trust Assumption: Implementation correctness and side-channel hygiene
  - Mitigation: FIPS-validated lineage (aws-lc-rs), wide deployment, audits

- **RustCrypto `hmac` / `sha2`, `p256`** (Rust)
  - Role: DRBG runtime execution (RC-3), runtime SHA-256 at non-promoted call
    sites, ES256 compat path
  - Trust Assumption: Implementation correctness
  - Mitigation: Widely reviewed crates; F*-verified construction above the
    primitive (DRBG); slice boundary conditions verified

#### 3. Runtime Components
- **Rust Compiler**: 1.91.0-nightly-2025-08-28
  - Role: System layer compilation
  - Trust Assumption: Memory safety guarantees
  - Mitigation: Unsafe blocks audited and minimized

- **Linux Kernel**: 6.15.11
  - Role: System calls, memory isolation
  - Trust Assumption: Process isolation, ASLR
  - Mitigation: Syscall filtering, minimal surface

- **HTTP / async stack (axum, hyper, tokio) and serde/serde_json**
  - Role: Request handling, async scheduling, JSON (de)serialization
  - Trust Assumption: Memory safety via Rust ownership; parser correctness
  - Mitigation: EverParse defense-in-depth at the FFI boundary for protocol
    payloads

- **TLS stack (rustls)**
  - Role: TLS termination on served endpoints where configured
  - Trust Assumption: Protocol and implementation correctness
  - Mitigation: Outside the formal claim; deployment guidance in the
    hardened reference deployment

#### 3a. Service Dependencies
- **PostgreSQL** (via sqlx)
  - Role: Management snapshot, token and client persistence
  - Trust Assumption: ACID properties and query correctness
  - Mitigation: Migrations reviewed; fail-closed startup checks

- **Redis** (fail-closed runtime-state surfaces, `AEGAEON_*_REDIS_URL`)
  - Role: DPoP replay store, nonce state, runtime counters
  - Trust Assumption: Atomic check-and-store under concurrency (RC-5 in the
    Runtime Contract Register)
  - Mitigation: Fail-closed configuration; replay-window bounds

#### 4. Hardware Dependencies
- **CPU**: x86_64 or ARM64
  - Trust Assumption: Constant-time operations (AES-NI, etc.)
  - Mitigation: dudect validation, no speculation in critical paths

- **RNG**: /dev/urandom
  - Trust Assumption: Sufficient entropy
  - Mitigation: getrandom(2) with GRND_RANDOM flag

## TCB Minimization Strategy

### Components Explicitly Excluded from TCB

1. **Observability Stack**
   - OpenTelemetry, Prometheus, Grafana
   - Rationale: Monitoring failures don't compromise security
   - Isolation: Separate process, read-only access

2. **Load Testing Tools**
   - k6, vegeta, custom load generators
   - Rationale: Testing infrastructure
   - Isolation: Never deployed to production

3. **Development Tools**
   - cargo-audit, cargo-deny, clippy
   - Rationale: Build-time only
   - Isolation: CI/CD pipeline separation

### Security Boundaries

```text
┌─────────────────────────────────────────────┐
│                Production System             │
│                                              │
│  ┌────────────────────────────────────┐     │
│  │         Core TCB (Verified)         │     │
│  │                                     │     │
│  │  ┌─────────────┐  ┌──────────────┐ │     │
│  │  │  F* Core    │  │  HACL*       │ │     │
│  │  │  - PKCE     │  │  - SHA2/HMAC │ │     │
│  │  │  - DPoP     │  │  - Ed25519   │ │     │
│  │  │  - PAR      │  │  - ChaCha20  │ │     │
│  │  └─────────────┘  └──────────────┘ │     │
│  │                                     │     │
│  │  ┌─────────────────────────────┐   │     │
│  │  │   Extracted C (KaRaMeL)     │   │     │
│  │  │   - Verified properties     │   │     │
│  │  │   - Constant-time critical  │   │     │
│  │  └─────────────────────────────┘   │     │
│  └────────────────────────────────────┘     │
│                                              │
│  ┌────────────────────────────────────┐     │
│  │      Extended TCB (System)         │     │
│  │                                     │     │
│  │  ┌──────────┐  ┌────────────────┐ │     │
│  │  │  Rust    │  │  Linux Kernel  │ │     │
│  │  │  Runtime │  │  - Syscalls    │ │     │
│  │  │  - FFI   │  │  - Networking  │ │     │
│  │  └──────────┘  └────────────────┘ │     │
│  └────────────────────────────────────┘     │
│                                              │
│  ┌────────────────────────────────────┐     │
│  │    Non-TCB (Auxiliary Services)    │     │
│  │    - Metrics                       │     │
│  │    - Logging                       │     │
│  │    - Admin UI                      │     │
│  └────────────────────────────────────┘     │
└─────────────────────────────────────────────┘
```

## Verification Evidence

### Formal Proofs
- **F* Verification**: 155 verified modules, 0 `admit()`
- **Tamarin Lemmas**: 247 security properties proven (54 models)
- **Kani**: bounded model-checking harnesses over JOSE/DPoP/token/federation
  code paths

The authoritative, regenerated snapshot of these figures is
`docs/verification/claims/assurance-case/verification-scope.md` and
`docs/verification/claims/claim-index.md`; this section is a summary only.

### Empirical Validation
- **dudect Results**: No timing leaks detected (p>0.01)
- **AFL Fuzzing**: 72 hours, 0 crashes
- **RFC 7520 Vectors**: 100% pass rate

## Supply Chain Security

### Binary Reproducibility
```bash
# Reproducible build verification
nix build .#aegaeon-server --rebuild
sha256sum result/bin/aegaeon-server
# Expected: d4f3b2c1a9e8f7d6b5c4a3e2f1d8c9b7a6e5f4d3c2b1a9e8f7d6b5c4a3e2f1d8
```

### Dependency Verification
- All dependencies pinned in Cargo.lock
- Nix flake.lock for toolchain determinism
- cargo-vet for transitive dependency audit

## TCB Update Policy

### Allowed Updates
1. **Security Patches**: CVE fixes with no API changes
2. **Verification Tool Updates**: After re-verification
3. **Compiler Updates**: After full regression suite

### Update Process
1. Update in development branch
2. Run full verification suite
3. dudect validation for CT-critical paths
4. 72-hour canary deployment
5. Gradual rollout with metrics monitoring

## Known Limitations

### Cryptographic Assumptions
- RSA-2048 considered secure until 2030
- ECDSA P-256 quantum-vulnerable
- SHA-256 collision resistance assumed

### Side Channels
- Power analysis not mitigated (cloud deployment assumed)
- Microarchitectural attacks partially mitigated (no speculation in critical paths)
- Network timing partially observable (rate limiting applied)

## Incident Response

### TCB Compromise Indicators
1. Verification proof failures in CI
2. Timing anomalies in dudect
3. Unexpected syscalls in audit logs
4. Memory safety violations in production

### Response Plan
1. **Immediate**: Isolate affected systems
2. **Short-term**: Rollback to last verified TCB
3. **Long-term**: Root cause analysis and re-verification

## Compliance Mapping

### NIST SP 800-53 Controls
- **SA-17**: Developer Security Architecture and Design
  - TCB minimization documented
- **SA-10**: Developer Configuration Management
  - Version pinning and reproducibility
- **SA-11**: Developer Testing and Evaluation
  - Formal verification and fuzzing

### Common Criteria (EAL4+)
- **ADV_ARC.1**: Security Architecture Description
  - TCB boundaries defined
- **AVA_VAN.3**: Focused Vulnerability Analysis
  - Side-channel analysis performed

## Review and Approval

- **Security Architect**: Reviewed 2025-09-02 (v1.0.0)
- **Lead Developer**: Approved 2025-09-02 (v1.0.0)
- **Compliance Officer**: Pending
- **v1.1.0 revision**: Verification-owner update 2026-07-23; re-approval due
  at next review
- **Next Review**: 2026-10-23 (quarterly)

## Appendices

### A. Tool Versions
```toml
[toolchain]
fstar = "2025.10"
z3 = "4.13.3"
karamel = "2025.10"
everparse = "2025.10"
kani = "0.66.0"
tamarin = "1.8+"
rust = "1.91.0-nightly-2025-08-28"
```

Authoritative versions are pinned in `flake.lock`; on conflict, the flake and
`docs/verification/claims/assurance-case/tcb-and-out-of-scope.md` win.

### B. Verification Commands
```bash
# F* verification
fstar --verify_all crates/fstar/*.fst

# Tamarin verification
tamarin-prover --prove proofs/tamarin/*.spthy

# Constant-time validation
dudect/dudect_bench_aegaeon

# Kani verification
cargo kani --package aegaeon-server
```

### C. Emergency Contacts
- Security Team: <security@aegaeon.example>
- On-call: +1-555-AEGAEON
- Incident Response: <incident@aegaeon.example>
