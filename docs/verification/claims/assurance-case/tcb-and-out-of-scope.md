# Formal Verification TCB And Out-of-Scope Boundaries

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split formal verification assurance case.

## 2. Trusted Computing Base (TCB)

The TCB is the set of components that must be correct for the verification
results to hold. A bug in any TCB component could invalidate all guarantees.

### 2.1 Verification Toolchain

| Component | Version | Role | Compromise impact |
|---|---|---|---|
| **F\* compiler** | 2025.10 (OCaml) | Type-checks F\* source, generates proof obligations | Could accept invalid proofs |
| **Z3 SMT solver** | 4.13.3 | Discharges proof obligations from F\* | Could report `sat` for unsatisfiable formulas (soundness bug) |
| **Tamarin prover** | 1.8+ | Verifies protocol security lemmas | Could report `verified` for false security properties |
| **Kani** | 0.66.0 (CBMC backend; pinned via `nix/kani/package.nix`) | Bounded model checking for Rust | Could miss counterexamples within bounds |
| **EverParse** | 2025.10 | Generates verified parsers from `.3d` schemas | Could produce incorrect C code |
| **KaRaMeL** | 2025.10 | Extracts F\* to C | Could introduce bugs during extraction |

### 2.2 Compilation and Runtime

| Component | Role | Compromise impact |
|---|---|---|
| **Rust compiler** (rustc + LLVM) | Compiles Rust source to machine code | Could miscompile verified invariants |
| **C compiler** (gcc/clang) | Compiles KaRaMeL/EverParse output and C ABI shim | Could miscompile extracted code |
| **OS kernel** (Linux) | Process isolation, memory protection, syscalls | Could violate memory isolation |
| **Hardware** (CPU, RAM) | Executes instructions | Could produce incorrect results (bit flips, speculative execution) |
| **Nix build system** | Reproducible builds, dependency pinning | Affects reproducibility, not correctness directly |

### 2.3 Runtime Dependencies (Unverified)

| Component | Role | Why it's trusted without proof |
|---|---|---|
| **aws-lc-rs / ring** | Runtime cryptography (RSA, ECDSA, AES-GCM, SHA-2, HKDF, CSPRNG) | FIPS-validated (aws-lc-rs), extensively audited; formal verification of these libraries is out of scope |
| **axum / hyper / tokio** | HTTP server, async runtime | Standard Rust ecosystem; memory safety from Rust ownership model |
| **serde / serde\_json** | JSON serialization/deserialization | EverParse provides defense-in-depth at FFI boundary |
| **PostgreSQL** (via sqlx) | Persistent storage | Database correctness and ACID properties are assumed |
| **Operating system entropy** (`/dev/urandom`) | CSPRNG seed | Assumed to provide cryptographically secure randomness |

---

## 3. What Is NOT Verified

This section documents honest gaps — areas where verification does not apply.

### 3.1 Runtime Cryptography

The F\* specifications model cryptographic primitives (signatures, hashes, RNG)
as abstract functions with assumed properties (correctness, unforgeability,
collision resistance). The runtime story is therefore split in two:

- **Verified-profile crypto**: the verified allowlist and linked verified paths
  (for example `HS*`, `EdDSA`, verified parsing, and verified ChaCha20-Poly1305)
  participate in the current strong-constraint claim.
- **Compat-profile crypto**: broader interoperability surfaces (`RS*`, `PS*`,
  `ES*`, AES-GCM, RSA-OAEP, and similar runtime paths) remain outside that
  claim unless a narrower exception is explicitly promoted.

This distinction matters for OIDC: the OP mandatory `RS256 Required Slice` and
the server-side `RS256 Interop Slice` (signed Request Objects, `request_uri`,
JWT bearer grant assertions, `private_key_jwt`) are explicitly promoted exceptions for the server claim,
while broader RSA / JOSE interoperability remains outside the current released
claim.

**Risk mitigation:** compat crypto paths rely on production-grade libraries such
as `aws-lc-rs`, `ring`, `p256`, or pure-Rust implementations, but those paths do
not become formally verified merely by being implemented. The abstract F\*
models capture the *security properties* these libraries must provide, enabling
verification of the protocol logic *assuming* the crypto is sound.

### 3.2 Network I/O and HTTP Handling

All network communication, TLS termination, HTTP request/response handling, and
middleware execution is handled by axum/hyper/tokio and is outside the
verification scope. The Tamarin model abstracts the network as an adversary-
controlled channel, which is sound for protocol analysis but does not verify
the implementation of the network stack.

### 3.3 Database Operations

PostgreSQL interactions (connection pooling, query execution, transaction
isolation, migration application) are not verified. The F\* specifications model
storage as in-memory sequences (`FStar.Seq`); the actual persistent storage
layer is trusted.

### 3.4 Concurrency and Thread Safety

Multi-threaded execution correctness relies on Rust's ownership model and
Tokio's cooperative scheduling. F\* specifications are sequential (single-thread
model). The Tamarin model reasons about interleaving at the protocol level
(message ordering) but not at the implementation level (thread scheduling).

### 3.5 Configuration and Environment

Parsing of environment variables (`AEGAEON_*`), TOML/YAML configuration files, and
runtime feature flags is not formally verified. Misconfiguration can undermine
verified properties (e.g., disabling DPoP nonce requirement).

### 3.6 Third-Party Dependencies

Beyond the cryptographic libraries listed in Section 2.3, the full dependency
tree (200+ crates) is not formally verified. Supply-chain integrity relies on
`cargo vet`, `cargo audit`, and Trivy scanning — not formal methods.

### 3.7 EverParse Schema Verification (RESOLVED)

All 7 EverParse `.3d` schemas are now F\*-verified in CI. The `Dpop` module name
conflict was resolved by creating renamed copies (`DpopSchema.fst`/`.fsti`) for
F\* verification while preserving the original files for the C build pipeline.
Runtime invocation remains narrower than schema verification coverage and is
tracked in `docs/verification/runbooks/extraction-status.md`.

---
