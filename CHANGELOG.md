# Changelog

All notable changes to Aegaeon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0-beta] - 2026-02-19

### Added

#### Core (Phases 0-2)
- OAuth 2.0 Authorization Server (RFC 6749) with Authorization Code flow and PKCE S256 (RFC 7636)
- Token endpoints: `/oauth/token`, revocation (RFC 7009), introspection (RFC 7662), PAR (RFC 9126), DCR (RFC 7591), and discovery metadata (RFC 8414)
- Sender-constrained tokens with DPoP (RFC 9449) and policy gates aligned with OAuth 2.0 Security BCP (RFC 9700)
- JOSE/JWT implementation (RFC 7515-7519) with algorithm allow-lists and RFC 7520 test vectors
- Optional OIDC mode (feature-flagged): ID Token issuance, discovery, UserInfo, logout, and Request Objects (JAR) replay protection
- Reproducible builds and verification via Nix Flakes

#### Phase 3/3b
- SD-JWT (RFC 9901) selective disclosure support
- OIDC RP upstream IdP brokering (authorize, callback, refresh routes)
- OpenID Connect Federation Phase 1 (entity configuration, subordinate statements)
- Upstream refresh token rotation with verified F* specification (OIDC-1-009, 17 lemmas)
- Supply chain hardening with `cargo-vet` integration
- CI expansion (12 to 35 workflows)

#### Phase 4-5
- Federation Phase 2: PostgreSQL repositories, RP wiring, trust chain verification
- Policy CRUD endpoints (`/oauthProfiles`, `/clientPolicyProfile`) with time-bounded exceptions and downgrade detection
- Audit read endpoints (list, filter, cursor pagination, JSON/CSV export)
- Connection CRUD endpoints for upstream IdP management

#### Phase 6
- RFC 8628 Device Authorization Grant
- RFC 9701 JWT Token Introspection
- RFC 9728 Protected Resource Metadata
- Federation OP: entity configuration, subordinate statement, fetch/list/resolve endpoints

#### Phase 7
- Upstream refresh rotation end-to-end verified (F* 17 lemmas + mock IdP e2e tests)
- Federation ES256 signing migration (HS256 to ES256 via ring ECDSA P-256)

#### Phase 8/8b
- SSRF defense module: private IP blocking and redirect policy enforcement
- Trust Mark verification: JWS signature check, claims validation, status URL verification
- RFC 7592 DCR Management: GET/PUT/DELETE `/register/{client_id}` with `registration_access_token` authentication and token rotation
- RFC 9068 JWT Access Tokens: `at+jwt` typ header, `cnf` claim binding (DPoP `jkt` and mTLS `x5t#S256`), metadata advertisement, opt-in via `AEGAEON_ENABLE_JWT_ACCESS_TOKENS`
- CI remediation: Nix v27, dtolnay/rust-toolchain alignment, `cargo deny`/`cargo audit` gate, Trivy pinning, workflow deduplication, `clippy -D warnings` gate

#### Phase 9
- OAuth 2.1 migration runbook (`docs/operations/oauth21-migration-runbook.md`)
- C ABI shim (`c/verified_core.c`, `include/verified_core.h`) wrapping KaRaMeL-extracted F* code with stable `vc_*` public API
- OAuth 2.1 compliance matrix: 42 rows (v21-001 to v21-041) covering all MUST/SHOULD requirements
- WASM smoke tests: 31 structural + 28 functional = 59 tests
- OAuth 2.1 enforcement integration tests (37 tests)

#### Phase 10
- SECURITY.md and CODE_OF_CONDUCT.md for OSS publication readiness
- CHANGELOG.md with comprehensive Phases 0-9 release notes
- README.md quickstart with 5-minute demo and OIDC signing key fixture
- Minimal sample RP (`examples/minimal-rp/`) demonstrating Authorization Code + PKCE flow
- Roadmap documentation: external-conformance-and-beta-plan.md, future-projects.md, current-execution-plan.md

#### Phase 11
- DPoP Nonce (RFC 9449 §5): server-side nonce generation, time-bounded rotation with grace period, `use_dpop_nonce` error code
- JAR metadata: `request_object_signing_alg_values_supported` discovery initialization
- OIDF conformance CI workflow (`.github/workflows/oidf-conformance.yml`) with correct plan names and plan discovery validation
- F* `Dpop.Nonce.fst` (4 lemmas, 0 admit): freshness, binding, rotation safety, enforcement
- Compliance matrix: 4 new entries (9449-011 through 9449-014), 308 total
- Plan discovery script (`scripts/oidf_conformance/discover_plans.sh`)

### Changed

#### Phase 7
- F* admit() complete closure: 4 remaining sites eliminated (0 total across all verified modules)
- Tamarin: SD-JWT and DCR proofs added (48 to 50 files)

#### Phase 8/8b
- F* assume val proofs: 10 proved (3 HeaderParser + 4 HeaderKeyLemmas + 3 quick wins)
- Tamarin expansion: 50 to 54 files, 247 lemmas (refresh rotation 6, trust anchor rotation 7, FCL 5, userinfo 5, SD-JWT/DCR 23)
- F* specifications added: TrustMark.fst (5 lemmas), JwtAccessToken.fst (5 lemmas), DcrManagement.fst (5 lemmas)

#### Phase 8c
- Tamarin: 6 failing files fixed (3 federation + 3 management), 37 lemmas across 6 files, all verified

#### Phase 9
- Nix verified-core-wasm.nix updated with C ABI shim integration

#### Phase 11
- DPoP nonce grace period bounded by `rotated_at + TTL`

### Fixed

#### Phase 3/3b-5
- C-1: Critical session fixation vulnerability
- C-2: Token endpoint CSRF
- C-4: Critical authorization bypass in federation trust chain
- H-1 through H-5: High-severity authentication and authorization issues
- M-1 through M-9: Medium-severity operational and policy enforcement issues

#### Phase 7
- S-FED-1: Federation entity list rate limiting
- S-FED-3: Federation signing algorithm upgrade (HS256 to ES256)
- S-JI-1: JWT introspection authentication configuration

#### Phase 8/8b
- P8-SSRF-1 (Medium): Private IP blocking for SSRF defense
- P8-SSRF-2 (Low): Redirect policy enforcement
- P8-TA-1 (Low): Trust Mark logging improvements
- P8-CACHE-1 (Info): LRU cache eviction policy

#### Phase 9
- H1: Optional handle registration failures in `vc_dpop_verify`/`vc_jwt_verify` silently downgraded validation (silent validation bypass)

### Security
- Formal verification: F* (155 modules, 0 admit, 11 assume vals across 5 files — see [Assumption Register](docs/verification/claims/assumptions/current-register.md)), Tamarin (54 files, 247 lemmas), Kani (139 harnesses)
- EverParse, KaRaMeL extraction, dudect constant-time analysis, fuzzing
- SBOM generation (`nix run .#security-sbom`) and dependency policy checks (`cargo deny`, `cargo audit`, `cargo vet`)
- 25 security findings across all phases — all resolved with audit trails
- Supply chain: cargo-vet integration, Trivy container scanning, Grype vulnerability scanning

### Documentation
- Operator policy toggles and environment configuration under `docs/`
- OAuth 2.1 migration runbook (`docs/operations/oauth21-migration-runbook.md`)
- Compliance matrix: 308 entries across 48+ RFC/OIDC specifications

### Testing
- 1151+ tests total (1092 Rust workspace + 59 WASM/shell), 0 failures
- Progression: 831 (Phase 4) -> 894 (Phase 5) -> 961 (Phase 6) -> 971 (Phase 7) -> 1027 (Phase 8) -> 1044 (Phase 8b) -> 1134 (Phase 9) -> 1151 (Phase 11)

---

For detailed RFC coverage, see [spec/compliance-matrix.yaml](spec/compliance-matrix.yaml).
