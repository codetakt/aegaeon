# Current Delivery Context Delivery Record

Last updated: 2026-07-08

Status: historical record

Owner: Engineering

Audience: contributors, maintainers

This historical record preserves the detailed delivery context that was active
before the 2026-07-08 documentation-structure cleanup. It is not the normative
product specification or active roadmap.

For the current developer-facing entrypoint, use
`docs/development/current-delivery-context.md`.

For the shortest current roadmap/status split, start with
`docs/program-management/roadmaps/summary/current-program-summary.md`.

For historical context from the May 2026 server self-review handoff, see
`docs/program-management/historical/thread-handoff-2026-05-21-aegaeon-server-review.md`.

## Current posture

- The server-side release claim is the authoritative product claim:
  - assumption-qualified
  - formally verified and security-tested
  - OAuth 2.0/2.1 and OIDC 1.0 identity-provider server
  - bounded OpenID Connect Federation **runtime support**
- The compliance matrix is currently sufficient for that server claim when read together with the
  assurance case and assumptions documents.
- The May 2026 `aegaeon-server` residual self-review list has been refreshed:
  the PAR confidential-client downgrade, JWT access-token temporal checks, DCR
  `private_key_jwt` secret echo, cross-endpoint `private_key_jwt` client
  authentication, request-URI credential guardrails, and local / management
  login rate-limit boundaries are now treated as closed unless a fresh code
  review produces new evidence.
- Legacy server compatibility surfaces are now narrower:
  `demo-token-endpoint` / `token_with_metrics` have been retired, and the JOSE
  `generic-object` raw-JSON surface is available only in test builds.
- Supported `aegaeon-server` runtime now requires the PostgreSQL-backed management snapshot for
  issuer policy, clients, and runtime keys. Startup-only runtime configuration is not a supported
  runtime mode. The former `AEGAEON_ENABLE_INTEGRATION_TEST_FIXTURES` crate-surface switch is
  retired; integration and conformance evidence must use PostgreSQL/Redis-backed fixtures without
  widening production compilation.
- PostgreSQL connection configuration is treated as bootstrap infrastructure, not runtime policy.
  `AEGAEON_DATABASE_URL` must name an explicit host. Loopback PostgreSQL may use plaintext for local
  fixtures, but non-loopback PostgreSQL must set `sslmode=require`, `sslmode=verify-ca`, or
  `sslmode=verify-full`; hostless Unix-socket style URLs are outside the supported server runtime.
- `AEGAEON_KEY_ENCRYPTION_KEY` is the supported host/bootstrap secret admission point for envelope
  encryption of managed key handles and upstream secret material. It is intentionally not stored in
  the management database; callers should inject it from the deployment secret manager with process
  environment scope and keep all policy/configuration knobs in PostgreSQL.
- Request admission intentionally revalidates the active runtime authority revision against
  PostgreSQL for every protected request instead of using the readiness cache. If the management
  database revision cannot be read, or a runtime-critical policy/key/DCR-token drift is observed, the
  server fails closed with a graceful-restart request before serving stale policy or key material.
  This is a strict correctness posture with an explicit availability tradeoff; `/health` and
  `/ready` are the only routes exempt from request-admission side effects.
- Device Authorization (RFC 8628) is entirely policy-gated. When the active runtime policy disables
  the `device_code` grant, the server omits the discovery endpoint metadata, rejects token endpoint
  `device_code` polling with `unsupported_grant_type`, and does not mount `/device_authorization`,
  `/device`, `/device/approve`, or `/device/deny` on the public router. Policy changes are applied
  through the same runtime-authority restart boundary as other router-shaping capabilities.
- OpenID Federation runtime support is bounded to RP-side trust-anchor/cache configuration and
  repository-backed trust-chain state. Public Federation OP endpoints
  (`/.well-known/openid-federation`, `fetch`, `list`, and `resolve`) are deliberately unavailable
  in the verified server runtime and return 404; there is no operator toggle to enable them.
  Bounded query parsers, entity-statement builders, and subordinate-statement builders remain as
  structural/future evidence, not as an active public OP conformance claim. Outbound Federation
  fetches use the database-backed `policy.federationOutboundAllowedDomains` allowlist when
  non-empty. Federation OP signing/entity-configuration remains deferred because it requires ES256,
  which is outside the promoted server claim boundary. Subordinate statement generation remains a
  compat/future surface until an ES256 promotion exists.
  Upstream OIDC provider HTTP calls use the separate database-backed
  `policy.upstreamOutboundAllowedDomains` allowlist when non-empty. Discovery admission applies that
  policy, plus HTTPS/no-credentials/no-query/no-fragment endpoint validation, to authorization,
  token, JWKS, and optional `end_session_endpoint` metadata. Published upstream logout endpoints are
  optional by OIDC semantics, but once present they are fail-closed under the same outbound boundary
  before relay state is appended; saved logout sessions are rechecked against the current active
  allowlist when a later logout target is constructed. Trust mark inclusion in resolve responses
  remains outside the current server claim.
- Shared Redis runtime-store URLs require `rediss://` for non-loopback endpoints; plain
  `redis://` is retained only for loopback development fixtures.
- The SDK/client track is release-ready from a runtime/readiness perspective, and publication-org
  rollout evidence is now ready; the released client claim is still gated by fresh hosted evidence,
  release custody, and public activation.
- The broader management-platform follow-on is no longer blocked on basic UI / SDK scaffolding:
  the sibling `aegaeon-sdk` repository now carries the `verified-core`, `runtime-node`,
  `runtime-web`, `management-client`, `issuer-spa`, and `rp-core` package workspaces plus hosted
  workflow contracts, and the sibling `aegaeon-admin-console` repository now carries a hosted
  stack-backed browser lane and source-managed SDK/auth boundary contracts.
- Repository-governance alignment is partially hardened across the server and sibling repositories:
  - commitlint, workflow inventory, and hook-driven file hygiene are already aligned across
    `aegaeon`, `aegaeon-sdk`, and `aegaeon-admin-console`
  - the TypeScript strict-type policy is source-managed in this repository's SDK scaffold/tests and
    in the sibling `aegaeon-sdk` workspace, with the current `runtime-node`, `runtime-web`,
    `verified-core`, and `issuer-spa` surfaces included
  - the server-side Rust strict-Clippy lane is now workspace-wide across this repository's current
    Rust packages: `aegaeon-client`, `aegaeon-core`, `aegaeon-crypto`, `aegaeon-jose`,
    `aegaeon-jose-tlv`, `aegaeon-loadtest`, `aegaeon-observability`, `aegaeon-server`, `ffi`, and
    `xtask`
  - the lane keeps `clippy::cargo` enabled while suppressing
    `clippy::multiple_crate_versions` as dependency-topology noise
  - a repo-wide strict-Rust claim is now accurate for the current Rust workspace in this
    repository
- The performance/load-smoke harness is now in a stable incremental posture:
  - `aegaeon-loadtest` covers the delivered sender-constrained success-path smokes for
    `dpop`, `introspection`, `revocation`, `par`, `mixed`, supporting-endpoint smokes for
    `discovery` and `jwks`, and an OIDC-backed `policy-mixed` scenario that intentionally mixes
    successful requests with expected policy rejections across `/introspect`, `/revoke`, and
    `/userinfo`
  - `performance.yml` now runs the public `smoke` load lane plus the OIDC-backed `policy-mixed`
    smoke on scheduled/manual heavy runs, while `push main` still limits itself to observability
    and coverage
- The JOSE raw JSON promotion now covers Phase 2, the full Phase 3 narrow-claim set, the
  Phase 4 broad-surface cleanup, the Phase 5 generic-object isolation, and the
  Phase 6 public-architecture simplification:
  - `ALL_RAW_JSON_SURFACES` now inventories the 11 promoted source-managed
    surfaces in normal builds
  - `PROMOTED_RAW_JSON_SURFACES` and `COMPAT_ONLY_RAW_JSON_SURFACES` now make the
    eleven promoted surfaces vs zero normal compat-only surfaces explicit in code
  - `verified-structural-v1` is now the default source-managed backend for the
    `jose-header`, `request-object`, `client-registration`,
    `software-statement`,
    `private-key-jwt-payload`, `jwt-bearer-assertion-payload`,
    `oidc-id-token-payload`, `jwt-access-token-header`,
    `jwt-access-token-payload`, `federation-entity-statement`, and
    `federation-trust-mark` surfaces
  - `current_claim_posture_for_surface(...)` now records `verified-structural-v1` plus
    `raw-bytes` for those eleven promoted surfaces
  - JOSE Low* normalization and the optional TLV bridge still share the same typed
    `key + (string | null)` decoder derived directly from verified structural IR
  - Required-RS256 OIDC ID Token verification now uses a typed `IdTokenClaims` decoder over
    structural IR rather than `serde_json::from_value(...)`, while still admitting open-ended
    additional claims as bounded per-member JSON values
  - JWT access-token verification now uses a typed header decoder over structural IR for the
    promoted `jwt-access-token-header` surface, extracting `kid` and `typ` without routing that
    path through a broad `serde_json::Value` object first
  - JWT access-token verification now also uses a typed payload decoder over structural IR for the
    promoted `jwt-access-token-payload` surface, extracting `iss` / `sub` / `aud` / `exp` /
    `iat` / `jti` without routing that path through a broad `serde_json::Value` object first
  - federation entity-statement parsing now uses a typed `EntityStatement` decoder over
    structural IR for the promoted `federation-entity-statement` surface, extracting
    `iss` / `sub` / `iat` / `exp` directly and admitting `jwks`, `metadata`,
    `metadata_policy`, `constraints`, `trust_marks`, `authority_hints`, and
    `source_endpoint` only as bounded per-member JSON values
  - federation trust-mark parsing now uses a typed `TrustMarkClaims` decoder over
    structural IR for the promoted `federation-trust-mark` surface, extracting
    `iss` / `sub` / `id` / `iat` / `exp` / `ref_` without routing that path
    through whole-object `serde_json::Value` materialization
  - the FFI structural fallback now scans number / bool / array / object values well enough to
    keep the OIDC promoted path fail-closed without dropping back to the generic serde object
    materialization route
  - request-object verification now decodes `RequestObjectClaims` plus the
    JWT validation subset from admitted top-level members produced by the
    promoted verified structural backend, so the claim-bearing path now
    reports `raw-bytes` while keeping open-ended fields such as
    `authorization_details` bounded as per-member JSON values
  - dynamic client registration now decodes `ClientRegistration` from admitted
    top-level members produced by the promoted verified structural backend with
    alias-aware duplicate rejection, so the create / update metadata path now
    reports `raw-bytes` while keeping open-ended fields such as `jwks` bounded
    as per-member JSON values
  - `software-statement`, `private-key-jwt-payload`, and
    `jwt-bearer-assertion-payload` now use dedicated `raw_json` surfaces
    instead of the shared `generic-object` selector, while DPoP nonce handling
    now comes directly from the verifier result
  - `private-key-jwt-payload` is the first post-Phase-6 promoted surface: it
    defaults to `verified-structural-v1`, reports `raw-bytes`, and validates
    registered claim shape through the same per-surface raw JSON decoder used by
    the promoted RS256 `private_key_jwt` and JWT bearer grant assertion slices
  - `jwt-bearer-assertion-payload` is now also promoted: it defaults to
    `verified-structural-v1`, reports `raw-bytes`, and validates registered
    claim shape through the same per-surface raw JSON decoder used by the JWT
    bearer grant assertion path
  - `software-statement` is now promoted under SSA Profile v1: it defaults to
    `verified-structural-v1`, reports `raw-bytes`, validates registered claim
    shape through the same per-surface raw JSON decoder, decodes recognized DCR
    metadata claims through the typed `ClientRegistration` field parser, rejects
    metadata alias collisions and nested `software_statement` fail-closed, and
    preserves unknown extension claims outside the promoted profile claim
  - the legacy `generic-object` raw JSON surface is now isolated to `test`
    builds; when compiled for tests it remains a compat boundary at
    `SerdeCompat` plus `top-level-object-members` and rejects structural-backend
    selection fail-closed
  - broad semantic object decode helpers are now explicitly separated as
    compat-only helpers, so promoted paths are described in surface-first
    terms and do not rely on a generic decode API
  - `software-statement`, `private-key-jwt-payload`, and
    `jwt-bearer-assertion-payload` now share a JOSE-owned registered-claims
    decoder over per-surface admitted top-level members, so those JWT-family
    paths no longer duplicate generic claim-shape parsing in server helpers
  - `software_statement`, `jwt_bearer`, and server-side client assertion
    verification now use the same narrow verification helper, so those
    JWT-family paths no longer depend on
    `jsonwebtoken::decode::<serde_json::Value>(...)` before the per-surface raw
    JSON duplicate-key / claim-shape gate runs
  - the remaining implicit `generic-object` convenience wrappers in
    `aegaeon_jose::raw_json` are now gated behind `test`; steady-state code
    must select a surface explicitly instead of relying on the default
    generic-object route
  - client assertion and `jwt_bearer` verification now reuse the request-object
    decoding-key resolver and no longer depend on
    `jsonwebtoken::decode::<serde_json::Value>(...)`; signature validation uses
    a narrow registered-claims probe while per-surface raw JSON decoding remains
    authoritative for duplicate-key rejection and top-level claim-shape checks
  - the active DCR `POST /register` and `PUT /register/{client_id}` routes now
    fail closed when a `software_statement` is present but unverifiable, so
    SSA verification is enforced consistently on both create and update paths
  - DCR is now a database policy capability: metadata and OIDC discovery publish
    `registration_endpoint` only when `policy.dcrEnabled` is active, and public
    DCR routes return JSON 404 while the capability is disabled
  - the next JOSE parser increment is deeper structural-parser coverage rather
    than more concrete claim-bearing surface promotion; `generic-object`
    compatibility and `SerdeCompat` raw-JSON backend selection are now test-only
- The remaining broad management-platform work is now concentrated in release-candidate evidence
  refresh and operational hardening:
  - hosted repository-settings confirmation
  - managed-provider evidence from provisioned real tenants
  - released client claim activation and package publication
  - release-candidate security evidence archive creation
  - management / issuer SLO baseline refresh from hosted or self-hosted evidence
- The KMS/HSM-backed OIDC signing follow-on now has an explicit backend design baseline in:
  - `docs/design/oidc-kms-signing-design.md`
  - production runtime-key wiring now exists for `databaseEncrypted` and feature-gated
    awsKms `OIDC_ID_TOKEN_SIGNING` keys from the management-database snapshot;
    production `aegaeon-server` rejects startup `AEGAEON_OIDC_SIGNING_*`
    variables, which are limited to focused parity/evidence harnesses outside
    the server runtime authority
  - a focused LocalStack-aware AWS KMS OIDC parity test now exists in
    `crates/server/src/oidc/config/tests/kms_parity.rs` and runs as the
    `test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt`
    library test
  - a fail-closed parity evidence lane now exists in:
    - `scripts/validation/run_oidc_kms_parity.sh`
    - `.github/workflows/oidc-kms-parity.yml`
  - an operator runbook now exists in:
    - `docs/operations/oidc-kms-signing.md`
    - `docs/operations/kms-hsm-deployment-classification.md`
  - the KMS/HSM implementation boundary is intentionally narrow:
    - claim-preserving classification applies per concrete OIDC ID Token
      `RS256` signing deployment only
    - hosted bootstrap and the management runtime-key API can create
      `OIDC_ID_TOKEN_SIGNING` `awsKms` runtime keys when built with `kms-aws`;
      the management path is limited to OIDC ID Token `RS256`, derives the
      public JWK from AWS KMS before persistence, stores the encrypted KMS key
      identifier as the key handle, and stores only the public `region` in
      provider configuration
    - JWT access-token signing, JWT introspection signing, OpenID Federation
      signing, and OIDC request-object decryption remain `databaseEncrypted` runtime-key
      surfaces
  - a source-managed classification schema / validator now exists in:
    - `spec/kms-hsm-deployment-classification.schema.json`
    - `scripts/validation/validate_kms_hsm_classification.py`
  - source-managed baseline classification manifests now exist in:
    - `docs/releases/evidence/kms-hsm-classifications/aws-kms-localstack-rs256-claim-preserving.json`
    - `docs/releases/evidence/kms-hsm-classifications/external-finished-jwt-gateway-compat-only.json`
  - remaining Workstream E gaps are now:
    - fresh hosted or production KMS/HSM classification manifests backed by
      deployment-specific parity evidence
- Stronger product claims remain future-gated:
  - `docs/program-management/roadmaps/active/enterprise-readiness-certification-ui-claim-plan.md`
  - `docs/program-management/roadmaps/active/verified-server-client-formal-claim-roadmap.md`
  - `spec/enterprise-readiness-claim.current.json`
  - `spec/certification-claim.current.json`
  - `spec/admin-ui-assurance-claim.current.json`
  - `spec/server-client-formal-assurance-claim.current.json`
  - `scripts/validation/validate_claim_gates.py`
  - `scripts/validation/validate_server_client_formal_assurance.py`
  - `scripts/validation/validate_server_client_pre_public_blockers.py`
  - `docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json`
  - `docs/releases/evidence/phase5-pre-public-blockers.json`
  - combined server/client formal-assurance wording is now explicitly separated
    from the current released server claim: the Phase 5 gate stays inactive
    until the released-client claim, hosted evidence, publication custody,
    release security archive, and multi-review signoff are complete
  - Phase 5 is internally complete for the bounded server/client formal-assurance
    gate: the claim gate is source-managed, required TCB boundaries are
    machine-checked, the internal evidence bundle validates, all non-public
    blockers are closed by a dedicated pre-public report, and public wording
    remains blocked only by activation tasks: released-client activation, fresh
    hosted evidence, release security archive, release custody review, external
    review, and final public wording release
  - phase execution and public wording are now explicitly separated:
    engineering work for Phase 2 certification and Phase 3 admin UI assurance
    may proceed while Phase 1 external enterprise-readiness evidence remains
    blocked; Phase 4 remains the only public claim activation checkpoint
  - Phase 2 certification is internally complete for the bounded
    `OIDF OpenID Provider Config + Basic internal evidence baseline`:
    `docs/releases/evidence/certification-phase2-internal-bundle.json` validates the
    current local conformance exports, explicit non-PASS dispositions, inactive
    certification claim gate binding, and `public_claim_ready=false`; external
    OIDF submission / review / public listing remains deferred to Phase 4
  - Phase 3 admin UI assurance is internally complete for the bounded admin
    control-plane security boundary:
    `docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json` validates the
    assurance case, finite state-machine model, OpenAPI to management-client
    operation coverage, write-method CSRF/Origin guard hooks, inactive admin UI
    claim gate binding, and `public_claim_ready=false`; hosted admin-console
    runtime evidence remains deferred to Phase 4
  - Phase 4 internal preflight is complete:
    `docs/releases/evidence/phase4-claim-activation-preflight.json` validates that
    enterprise-readiness, certification, and admin UI assurance claim gates stay
    inactive; internal schemas, validators, runbooks, and internal bundles are
    present; and every non-complete activation item is explicitly listed as an
    external hosted-evidence, external certification/publication, or public
    wording release blocker
  - claim-gate validation now rejects duplicate `required_evidence` IDs, insecure
    `http://` evidence URIs, and absolute local evidence paths before any stronger claim can be
    activated
  - local procedures / validators now exist for regulated runbooks, hardened deployment,
    managed-provider evidence, publication-org rollout evidence, release-security evidence,
    enterprise SLO baselines, KMS/HSM classification, and the consolidated
    enterprise-readiness evidence bundle
  - enterprise managed-provider evidence now requires an HTTPS issuer, hosted passing lane,
    shaped GitHub source metadata, no more than 168 hours of generated-at age at the source or
    archive reference time, released-client claim phase, non-compat default profile, non-empty
    promoted client slices, and any compat-only surfaces recorded outside the released-client
    formal claim
  - publication rollout readiness now requires non-empty detail on completed tasks, KMS/HSM
    approved classifications require a reviewer in both claim-preserving and compat-only modes,
    and enterprise SLO baselines require an HTTPS deployment target URL
  - `scripts/validation/validate_enterprise_readiness_phase1.py` now provides the final Phase 1
    closure check: canonical required evidence IDs must be complete, `claim_active` must remain
    false, the bundle must point at the same claim gate under review, and the approved
    enterprise-readiness bundle must validate
  - the enterprise-readiness bundle validator now validates release-security manifests in
    enterprise mode, requiring non-empty required `publication`, `managed_provider`,
    `performance`, and `kms` evidence groups while keeping ordinary non-enterprise release
    manifests less constrained; it also requires the release manifest's publication group to
    contain a required local `sdk-release-publication-bundle` that passes enterprise-ready SDK
    publication semantics; it also requires the bundle's publication rollout report,
    managed-provider evidence, enterprise SLO baseline, and KMS/HSM classification manifests to be
    linked as required local evidence in the same release manifest, requires `sha256` on every
    required release-manifest evidence item, verifies local evidence hashes, rejects required local
    evidence paths that are absolute or escape the release archive root, rejects duplicate resolved
    KMS/HSM classification paths in the bundle, rejects duplicate evidence item IDs within a
    release-manifest evidence group, rejects insecure or incorrectly typed required external
    release-manifest evidence URIs in all validation modes,
    rejects nested KMS parity and SLO report / observability URIs that use `http://` or escape
    their manifest evidence directories, and rejects server-release evidence whose
    `source_revision` differs across the bundle, release manifest, KMS/HSM classification, and
    enterprise SLO baseline; the bundle `release_id` must also match
    the referenced release manifest `release_id`; referenced evidence
    `generated_at` timestamps must not be after the bundle `generated_at`; final activation review
    can additionally use `--require-approved` to require approved reviews on the bundle, release
    manifest, KMS/HSM classifications, and enterprise SLO baseline
  - `scripts/flake/verify_reqs.sh` now runs claim-gate, admin UI assurance,
    certification evidence, Phase 4 preflight, and enterprise-readiness
    validator semantic self-tests before proof-reference and runtime-link checks
  - remaining enterprise-readiness blockers are publication-org rollout, real managed-provider
    tenant evidence, concrete KMS/HSM deployment manifests, release-candidate evidence archive,
    fresh management / issuer SLO evidence, and a validated release-candidate evidence bundle
  - `docs/releases/runbooks/phase1-evidence-acquisition.md` is the current operator runbook for
    regenerating those external artifacts and feeding them into the Phase 1 collector
  - the 2026-05-20 Phase 1 closure attempt is recorded in
    `artifacts/phase1-closure-attempt/current/phase1-closure-status.json`; it is a failed
    closure record, not activation evidence
- The admin console is **not publicly claimed as a formally verified UI**. The bounded
  admin control-plane security boundary now has an internal assurance case and
  mechanically checked state-machine/drift model, but public wording remains blocked until hosted
  runtime evidence and Phase 4 activation review are complete.
- The preferred admin-console runtime shape remains a browser SPA. If stronger administrator
  reauthentication or step-up is added, the assurance-bearing logic must stay on a server-owned
  management-auth surface rather than in runtime SSR/BFF/frontend code paths.

## Current repo-wide boundaries

- Server claim boundary:
  - `docs/product-positioning.md`
  - `docs/verification/claims/assurance-case.md`
  - `docs/verification/claims/assumptions.md`
- Admin console control-plane/auth boundary:
  - `docs/development/admin-console-handoff.md`
  - sibling `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json`
  - sibling `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`
- Current local-credential-plane design:
  - `docs/specs/primary-authority-local-credential-plane.md`

## Current roadmap status

- The federated broker / downstream IdP roadmap Phase B is complete in the current source tree.
  - B1-B7 are delivered in the server, generated management-client surface, and the sibling admin
    console.
  - This completion was revalidated on 2026-04-27 against the current source trees with targeted
    server, SDK, and admin-console regression runs.
  - The 2026-04-27 revalidation repaired two evidence-layer regressions:
    - the feature-gated upstream logout E2E fixture had drifted after `UpstreamAuthRequest` gained
      `claim_release_policy`
    - the admin-console federation diagnostics tests were made time-stable so expiry-derived
      health assertions no longer depend on wall-clock date
  - Account-link remediation now fails closed for:
    - stored upstream refresh-token reassignment without explicit handling
    - low-confidence conflict resolution without explicit handling
    - reassignment to non-`ACTIVE` local users without explicit handling
  - Follow-on operational platform work is now tracked in
    `docs/program-management/roadmaps/future/future-projects.md`.
- The Primary Authority user-management roadmap Phase A is complete.
  - A1-A6 are delivered in the server, generated OpenAPI/SDK surface, and the sibling admin
    console.
  - The local credential plane remains server-handled on `/auth/*`; do not move credential
    submission into the admin SPA.
- The broader management-platform follow-on remains active, but its center of gravity has shifted.
  - The sibling `aegaeon-sdk` repository now carries hosted workflows
    (`verify-core.yml`, `ci.yml`, `lint.yml`, `playwright.yml`, `managed-provider-evidence.yml`,
    `client-claim-promotion.yml`, `released-client-readiness.yml`, `publish.yml`) and the
    source-managed spec contracts they rely on.
  - The sibling `aegaeon-admin-console` repository now carries hosted workflows
    (`ci.yml`, `lint.yml`, `stack-e2e.yml`) plus source-managed SDK/auth boundaries and admin-SDK
    evidence schema.
  - The remaining work is no longer “build the first UI/SDK surfaces”, but “promote the existing
    surfaces through hosted evidence, publication custody, and operations hardening”.

## Current execution priority

The current implementation priority is:

1. keep Phase A fail-closed and regression-tested across server, SDK, and admin console
2. continue the follow-on operational platform workstream tracked in
    `docs/program-management/roadmaps/future/future-projects.md`
3. preserve the delivered issuer-plane/control-plane boundary while iterating on local credentials

The key design decision for the delivered local credential plane remains fixed:

- end-user credential submission must be **server-handled / server-terminated**
- the current admin console must remain a control-plane SPA
- password / reset / activation / MFA / WebAuthn submission must not be added to the current admin
  SPA

Read these before changing local credential behavior:

- `docs/specs/primary-authority-user-management.md`
- `docs/specs/primary-authority-local-credential-plane.md`

## Local credential plane maintenance rule of thumb

When modifying local credential capabilities, keep the split in this order:

1. database tables and migration
2. management-plane issuance/revocation APIs
3. issuer/auth server-handled endpoints
4. SDK source-of-truth and sibling SDK package updates
5. focused tests
6. admin-console control-plane affordances only

Do **not** start by adding password/reset forms to the current admin console.

## Operational note

- The current local evidence for Phase B completion is the 2026-04-27 targeted regression pass
  across:
  - server federation configuration / JIT / claim-release / account-link / upstream logout tests
  - the sibling `@aegaeon/management-client` test suite
  - the sibling admin-console broker / federation route tests
- Treat broader CI or mirror status as an operational signal only when it has been freshly checked;
  do not use stale mirror state as a substitute for the local source trees or the normative docs
  above.
