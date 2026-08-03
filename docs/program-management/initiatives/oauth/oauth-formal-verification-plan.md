# OAuth Formal Verification Definition Catalog (F* + Tamarin)

Last updated: 2026-01-23

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document is a **planning artifact**: it enumerates the definitions/invariants/lemmas that
should be verified (F* + Tamarin) as Aegaeon expands OAuth RFC coverage.

It is not the authoritative status tracker; that remains `spec/compliance-matrix.yaml`.

## How we translate RFC text into proof obligations

For each RFC feature area, we aim to produce:

1. **Computational specification (F\*)**
   - Refinement types / invariants for parsing + validation functions.
   - Store semantics (single-use, TTL, replay windows, monotonicity).
   - Deterministic precedence rules (e.g., PAR/JAR overriding query params).
2. **Symbolic protocol model (Tamarin)**
   - Session integrity, injection resistance, replay resistance, mix-up resistance.
   - Binding properties: client↔request, token↔sender constraint, authorization↔resource.
3. **Executable evidence**
   - Rust unit/integration tests for negative paths and edge cases.
   - Optional conformance exports where appropriate (stored under `artifacts/`).

### Proof boundary rules (non-negotiable)

- Fail closed: unknown values / missing required inputs must reject (no “best effort” acceptance).
- Linear use for one-time secrets (codes, `jti`, device codes, etc.): “consumed once” is a first-class property.
- Time bounds must be explicit and configurable; verification assumes bounded skew and bounded TTLs.

## Already-verified foundations to reuse

These existing verification assets should be treated as building blocks, not reimplemented:

- Auth code + PKCE: single-use codes, bounded lifetime (`fstar/authcode`, `fstar/pkce`, Tamarin authcode/pkce).
- PAR + request_uri binding: single-use request_uri store and fixation resistance (`fstar/par`, Tamarin par).
- DPoP: proof validation + replay store + token binding (`fstar/dpop`, Tamarin dpop).
- Bearer BCP posture: no implicit/ROPC, issuer parameter, sender-constrained tokens, audience/scope policy (`fstar/token`, Tamarin bearer).
- JOSE/JWT safety: algorithm allow-lists, `none` rejection, time-claim validation (`fstar/jose`, JOSE tests).

## Target RFCs: proof obligation catalog (expansion scope)

The sections below describe what we should verify when implementing (or completing) each RFC.

### RFC 7523 (JWT Profile for Client Authentication + Authorization Grants)

#### Scope decision
- Client authentication (`private_key_jwt`, optionally `client_secret_jwt`) is in scope.
- JWT Bearer authorization grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`) should be treated as a
  separate decision and gated by policy (default off).

#### F\* definitions to verify
- `validate_client_assertion`:
  - If validation succeeds, then signature verification used an allowed algorithm and a key registered to the client.
  - Claim invariants hold: `iss=sub=client_id`, `aud` matches the expected endpoint identifier, and `exp/nbf/iat`
    satisfy configured windows.
  - `jti` is present (policy) and is accepted only once within a bounded replay window.
- JWKS resolution safety:
  - `kid`-based key selection is deterministic; unknown `kid` fails closed.
  - If a `kid` requirement is enabled, missing `kid` fails closed.
- Error mapping (security relevant):
  - Distinguish `invalid_client` vs `invalid_request` consistently and do not leak key material.

#### Tamarin lemmas to verify
- **Client authentication integrity**: an attacker cannot obtain a token “as” an honest client without the
  client’s signing key / shared secret.
- **Assertion replay resistance**: the same `jti` cannot be used to authenticate successfully twice.
- **Audience binding**: a valid assertion for endpoint A cannot be replayed at endpoint B.

### RFC 8725 (JWT Best Current Practices)

#### F\* definitions to verify
- `alg` allow-list enforcement is complete for each JWT usage category:
  - client assertions, request objects, ID tokens (when OIDC enabled), (optional) JWT access tokens.
- Reject structurally dangerous forms (`none`, unexpected critical headers if supported, oversized headers/payloads).
- Time claim monotonicity and bounded skew assumptions are explicit (`exp/nbf/iat`).

#### Implementation mapping (AS)
- Client assertions + JWT bearer: `crates/server/src/client_registry.rs` enforces alg allow-list, rejects `none`,
  validates `aud`, and binds `iss/sub` to the client registration; F* invariants in `fstar/auth/Pkjwt.fst`.
- Request Objects: `crates/jose/src/request_object.rs` enforces signing alg allow-list and rejects `none` for
  `/authorize`-scoped JWTs.
- JOSE header hygiene: `docs/policies/jose-header-policy.md` + `crates/jose/src/jws.rs` reject `jku/x5u` header
  dereferencing and bound `kid` to safe length/charset to avoid SSRF and header confusion.
- ID Token alg posture: `crates/server/src/dcr.rs` restricts `id_token_signed_response_alg` to RS256 (default). The runtime requirement is satisfied today; the stronger verification-boundary closure for that OIDC-mandated `RS256` surface is tracked separately as `RS256 Required Slice`.

#### Test/lemma alignment
- `crates/server/tests/private_key_jwt_tests.rs` ↔ `fstar/auth/Pkjwt.fst` (`pkjwt_*` invariants).
- `crates/server/tests/jwt_bearer_grant_http_test.rs` ↔ `proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy`.
- `crates/server/tests/jar_par_binding_test.rs` ↔ `crates/jose/src/request_object.rs` allow-list enforcement.

#### Tamarin lemmas to verify
- Primarily “model hygiene”: ensure JWT-based auth does not introduce new replay/injection traces beyond the intended ones.

### RFC 8705 (mTLS Client Auth + Certificate-Bound Access Tokens)

#### F\* definitions to verify
- When mTLS is enabled:
  - Token issuance requires successful client certificate authentication at the appropriate endpoints.
  - Issued tokens are bound to the certificate identity (e.g., `x5t#S256` thumbprint) in a well-defined way.
  - Token verification rejects mismatched or missing certificate bindings.
- Store semantics (if any): if binding state is stored separately, prove uniqueness and lifetime bounds.

#### Tamarin lemmas to verify
- **Sender constraint (mTLS)**: an attacker cannot use a certificate-bound token without the correct certificate.
- **Binding soundness**: the token’s binding corresponds to the certificate used at issuance (no substitution).

### RFC 8707 (Resource Indicators)

#### F\* definitions to verify
- `resource` processing:
  - Tokens are bound to the intended resource(s) (audience) and cannot be used cross-resource.
  - Resource requests are policy-checked per client and fail closed on unknown/disallowed resources.
  - Precedence rules are deterministic across `/authorize` and `/token` (and PAR/JAR integration).
- Token policy:
  - Audience restriction is enforced consistently in issuance, introspection, and RS verification logic.
- Implementation: `fstar/resource/ResourceIndicators.fst` (resource indicator validation, selection, audience binding).

#### Tamarin lemmas to verify
- **Audience separation**: tokens issued for resource A are unusable at resource B (model-level).
- Implementation: `proofs/tamarin/resource/resource_indicators.spthy` (`resource_audience_enforced`).

### RFC 7800 (Proof-of-Possession Key Semantics for JWTs)

#### F\* definitions to verify
- Confirmation (`cnf`) handling is consistent across token issuance and token introspection/verification:
  - The `cnf` structure used for sender-constrained tokens is well-formed and unambiguous.
  - If a token is issued with a PoP binding, verification rejects missing/mismatched PoP material.
- Implementation: `fstar/token/Bearer.Policy.fst` (`cnf_from_sender_binding`, `lemma_cnf_single_key`).

#### Tamarin lemmas to verify
- **PoP soundness**: tokens with PoP bindings cannot be used without satisfying the binding (modeled per binding type).
- Implementation: `proofs/tamarin/bearer/cnf_single_key.spthy` (`cnf_single_key`).

### RFC 9278 (JWK Thumbprint URI)

#### F\* definitions to verify
- Thumbprint URI construction/parsing:
  - `jwk_thumbprint_uri` is computed deterministically from the underlying JWK material.
  - Inputs are canonicalized exactly as required; ambiguous encodings are rejected.
- Interop surfaces:
  - Emit `jwk_thumbprint_uri` under introspection `sender_binding` for DPoP; keep `cnf.jkt` as the canonical PoP identifier.
  - Accept thumbprint URI forms when enforcing sender binding (normalize URI→jkt before comparison).
- Implementation: `fstar/jose/Jose.Jwk_thumbprint_uri.fst` (URI prefix and construction invariants).

#### Tamarin lemmas to verify
- Typically not required (pure identifier representation), unless it becomes part of a binding decision.

### RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens)

**Scope decision**:
- JWT access tokens should be an **opt-in** feature. Default remains opaque access tokens + introspection.

#### F\* definitions to verify
- JWT access token claim invariants:
  - `iss`, `aud`, `sub`, `exp`, `iat` constraints, and scope/audience encoding are consistent with RS verification rules.
  - Sender constraint (`cnf`) integration is correct when DPoP/mTLS is enabled.
- Implementation: `fstar/token/JwtAccessToken.fst` (`has_required_claims`, `lemma_required_claims_present`).
- Key rotation/overlap:
  - Verification succeeds across configured overlap windows and fails closed otherwise.

#### Tamarin lemmas to verify
- **Audience separation** and **sender constraint** should continue to hold when switching token format from opaque→JWT.

### RFC 8693 (Token Exchange)

#### Scope decision (Aegaeon profile)
- Token exchange is **opt-in** (operator gate; e.g., `AEGAEON_ENABLE_TOKEN_EXCHANGE=1`) and must not be advertised when disabled.
- MVP support is intentionally narrow and fail-closed:
  - `subject_token_type`: accept only `urn:ietf:params:oauth:token-type:access_token` **issued by Aegaeon** (no third-party JWT/SAML as subject_token in the first profile).
  - `actor_token` / `actor_token_type`: not supported in the MVP; the “acting party” is the authenticated OAuth client.
  - Targets: support **at most one** `resource` value (reject multiple `resource` / `audience` values with `invalid_target` per RFC 8693 §2.1.1 guidance).
  - `requested_token_type`: default to issuing an access token; reject unsupported token types with `invalid_request`.

#### F\* definitions to verify
- Request parsing + validation (RFC 8693 §2.1):
  - `grant_type` exact match (`urn:ietf:params:oauth:grant-type:token-exchange`).
  - `subject_token` and `subject_token_type` are present and non-empty; unknown token_type identifiers fail closed.
  - `actor_token_type` is REQUIRED iff `actor_token` is present and MUST NOT be present otherwise.
  - `resource` values are absolute URIs and MUST NOT include fragments (query permitted); multiple target values are rejected under the MVP profile.
- Subject token validation:
  - Subject token is _active_ (time window, revocation state, and policy checks) and corresponds to an Aegaeon-issued access token.
  - If sender-constrained tokens are in use, the token exchange policy must be explicit about whether the subject token’s sender binding is required/rechecked and what gets propagated to the issued token.
- Output token computation (core computational safety):
  - **No privilege escalation**: issued scopes and target(s) are a policy-limited function of the subject token, the requesting client’s policy, and the request parameters.
  - Issued token lifetimes are bounded and auditable; error paths are fail-closed when audit sinks fail.
- Error mapping (RFC 8693 §2.2.2):
  - Invalid requests / invalid subject tokens yield `invalid_request`.
  - Unwilling/unable to issue for requested `resource`/`audience` yields `invalid_target`.
- Response construction (RFC 8693 §2.2.1):
  - Success responses include `access_token`, `issued_token_type`, `token_type` (and `expires_in` is populated when applicable).
  - `scope` is included when it differs from the request’s scope (required by §2.2.1).

#### Tamarin lemmas to verify
- **Delegation safety**: token exchange cannot create a trace where a party gains access not derivable from prior authorization and configured policy.
- **Substitution resistance**: swapping `subject_token` (and later, `actor_token`) cannot yield higher privilege.
- **Target/scope integrity**: an attacker cannot obtain a token for a different target service or broader scope than allowed by the subject token + policy.

### RFC 9396 (Rich Authorization Requests / `authorization_details`)

#### F\* definitions to verify
- Parsing/validation:
  - `authorization_details` structure is validated (types, required fields, bounded sizes) and unknown types fail closed.
- Deterministic precedence:
  - Request Object `authorization_details` override form parameters in `/par` and `/authorize`.
  - `request_uri` (PAR) `authorization_details` override query parameters in `/authorize`.
- Binding:
  - The authorization_details accepted at authorization time are the ones reflected in the resulting tokens/introspection.
  - Composition rules with PAR/JAR are deterministic and fixation-safe (no lower-precedence override).
- Draft module: `fstar/rar/Rar.AuthorizationDetails.fst` (well-formedness + precedence selection).

#### Implementation mapping (AS)
- Parsing/validation: `crates/server/src/util.rs` (`parse_authorization_details`, `validate_authorization_details`) enforces JSON array/object shape, non-empty type, and supported types; rejects with `invalid_authorization_details`.
- PAR + Request Object precedence: `crates/server/src/web/mod.rs` (`par`) accepts Request Object `authorization_details` first, then falls back to form parameters when missing.
- /authorize PAR override: `crates/server/src/web/mod.rs` (`parse_authorize_request`) resolves `request_uri` via `authorize_with_par` and uses PAR-bound `authorization_details`, ignoring raw query values.
- Token/introspection propagation: `crates/server/src/web/mod.rs` (`persist_access_with_meta`, `introspect`) stores and returns `authorization_details` via `BearerTokenMeta`.

#### Test/lemma alignment
- `crates/server/tests/rar_authorization_details_http_test.rs` (invalid type rejection, PAR overrides query) ↔ `par_precedence_over_query`, `par_authorization_details_used`.
- `crates/server/tests/jar_par_binding_test.rs` (Request Object overrides PAR form, propagation) ↔ `request_object_overrides_form_in_par`, `par_storage_requires_auth`.

#### Tamarin lemmas to verify
- **Authorization detail integrity**: an attacker cannot inject/modify `authorization_details` between the request
  and token issuance.
- **Precedence safety**: a trace cannot exist where lower-precedence authorization_details (query/form) override
  those bound to PAR/request objects.
- Draft model: `proofs/tamarin/rar/rar_authorization_details.spthy` (`par_authorization_details_used`,
  `par_precedence_over_query`, `request_object_precedence_over_query`, `request_object_precedence_over_form`,
  `request_object_overrides_form_in_par`, `par_storage_requires_auth`).

### RFC 9470 (Step-Up Authentication Challenge Protocol)

#### F\* definitions to verify
- Challenge issuance:
  - Challenges are bound to a session/client/request and have bounded lifetime.
  - Replay of a completed challenge is rejected.
- Enforcement:
  - Step-up requirements cannot be bypassed by manipulating redirect parameters or repeating requests.

#### Tamarin lemmas to verify
- **Step-up soundness**: if a resource/policy requires step-up, the model has no trace where an access token is
  issued without the step-up event occurring.
- Draft module: `fstar/stepup/StepUp.fst` (challenge issuance, TTL bounds, replay rejection, enforcement).
- Draft model: `proofs/tamarin/stepup/stepup_soundness.spthy` (`stepup_soundness`).

### RFC 8628 (Device Authorization Grant)

#### F\* definitions to verify
- Code generation:
  - `device_code` / `user_code` uniqueness and sufficient entropy assumptions.
  - TTL bounds and single-use consumption semantics.
- Polling semantics:
  - Token polling respects authorization state transitions (pending, approved, denied, expired).

#### Tamarin lemmas to verify
- **Code injection/replay resistance**: attacker cannot redeem a device code without completing the user authorization step.

### RFC 9701 (JWT-formatted Introspection Response)

#### F\* definitions to verify
- JWT introspection response correctness:
  - Claims accurately reflect the server’s token validity decision.
  - Audience/issuer/time-window claims are consistent and verifiable by RS.
  - Signing key rotation/overlap rules are explicit.

#### Tamarin lemmas to verify
- Optional: prove that JWT introspection does not introduce a new token substitution trace beyond opaque introspection.

### RFC 9728 (Protected Resource Metadata)

**Scope decision**:
- If Aegaeon ships a reference RS component, implement and verify.
- Otherwise treat as docs-only (guidance for RS operators).

### RFC 7592 (Dynamic Client Registration Management Protocol)

**Scope decision**:
- This RFC likely belongs to the operational platform workstream (persistence + admin plane) and should be tracked as
  a management-plane feature (not a “core OAuth hot path”).

**F\* definitions to verify**
- Client update semantics (when implemented):
  - Updates preserve security invariants (no enabling implicit/ROPC, strict redirect URI matching, sender constraints).
  - Rotation/update operations are authenticated, authorised, and audited (fail-closed on audit sink failure).

#### Tamarin lemmas to verify
- Optional: model that an attacker cannot modify a registered client without possessing the correct management credentials.

## “Doc-only” RFCs (no new proofs by default)

Some RFCs are primarily guidance/registries. They may still require documentation updates and targeted tests, but
do not necessarily introduce new proof obligations:

- RFC 6755 (OAuth URN namespace), RFC 6819 (historical security considerations), RFC 8252 (native apps),
  RFC 9123 (browser-based apps).

## Turning this plan into compliance matrix rows

When implementing a target RFC:

1. Add requirement-level rows under `spec/compliance-matrix.yaml` (avoid a single tracking row).
2. Attach:
   - F\* lemma names / modules for computational properties.
   - Tamarin lemmas/files for protocol properties.
   - Rust tests covering negative paths and policy toggles.
3. Ensure metadata does not over-claim support.
