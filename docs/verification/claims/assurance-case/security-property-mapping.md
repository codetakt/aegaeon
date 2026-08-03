# Formal Verification Security Property Mapping

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split formal verification assurance case.

## 4. Security Property Mapping

This section maps verification artifacts to concrete security threats from
the OAuth Threat Model (RFC 6819) and Security BCP.

### 4.1 Authorization Code Attacks

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| Code replay | `code_replay.spthy` (2 lemmas) | `AuthCode.Store.fst` (use\_auth\_code) | Single-use enforcement |
| Code injection | `code_injection.spthy` (2 lemmas) | `AuthCode.Flow.fst` (token\_exchange) | PKCE binding verification |
| CSRF | `csrf_protection.spthy` (2 lemmas) | `par/Par.fst` | State parameter binding |
| Session fixation | `authcode_session_integrity.spthy` (10 lemmas) | `AuthCode.Flow.fst` (authorize) | Session-to-code binding |
| Refresh token theft | `refresh_token_rotation.spthy` (6 lemmas) | `AuthCode.Store.fst` | Rotation on use |

### 4.2 Token and Bearer Attacks

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| Bearer token theft | `bearer_bcp.spthy` (12 lemmas) | `token/Bearer.fst`, `Bearer.Policy.fst` | Sender-constrained tokens (DPoP/mTLS) |
| Token replay | `dpop_replay.spthy` (4 lemmas) | `dpop/Dpop.Replay.fst`, `Dpop.Nonce.fst` | JTI uniqueness + nonce binding |
| Confirmation key confusion | `cnf_single_key.spthy` (1 lemma) | `token/JwtAccessToken.fst` | Single `cnf` method per token |

### 4.3 Client Impersonation

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| Missing client auth | `token_endpoint_auth_required.spthy` | `par/Client_auth.fst` | Auth method enforcement |
| Private key JWT misuse | `private_key_jwt.spthy` (4 lemmas) | `auth/Pkjwt.fst` | Audience and expiry validation |
| Client auth bypass | `client_authentication.spthy` (2 lemmas) | `par/Client_auth.fst` | Method-specific validation |

### 4.4 Redirect and Phishing Attacks

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| Redirect URI manipulation | `par_redirect_integrity.spthy` (10 lemmas) | `par/Par.fst`, `ParBinding.fst` | PAR-bound redirect |
| Issuer mix-up | `iss_mixup.spthy` (2 lemmas) | `oidc/IdToken.fst` | Issuer claim validation |
| Open redirect | `error_redirect_state.spthy` (2 lemmas), `success_redirect_code_state.spthy` (4 lemmas) | `par/Response.fst` | Registered URI enforcement |

### 4.5 Federation Attacks

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| Trust chain forgery | `trust_chain.spthy` (9 lemmas) | `Jose.Federation.fst` | Chain signature verification + entity key uniqueness |
| Key rotation attacks | `federation_key_rotation.spthy` (6 lemmas), `key_rotation_race.spthy` (5 lemmas) | `Management.KeyRotation.fst` | Active key persistence, single-use retire |
| Trust anchor compromise | `trust_anchor_rotation.spthy` (7 lemmas) | `Jose.Federation.fst` | Anchor registry validation |
| SSRF via federation | `federation_ssrf_chain.spthy` (3 lemmas) | (Rust: `ssrf.rs`) | Private IP blocking, redirect policy |
| Cache poisoning | `cache_poisoning_resistance.spthy` (5 lemmas) | `Federation.PgRepo.fst` | Signed metadata verification |
| Policy downgrade | `policy_downgrade.spthy` (4 lemmas), `policy_enforcement_monotonicity.spthy` (7 lemmas) | `Jose.Federation.Policy.{Merge,Order,Lemmas}.fst` | Merge monotonicity, restrictiveness ordering |

### 4.6 OIDC-Specific Attacks

| Threat | Tamarin file(s) | F\* module(s) | Property |
|---|---|---|---|
| ID token replay | `id_token_nonce.spthy` (1 lemma) | `oidc/IdToken.Spec.fst` | Nonce binding |
| Logout CSRF | `logout_session_termination.spthy` (3 lemmas), `front_channel_logout.spthy` (5 lemmas) | `oidc/Logout.fst`, `Logout.Spec.fst` | Session termination integrity |
| Upstream IdP compromise | `upstream_refresh_rotation.spthy` (5 lemmas) | `federation/UpstreamRefresh.fst` (17 lemmas) | Refresh token rotation |

---
