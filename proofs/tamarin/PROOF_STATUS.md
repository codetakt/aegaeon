# Tamarin Proof Status

Last updated: 2026-03-10

## Summary

- **54 total `.spthy` files** in `proofs/tamarin/`
- **50 claim-supporting models verified in CI** via `ci/tamarin_proofs.sh` / `scripts/flake/verify_tamarin.sh`
- **215/215 claim-supporting lemmas verified** in the fresh 2026-03-10 baseline rerun
- **2 extended models kept outside the blocking CI baseline** (`stepup/stepup_acr_enforcement.spthy`, `federation/trust_anchor_rotation.spthy`)
- **2 shared theory libraries** (included by other models, not verified independently)

## CI-Verified Models (50)

| Directory | Model | Status |
|-----------|-------|--------|
| authcode/ | code_injection.spthy | Verified |
| authcode/ | code_replay.spthy | Verified |
| authcode/ | csrf_protection.spthy | Verified |
| authcode/ | authcode_session_integrity.spthy | Verified |
| authcode/ | state_echo_integrity.spthy | Verified (implemented; 4 lemmas: StateEcho, StateFreshness, StateSingleUse, StateUnpredictability) |
| authcode/ | refresh_token_rotation.spthy | **Phase 8** — 6 lemmas: rotation_single_use, replay_detection_and_revocation, rotation_chain_integrity, cross_client_isolation, rotation_count_monotonicity, no_token_after_revocation |
| authorize/ | error_redirect_state.spthy | Verified |
| authorize/ | success_redirect_code_state.spthy | Verified |
| bearer/ | bearer_bcp.spthy | Verified |
| bearer/ | cnf_single_key.spthy | Verified |
| client_auth/ | client_authentication.spthy | Verified |
| client_auth/ | token_endpoint_auth_required.spthy | Verified |
| client_auth/ | private_key_jwt.spthy | Verified |
| dpop/ | dpop_replay.spthy | Verified |
| introspection/ | introspection_security.spthy | Verified |
| jwt_bearer/ | jwt_bearer_security.spthy | Verified |
| oidc/ | oidc_core.spthy | Verified |
| oidc/ | id_token_nonce.spthy | Verified |
| oidc/ | iss_mixup.spthy | Verified |
| oidc/ | logout_session_termination.spthy | Verified |
| oidc/ | front_channel_logout.spthy | **Phase 8** — 5 lemmas: session_termination_reach, post_logout_redirect_validation, no_open_redirect, iframe_origin_check, logout_consistency |
| oidc/ | userinfo_security.spthy | **Phase 8** — 5 lemmas: access_token_required, scope_claim_correspondence, no_claim_leakage, sub_consistency, token_binding_check |
| par/ | par_security.spthy | Verified |
| par/ | par_redirect_integrity.spthy | Verified |
| par/ | jar_par_fixation.spthy | Verified |
| pkce/ | pkce_security.spthy | Verified |
| rar/ | rar_authorization_details.spthy | Verified |
| resource/ | resource_indicators.spthy | Verified |
| revocation/ | revocation_auth.spthy | Verified |
| stepup/ | stepup_soundness.spthy | Verified (reworked 2026-08-05: reachability witness added; previously vacuous) |
| token_exchange/ | token_exchange_security.spthy | Verified |
| federation/ | id_token_chain.spthy | Verified (T-4/T-5/T-7 fixed; 9 lemmas including unforgeability) |
| federation/ | rp_brokering.spthy | Verified (fixed 2026-02-13; 7 sound lemmas) |
| federation/ | account_linking.spthy | Verified (enhanced 2026-02-13; 8 lemmas) |
| federation/ | trust_chain.spthy | Verified (enhanced 2026-02-13; 9 lemmas) |
| federation/ | upstream_refresh_rotation.spthy | Verified (5 lemmas: rotation_single_use, replay_triggers_detection, token_chain_integrity, consumed_was_active, cross_client_isolation) |
| federation/ | account_unlinking.spthy | Verified (4 lemmas: no_auth_after_unlink, unlink_requires_admin, link_uniqueness, auth_requires_link) |
| federation/ | federation_key_rotation.spthy | Verified (5 lemmas: token_provenance, verified_uses_registered_key, rotation_continuity, post_rotation_old_key_valid, registered_key_authenticity) |
| federation/ | federation_ssrf_chain.spthy | Verified (3 lemmas: no_internal_fetch, authority_hint_validated, chain_requires_fetch) — C-3 finding |
| federation/ | rp_authorize_callback.spthy | Verified (7 lemmas: authorize_callback_binding, trust_chain_cache_soundness, id_token_issuer_verification, no_callback_without_chain, cache_reuse_consistency, session_state_integrity, id_token_unforgeability) |
| federation/ | cache_poisoning_resistance.spthy | Verified (5 lemmas: no_unverified_cache, attacker_cannot_poison, environment_isolation, cache_entry_authenticity, no_stale_key_cache) |
| federation/ | account_link_isolation.spthy | Verified (5 lemmas: cross_tenant_isolation, cross_env_denial, upstream_sub_binding, environment_scoped_login, link_tenant_binding) |
| management/ | policy_downgrade.spthy | Verified (3 lemmas: policy_monotonicity, no_silent_downgrade, upgrade_always_allowed) — H-4 finding |
| management/ | key_rotation_race.spthy | Verified (4 lemmas: always_one_active_key, rotation_preserves_environment, rotation_single_use, key_provenance) — M-5 finding |
| management/ | policy_enforcement_monotonicity.spthy | Verified (7 lemmas: fallback_monotonicity, child_cannot_weaken_parent, global_pkce_enforced, timed_exception_auto_expire, exception_requires_admin, resolution_preserves_global, effective_policy_deterministic) |
| device_auth/ | device_authorization_security.spthy | **Phase 6** — 8 lemmas: no_token_without_user_approval, device_code_single_use, user_code_device_binding, no_token_after_expiry, device_code_not_in_network, environment_isolation, polling_requires_valid_code, no_token_after_denial |
| introspection/ | jwt_introspection_security.spthy | **Phase 6** — 6 lemmas: response_unforgeability, audience_binding, issuer_binding, no_token_swap, jti_replay_prevention, cross_tenant_isolation |
| federation/ | op_entity_configuration.spthy | **Phase 6** — 7 lemmas: entity_config_self_signed, entity_config_integrity, subordinate_only_for_registered, fetch_serves_valid_subordinate, resolve_chain_integrity, no_cross_environment_subordinate, chain_unforgeability |

## Excluded from CI

| File | Reason |
|------|--------|
| common.spthy | Shared theory library (included by other models) |
| common/common_model.spthy | Shared theory library (included by other models) |
| stepup/stepup_acr_enforcement.spthy | Extended RFC 9470 ACR/max_age model. Not referenced by the current compliance-matrix claim set; kept in `ci/tamarin_proofs_extended.sh` because `max_age_triggers_reauth` is solver-memory volatile under the blocking CI budget. |
| federation/trust_anchor_rotation.spthy | Extended federation trust-anchor lifecycle model. Not referenced by the current compliance-matrix claim set; kept in `ci/tamarin_proofs_extended.sh` because `revoked_anchor_no_trust` / `rollback_prevention` exceed the blocking CI budget. |

## Fixes Applied

### T-4: issuer_rewriting_integrity (id_token_chain.spthy)
- **Problem**: Lemma was trivially satisfied — DownstreamRP_Verify used `!DS_IDToken_Record` (server-side fact) to match the token, so the issuer was always correct by construction.
- **Fix**: DownstreamRP_Verify now uses purely cryptographic verification (`In()` + `verify()` against broker public key). The RP receives tokens from the attacker-controlled network. The lemma proves that the claimed issuer must be the broker's registered issuer, or a signing key was compromised. Non-trivial because the attacker could inject tokens with arbitrary issuers, but only broker-signed tokens pass verification.

### T-5/T-7: Federation secrecy lemmas (id_token_chain.spthy)
- **Problem**: Secrecy lemmas were trivially satisfied because tokens are public via `Out()` (front-channel transport by design).
- **Fix**: Replaced with **unforgeability** properties:
  - `downstream_token_unforgeability`: A verified downstream token was either legitimately issued by the broker (with a valid upstream chain), or a signing key was compromised.
  - `end_to_end_authentication`: Downstream RP authentication requires upstream IdP authentication, unless a key was compromised.
  - These are non-trivial because the RP performs crypto-only verification on tokens received from the network.

### state_echo_integrity.spthy (placeholder → implemented)
- **Problem**: Was a placeholder with only commented-out sketch.
- **Fix**: Full implementation with 3 rules (Client_Initiate, AS_Issue_Code, Client_Accept) and 4 verified lemmas (StateEcho, StateFreshness, StateSingleUse, StateUnpredictability).

## Phase 6 New Models

### device_auth/device_authorization_security.spthy (RFC 8628)
Models the Device Authorization Grant flow. Device obtains (device_code, user_code) from AS; user authorizes via out-of-band verification URI; device polls for token. Key design: device_code never enters Out() (HTTPS-only channel), user_code is public. Linear fact chain: AS_Pending → AS_Approved → consumed by AS_Issue_Token. Covers DA-1 through DA-7 threat model. Hash-based storage modeled via h(device_code).

### introspection/jwt_introspection_security.spthy (RFC 9701)
Models JWT-formatted introspection responses. Extends the existing RFC 7662 model with signed responses. Uses builtins: signing for SUF-CMA unforgeability proofs. JWT response binds token identity, audience (RS), and issuer (AS) inside the signed claims. Non-trivial: RS receives JWT via In() (Dolev-Yao attacker can inject forged responses). Covers JI-1 through JI-6 threat model. Note: implementation uses HS256 (HMAC); model uses asymmetric signing — properties hold for both against network attacker.

### stepup/stepup_acr_enforcement.spthy (RFC 9470, extended)
Extends minimal stepup_soundness (2 lemmas) to full ACR enforcement. Models two ACR levels ('basic', 'mfa') with ordering restrictions. Session upgrade via step-up consumes linear facts (challenge single-use). max_age enforcement via session expiry (Auth_Time_Expire consumes Session). This model is retained as an **extended** proof target outside the blocking CI baseline; the current compliance-matrix claim for RFC 9470 continues to rely on `fstar/stepup/StepUp.fst` and `stepup/stepup_soundness.spthy`.

### federation/op_entity_configuration.spthy (Federation OP)
Models Aegaeon as OP in federation. Entity Configuration (iss==sub, self-signed), subordinate statement issuance (registered RPs only), fetch/resolve endpoint security. Full chain verification: RP → OP → TA with JWS checks at each level. Key rotation with grace period. Proves unforgeability under Dolev-Yao.

## Phase 8 New Models

### authcode/refresh_token_rotation.spthy (RFC 9700 Local Refresh Token Rotation)
Models the AS-side refresh token rotation mechanism per RFC 9700 §6.1. Refresh tokens are bound to (client, user) with a monotonically increasing rotation_count. Each rotation consumes the old RT (linear fact) and issues a fresh RT. Replay detection: if a consumed RT is presented again, the AS detects the attack and triggers cascade revocation of the entire token family. Key design: Active_RT is a linear fact (consumed on rotation), Consumed_RT is persistent (enables replay detection), Revoked_Family triggers cascade invalidation. Models client compromise (RT leak to Dolev-Yao attacker). Implementation correspondence: TokenStore::rotate_refresh_token (store.rs:360), RefreshToken::rotate (types.rs:250), TokenStore::revoke_token (store.rs:398).

### oidc/front_channel_logout.spthy (OIDC Front-Channel Logout)
Extends the back-channel-only logout model (logout_session_termination.spthy) with front-channel (iframe-based) logout and post_logout_redirect_uri security. Models RP-initiated logout via end_session_endpoint with id_token_hint validation (JWS signature check via signing builtin). Front-channel: OP renders iframes with src constrained to registered frontchannel_logout_uri per RP. Post-logout redirect: validated against client's registered post_logout_redirect_uris allowlist (no open redirect). Proves that front-channel and back-channel notifications produce consistent session termination for the same sid. Implementation correspondence: logout() handler (web/mod.rs:7884), validate_post_logout_redirect_uri (client_registry.rs:286), dispatch_backchannel_logout (web/mod.rs:7840).

### oidc/userinfo_security.spthy (OIDC UserInfo Endpoint)
Models the UserInfo endpoint (OIDC Core §5.3) security. Access tokens issued with specific scopes; UserInfo returns only claims matching the granted scope. Sub claim always returned (OIDC Core §5.3.2). Sender-constrained tokens (DPoP/mTLS) require proof-of-possession: binding_proof must match binding_key stored at issuance. Attacker model includes token theft without binding key (stolen bearer token cannot pass sender binding check). Scope→claim correspondence is structurally enforced: Active_Token carries granted scope, !User_Claim requires matching scope. Implementation correspondence: UserinfoEndpoint::fetch_userinfo (userinfo.rs:273), filter_claims_by_scope (userinfo.rs:190), TokenPolicyContext enforcement.

## Lemma Count Summary

| Category | Models | Lemmas |
|----------|--------|--------|
| authcode | 6 | 26 |
| authorize | 2 | 6 |
| bearer | 2 | 13 |
| client_auth | 3 | 7 |
| device_auth | 1 | 8 |
| dpop | 1 | 4 |
| introspection | 2 | 12 |
| jwt_bearer | 1 | 3 |
| oidc | 6 | 25 |
| par | 3 | 13 |
| pkce | 1 | 1 |
| rar | 1 | 6 |
| resource | 1 | 1 |
| revocation | 1 | 2 |
| stepup | 2 | 8 |
| token_exchange | 1 | 3 |
| federation | 13 | 81 |
| management | 3 | 14 |
| **Total** | **52** | **245** |
