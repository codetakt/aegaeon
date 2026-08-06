#!/usr/bin/env bash
# Shared list of Tamarin proofs and lemmas for CI and flake verification.
# Paths are relative to proofs/tamarin.
PROOFS=(
	# --- authcode ---
	"authcode/code_injection.spthy:no_code_injection,state_binding"
	"authcode/authcode_session_integrity.spthy:"
	"session_integrity,code_single_use,state_csrf_protection,"
	"nonce_replay_protection"
	"authcode/csrf_protection.spthy:csrf_protection,state_unpredictability"
	"authcode/code_replay.spthy:code_single_use,code_freshness"
	"authcode/state_echo_integrity.spthy:"
	"StateEcho,StateFreshness,StateSingleUse,StateUnpredictability"
	"authcode/refresh_token_rotation.spthy:"
	"rotation_single_use,replay_detection_and_revocation,rotation_chain_integrity,"
	"cross_client_isolation,rotation_count_monotonicity,no_token_after_revocation"

	# --- authorize ---
	"authorize/error_redirect_state.spthy:ErrorStateEcho,StateEchoEq"
	"authorize/success_redirect_code_state.spthy:"
	"SuccessStateEcho,CodeFreshAndBound,RedirectRequiresRequest,CodeIssuedUnique"

	# --- bearer ---
	"bearer/bearer_bcp.spthy:"
	"no_access_after_revocation,mixup_resistance,redirect_uri_exact_match,"
	"dpop_sender_constraint,auth_code_single_use,token_secrecy,session_integrity"
	"bearer/cnf_single_key.spthy:cnf_single_key"

	# --- client_auth ---
	"client_auth/token_endpoint_auth_required.spthy:TokenAuth"
	"client_auth/client_authentication.spthy:client_authentication,client_credential_secrecy"
	"client_auth/private_key_jwt.spthy:"
	"pkjwt_client_auth_integrity,pkjwt_audience_binding,"
	"pkjwt_unforgeability,pkjwt_no_replay"

	# --- dpop ---
	"dpop/dpop_replay.spthy:dpop_resource_grant_reachable,dpop_replay_impossible"

	# --- introspection ---
	"introspection/introspection_security.spthy:"
	"introspection_requires_authz,introspection_active_claim_sound,"
	"introspection_inactive_claim_sound,introspection_confidentiality,"
	"introspection_cache_control,token_owner_privacy"

	# --- jwt_bearer ---
	"jwt_bearer/jwt_bearer_security.spthy:"
	"jwt_bearer_grant_integrity,jwt_bearer_unforgeability,jwt_bearer_no_replay"

	# --- oidc ---
	"oidc/iss_mixup.spthy:no_issuer_mixup,issuer_binding"
	"oidc/oidc_core.spthy:"
	"id_token_session_binding,nonce_replay_prevention,session_integrity,"
	"token_binding_integrity,auth_code_single_use,no_access_after_revocation,"
	"id_token_secrecy,auth_time_consistency,pkce_code_injection_prevention"
	"oidc/id_token_nonce.spthy:nonce_session_integrity"
	"oidc/logout_session_termination.spthy:"
	"logout_requires_id_token,no_id_token_after_logout,backchannel_logout_jti_stable"
	"oidc/front_channel_logout.spthy:"
	"session_termination_reach,post_logout_redirect_validation,no_open_redirect,"
	"iframe_origin_check,logout_consistency"
	"oidc/userinfo_security.spthy:"
	"access_token_required,scope_claim_correspondence,no_claim_leakage,"
	"sub_consistency,token_binding_check"

	# --- par ---
	"par/par_redirect_integrity.spthy:"
	"redirect_integrity,request_uri_single_use,no_request_uri_injection,"
	"request_uri_consumed_on_use,request_uri_issued_unique"
	"par/par_security.spthy:par_redirect_binding,par_integrity"
	"par/jar_par_fixation.spthy:jar_parameter_fixation"

	# --- pkce ---
	"pkce/pkce_security.spthy:mismatched_verifiers_cannot_inject_codes"

	# --- rar ---
	"rar/rar_authorization_details.spthy:"
	"par_authorization_details_used,par_storage_requires_auth,"
	"par_precedence_over_query,request_object_precedence_over_query,"
	"request_object_precedence_over_form,request_object_overrides_form_in_par"

	# --- resource ---
	"resource/resource_indicators.spthy:resource_access_reachable,resource_audience_enforced"

	# --- revocation ---
	"revocation/revocation_auth.spthy:token_revocation_reachable,authorized_revocation,revocation_authorization"

	# --- stepup ---
	"stepup/stepup_soundness.spthy:token_issuance_reachable,stepup_soundness"

	# --- token_exchange ---
	"token_exchange/token_exchange_security.spthy:"
	"token_exchange_scope_subset,token_exchange_preserves_audience_and_client,"
	"token_exchange_preserves_sender_binding"

	# --- federation ---
	"federation/rp_brokering.spthy:"
	"flow_relay_integrity,pkce_upstream_required,code_confusion_prevention,"
	"issuer_validation_before_downstream,upstream_code_single_use,"
	"mixup_resistance_brokered,no_downstream_without_upstream"
	"federation/id_token_chain.spthy:"
	"chain_binding,upstream_jwks_verification,nonce_chain_integrity,"
	"at_hash_downstream_only,claims_provenance,issuer_rewriting_integrity,"
	"no_downstream_without_upstream,downstream_token_unforgeability,"
	"end_to_end_authentication"
	"federation/account_linking.spthy:"
	"unique_upstream_binding,squatting_prevention,linkage_immutability,"
	"cross_idp_isolation,no_auth_without_link,unlink_requires_admin,"
	"account_isolation,link_requires_honest_idp"
	"federation/trust_chain.spthy:"
	"chain_to_trust_anchor,intermediate_chain_key_authenticity,"
	"subordinate_statement_authenticity,metadata_policy_enforcement,"
	"entity_key_uniqueness,key_rotation_authorization,no_trust_without_chain,"
	"intermediate_must_be_verified,direct_chain_no_intermediate"
	"federation/upstream_refresh_rotation.spthy:"
	"rotation_single_use,replay_triggers_detection,token_chain_integrity,"
	"consumed_was_active,cross_client_isolation"
	"federation/account_unlinking.spthy:"
	"no_auth_after_unlink,unlink_requires_admin,link_uniqueness,auth_requires_link"
	"federation/federation_key_rotation.spthy:"
	"idp_key_was_active,token_provenance,verified_uses_registered_key,"
	"rotation_continuity,post_rotation_old_key_valid,registered_key_authenticity"
	"federation/federation_ssrf_chain.spthy:"
	"no_internal_fetch,authority_hint_validated,chain_requires_fetch"
	"federation/rp_authorize_callback.spthy:"
	"authorize_callback_binding,trust_chain_cache_soundness,"
	"id_token_issuer_verification,no_callback_without_chain,"
	"cache_reuse_consistency,session_state_integrity,id_token_unforgeability"
	"federation/cache_poisoning_resistance.spthy:"
	"no_unverified_cache,attacker_cannot_poison,environment_isolation,"
	"cache_entry_authenticity,no_stale_key_cache"
	"federation/account_link_isolation.spthy:"
	"cross_tenant_isolation,cross_env_denial,upstream_sub_binding,"
	"environment_scoped_login,link_tenant_binding"

	# --- management ---
	"management/policy_downgrade.spthy:"
	"policy_monotonicity,no_silent_downgrade,"
	"downgrade_requires_registered_admin,upgrade_always_allowed"
	"management/key_rotation_race.spthy:"
	"always_one_active_key,rotation_single_use,env_key_was_activated,"
	"rotation_preserves_environment,key_provenance"
	"management/policy_enforcement_monotonicity.spthy:"
	"fallback_monotonicity,child_cannot_weaken_parent,global_pkce_enforced,"
	"timed_exception_auto_expire,exception_requires_admin,"
	"resolution_preserves_global,effective_policy_deterministic"

	# --- device_auth (RFC 8628) ---
	"device_auth/device_authorization_security.spthy:"
	"no_token_without_user_approval,device_code_single_use,"
	"user_code_device_binding,no_token_after_expiry,device_code_not_in_network,"
	"environment_isolation,polling_requires_valid_code,no_token_after_denial"

	# --- introspection (RFC 9701 JWT) ---
	"introspection/jwt_introspection_security.spthy:"
	"response_unforgeability,audience_binding,issuer_binding,no_token_swap,"
	"jti_replay_prevention,cross_tenant_isolation"

	# --- federation OP ---
	"federation/op_entity_configuration.spthy:"
	"entity_config_self_signed,entity_config_integrity,"
	"subordinate_only_for_registered,fetch_serves_valid_subordinate,"
	"resolve_chain_integrity,no_cross_environment_subordinate,"
	"chain_unforgeability"

	# --- sd_jwt (RFC 9901 Selective Disclosure) ---
	"sd_jwt/sd_jwt_selective_disclosure.spthy:"
	"disclosure_non_forgeability,selective_privacy,binding_integrity,"
	"no_disclosure_without_key,salt_uniqueness,no_disclosure_without_salt"

	# --- dcr (RFC 7591/7592 Dynamic Client Registration Management) ---
	"dcr/dcr_management_security.spthy:"
	"registration_token_binding,no_unauthorized_update,client_identity_integrity,"
	"registration_access_token_secrecy,no_unauthorized_delete,rat_rotation_on_update"

)

normalize_tamarin_proofs() {
	local part
	local current=""

	TAMARIN_PROOF_SPECS=()
	for part in "${PROOFS[@]}"; do
		if [[ $part == *:* ]]; then
			if [[ -n $current ]]; then
				TAMARIN_PROOF_SPECS+=("$current")
			fi
			current="$part"
		else
			current+="$part"
		fi
	done

	if [[ -n $current ]]; then
		TAMARIN_PROOF_SPECS+=("$current")
	fi
}
