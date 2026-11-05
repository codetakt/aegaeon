-- Ordinary application privileges for the reviewed schema in this PR.
-- Run after migrations and subject-ownership provisioning. Default: ROLLBACK.
-- Protected Organizations/ownership/lifecycle grants use their separate scripts.
-- No future-table/default privileges, ownership, CREATE, TRUNCATE, or delegation.
\set ON_ERROR_STOP on
\if :{?runtime_role}
\else
  \echo 'runtime_role is required'
  \quit 3
\endif
\if :{?commit}
\else
  \set commit false
\endif
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SELECT aegaeon.subject_history_preflight(:'runtime_role');
GRANT USAGE ON SCHEMA aegaeon TO :"runtime_role";
GRANT SELECT,INSERT,UPDATE,DELETE ON
  aegaeon.account_links,
  aegaeon.administrators,
  aegaeon.api_key_capabilities,
  aegaeon.api_keys,
  aegaeon.application_authorizations,
  aegaeon.authorization_consents,
  aegaeon.authorization_logins,
  aegaeon.client_secrets,
  aegaeon.clients,
  aegaeon.configuration_versions,
  aegaeon.connections,
  aegaeon.control_plane_policies,
  aegaeon.dynamic_client_registrations,
  aegaeon.end_user_password_credentials,
  aegaeon.end_user_profiles,
  aegaeon.end_user_recovery_tokens,
  aegaeon.end_users,
  aegaeon.environment_dcr_bearer_tokens,
  aegaeon.environment_key_stores,
  aegaeon.environment_policies,
  aegaeon.environment_revoked_client_secrets,
  aegaeon.environment_scope_allowlist,
  aegaeon.environments,
  aegaeon.federation_entity_cache,
  aegaeon.federation_logout_recovery_incidents,
  aegaeon.federation_trust_anchors,
  aegaeon.federation_trust_chains,
  aegaeon.logout_confirmations,
  aegaeon.lti_identifiers,
  aegaeon.lti_launch_intents,
  aegaeon.lti_registration_revisions,
  aegaeon.lti_registrations,
  aegaeon.management_user_runtime_commands,
  aegaeon.oauth_profiles,
  aegaeon.runtime_authorization_codes,
  aegaeon.runtime_authorization_observations,
  aegaeon.runtime_browser_session_scopes,
  aegaeon.runtime_browser_sessions,
  aegaeon.runtime_csrf_tokens,
  aegaeon.runtime_device_codes,
  aegaeon.runtime_dpop_nonces,
  aegaeon.runtime_exchange_roots,
  aegaeon.runtime_jwks_bindings,
  aegaeon.runtime_jwks_fetches,
  aegaeon.runtime_keys,
  aegaeon.runtime_logout_relays,
  aegaeon.runtime_management_session_scopes,
  aegaeon.runtime_management_sessions,
  aegaeon.runtime_oidc_auth_bindings,
  aegaeon.runtime_oidc_clients,
  aegaeon.runtime_oidc_sessions,
  aegaeon.runtime_par_requests,
  aegaeon.runtime_refresh_families,
  aegaeon.runtime_replay_entries,
  aegaeon.runtime_request_object_jtis,
  aegaeon.runtime_security_budgets,
  aegaeon.runtime_stepup_challenges,
  aegaeon.runtime_token_capabilities,
  aegaeon.runtime_token_subjects,
  aegaeon.runtime_upstream_auth,
  aegaeon.team_memberships,
  aegaeon.teams,
  aegaeon.tenants TO :"runtime_role";
GRANT SELECT,INSERT ON aegaeon.audit_events, aegaeon.audit_events_default TO :"runtime_role";
GRANT SELECT ON aegaeon.user_attribute_sources, aegaeon.active_runtime_environments TO :"runtime_role";
-- SELECT FOR SHARE on this joined view requires one updateable view column.
GRANT UPDATE(configuration_version_id) ON aegaeon.active_runtime_environments TO :"runtime_role";
SELECT aegaeon.subject_history_preflight(:'runtime_role');
\if :commit
COMMIT;
\else
ROLLBACK;
\endif
