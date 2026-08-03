#![allow(clippy::result_large_err)] // Web handlers return HTTP responses as error payloads by design.

mod access_token_persistence;
mod auth_session;
mod auth_session_flow;
mod authorize_context;
mod authorize_endpoint;
mod authorize_login_redirect;
mod authorize_request;
mod authorize_validation;
mod backchannel_logout;
mod dcr_client_build;
mod dcr_configuration;
mod dcr_profile_validation;
mod dcr_registration;
mod dcr_response;
mod dcr_runtime;
mod dcr_scope;
mod device_flow;
mod form_helpers;
mod local_auth;
mod local_auth_audit;
mod local_auth_recovery;
mod local_auth_support;
mod logout_context;
mod logout_dispatch;
mod logout_endpoint;
mod logout_id_token_hint;
pub mod management;
mod metadata;
mod oauth_audit;
mod oauth_errors;
#[cfg(test)]
mod openid_federation;
mod par_endpoint;
mod profile_policy;
mod request_admission;
mod request_id;
mod resource_endpoint;
mod router;
mod runtime_authority_guard;
mod shared;
mod state;
#[cfg(test)]
mod test_prelude;
mod token_authorization_code;
mod token_client_credentials;
mod token_device_code;
mod token_endpoint;
mod token_exchange;
mod token_form;
mod token_jwt_bearer;
mod token_lifecycle;
mod token_refresh;
mod token_response;
mod token_sender_binding;
mod transport_boundary;
mod upstream_authorize;
mod upstream_callback;
mod upstream_callback_connection;
mod upstream_callback_exchange;
mod upstream_callback_session_failure_audit;
mod upstream_callback_state;
mod upstream_callback_users;
mod upstream_id_token;
mod upstream_logout_incidents;
mod upstream_logout_relay;
mod upstream_logout_sessions;
mod upstream_metadata;
mod upstream_refresh;
mod upstream_refresh_links;
mod upstream_refresh_token_envelope;
mod upstream_token_response;
mod upstream_users;
mod userinfo;

use access_token_persistence::{
    access_token_expires_at, persist_access_with_meta_async, scope_members, AccessTokenPersistence,
};
pub use auth_session::AuthSessionStore;
use auth_session::AuthSessionTimes;
#[cfg(test)]
use auth_session_flow::local_logout_redirect_target;
use auth_session_flow::{
    auth_session_store_logout_error_response, auth_session_store_lookup_error_response,
    create_auth_session_or_error_response_async, local_logout_redirect_target_with_policy,
    local_password_session_acr, normalized_acr, validate_return_to,
};
use authorize_endpoint::authorize;
use authorize_validation::{authorize_error_response, AuthorizeErrorContext};
use dcr_registration::register;
use device_flow::{
    device_approve, device_authorization, device_deny, device_verify_get, device_verify_post,
};
use form_helpers::*;
use logout_endpoint::{logout, upstream_logout_callback};
use oauth_errors::{json_error_with_iss, no_cache_header_error, no_cache_json_error_with_iss};
use par_endpoint::par;
use profile_policy::{
    downstream_profile_violation_response, resolve_downstream_profile_for_endpoint,
    validate_downstream_device_profile_policy, validate_downstream_endpoint_auth_profile,
    validate_downstream_par_profile_policy,
};
use request_admission::{
    enforce_no_credentials_in_uri, enforce_no_credentials_in_uri_with_policy, QueryCredentialPolicy,
};
use request_id::request_id_from_headers;
use resource_endpoint::resource;
use runtime_authority_guard::runtime_authority_guard_middleware;
use shared::{
    build_upstream_logout_callback_uri, clock_error_response, issuer_host_from_url,
    no_cache_redirect_response, normalize_issuer, now_epoch_secs, parse_acr_values,
    select_supported_acr, AUTH_SESSION_COOKIE_NAME, CLIENT_ASSERTION_TYPE_JWT_BEARER,
    CSRF_COOKIE_MAX_AGE_SECS, DEVICE_CODE_GRANT_TYPE, LOCAL_AUTH_CSRF_COOKIE_NAME,
    OAUTH_PROFILE_TYPE_DOWNSTREAM, OAUTH_PROFILE_TYPE_UPSTREAM, OAUTH_TOKEN_TYPE_ACCESS_TOKEN,
    RESOURCE_SCOPES, TOKEN_EXCHANGE_GRANT_TYPE, UPSTREAM_MAX_BODY_BYTES,
    X_FORWARDED_CLIENT_CERT_HEADER,
};
#[cfg(test)]
use test_prelude::*;
use token_endpoint::{
    client_auth_presence, multiple_client_auth_methods_present, resolve_session_user, token,
    token_auth_presence, token_client_auth_method, validate_private_key_jwt_client_assertion,
    validate_token_scope_subset, ClientAuthPresence, TokenEndpointContext,
};
use token_form::{optional_token_param, required_token_param, TokenForm};
use token_lifecycle::{introspect, revoke};
use token_response::{
    token_error_response, token_internal_error_response, token_issuer_error_response,
    token_json_response, token_registry_state_error_response, token_success_body,
};
use token_sender_binding::{
    dpop_binding_from_request, refresh_sender_binding_violation, trusted_mtls_fingerprint,
};
use transport_boundary::{transport_rejection, transport_security_middleware};
use upstream_authorize::upstream_authorize;
use upstream_callback::upstream_callback;
pub use upstream_logout_relay::{UpstreamLogoutRelayState, UpstreamLogoutRelayStore};
use upstream_logout_sessions::build_upstream_logout_redirect_target_with_relay;
use upstream_refresh::upstream_refresh;
use userinfo::{userinfo_get, userinfo_post};

pub use crate::runtime_authority::{
    RuntimeAuthorityState, RuntimeAuthorityStateError, RuntimeClientProjectionSyncError,
};
pub use router::build_router;
pub use state::{
    AppState, BrowserAuthState, DeviceState, FederationState, KeyManagersState, OidcState,
    ProtocolState, ReadinessState, TokenState, UpstreamState,
};

#[cfg(test)]
mod endpoint_profile_policy_tests;

#[cfg(test)]
mod token_exchange_tests;

#[cfg(test)]
mod upstream_tests;
