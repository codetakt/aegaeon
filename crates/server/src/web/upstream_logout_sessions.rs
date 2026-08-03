use super::auth_session::UpstreamLogoutSession;
use super::oauth_errors::no_cache_json_error_with_iss;
use super::upstream_logout_incidents::{
    create_upstream_logout_incident, UpstreamLogoutIncidentRequest,
};
use super::upstream_logout_relay::UpstreamLogoutRelayState;
use super::upstream_metadata::validate_upstream_metadata_endpoint;
use super::{build_upstream_logout_callback_uri, AppState};
use axum::{http::StatusCode, response::Response};
use url::Url;

use crate::oidc::{IdToken, OidcDiscovery};
use crate::upstream::{random_token, UpstreamAuthRequest, UpstreamLogoutPolicy};

fn extract_upstream_logout_claim_value(id_token: &IdToken, claim_name: &str) -> Option<String> {
    match claim_name {
        "sid" => id_token.claims.sid.clone(),
        "sub" => Some(id_token.claims.sub.clone()),
        "iss" => Some(id_token.claims.iss.clone()),
        "acr" => id_token.claims.acr.clone(),
        other => id_token
            .claims
            .additional_claims
            .get(other)
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
    }
}

pub(super) fn build_upstream_logout_session(
    policy: Option<&UpstreamLogoutPolicy>,
    issuer: &str,
    discovery: &OidcDiscovery,
    id_token: &IdToken,
    request: &UpstreamAuthRequest,
    allowed_domains: &[String],
) -> Option<UpstreamLogoutSession> {
    let policy = policy?;
    let context = request.managed_connection_context();
    let end_session_endpoint = discovery
        .end_session_endpoint
        .as_ref()
        .and_then(|endpoint| {
            validate_upstream_metadata_endpoint(endpoint, "end_session_endpoint", allowed_domains)
                .ok()
                .map(|()| endpoint.clone())
        });
    let session_hint_value = policy
        .session_hint_claim
        .as_deref()
        .and_then(|claim_name| extract_upstream_logout_claim_value(id_token, claim_name));

    Some(UpstreamLogoutSession {
        issuer: issuer.to_string(),
        end_session_endpoint,
        back_channel: policy.back_channel,
        session_hint_claim: policy.session_hint_claim.clone(),
        session_hint_value,
        recovery_policy: policy.recovery_policy,
        team_id: Some(context.team_id),
        tenant_id: Some(context.tenant_id),
        environment_id: Some(context.environment_id),
        connection_id: Some(context.connection_id),
    })
}

fn upstream_logout_endpoint_url(
    session: &UpstreamLogoutSession,
    allowed_domains: &[String],
) -> Option<Url> {
    if session.back_channel {
        return None;
    }
    let endpoint = session.end_session_endpoint.as_ref()?;
    validate_upstream_metadata_endpoint(endpoint, "end_session_endpoint", allowed_domains).ok()?;
    let url = Url::parse(endpoint).ok()?;
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    Some(url)
}

pub(super) fn build_upstream_logout_redirect_target(
    session: &UpstreamLogoutSession,
    allowed_domains: &[String],
) -> Option<String> {
    let mut url = upstream_logout_endpoint_url(session, allowed_domains)?;
    if let Some(session_hint_value) = session.session_hint_value.as_ref() {
        url.query_pairs_mut()
            .append_pair("logout_hint", session_hint_value);
    }
    Some(url.into())
}

pub(super) fn upstream_logout_relay_store_unavailable_response(
    error: &str,
    issuer_base: &str,
) -> Response {
    tracing::error!(error = %error, "upstream logout relay store unavailable");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("upstream logout relay store unavailable"),
        issuer_base,
    )
}

pub(super) async fn build_upstream_logout_redirect_target_with_relay(
    state: &AppState,
    session: &UpstreamLogoutSession,
    downstream_client_id: Option<&str>,
    downstream_redirect_uri: &str,
    downstream_state: Option<&str>,
    actor_id: Option<&str>,
    request_id: &str,
) -> Result<Option<String>, Response> {
    if session.back_channel {
        return Ok(None);
    }
    let Some(mut url) =
        upstream_logout_endpoint_url(session, state.cfg.upstream().outbound_allowed_domains())
    else {
        return Ok(None);
    };
    let callback_uri = build_upstream_logout_callback_uri(state.base_url.as_str());
    let relay_token = random_token(24);
    let incident_id = create_upstream_logout_incident(
        &state.db_pool,
        UpstreamLogoutIncidentRequest {
            session,
            downstream_client_id,
            downstream_redirect_uri,
            downstream_state,
            relay_token: &relay_token,
            relay_ttl_secs: state.upstream.logout_relay_store.ttl().as_secs(),
            actor_id,
            request_id,
        },
    )
    .await;
    {
        let mut query = url.query_pairs_mut();
        if let Some(session_hint_value) = session.session_hint_value.as_ref() {
            query.append_pair("logout_hint", session_hint_value);
        }
        query.append_pair("post_logout_redirect_uri", &callback_uri);
        query.append_pair("state", &relay_token);
    }
    state
        .upstream
        .logout_relay_store
        .try_insert_async(
            relay_token.clone(),
            UpstreamLogoutRelayState {
                incident_id,
                downstream_redirect_uri: downstream_redirect_uri.to_string(),
                downstream_state: downstream_state.map(str::to_string),
            },
        )
        .await
        .map_err(|err| {
            upstream_logout_relay_store_unavailable_response(&err, state.issuer.as_str())
        })?;
    Ok(Some(url.into()))
}
