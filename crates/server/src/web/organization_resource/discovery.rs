//! Discovery is a separate resource contract, not a selected Organization token.
use super::*;
use crate::organizations::operators::mutations::targets::MAX_AUDIENCE_BYTES;
use crate::organizations::{discovery, repository::RepositoryError, selection};
use serde::Deserialize;

pub(in crate::web) const PATH: &str = "/organizations/memberships";

// Every byte of both names and values may be percent-encoded. Keep a raw
// allocation bound that admits both decoded limits together, plus '=' and '&'.
const MAX_QUERY_BYTES: usize =
    3 * ("audience".len() + MAX_AUDIENCE_BYTES + "cursor".len() + discovery::MAX_CURSOR_BYTES) + 3;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    audience: String,
    cursor: Option<String>,
}

fn parse_query(raw: &str) -> Result<Query, ()> {
    if raw.len() > MAX_QUERY_BYTES {
        return Err(());
    }
    let query: Query = serde_urlencoded::from_str(raw).map_err(|_| ())?;
    if query.audience.len() > MAX_AUDIENCE_BYTES
        || query
            .cursor
            .as_ref()
            .is_some_and(|value| value.len() > discovery::MAX_CURSOR_BYTES)
    {
        return Err(());
    }
    Ok(query)
}

#[cfg(test)]
mod query_tests;

pub(in crate::web) async fn memberships(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    match read(&state, &admission, remote, request).await {
        Ok(page) => super::super::token_json_response(
            StatusCode::OK,
            serde_json::json!({
                "organizations":page.organizations.iter().map(|entry| serde_json::json!({"identifier":entry.identifier})).collect::<Vec<_>>(),"next_cursor":page.next_cursor,
            }),
        ),
        Err(response) => response,
    }
}

async fn read(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    request: Request<Body>,
) -> Result<discovery::Page, Response> {
    state.require_subject_namespace()?;
    if state.runtime_restart.is_requested() {
        return Err(unavailable(state));
    }
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(state, kind, PATH)
        })?;
    if !matches!(parts.method, Method::GET | Method::HEAD) || to_bytes(body, 0).await.is_err() {
        return Err(error(state, StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let raw = parts
        .uri
        .query()
        .ok_or_else(|| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?;
    let query =
        parse_query(raw).map_err(|_| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?;
    let meta = authentication::for_discovery(state, admission, parts).await?;
    validate_meta(&meta).map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let Some(SenderBinding::DPoP { jkt }) = &meta.sender_binding else {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    };
    let mut connection = admission
        .0
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable(state))?;
    let mut tx = connection.begin().await.map_err(|_| unavailable(state))?;
    let result = discovery::page(
        &mut tx,
        &discovery::Query {
            environment_id: state.environment_id,
            issuer: &state.issuer,
            client_id: &meta.client_id,
            subject: &meta.user_id,
            auth_time: meta
                .auth_time_epoch_secs
                .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?,
            dpop_jkt: jkt,
            audience: &query.audience,
            privileges: None,
            discovery_audience: Some(&meta.audience),
            cursor: query.cursor.as_deref(),
        },
    )
    .await
    .map_err(|e| match e {
        RepositoryError::Authority(crate::organizations::AuthorityError::Invalid) => {
            error(state, StatusCode::BAD_REQUEST, "invalid_request")
        }
        RepositoryError::Authority(_) => error(state, StatusCode::FORBIDDEN, "insufficient_scope"),
        _ => unavailable(state),
    })?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(result)
}

fn validate_meta(meta: &BearerTokenMeta) -> Result<(), ()> {
    let scopes = meta.granted_scopes.join(" ");
    if !selection::valid_discovery_scopes(Some(&scopes))
        || meta.auth_time_epoch_secs.is_none()
        || meta.authorization_details.is_some()
        || meta.exchange_grant.is_some()
        || meta.selected_organization.is_some()
        || meta.application_grant.is_some()
        || meta.client_credentials_grant.is_some()
        || meta.refresh_grant.is_some()
        || meta.refresh_parent.is_some()
        || meta
            .expires_at
            .duration_since(meta.issued_at)
            .map_or(true, |ttl| {
                ttl > std::time::Duration::from_secs(selection::DISCOVERY_TTL_SECONDS)
            })
    {
        return Err(());
    }
    Ok(())
}

/// Producers check current primary registration as well as the resource consumer.
pub(in crate::web) async fn permission(
    state: &AppState,
    client: &str,
    audience: &str,
) -> Result<(), Response> {
    let owner =
        crate::organizations::request_work::async_store::current_epoch_owner(state.environment_id)
            .map_err(|_| unavailable(state))?;
    let mut connection = owner
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable(state))?;
    let mut tx = connection.begin().await.map_err(|_| unavailable(state))?;
    discovery::token_permission(&mut tx, state.environment_id, client, audience)
        .await
        .map_err(|e| match e {
            RepositoryError::Authority(_) => error(state, StatusCode::BAD_REQUEST, "invalid_scope"),
            _ => unavailable(state),
        })?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(())
}
