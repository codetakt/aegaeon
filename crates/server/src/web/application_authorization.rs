use super::{token_error_response, AppState, TokenEndpointContext};
use crate::application_authorization::{inorii::Grant, store};
use crate::authcode::types::BearerTokenMeta;
use axum::{http::StatusCode, response::Response};

pub(super) async fn authorization_context(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: axum::http::HeaderMap,
) -> Response {
    // This application surface accepts exactly the authenticated UserInfo credential and
    // its original sender binding, while obtaining authority exclusively from the grant.
    let authenticated = super::userinfo::userinfo_get(
        axum::extract::State(state.clone()),
        axum::extract::ConnectInfo(remote),
        axum::extract::OriginalUri(uri),
        headers.clone(),
    )
    .await;
    if !authenticated.status().is_success() {
        return authenticated;
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_whitespace().nth(1));
    let Some(token) = token else {
        return resource_rejected(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        );
    };
    let meta = match state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_owned())
        .await
    {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return resource_rejected(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
            )
        }
        Err(_) => {
            return token_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            )
        }
    };
    let Some(grant) = meta.application_grant.as_ref() else {
        return resource_rejected(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        );
    };
    if !grant.audiences.contains(&meta.audience) {
        return resource_rejected(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        );
    }
    if let Err(response) =
        require_current(&state, Some(grant), &meta.client_id, &meta.user_id).await
    {
        return if response.status().is_server_error() {
            response
        } else {
            resource_rejected(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
            )
        };
    }
    super::token_json_response(
        StatusCode::OK,
        serde_json::json!({
            "iss":state.issuer.as_str(),"sub":meta.user_id,"client_id":meta.client_id,
            crate::application_authorization::inorii::CLAIM_NAME: grant.claims,
        }),
    )
}

fn resource_rejected(authorization: Option<&str>) -> Response {
    let mut response = token_error_response(StatusCode::UNAUTHORIZED, "invalid_token", None);
    let scheme = if authorization
        .and_then(|v| v.split_whitespace().next())
        .is_some_and(|v| v.eq_ignore_ascii_case("DPoP"))
    {
        "DPoP"
    } else {
        "Bearer"
    };
    super::oauth_errors::apply_oauth_authenticate_header(&mut response, scheme, "invalid_token");
    response
}

pub(super) async fn check_resource(
    state: &AppState,
    meta: &BearerTokenMeta,
    authorization: &str,
) -> Result<(), Response> {
    if let Some(grant) = meta.application_grant.as_ref() {
        if !current(state, grant).await? {
            let mut response =
                token_error_response(StatusCode::UNAUTHORIZED, "invalid_token", None);
            let scheme = if authorization
                .split_whitespace()
                .next()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("DPoP"))
            {
                "DPoP"
            } else {
                "Bearer"
            };
            super::oauth_errors::apply_oauth_authenticate_header(
                &mut response,
                scheme,
                "invalid_token",
            );
            return Err(response);
        }
    }
    Ok(())
}

pub(super) async fn require_current(
    state: &AppState,
    grant: Option<&Grant>,
    client: &str,
    subject: &str,
) -> Result<Option<store::PublicationGuard>, Response> {
    let Some(grant) = grant else {
        return Ok(None);
    };
    if grant.client_id != client || grant.subject != subject {
        return Err(stale());
    }
    let authority = state
        .application_authority
        .as_ref()
        .ok_or_else(unavailable)?;
    match authority.memberships_current(grant).await {
        Ok(true) => {}
        Ok(false) => return Err(stale()),
        Err(_) => return Err(unavailable()),
    }
    match store::lock_current(
        &authority.projections,
        state.environment_id,
        &state.issuer,
        grant,
    )
    .await
    {
        Ok(Some(guard)) => Ok(Some(guard)),
        Ok(None) => Err(stale()),
        Err(_) => Err(token_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("application authority unavailable"),
        )),
    }
}

fn stale() -> Response {
    token_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        Some("application authorization has changed; authorize again"),
    )
}

pub(super) async fn exchange_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject: &BearerTokenMeta,
    audience: &str,
) -> Result<(Option<Grant>, Option<store::PublicationGuard>), Response> {
    let guard = require_current(
        state,
        subject.application_grant.as_ref(),
        &ctx.client_id,
        &subject.user_id,
    )
    .await
    .map_err(|response| {
        if response.status().is_server_error() {
            response
        } else {
            token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("subject_token is unacceptable"),
            )
        }
    })?;
    let selectors: Vec<_> = ctx
        .params
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "organization_id" | "organizationId"))
        .collect();
    if selectors.len() > 1
        || selectors
            .first()
            .is_some_and(|(name, value)| name != "organization_id" || value.is_empty())
    {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("organization_id must be a single nonempty application selector"),
        ));
    }
    let selector = selectors.first().map(|(_, value)| value.as_str());
    let invalid = || {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("application authorization does not cover the requested target or organization"),
        )
    };
    match subject.application_grant.as_ref() {
        None if selector.is_some() => Err(invalid()),
        None => Ok((None, guard)),
        Some(grant) => {
            // Human organization grants must be selected explicitly on a downstream exchange.
            if selector.is_none()
                && grant.selected_organization.is_none()
                && !grant.claims.organization_roles.is_empty()
            {
                return Err(invalid());
            }
            grant
                .restrict(audience, selector)
                .map(|grant| (Some(grant), guard))
                .map_err(|_| invalid())
        }
    }
}

fn unavailable() -> Response {
    token_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("application authority unavailable"),
    )
}

pub(super) async fn capture(
    state: &AppState,
    client: &str,
    subject: &str,
) -> Result<Option<Grant>, Response> {
    let Some(authority) = state.application_authority.as_ref() else {
        return Ok(None);
    };
    let grant = store::capture(
        &authority.projections,
        state.environment_id,
        &state.issuer,
        client,
        subject,
    )
    .await
    .map_err(|_| unavailable())?;
    if let Some(grant) = grant.as_ref() {
        match authority.memberships_current(grant).await {
            Ok(true) => {}
            Ok(false) => return Err(stale()),
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(grant)
}

pub(super) async fn current(state: &AppState, grant: &Grant) -> Result<bool, Response> {
    let authority = state
        .application_authority
        .as_ref()
        .ok_or_else(unavailable)?;
    Ok(store::is_current(
        &authority.projections,
        state.environment_id,
        &state.issuer,
        grant,
    )
    .await
    .map_err(|_| unavailable())?
        && authority
            .memberships_current(grant)
            .await
            .map_err(|_| unavailable())?)
}

#[cfg(test)]
mod tests;
