//! Native Organizations selection. Called only after client, sender and root authentication.
use crate::authcode::types::{BearerTokenMeta, SenderBinding};
use crate::organizations::{consent, selected::SelectedAuthority, AccessRequest, Binding};
use crate::web::{token_error_response, AppState, TokenEndpointContext};
use axum::{http::StatusCode, response::Response};

fn invalid() -> Response {
    token_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_authorization_details",
        Some("organization selection is not authorized"),
    )
}

pub(super) fn validate_request(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject: &BearerTokenMeta,
) -> Result<(), Response> {
    let selection = crate::web::token_form::optional_token_param(
        &ctx.params,
        "authorization_details",
        &state.issuer,
    )?;
    let original = subject
        .exchange_grant
        .as_ref()
        .filter(|grant| grant.organization.is_some());
    if subject.selected_organization.is_some()
        || ((subject.authorization_details.is_some() || original.is_some())
            && !original.is_some_and(|grant| {
                grant.original_details_match(subject.authorization_details.as_ref())
            }))
    {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token contains unsupported authorization details"),
        ));
    }
    if selection.is_none() && original.is_none() {
        return Ok(());
    }
    let details = selection.ok_or_else(invalid)?;
    if ctx
        .params
        .iter()
        .filter(|(key, _)| key == "audience")
        .count()
        != 1
        || ctx.params.iter().any(|(key, _)| key == "resource")
        || original.is_none()
        || AccessRequest::parse(&details).is_err()
        || subject.application_grant.is_some()
        || subject.client_credentials_grant.is_some()
        || crate::web::token_form::optional_token_param(
            &ctx.params,
            "organization_id",
            &state.issuer,
        )?
        .is_some()
        || ![
            consent::GRANT_TYPE,
            crate::organizations::ORGANIZATION_ACCESS_TYPE,
        ]
        .iter()
        .all(|t| {
            state
                .cfg
                .authorization_details_types_supported
                .iter()
                .any(|v| v == t)
        })
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) async fn prepare(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject: &BearerTokenMeta,
    audience: &str,
) -> Result<Option<SelectedAuthority>, Response> {
    let Some(raw) = crate::web::token_form::optional_token_param(
        &ctx.params,
        "authorization_details",
        &state.issuer,
    )?
    else {
        return Ok(None);
    };
    validate_request(state, ctx, subject)?;
    if !state.cfg.enable_jwt_access_tokens || state.keys.access_token.jwt_signing_alg() != "RS256" {
        return Err(invalid());
    }
    let grant = subject.exchange_grant.as_ref().ok_or_else(invalid)?;
    let original = grant.organization.as_ref().ok_or_else(invalid)?;
    let Some(SenderBinding::DPoP { jkt }) = ctx.sender_binding.as_ref() else {
        return Err(invalid());
    };
    if original.consent.scope.environment_id != state.environment_id
        || subject.auth_time_epoch_secs != Some(original.consent.auth_time)
    {
        return Err(invalid());
    }
    let binding = Binding {
        scope: original.consent.scope,
        issuer: state.issuer.to_string(),
        client_id: ctx.client_id.clone(),
        client_registration_id: original.consent.client_registration_id,
        subject: subject.user_id.clone(),
        user_id: original.consent.user_id,
        root_id: grant.root().ok_or_else(invalid)?.id.clone(),
        dpop_jkt: jkt.clone(),
    };
    let request = AccessRequest::parse(&raw).map_err(|_| invalid())?;
    let parent_expires_at = crate::util::unix_epoch_secs(subject.expires_at)
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(invalid)?;
    crate::web::organization_authority::select(
        state,
        original,
        &binding,
        &request,
        audience,
        parent_expires_at,
    )
    .await
    .map(Some)
}

/// Do not deliver the newly stored token until both stores and the signed value agree.
pub(super) async fn published(state: &AppState, token: &str) -> Result<(), Response> {
    let unavailable = || {
        token_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("organization token publication unavailable"),
        )
    };
    let (access, meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta_async(format!("Bearer {token}"))
        .await
        .map_err(|e| {
            if e.is_internal() {
                unavailable()
            } else {
                invalid()
            }
        })?;
    let meta = meta.ok_or_else(invalid)?;
    state
        .tokens
        .validator
        .validate_stored_access_token_jwt(&access, Some(&meta))
        .map_err(|e| {
            if e.is_internal() {
                unavailable()
            } else {
                invalid()
            }
        })?;
    if !crate::web::organization_authority::current(state, &meta, None).await? {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_signed_parent(
    state: &AppState,
    access: &crate::authcode::types::AccessToken,
    subject: &BearerTokenMeta,
) -> Result<(), Response> {
    if subject
        .exchange_grant
        .as_ref()
        .is_some_and(|grant| grant.organization.is_some())
    {
        state
            .tokens
            .validator
            .validate_stored_access_token_jwt(access, Some(subject))
            .map_err(|e| {
                if e.is_internal() {
                    token_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        Some("token verification unavailable"),
                    )
                } else {
                    invalid()
                }
            })?;
    }
    Ok(())
}
