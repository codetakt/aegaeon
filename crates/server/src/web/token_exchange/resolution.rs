use axum::{http::StatusCode, response::Response};
use std::collections::HashSet;
use std::time::SystemTime;

use crate::authcode::types::BearerTokenMeta;
use crate::policy::token_exchange::ExchangeAuthorizationError;

use super::super::{
    scope_members, token_error_response, token_registry_state_error_response, AppState,
    TokenEndpointContext,
};

pub(super) struct ResolvedExchange {
    pub(super) audience: String,
    pub(super) scope: Option<String>,
    pub(super) grant: Option<crate::policy::token_exchange::ExchangeGrant>,
}

pub(super) fn resolve_exchange(
    state: &AppState,
    ctx: &TokenEndpointContext,
    issuer: &str,
    subject: &BearerTokenMeta,
) -> Result<ResolvedExchange, Response> {
    // Same-audience copying also needs a semantic handler. Preserving JSON in
    // metadata alone cannot preserve constraints that resources cannot enforce.
    if subject.authorization_details.is_some() {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token contains unsupported authorization details"),
        ));
    }
    let policy = &state.cfg.token_exchange;
    let selectors: Vec<_> = ctx
        .params
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "audience" | "resource"))
        .cloned()
        .collect();
    // Historical same-audience exchange remains available, with no new target authority.
    if subject.exchange_grant.is_none() {
        let audience = if selectors.is_empty() {
            ctx.client_id.clone()
        } else {
            let first = &selectors[0].1;
            if selectors.iter().any(|(_, value)| value != first) {
                return Err(target_error("conflicting exchange targets"));
            }
            for (kind, value) in &selectors {
                if kind == "resource"
                    && !url::Url::parse(value).is_ok_and(|url| url.fragment().is_none())
                {
                    return Err(target_error("invalid resource indicator"));
                }
            }
            first.clone()
        };
        if audience != subject.audience {
            return Err(target_error("subject has no authorization for this target"));
        }
        return Ok(ResolvedExchange {
            audience,
            scope: resolve_token_exchange_scope(state, ctx, subject)?,
            grant: None,
        });
    }
    if !state.cfg.security_policy.retain_refresh_chain() || subject.refresh_parent.is_none() {
        return Err(target_error(
            "target exchange requires an active refresh lineage",
        ));
    }
    let audience = policy
        .resolve_target(&selectors)
        .map_err(target_error)?
        .ok_or_else(|| target_error("an explicit exchange target is required"))?;
    let requested = ctx
        .form
        .scope
        .as_deref()
        .map(crate::oauth_scope::parse_scope_string)
        .transpose()
        .map_err(|error| scope_error(&error.to_string()))?;
    let grant = subject
        .exchange_grant
        .as_ref()
        .ok_or_else(|| target_error("missing exchange authority"))?;
    let (scopes, grant) = policy
        .authorize(
            grant,
            issuer,
            &ctx.client_id,
            &subject.user_id,
            &subject.audience,
            &subject.granted_scopes,
            &audience,
            requested.as_deref(),
        )
        .map_err(|error| match error {
            ExchangeAuthorizationError::InvalidTarget(reason) => target_error(reason),
            ExchangeAuthorizationError::InvalidScope(reason) => scope_error(reason),
        })?;
    let allowed = state
        .clients
        .try_validate_scope_subset(&ctx.client_id, &scopes)
        .map_err(|error| token_registry_state_error_response("exchange_target_scopes", error))?;
    if !allowed {
        return Err(scope_error("target scope is not allowed for this client"));
    }
    Ok(ResolvedExchange {
        audience,
        scope: Some(scopes.join(" ")),
        grant: Some(grant),
    })
}

fn target_error(reason: &str) -> Response {
    token_error_response(StatusCode::BAD_REQUEST, "invalid_target", Some(reason))
}
fn scope_error(reason: &str) -> Response {
    token_error_response(StatusCode::BAD_REQUEST, "invalid_scope", Some(reason))
}

pub(super) fn resolve_token_exchange_scope(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject_meta: &BearerTokenMeta,
) -> Result<Option<String>, Response> {
    let requested_scopes = scope_members(ctx.form.scope.as_deref()).map_err(|error| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some(&error.to_string()),
        )
    })?;
    let subject_scope_set: HashSet<&str> = subject_meta
        .granted_scopes
        .iter()
        .map(String::as_str)
        .collect();
    let final_scopes = if requested_scopes.is_empty() {
        subject_meta.granted_scopes.clone()
    } else {
        if requested_scopes
            .iter()
            .any(|scope| !subject_scope_set.contains(scope.as_str()))
        {
            return Err(token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                Some("requested scope is not allowed by subject_token"),
            ));
        }
        requested_scopes
    };
    if final_scopes.iter().any(|scope| scope == "openid") {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("openid scope is not allowed for the token-exchange grant"),
        ));
    }
    let client_scope_allowed = if final_scopes.is_empty() {
        true
    } else {
        state
            .clients
            .try_validate_scope_subset(&ctx.client_id, &final_scopes)
            .map_err(|error| {
                token_registry_state_error_response("token_exchange_validate_scope_subset", error)
            })?
    };
    if !client_scope_allowed {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("requested scope is not allowed for this client"),
        ));
    }
    Ok((!final_scopes.is_empty()).then(|| final_scopes.join(" ")))
}

pub(in crate::web) fn token_exchange_expires_in(
    subject_expires_at: SystemTime,
    now: SystemTime,
    access_token_ttl_secs: u64,
) -> Option<u64> {
    let remaining = subject_expires_at.duration_since(now).ok()?.as_secs();
    if remaining == 0 {
        None
    } else {
        Some(remaining.min(access_token_ttl_secs))
    }
}

pub(super) fn resolve_token_exchange_expires_in(
    subject_meta: &BearerTokenMeta,
    access_token_ttl_secs: u64,
    now: SystemTime,
) -> Result<u64, Response> {
    token_exchange_expires_in(subject_meta.expires_at, now, access_token_ttl_secs).ok_or_else(
        || {
            token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("invalid subject_token"),
            )
        },
    )
}

#[cfg(kani)]
mod kani_proofs;
