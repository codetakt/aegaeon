//! Explicit per-request consent. Issuer APIs continue to accept already-authorized grants.
mod rendering;
mod storage;
mod submission;

use super::super::{authorize_context::AuthorizeRequestContext, AppState};
use super::session::AuthorizeSessionState;
use axum::{http::Uri, response::Response};
use serde_json::{json, Value};

pub(in crate::web) use submission::submit;

fn has_prompt(ctx: &AuthorizeRequestContext, value: &str) -> bool {
    ctx.prompt.split(' ').any(|p| p == value)
}

fn error(state: &AppState, ctx: &AuthorizeRequestContext, code: &str, message: &str) -> Response {
    super::super::authorize_error_response(
        super::issue::authorize_error_context(
            state,
            &ctx.req,
            ctx.response_mode,
            &state.issuer,
            ctx.state_for_echo.as_deref(),
        ),
        code,
        Some(message),
    )
}

pub(super) fn validate_prompt(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
) -> Result<(), Response> {
    if super::super::authorize_request::prompt_has_conflict(&ctx.prompt) {
        return Err(error(
            state,
            ctx,
            "invalid_request",
            "prompt=none cannot be combined with other prompt values",
        ));
    }
    Ok(())
}

fn snapshot(ctx: &AuthorizeRequestContext) -> Result<Value, serde_json::Error> {
    Ok(
        json!({"request": serde_json::to_value(&ctx.req)?, "prompt": ctx.prompt,
        "response_mode": format!("{:?}", ctx.response_mode), "reauthenticated": ctx.reauthenticated}),
    )
}

fn continuation_uri(ctx: &AuthorizeRequestContext, uri: &Uri) -> String {
    let Some(continuation) = ctx.par_authorize_continuation.as_deref() else {
        return uri.to_string();
    };
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
        if k != "aeg_par_continue" {
            pairs.append_pair(&k, &v);
        }
    }
    pairs.append_pair("aeg_par_continue", continuation);
    format!("{}?{}", uri.path(), pairs.finish())
}

pub(super) async fn prepare(
    state: &AppState,
    ctx: &mut AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    uri: &Uri,
) -> Result<Option<Response>, Response> {
    // OIDC Core section 11: no established alternative offline-consent contract.
    // Requested scopes and an authenticated browser session are not consent.
    if !has_prompt(ctx, "consent") || ctx.req.response_type != "code" {
        if let Some(scope) = &ctx.req.scope {
            ctx.req.scope = Some(
                scope
                    .split(' ')
                    .filter(|s| *s != "offline_access")
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        return Ok(None);
    }
    let snapshot = snapshot(ctx).map_err(|_| storage::unavailable())?;
    let token = storage::create(state, session, &continuation_uri(ctx, uri), &snapshot).await?;
    Ok(Some(rendering::form(ctx, &token, &state.issuer)))
}
