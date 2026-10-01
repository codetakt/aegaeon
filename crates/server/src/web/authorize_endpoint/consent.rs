//! Explicit per-request consent. Issuer APIs continue to accept already-authorized grants.
mod rendering;
mod storage;
mod submission;

use super::super::{authorize_context::AuthorizeRequestContext, AppState};
use super::session::AuthorizeSessionState;
use axum::response::Response;
use serde_json::Value;

pub(in crate::web) use submission::submit;

fn has_prompt(ctx: &AuthorizeRequestContext, value: &str) -> bool {
    ctx.prompt.contains(value)
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

fn snapshot(ctx: &AuthorizeRequestContext) -> Result<Value, serde_json::Error> {
    super::super::authorization_snapshot::AuthorizationSnapshot::encode(ctx)
}

pub(super) async fn prepare(
    state: &AppState,
    ctx: &mut AuthorizeRequestContext,
    session: &AuthorizeSessionState,
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
    let token = storage::create(state, session, "/authorize", &snapshot).await?;
    Ok(Some(rendering::form(ctx, &token, &state.issuer)))
}
