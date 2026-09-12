use super::super::session::{authorize_decide_session, resolve_authorize_session_state};
use super::{has_prompt, storage};
use crate::web::{
    authorize_context::build_authorize_request_context, form_helpers::auth_session_cookie, AppState,
};
use axum::{
    extract::{rejection::FormRejection, Form, State},
    http::HeaderMap,
    response::Response,
};
use tracing::Instrument;

fn fields(
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Result<(String, String), Response> {
    let Form(pairs) = form.map_err(|_| storage::invalid())?;
    if pairs.len() != 2 {
        return Err(storage::invalid());
    }
    let token = pairs
        .iter()
        .filter(|(k, _)| k == "transaction")
        .collect::<Vec<_>>();
    let choice = pairs
        .iter()
        .filter(|(k, _)| k == "decision")
        .collect::<Vec<_>>();
    if token.len() != 1 || choice.len() != 1 {
        return Err(storage::invalid());
    }
    if token[0].1.len() != 43
        || !token[0]
            .1
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        || !matches!(choice[0].1.as_str(), "approve" | "deny")
    {
        return Err(storage::invalid());
    }
    Ok((token[0].1.clone(), choice[0].1.clone()))
}

async fn process(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
    choice: &str,
) -> Result<Response, Response> {
    let origin = crate::util::single_header_str(headers, "origin")
        .map_err(|_| storage::rejected("consent_origin_malformed"))?;
    let expected = url::Url::parse(&state.issuer)
        .map_err(|_| storage::unavailable())?
        .origin()
        .ascii_serialization();
    if origin != Some(expected.as_str()) {
        return Err(storage::rejected("consent_origin_missing_or_mismatched"));
    }
    let sid = auth_session_cookie(headers)
        .map_err(|_| storage::rejected("consent_session_cookie_malformed"))?
        .ok_or_else(|| storage::rejected("consent_session_cookie_missing"))?;
    let browser = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await
        .map_err(|_| storage::unavailable())?
        .ok_or_else(|| storage::rejected("consent_session_unavailable"))?;
    let pending = storage::load(state, &sid, &browser.user_id, token).await?;
    let uri = pending.uri.parse().map_err(|_| storage::invalid())?;
    let mut ctx =
        build_authorize_request_context(state, &uri, &state.issuer, pending.id.to_string()).await?;
    // Only a consent row already bound to this subject/session may carry the
    // receipt. Do not re-consume its login continuation or trust an HTTP flag.
    ctx.reauthenticated = pending
        .snapshot
        .get("reauthenticated")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(storage::invalid)?;
    super::validate_prompt(state, &ctx)?;
    if !has_prompt(&ctx, "consent")
        || super::snapshot(&ctx).map_err(|_| storage::unavailable())? != pending.snapshot
    {
        return Err(storage::rejected("consent_request_snapshot_mismatch"));
    }
    let decision = authorize_decide_session(state, headers, &ctx, &state.issuer).await?;
    if decision.needs_login || decision.stepup_required {
        return Err(storage::rejected("consent_reauthentication_required"));
    }
    let session = resolve_authorize_session_state(&decision, &state.issuer).await?;
    storage::decide(state, &session, &pending, choice).await?;
    if choice == "deny" {
        return Ok(super::error(
            state,
            &ctx,
            "access_denied",
            "the user denied this authorization",
        ));
    }
    Ok(super::super::finish_authorization(state, ctx, &session).await)
}

pub(in crate::web) async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = async {
        let (token, choice) = match fields(form) {
            Ok(fields) => fields,
            Err(response) => return response,
        };
        match process(&state, &headers, &token, &choice).await {
            Ok(response) | Err(response) => response,
        }
    }
    .instrument(tracing::warn_span!("authorization_consent", request_id = %request_id))
    .await;
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}
