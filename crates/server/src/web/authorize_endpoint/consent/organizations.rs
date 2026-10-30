use super::{error, has_prompt, storage};
use crate::organizations::{
    consent::{self, CaptureContext, Consent, GrantRequest},
    request_work::Admission,
};
use crate::web::{
    authorize_context::AuthorizeRequestContext, authorize_endpoint::session::AuthorizeSessionState,
    AppState,
};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Connection;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    authorization: Value,
    organization: Consent,
}

pub(super) fn unpack(value: &Value) -> Result<(Value, Option<Consent>), Response> {
    if value.get("organization").is_none() {
        return Ok((value.clone(), None));
    }
    let envelope: Envelope =
        serde_json::from_value(value.clone()).map_err(|_| storage::invalid())?;
    if envelope.version != 1 {
        return Err(storage::invalid());
    }
    Ok((envelope.authorization, Some(envelope.organization)))
}

pub(super) async fn prepare(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    snapshot: Value,
) -> Result<(Value, Option<Consent>), Response> {
    if ctx.req.authorization_details.is_none() {
        return Ok((snapshot, None));
    }
    let captured_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or_else(storage::unavailable)?;
    let consent = capture(state, ctx, session, captured_at).await?;
    let envelope = serde_json::to_value(Envelope {
        version: 1,
        authorization: snapshot,
        organization: consent.clone(),
    })
    .map_err(|_| storage::unavailable())?;
    if serde_json::to_vec(&envelope)
        .map_err(|_| storage::unavailable())?
        .len()
        > 64 * 1024
    {
        return Err(storage::invalid());
    }
    Ok((envelope, Some(consent)))
}

pub(super) async fn capture(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    captured_at: i64,
) -> Result<Consent, Response> {
    let denied = || {
        error(
            state,
            ctx,
            "invalid_authorization_details",
            "organization authorization is unavailable",
        )
    };
    let details = ctx.req.authorization_details.as_ref().ok_or_else(denied)?;
    let request = GrantRequest::parse(details).map_err(|_| denied())?;
    let dpop = ctx.req.dpop_jkt.as_ref().ok_or_else(denied)?;
    if ctx.req.response_type != "code"
        || !has_prompt(ctx, "consent")
        || !ctx
            .req
            .scope
            .as_deref()
            .is_some_and(|s| s.split(' ').any(|p| p == "offline_access"))
        || !state.cfg.security_policy.retain_refresh_chain()
    {
        return Err(denied());
    }
    let admission = Admission::try_acquire().map_err(|_| storage::unavailable())?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| storage::unavailable())?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| storage::unavailable())?
            .begin()
            .await
            .map_err(|_| storage::unavailable())?;
        let value = consent::capture(
            &mut tx,
            CaptureContext {
                environment_id: state.environment_id,
                issuer: &state.issuer,
                client_id: &ctx.req.client_id,
                subject: &session.user_id,
                dpop_jkt: dpop.as_str(),
                auth_time: session.auth_time_epoch_secs,
                captured_at,
                original_authentication: session.original_authentication.as_ref(),
            },
            &request,
        )
        .await
        .map_err(|e| match e {
            crate::organizations::repository::RepositoryError::Authority(_) => denied(),
            _ => storage::unavailable(),
        })?;
        tx.commit().await.map_err(|_| storage::unavailable())?;
        connection.release().await;
        Ok(value)
    })
    .await
    .map_err(|_| storage::unavailable())?;
    result
}

pub(super) async fn recheck(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    saved: &Consent,
) -> Result<(), Response> {
    if !saved.support.is_empty() {
        let now = crate::util::now_unix_epoch_secs()
            .ok()
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(storage::unavailable)?;
        let evidence = saved
            .original_authentication
            .as_ref()
            .ok_or_else(|| storage::rejected("organization_support_authentication_missing"))?;
        if now < evidence.auth_time || now - evidence.auth_time >= 300 {
            return Err(storage::rejected(
                "organization_support_authentication_expired",
            ));
        }
    }
    let current = capture(state, ctx, session, saved.captured_at).await?;
    if current != *saved {
        return Err(storage::rejected("organization_consent_authority_changed"));
    }
    Ok(())
}
