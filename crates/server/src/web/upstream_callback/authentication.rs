use super::*;
use crate::organizations::authentication::OriginalAuthentication;
use sqlx::{Postgres, Row, Transaction};

/// Called only after ID Token validation and the callback's identity/profile writes.
/// These are provenance facts; accepted MFA policy is checked separately at use.
pub(super) async fn capture(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    exchange: &super::super::upstream_callback_exchange::UpstreamCallbackExchange,
    user: &UpstreamCallbackUserResolution,
) -> Result<Option<OriginalAuthentication>, sqlx::Error> {
    let Some(auth_time) = exchange.id_token.claims.auth_time else {
        return Ok(None);
    };
    let Some(user_id) = user.local_end_user_id else {
        return Ok(None);
    };
    let Some(observed_at) = now_epoch_secs().ok().and_then(|v| i64::try_from(v).ok()) else {
        return Ok(None);
    };
    let row = sqlx::query("SELECT l.id,l.binding_revision,l.binding_provenance,u.organization_identity_revision FROM aegaeon.account_links l JOIN aegaeon.end_users u ON u.id=l.end_user_id AND u.environment_id=l.environment_id WHERE l.environment_id=$1 AND l.connection_id=$2 AND l.upstream_issuer=$3 COLLATE \"C\" AND l.upstream_sub_hash=$4 COLLATE \"C\" AND u.id=$5 AND u.subject=$6 COLLATE \"C\" AND u.status='ACTIVE' FOR SHARE OF l,u")
        .bind(request.context.environment_id).bind(request.context.connection_id)
        .bind(&request.issuer).bind(&exchange.upstream_sub_hash).bind(user_id)
        .bind(&user.user_id).fetch_optional(&mut **tx).await?;
    let Some(row) = row else { return Ok(None) };
    let evidence = OriginalAuthentication {
        version: 1,
        context: request.context,
        issuer: exchange.id_token.claims.iss.clone(),
        upstream_client_id: request.client_id.clone(),
        upstream_subject_hash: exchange.upstream_sub_hash.clone(),
        user_id,
        subject: user.user_id.clone(),
        identity_revision: row.try_get("organization_identity_revision")?,
        account_link_id: row.try_get("id")?,
        account_link_revision: row.try_get("binding_revision")?,
        account_link_provenance: row.try_get("binding_provenance")?,
        auth_time,
        observed_at,
        acr: exchange.id_token.claims.acr.clone(),
        amr: exchange.id_token.claims.amr.clone(),
    };
    Ok(evidence.validate().is_ok().then_some(evidence))
}
