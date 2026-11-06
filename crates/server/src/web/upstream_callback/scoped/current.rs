use super::*;
use sqlx::Row;

#[derive(PartialEq, Eq)]
pub(super) struct Linked {
    pub id: uuid::Uuid,
    pub subject: String,
}

pub(super) async fn check(
    callback: &Callback<'_>,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), Response> {
    let Callback {
        state,
        request,
        exchange,
        expected,
        started,
        ..
    } = callback;
    super::super::super::organization_authority::recheck_projection(state, tx, expected).await?;
    let c = request.context;
    let document: Option<serde_json::Value>=sqlx::query_scalar("SELECT cv.configuration_document FROM aegaeon.connections c JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id JOIN aegaeon.configuration_versions cv ON cv.id=c.configuration_version_id AND cv.environment_id=e.id JOIN aegaeon.tenants n ON n.id=e.tenant_id JOIN aegaeon.teams t ON t.id=n.team_id WHERE c.id=$1 AND e.id=$2 AND c.configuration_version_id=$3 AND t.id=$4 AND n.id=$5 AND c.issuer_url=$6 COLLATE \"C\" AND c.client_id=$7 COLLATE \"C\" AND c.client_auth_method=$8 COLLATE \"C\" AND c.status='ACTIVE' AND c.deleted_at IS NULL AND c.connection_type='OIDC' AND cv.status='ACTIVE' AND e.status='ACTIVE' AND n.status='ACTIVE' AND t.status='ACTIVE' FOR SHARE OF c,cv,e,n,t")
        .bind(c.connection_id).bind(c.environment_id).bind(c.configuration_version_id).bind(c.team_id).bind(c.tenant_id)
        .bind(&request.issuer).bind(&request.client_id).bind(&request.client_auth_method)
        .fetch_optional(&mut **tx).await.map_err(|_|unavailable(state))?;
    let document = document.ok_or_else(|| denied(state))?;
    let federation = document.get("federation");
    let jit = crate::upstream::parse_upstream_jit_provisioning_policy(federation)
        .map_err(|_| denied(state))?;
    let mappings = crate::upstream::parse_upstream_attribute_mappings(federation)
        .map_err(|_| denied(state))?;
    let release = crate::upstream::parse_upstream_claim_release_policy(federation, &mappings)
        .map_err(|_| denied(state))?;
    let logout =
        crate::upstream::parse_upstream_logout_policy(federation).map_err(|_| denied(state))?;
    if jit != request.jit_provisioning_policy
        || mappings != request.attribute_mappings
        || release != request.claim_release_policy
        || logout != request.logout_policy
    {
        return Err(denied(state));
    }
    let clock = std::time::SystemTime::now();
    let now = clock
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| unavailable(state))?
        .as_secs();
    let time = i64::try_from(now).map_err(|_| unavailable(state))?;
    let claims = &exchange.id_token.claims;
    if now < *started
        || clock < request.issued_at
        || clock >= request.expires_at
        || claims.iat > time
        || claims.exp <= time
        || claims.iss != request.issuer
        || crate::upstream::upstream_subject_link_hash(&claims.iss, &claims.sub)
            != exchange.upstream_sub_hash
    {
        return Err(denied(state));
    }
    Ok(())
}

pub(super) async fn linked(
    callback: &Callback<'_>,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<Linked>, Response> {
    let row=sqlx::query("SELECT u.id,u.subject,u.status::text AS status,l.connection_id FROM aegaeon.account_links l JOIN aegaeon.end_users u ON u.id=l.end_user_id AND u.environment_id=l.environment_id WHERE l.environment_id=$1 AND l.upstream_issuer=$2 COLLATE \"C\" AND l.upstream_sub_hash=$3 COLLATE \"C\" FOR UPDATE OF l,u")
        .bind(callback.state.environment_id).bind(&callback.request.issuer).bind(&callback.exchange.upstream_sub_hash)
        .fetch_optional(&mut **tx).await.map_err(|_|unavailable(callback.state))?;
    let Some(row) = row else { return Ok(None) };
    let status: String = row
        .try_get("status")
        .map_err(|_| unavailable(callback.state))?;
    let connection: uuid::Uuid = row
        .try_get("connection_id")
        .map_err(|_| unavailable(callback.state))?;
    if status != "ACTIVE" || connection != callback.request.context.connection_id {
        return Err(denied(callback.state));
    }
    Ok(Some(Linked {
        id: row.try_get("id").map_err(|_| unavailable(callback.state))?,
        subject: row
            .try_get("subject")
            .map_err(|_| unavailable(callback.state))?,
    }))
}
