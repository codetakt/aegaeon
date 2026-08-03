use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    require_federation_lifecycle_scope, require_team_lifecycle_role_in_transaction,
};
use super::{
    audit::write_trust_anchor_created_audit,
    persistence::{ensure_federation_trust_anchor_unique, insert_federation_trust_anchor},
    validation::{normalized_trust_anchor_entity_id, validate_trust_anchor_jwks},
};
use crate::management::types::{CreateFederationTrustAnchorRequest, FederationTrustAnchor};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

const TRUST_ANCHOR_FORBIDDEN_MESSAGE: &str =
    "Insufficient permissions for federation trust anchor operations";

pub(super) async fn create_federation_trust_anchor_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &CreateFederationTrustAnchorRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<FederationTrustAnchor, Response> {
    let scope = require_federation_lifecycle_scope(
        pool,
        params,
        session,
        request_id,
        TRUST_ANCHOR_FORBIDDEN_MESSAGE,
    )
    .await?;
    let entity_id = normalized_trust_anchor_entity_id(&req.entity_id, request_id)?;
    validate_trust_anchor_jwks(&req.jwks, request_id)?;
    ensure_federation_trust_anchor_unique(pool, scope, &entity_id, request_id).await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        TRUST_ANCHOR_FORBIDDEN_MESSAGE,
    )
    .await?;
    let trust_anchor =
        insert_federation_trust_anchor(&mut tx, scope, &entity_id, req, request_id).await?;
    write_trust_anchor_created_audit(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        &trust_anchor,
        &entity_id,
        req.metadata_policy.is_some(),
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(trust_anchor)
}
