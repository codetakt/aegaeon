use super::super::super::{
    load_account_link_conflict_candidates, load_account_link_connection,
    load_account_link_summary_by_upstream_subject, parse_account_link_subject, parse_uuid_param,
    require_account_link_lifecycle_scope,
};
use crate::management::types::{AccountLinkConflictPreview, PreviewAccountLinkConflictRequest};
use crate::upstream::upstream_subject_link_hash;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn preview_account_link_conflict_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &PreviewAccountLinkConflictRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<AccountLinkConflictPreview, Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let connection_id = parse_uuid_param(&req.connection_id, "connectionId", request_id)?;
    let upstream_subject = parse_account_link_subject(&req.upstream_subject, request_id)?;
    let connection = load_account_link_connection(pool, scope, connection_id, request_id).await?;
    let upstream_sub_hash = upstream_subject_link_hash(&connection.issuer_url, &upstream_subject);
    let existing_account_link = load_account_link_summary_by_upstream_subject(
        pool,
        scope.team,
        scope.environment,
        &connection.issuer_url,
        &upstream_sub_hash,
        request_id,
    )
    .await?;
    let candidate_end_users = load_account_link_conflict_candidates(
        pool,
        scope.team,
        scope.environment,
        &upstream_subject,
        request_id,
    )
    .await?;

    Ok(AccountLinkConflictPreview {
        requested_connection_id: connection_id.to_string(),
        requested_connection_identifier: connection.connection_identifier,
        requested_connection_name: connection.name,
        upstream_issuer: connection.issuer_url,
        upstream_subject,
        existing_account_link,
        candidate_end_users,
    })
}
