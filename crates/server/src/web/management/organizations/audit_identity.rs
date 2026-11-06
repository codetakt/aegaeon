//! Audit delivery alone accepts an explicitly scoped machine credential.
use super::boundary::{failure, require_organization_management_session};
use super::AppState;
use crate::management::types::ApiKeyCapability;
use crate::organizations::request_work::Admission;
use crate::web::management::{session_support, sha256_array, state::ManagementSession};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    team: Uuid,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    if session_support::management_bearer_api_key(headers, request_id)?.is_none() {
        return require_organization_management_session(
            state, headers, admission, request_id, None,
        )
        .await;
    }
    let session =
        session_support::require_management_session_async(state, headers, request_id).await?;
    if session.api_key_team_id() != Some(team)
        || !session.api_key_has_capability(ApiKeyCapability::OrganizationAuditExport)
    {
        return Err(failure(StatusCode::FORBIDDEN, "forbidden", request_id));
    }
    Ok(session)
}

/// Final authorization shares the delivery transaction and retained row locks.
pub(super) async fn recheck_current(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    tx: &mut Transaction<'_, Postgres>,
    session: &ManagementSession,
    team: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    if session.is_human_session() {
        let current = require_organization_management_session(
            state,
            headers,
            admission,
            request_id,
            Some(tx),
        )
        .await?;
        if current.administrator_id != session.administrator_id
            || current.created_at_epoch_secs != session.created_at_epoch_secs
        {
            return Err(failure(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                request_id,
            ));
        }
    } else {
        lock_current(tx, session, headers, team, request_id).await?;
    }
    Ok(())
}

pub(super) async fn lock_current(
    tx: &mut Transaction<'_, Postgres>,
    session: &ManagementSession,
    headers: &HeaderMap,
    team: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    let key = session
        .api_key_id()
        .ok_or_else(|| failure(StatusCode::FORBIDDEN, "forbidden", request_id))?;
    let raw = session_support::management_bearer_api_key(headers, request_id)?
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id))?;
    // Hold the credential and explicit capability through the delivery commit.
    // The materialized lock stage precedes expiry evaluation, including after
    // waiting for a concurrent writer. Do not filter expiry before row locking.
    let found: Option<Uuid> = sqlx::query_scalar(
        "WITH credential AS MATERIALIZED (SELECT ak.id,ak.expires_at FROM aegaeon.api_keys ak JOIN aegaeon.administrators a ON a.id=ak.service_administrator_id JOIN aegaeon.api_key_capabilities c ON c.api_key_id=ak.id WHERE ak.id=$1 AND ak.team_id=$2 AND a.id=$3 AND ak.key_hash=$4 AND ak.status='ACTIVE' AND a.status='ACTIVE' AND a.kind='SERVICE' AND c.capability::text='ORGANIZATION_AUDIT_EXPORT' FOR SHARE OF ak,a,c) SELECT id FROM credential WHERE expires_at IS NULL OR expires_at>clock_timestamp()",
    ).bind(key).bind(team).bind(session.administrator_id).bind(sha256_array(raw.as_bytes()).as_slice())
        .fetch_optional(&mut **tx).await
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", request_id))?;
    if found != Some(key) {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            request_id,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "audit_identity/tests.rs"]
mod tests;
