use crate::management::types::{ApplicationAuthorizationResponse, ApplicationAuthorizationUpdate};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use super::super::user_support::{
    write_application_authorization_audit_event, ApplicationAuthorizationAuditTarget,
};
use super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    management_internal_error, require_user_management_context, AppState, RequestContext,
    TeamEnvironmentPath,
};
use crate::application_authorization::inorii::Grant;

pub(super) async fn update(
    State(state): State<AppState>,
    Extension(request): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentPath>,
    Json(body): Json<ApplicationAuthorizationUpdate>,
) -> Response {
    match update_inner(&state, &request.request_id, &headers, &params, body).await {
        Ok(revision) => {
            let mut response = (
                StatusCode::OK,
                Json(ApplicationAuthorizationResponse { revision }),
            )
                .into_response();
            crate::util::apply_no_cache_headers(&mut response);
            response
        }
        Err(response) => response,
    }
}

async fn update_inner(
    state: &AppState,
    request_id: &str,
    headers: &HeaderMap,
    params: &TeamEnvironmentPath,
    body: ApplicationAuthorizationUpdate,
) -> Result<i64, Response> {
    let context = require_user_management_context(state, headers, params, request_id).await?;
    let invalid = || invalid_projection_response(request_id);
    let failed =
        || management_internal_error(request_id, "Application authorization update failed");
    if !valid_update_metadata(&body) {
        return Err(invalid());
    }
    let revision = next_projection_revision(&body).ok_or_else(invalid)?;
    let grant = Grant {
        version: 1,
        environment_id: context.environment_id,
        issuer: state.issuer.to_string(),
        client_id: body.client_id,
        subject: body.subject,
        revision,
        audiences: body.audiences,
        selected_organization: None,
        claims: body.claims,
    };
    grant.validate().map_err(|_| invalid())?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    // Lock the existing projection before deciding whether this is a revocation.
    // Revocation must remain possible after either identity becomes inactive.
    let previous = sqlx::query("SELECT revision, authority, source_revision, client_record_id, end_user_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1 AND client_id=$2 AND subject=$3 FOR UPDATE")
        .bind(context.environment_id).bind(&grant.client_id).bind(&grant.subject)
        .fetch_optional(&mut *tx).await.map_err(|_| failed())?;
    if !body.enabled && previous.is_none() {
        return Err(invalid());
    }
    let revoking = !body.enabled && previous.is_some();
    let identities = lock_projection_identities(
        &mut tx,
        context.environment_id,
        &grant,
        previous.as_ref(),
        revoking,
        request_id,
    )
    .await?;
    // The unique-key conflict handles concurrent first writes. Existing updates use row locking/CAS.
    if previous.as_ref().map_or(body.base_revision != 0, |row| {
        row.get::<i64, _>("revision") != body.base_revision
            || row.get::<String, _>("authority") != body.authority
            || row.get::<i64, _>("source_revision") >= body.source_revision
    }) {
        return Err(error_response(
            StatusCode::CONFLICT,
            "base_revision_mismatch",
            "Application authorization revision or authority has changed",
            None,
            Some(request_id),
        ));
    }
    let inserted = sqlx::query("INSERT INTO aegaeon.application_authorizations (environment_id,client_id,subject,revision,authority,source_revision,audiences,claims,enabled,client_record_id,end_user_record_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$11,$12) ON CONFLICT (environment_id,client_id,subject) DO UPDATE SET revision=EXCLUDED.revision,source_revision=EXCLUDED.source_revision,audiences=EXCLUDED.audiences,claims=EXCLUDED.claims,enabled=EXCLUDED.enabled,client_record_id=EXCLUDED.client_record_id,end_user_record_id=EXCLUDED.end_user_record_id,updated_at=statement_timestamp() WHERE application_authorizations.revision=$10 AND application_authorizations.authority=EXCLUDED.authority AND application_authorizations.source_revision < EXCLUDED.source_revision")
        .bind(context.environment_id).bind(&grant.client_id).bind(&grant.subject).bind(revision)
        .bind(&body.authority).bind(body.source_revision).bind(json!(grant.audiences)).bind(json!(grant.claims)).bind(body.enabled).bind(body.base_revision)
        .bind(identities.client_record_id).bind(identities.end_user_record_id)
        .execute(&mut *tx).await.map_err(|_| failed())?;
    if inserted.rows_affected() != 1 {
        return Err(error_response(
            StatusCode::CONFLICT,
            "base_revision_mismatch",
            "Application authorization revision has changed",
            None,
            Some(request_id),
        ));
    }
    write_application_authorization_audit_event(&mut tx,&context,request_id,identities.target,
        json!({"clientId":grant.client_id,"subject":grant.subject,"fromRevision":body.base_revision,
            "toRevision":revision,"authority":body.authority,"sourceRevision":body.source_revision,
            "enabled":body.enabled,"clientRecordId":identities.client_record_id,"endUserRecordId":identities.end_user_record_id,"audiences":grant.audiences,"claims":grant.claims,"reason":body.reason}),
    ).await?;
    commit_management_transaction(tx, request_id).await?;
    Ok(revision)
}

struct BoundProjectionIdentities<'a> {
    client_record_id: Option<Uuid>,
    end_user_record_id: Option<Uuid>,
    target: ApplicationAuthorizationAuditTarget<'a>,
}

async fn lock_projection_identities<'a>(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    environment: Uuid,
    grant: &'a Grant,
    previous: Option<&sqlx::postgres::PgRow>,
    revoking: bool,
    request_id: &str,
) -> Result<BoundProjectionIdentities<'a>, Response> {
    let invalid = || invalid_projection_response(request_id);
    let failed =
        || management_internal_error(request_id, "Application authorization update failed");
    let projection_target = || ApplicationAuthorizationAuditTarget::Projection {
        client_id: &grant.client_id,
        subject: &grant.subject,
    };
    if revoking {
        let previous = previous.ok_or_else(invalid)?;
        let client_record_id = previous.try_get("client_record_id").map_err(|_| failed())?;
        let end_user_record_id: Option<Uuid> = previous
            .try_get("end_user_record_id")
            .map_err(|_| failed())?;
        // Revoke the stored identity, never whoever now owns the textual subject.
        let target = end_user_record_id.map_or_else(
            projection_target,
            ApplicationAuthorizationAuditTarget::EndUser,
        );
        return Ok(BoundProjectionIdentities {
            client_record_id,
            end_user_record_id,
            target,
        });
    }
    // Projection -> client -> user is also the publication lock order. Shared
    // identity locks block deletion/rename but allow unrelated projection writes.
    let active_client = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2 AND status='ACTIVE' AND deleted_at IS NULL FOR SHARE")
        .bind(environment).bind(&grant.client_id).fetch_optional(&mut **tx).await.map_err(|_| failed())?;
    if active_client.is_none() {
        return Err(invalid());
    }
    let (active_user, target) = if grant.subject == grant.client_id {
        (None, projection_target())
    } else {
        let id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM aegaeon.end_users WHERE subject=$1 AND environment_id=$2 AND status='ACTIVE' FOR SHARE",
        ).bind(&grant.subject).bind(environment).fetch_optional(&mut **tx)
            .await.map_err(|_| failed())?.ok_or_else(invalid)?;
        (Some(id), ApplicationAuthorizationAuditTarget::EndUser(id))
    };
    Ok(BoundProjectionIdentities {
        client_record_id: active_client,
        end_user_record_id: active_user,
        target,
    })
}

fn invalid_projection_response(request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Invalid application authorization projection",
        None,
        Some(request_id),
    )
}

fn next_projection_revision(body: &ApplicationAuthorizationUpdate) -> Option<i64> {
    // Reserve one final revision for an audited disable. Rejecting only MAX
    // would leave a projection at MAX - 1 unable to revoke its authority.
    // Exhausted tombstones cannot be reactivated or have their counters reset.
    let ceiling = if body.enabled {
        i64::MAX - 2
    } else {
        i64::MAX - 1
    };
    if !(1..=ceiling).contains(&body.source_revision) {
        return None;
    }
    body.base_revision
        .checked_add(1)
        .filter(|revision| (1..=ceiling).contains(revision))
}

fn valid_update_metadata(body: &ApplicationAuthorizationUpdate) -> bool {
    !body.reason.trim().is_empty()
        && body.reason.len() <= 1024
        && !body.authority.is_empty()
        && body.authority.len() <= 255
        && body.client_id.len() <= 255
        && body.subject.len() <= 255
}
