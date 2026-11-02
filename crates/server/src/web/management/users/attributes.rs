use crate::management::types::ReplaceLocalAttributesRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use super::super::{
    begin_management_transaction, commit_management_transaction, enforce_if_match, error_response,
    load_managed_user_identity_for_share, load_managed_user_identity_for_update,
    management_internal_error, require_user_id_param, require_user_management_context,
    write_user_management_audit_event, AppState, EndUserAuditEvent, RequestContext,
    TeamEnvironmentUserPath,
};
use crate::attribute_mapping::{self, AttributeStoreError};

fn audit_data(
    previous_revision: i64,
    revision: i64,
    values: &serde_json::Map<String, Value>,
) -> Result<Value, serde_json::Error> {
    // Bound both serialized bytes and entries before collecting names. Counts
    // retain explicit omission evidence; attribute values never enter the event.
    let mut names = Vec::new();
    let mut bytes = 2; // JSON array brackets.
    for name in values.keys().take(32) {
        let next = serde_json::to_string(name)?.len() + usize::from(!names.is_empty());
        if next > 1024 - bytes {
            break;
        }
        bytes += next;
        names.push(name.as_str());
    }
    Ok(json!({
        "source":"local", "previousRevision":previous_revision, "revision":revision,
        "attributeNames":names, "attributeNameCount":values.len(),
        "omittedAttributeNameCount":values.len() - names.len(),
    }))
}

fn store_error(error: &AttributeStoreError, request_id: &str) -> Response {
    match error {
        AttributeStoreError::OwnerNotFound => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found",
            None,
            Some(request_id),
        ),
        AttributeStoreError::RevisionMismatch { current } => error_response(
            StatusCode::CONFLICT,
            "base_version_mismatch",
            "Attribute baseRevision does not match current revision",
            Some(json!({"currentRevision":current})),
            Some(request_id),
        ),
        AttributeStoreError::InvalidInput | AttributeStoreError::Mapping(_) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid attribute source input",
            None,
            Some(request_id),
        ),
        AttributeStoreError::InvalidData | AttributeStoreError::Database(_) => {
            management_internal_error(request_id, "Attribute source operation failed")
        }
    }
}

pub(super) async fn get(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentUserPath>,
) -> Response {
    match get_inner(&state, &headers, &params, &ctx.request_id).await {
        Ok(value) => super::super::etagged_json(value, &ctx.request_id),
        Err(response) => response,
    }
}

async fn get_inner(
    state: &AppState,
    headers: &HeaderMap,
    params: &TeamEnvironmentUserPath,
    request_id: &str,
) -> Result<Value, Response> {
    let context = require_user_management_context(state, headers, params, request_id).await?;
    let user = require_user_id_param(params, request_id)?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_for_read_in_transaction(&mut tx, request_id)
        .await?;
    load_managed_user_identity_for_share(
        &mut tx,
        context.team_id,
        context.environment_id,
        user,
        request_id,
    )
    .await?;
    let sources = attribute_mapping::load_attribute_sources(&mut *tx, context.environment_id, user)
        .await
        .map_err(|error| store_error(&error, request_id))?;
    commit_management_transaction(tx, request_id).await?;
    Ok(json!({"userId":user,"sources":sources}))
}

pub(super) async fn replace_local(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentUserPath>,
    Json(body): Json<ReplaceLocalAttributesRequest>,
) -> Response {
    match replace_inner(&state, &headers, &params, body, &ctx.request_id).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(response) => response,
    }
}

async fn replace_inner(
    state: &AppState,
    headers: &HeaderMap,
    params: &TeamEnvironmentUserPath,
    body: ReplaceLocalAttributesRequest,
    request_id: &str,
) -> Result<Value, Response> {
    let context = require_user_management_context(state, headers, params, request_id).await?;
    let user = require_user_id_param(params, request_id)?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    load_managed_user_identity_for_update(
        &mut tx,
        context.team_id,
        context.environment_id,
        user,
        request_id,
    )
    .await?;
    if headers.contains_key(axum::http::header::IF_MATCH) {
        let sources =
            attribute_mapping::load_attribute_sources(&mut *tx, context.environment_id, user)
                .await
                .map_err(|error| store_error(&error, request_id))?;
        enforce_if_match(
            headers,
            &json!({"userId":user,"sources":sources}),
            request_id,
        )?;
    }
    let source = attribute_mapping::replace_local_attributes(
        &mut tx,
        context.environment_id,
        user,
        body.base_revision,
        &body.values,
        context.session.administrator_id,
    )
    .await
    .map_err(|error| store_error(&error, request_id))?;
    let values = source
        .values
        .as_object()
        .ok_or_else(|| management_internal_error(request_id, "Invalid stored attribute object"))?;
    let data = audit_data(body.base_revision, source.revision, values)
        .map_err(|_| management_internal_error(request_id, "Attribute audit encoding failed"))?;
    write_user_management_audit_event(
        &mut tx,
        &context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.attributes.replaced.v1",
            target_id: user,
            data,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    Ok(json!({"userId":user,"source":source}))
}
