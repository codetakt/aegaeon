use super::super::http_boundary::RequestContext;
use super::read::ListQuery;
use super::{
    boundary::{failure, input_error, require_organization_management_session, storage_error},
    AppState,
};
use crate::organizations::{
    http_input::{self, pagination, OrganizationClientListResponse},
    operators::mutations::clients,
    request_work::Admission,
    Scope,
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::Connection;
use uuid::Uuid;

pub(super) async fn list(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let request_id = &context.request_id;
        let session =
            require_organization_management_session(&state, &headers, &admission, request_id)
                .await?;
        let unavailable = || {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                request_id,
            )
        };
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| unavailable())?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable())?
            .begin()
            .await
            .map_err(|_| unavailable())?;
        let scope = Scope {
            environment_id,
            domain_id,
        };
        let values = clients::list(&mut tx, scope, team, session.administrator_id)
            .await
            .map_err(|e| storage_error(&e, request_id))?;
        let encoded = encode_page(scope, values, &query, request_id)?;
        let current =
            require_organization_management_session(&state, &headers, &admission, request_id)
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
        admission.admit_commit().map_err(|_| unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        connection.release().await;
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(encoded),
        )
            .into_response())
    }
    .await;
    match result {
        Ok(response) | Err(response) => response,
    }
}

fn encode_page(
    scope: Scope,
    values: Vec<clients::ClientBinding>,
    query: &ListQuery,
    request_id: &str,
) -> Result<Vec<u8>, Response> {
    let unavailable = || {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    };
    let limit = http_input::page_size(query.page_size.as_deref())
        .map_err(|e| input_error(e, request_id))?;
    let token = query
        .page_token
        .as_deref()
        .map(|v| {
            v.strip_prefix("clients.")
                .ok_or_else(|| input_error(http_input::InputError::Invalid, request_id))
        })
        .transpose()?;
    let after = pagination::decode(scope, token).map_err(|e| input_error(e, request_id))?;
    let mut page = Vec::new();
    let mut bytes = 0;
    let mut more = false;
    for value in values
        .into_iter()
        .filter(|v| after.is_none_or(|id| v.id > id))
    {
        let length = serde_json::to_vec(&value).map_err(|_| unavailable())?.len();
        if page.len() >= limit || bytes + length > 60 * 1024 {
            more = true;
            break;
        }
        bytes += length;
        page.push(value);
    }
    let next = if more {
        Some(format!(
            "clients.{}",
            pagination::encode(scope, page.last().ok_or_else(unavailable)?.id)
                .map_err(|_| unavailable())?
        ))
    } else {
        None
    };
    let response = OrganizationClientListResponse {
        clients: page,
        page_info: crate::management::types::PageInfo {
            next_page_token: next,
        },
    };
    let encoded = serde_json::to_vec(&response).map_err(|_| unavailable())?;
    if encoded.len() > http_input::MAX_BODY_BYTES {
        return Err(unavailable());
    }
    Ok(encoded)
}
