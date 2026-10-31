use super::super::http_boundary::RequestContext;
use super::{
    boundary::{failure, input_error, require_organization_management_session, storage_error},
    read::ListQuery,
    AppState,
};
use crate::organizations::{audit, http_input, request_work::Admission, Scope};
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
        let limit = http_input::page_size(query.page_size.as_deref())
            .map_err(|e| input_error(e, request_id))?;
        let after = audit::cursor(scope, query.page_token.as_deref())
            .map_err(|e| input_error(e, request_id))?;
        let value = audit::read(&mut tx, scope, team, session.administrator_id, limit, after)
            .await
            .map_err(|e| storage_error(&e, request_id))?;
        let encoded = serde_json::to_vec(&value).map_err(|_| unavailable())?;
        if encoded.len() > http_input::MAX_BODY_BYTES {
            return Err(unavailable());
        }
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
