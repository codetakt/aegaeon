use super::super::http_boundary::RequestContext;
use super::{
    boundary::{failure, input_error, require_organization_management_session, storage_error},
    AppState,
};
use crate::organizations::{
    http_input::{self, pagination, OperatorListResponse},
    operators::{
        lock_operator_authority, mutations::OperatorGrant, validate_capabilities, Capability,
        MAX_OPERATORS,
    },
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
use serde::Deserialize;
use sqlx::{Connection, Row};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ListQuery {
    pub(super) page_size: Option<String>,
    pub(super) page_token: Option<String>,
}

pub(super) async fn operators(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let request_id = &context.request_id;
        let session = require_organization_management_session(&state,&headers,&admission,request_id).await?;
        let unavailable = || failure(StatusCode::SERVICE_UNAVAILABLE,"temporarily_unavailable",request_id);
        let mut connection = admission.connection(&state.db_pool).await.map_err(|_| unavailable())?;
        let mut tx = connection.as_mut().map_err(|_| unavailable())?.begin().await.map_err(|_| unavailable())?;
        let scope = Scope { environment_id,domain_id };
        lock_operator_authority(&mut tx,scope,team,session.administrator_id,Capability::Configure).await.map_err(|e| storage_error(&e,request_id))?;
        let limit = http_input::page_size(query.page_size.as_deref()).map_err(|e| input_error(e,request_id))?;
        let after = pagination::decode(scope,query.page_token.as_deref()).map_err(|e| input_error(e,request_id))?;
        let rows = sqlx::query("SELECT id,administrator_id,active,revision,capabilities FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2 ORDER BY id LIMIT 65")
            .bind(environment_id).bind(domain_id).fetch_all(&mut *tx).await.map_err(|_| unavailable())?;
        if rows.len()>MAX_OPERATORS { return Err(unavailable()); }
        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(|_| unavailable())?;
            let administrator_id: Uuid = row.try_get("administrator_id").map_err(|_| unavailable())?;
            let revision: i64 = row.try_get("revision").map_err(|_| unavailable())?;
            let values: Vec<Capability> = serde_json::from_value(row.try_get("capabilities").map_err(|_| unavailable())?).map_err(|_| unavailable())?;
            let capabilities = validate_capabilities(&values).map_err(|_| unavailable())?;
            if id.is_nil() || administrator_id.is_nil() || revision<=0 { return Err(unavailable()); }
            if after.is_none_or(|after| id>after) {
                grants.push(OperatorGrant {id,scope,administrator_id,revision,capabilities,active:row.try_get("active").map_err(|_| unavailable())?});
            }
        }
        let more = grants.len()>limit;
        grants.truncate(limit);
        let next = if more {
            Some(pagination::encode(scope,grants.last().ok_or_else(unavailable)?.id).map_err(|_| unavailable())?)
        } else { None };
        let response = OperatorListResponse {operators:grants.into_iter().map(Into::into).collect(),page_info:crate::management::types::PageInfo {next_page_token:next}};
        let encoded = serde_json::to_vec(&response).map_err(|_| unavailable())?;
        if encoded.len()>http_input::MAX_BODY_BYTES { return Err(unavailable()); }
        let current = require_organization_management_session(&state,&headers,&admission,request_id).await?;
        if current.administrator_id!=session.administrator_id || current.created_at_epoch_secs!=session.created_at_epoch_secs {
            return Err(failure(StatusCode::UNAUTHORIZED,"unauthenticated",request_id));
        }
        admission.admit_commit().map_err(|_|unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        connection.release().await;
        Ok((StatusCode::OK,[(header::CONTENT_TYPE,"application/json")],Body::from(encoded)).into_response())
    }.await;
    match result {
        Ok(response) | Err(response) => response,
    }
}
