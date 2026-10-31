use super::super::http_boundary::RequestContext;
use super::{
    boundary::{failure, input_error, require_organization_management_session, storage_error},
    read::ListQuery,
    AppState,
};
use crate::organizations::{
    http_input::{
        self,
        objects::{OrganizationListResponse, OrganizationResponse},
        pagination,
    },
    operators::{lock_operator_authority, Capability},
    request_work::Admission,
    Organization, Scope,
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::{Connection, Row};
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
        let session = require_organization_management_session(&state,&headers,&admission,request_id).await?;
        let unavailable = || failure(StatusCode::SERVICE_UNAVAILABLE,"temporarily_unavailable",request_id);
        let mut connection = admission.connection(&state.db_pool).await.map_err(|_| unavailable())?;
        let mut tx = connection.as_mut().map_err(|_| unavailable())?.begin().await.map_err(|_| unavailable())?;
        let scope = Scope { environment_id,domain_id };
        lock_operator_authority(&mut tx,scope,team,session.administrator_id,Capability::Reconcile).await.map_err(|e| storage_error(&e,request_id))?;
        let limit = http_input::page_size(query.page_size.as_deref()).map_err(|e| input_error(e,request_id))?;
        let token = query.page_token.as_deref().map(|v| v.strip_prefix("organizations.").ok_or_else(|| input_error(http_input::InputError::Invalid,request_id))).transpose()?;
        let after = pagination::decode(scope,token).map_err(|e| input_error(e,request_id))?;
        let rows = sqlx::query("SELECT id,external_id,state,revision,grant_generation FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4")
            .bind(environment_id).bind(domain_id).bind(after).bind((limit+1) as i64).fetch_all(&mut *tx).await.map_err(|_| unavailable())?;
        let mut more = rows.len()>limit;
        let mut values = Vec::with_capacity(limit);
        let mut bytes = 0;
        for row in rows.into_iter().take(limit) {
            let value = Organization { scope, id:row.try_get("id").map_err(|_| unavailable())?, external_id:row.try_get("external_id").map_err(|_| unavailable())?, state:serde_json::from_value(serde_json::json!(row.try_get::<String,_>("state").map_err(|_| unavailable())?)).map_err(|_| unavailable())?, revision:row.try_get("revision").map_err(|_| unavailable())?, grant_generation:row.try_get("grant_generation").map_err(|_| unavailable())? };
            value.validate().map_err(|_| unavailable())?;
            let value = OrganizationResponse::from(value);
            let length = serde_json::to_vec(&value).map_err(|_| unavailable())?.len();
            if bytes + length > 60 * 1024 { more = true; break; }
            bytes += length;
            values.push(value);
        }
        let next = if more { Some(format!("organizations.{}",pagination::encode(scope,values.last().ok_or_else(unavailable)?.id).map_err(|_| unavailable())?)) } else { None };
        let value = OrganizationListResponse { organizations:values,page_info:crate::management::types::PageInfo { next_page_token:next } };
        let encoded = serde_json::to_vec(&value).map_err(|_| unavailable())?;
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
