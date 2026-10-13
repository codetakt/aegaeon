use super::{
    begin_management_transaction, commit_management_transaction, error_response,
    require_user_management_context, AppState, RequestContext, TeamEnvironmentPath,
};
use crate::lti::{model::ToolConfiguration, store, LtiError};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/lti/registrations",
            get(read).put(replace),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/lti/registrations/activate",
            post(activate),
        )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientQuery {
    client_id: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplaceLtiRegistrationRequest {
    client_id: String,
    base_revision: i64,
    configuration: ToolConfiguration,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivateLtiRegistrationRequest {
    client_id: String,
    revision: i64,
}

fn failure(error: &LtiError, request: &str) -> Response {
    let (status, code, message) = match error {
        LtiError::Invalid | LtiError::Mapping(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid LTI configuration",
        ),
        LtiError::Capacity => (
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "LTI capacity unavailable",
        ),
        LtiError::Conflict => (
            StatusCode::CONFLICT,
            "base_revision_mismatch",
            "LTI revision or permanent identity conflict",
        ),
        LtiError::Denied => (
            StatusCode::NOT_FOUND,
            "not_found",
            "LTI registration or active client not found",
        ),
        LtiError::Unavailable | LtiError::Database(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "LTI configuration store unavailable",
        ),
    };
    error_response(status, code, message, None, Some(request))
}

async fn read(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Query(query): Query<ClientQuery>,
) -> Response {
    let result=async {
        let context=require_user_management_context(&state,&headers,&path,&ctx.request_id).await?;
        let mut tx=begin_management_transaction(&context.pool,&ctx.request_id).await?;
        context.require_lifecycle_role_in_transaction(&mut tx,&ctx.request_id).await?;
        let entry=store::load(&mut tx,context.environment_id,&query.client_id,false).await
            .map_err(|error|failure(&error,&ctx.request_id))?.ok_or_else(||failure(&LtiError::Denied,&ctx.request_id))?;
        let issuer:String=sqlx::query_scalar("SELECT issuer_url FROM aegaeon.environments WHERE id=$1")
            .bind(context.environment_id).fetch_one(&mut *tx).await.map_err(|error|failure(&LtiError::Database(error),&ctx.request_id))?;
        let base=issuer.trim_end_matches('/');
        let exported=json!({"registration":entry,"platform":{"issuer":issuer,"authorizationEndpoint":format!("{base}/lti/authorize"),"jwksUri":format!("{base}/jwks"),"tokenEndpoint":format!("{base}/token"),"launchProducerEndpoint":format!("{base}/lti/launches"),"idTokenSigningAlg":"RS256","messageTypes":["LtiResourceLinkRequest"],"services":[]}});
        commit_management_transaction(tx,&ctx.request_id).await?;
        Ok::<_,Response>(exported)
    }.await;
    match result {
        Ok(entry) => {
            let mut response = Json(entry).into_response();
            crate::util::apply_no_cache_headers(&mut response);
            response
        }
        Err(response) => response,
    }
}

async fn replace(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(body): Json<ReplaceLtiRegistrationRequest>,
) -> Response {
    let result=async {
        let context=require_user_management_context(&state,&headers,&path,&ctx.request_id).await?;
        let mut tx=begin_management_transaction(&context.pool,&ctx.request_id).await?;
        context.require_lifecycle_role_in_transaction(&mut tx,&ctx.request_id).await?;
        let entry=store::replace(&mut tx,context.environment_id,&body.client_id,body.base_revision,&body.configuration,context.session.administrator_id)
            .await.map_err(|error|failure(&error,&ctx.request_id))?;
        store::audit(&mut tx,context.environment_id,&context.session.administrator_id.to_string(),"ADMINISTRATOR",entry.id,
            "management.lti.registration.revised.v1",json!({"revision":entry.revision,"activeRevision":entry.active_revision,"security":entry.configuration.security}))
            .await.map_err(|error|failure(&error,&ctx.request_id))?;
        commit_management_transaction(tx,&ctx.request_id).await?;
        Ok::<_,Response>(entry)
    }.await;
    match result {
        Ok(entry) => {
            let mut response = Json(entry).into_response();
            crate::util::apply_no_cache_headers(&mut response);
            response
        }
        Err(response) => response,
    }
}

async fn activate(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(body): Json<ActivateLtiRegistrationRequest>,
) -> Response {
    let result = async {
        let context =
            require_user_management_context(&state, &headers, &path, &ctx.request_id).await?;
        let mut tx = begin_management_transaction(&context.pool, &ctx.request_id).await?;
        context
            .require_lifecycle_role_in_transaction(&mut tx, &ctx.request_id)
            .await?;
        let entry = store::activate(
            &mut tx,
            context.environment_id,
            &body.client_id,
            body.revision,
        )
        .await
        .map_err(|error| failure(&error, &ctx.request_id))?;
        store::audit(
            &mut tx,
            context.environment_id,
            &context.session.administrator_id.to_string(),
            "ADMINISTRATOR",
            entry.id,
            "management.lti.registration.activated.v1",
            json!({"revision":entry.revision,"security":entry.configuration.security}),
        )
        .await
        .map_err(|error| failure(&error, &ctx.request_id))?;
        commit_management_transaction(tx, &ctx.request_id).await?;
        Ok::<_, Response>(entry)
    }
    .await;
    match result {
        Ok(entry) => {
            let mut response = Json(entry).into_response();
            crate::util::apply_no_cache_headers(&mut response);
            response
        }
        Err(response) => response,
    }
}
