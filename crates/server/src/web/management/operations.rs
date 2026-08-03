use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use prometheus::{Encoder, TextEncoder};

use crate::management::types::ApiKeyCapability;
use crate::web::AppState;

use super::{
    forbidden, require_management_session_async, state::ManagementSession, RequestContext,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/operations/metrics", get(metrics))
}

async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(ctx): Extension<RequestContext>,
) -> Response {
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    if !can_read_operational_metrics(&session) {
        return forbidden(
            "forbidden",
            "Insufficient permissions for operational metrics",
            &ctx.request_id,
        );
    }
    render_metrics(state.registry.as_ref())
}

fn can_read_operational_metrics(session: &ManagementSession) -> bool {
    session.is_human_session() || session.api_key_has_capability(ApiKeyCapability::AuditRead)
}

fn render_metrics(registry: &prometheus::Registry) -> Response {
    let encoder = TextEncoder::new();
    let mut families = registry.gather();
    let mut global = prometheus::gather();
    families.append(&mut global);

    let mut buf = Vec::new();
    if encoder.encode(&families, &mut buf).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let Ok(text) = String::from_utf8(buf) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, encoder.format_type())],
        text,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn api_key_session(capability: ApiKeyCapability) -> ManagementSession {
        ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![capability],
        )
    }

    #[test]
    fn operational_metrics_read_allows_human_sessions() {
        assert!(can_read_operational_metrics(&ManagementSession::human(
            Uuid::new_v4(),
            1
        )));
    }

    #[test]
    fn operational_metrics_read_allows_audit_or_team_admin_api_keys() {
        assert!(can_read_operational_metrics(&api_key_session(
            ApiKeyCapability::AuditRead
        )));
        assert!(can_read_operational_metrics(&api_key_session(
            ApiKeyCapability::TeamAdministration
        )));
    }

    #[test]
    fn operational_metrics_read_rejects_non_audit_api_keys() {
        assert!(!can_read_operational_metrics(&api_key_session(
            ApiKeyCapability::Read
        )));
    }
}
