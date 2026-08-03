mod export;
mod read;
mod scope;
mod store;

use super::AppState;
use axum::{routing::get, Router};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/auditEvents",
            get(read::list_team_audit_events),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/auditEvents",
            get(read::list_environment_audit_events),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/auditEvents/export",
            get(export::export_environment_audit_events),
        )
        .route(
            "/teams/:teamId/auditEvents/export",
            get(export::export_team_audit_events),
        )
        .route(
            "/teams/:teamId/auditEvents/:auditEventId",
            get(read::get_audit_event),
        )
}
