pub(super) use super::topology_environment::environment_identity_routes;
use super::topology_environment::{create_environment, list_environments};
use super::AppState;
use axum::{routing::get, Router};

mod teams;
mod tenants;
pub(in crate::web::management) use teams::get_team_inner;
use teams::{create_team, delete_team, get_team, list_teams, update_team};
pub(in crate::web::management) use tenants::get_tenant_inner;
use tenants::{create_tenant, delete_tenant, get_tenant, list_tenants, update_tenant};

pub(super) fn team_routes() -> Router<AppState> {
    Router::new()
        .route("/teams", get(list_teams).post(create_team))
        .route(
            "/teams/:teamId",
            get(get_team).patch(update_team).delete(delete_team),
        )
}

pub(super) fn tenant_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/tenants",
            get(list_tenants).post(create_tenant),
        )
        .route(
            "/teams/:teamId/tenants/:tenantId",
            get(get_tenant).patch(update_tenant).delete(delete_tenant),
        )
        .route(
            "/teams/:teamId/tenants/:tenantId/environments",
            get(list_environments).post(create_environment),
        )
}
