use axum::{middleware, Router};

use super::http_boundary::{build_management_cors_layer, management_security_middleware};
use super::state::ManagementState;
use super::{
    account_link, api_keys, audit_events, client_secrets, clients, configuration_versions,
    connections, core, dcr_bearer_tokens, federation, federation_logout_recovery, key_stores,
    oauth_profiles, operations, runtime_keys, topology, user_credentials, user_inventory, users,
};
use crate::web::AppState;

fn core_routes() -> Router<AppState> {
    core::routes().merge(topology::team_routes())
}

pub(in crate::web) fn observed_router(
    mgmt: ManagementState,
    boundary: crate::web::observed_dispatch::Boundary,
) -> Router<AppState> {
    // Keep preflight and error CORS outside target selection as well. Neither
    // layer uses a store or confers authentication/Environment authority.
    let cors = build_management_cors_layer(&mgmt);
    router(mgmt)
        .layer(middleware::from_fn_with_state(
            boundary,
            crate::web::observed_dispatch::management_target,
        ))
        .layer(cors)
}

fn tenant_routes() -> Router<AppState> {
    topology::tenant_routes()
}

fn environment_identity_routes() -> Router<AppState> {
    topology::environment_identity_routes()
        .merge(configuration_versions::routes())
        .merge(oauth_profiles::routes())
        .merge(connections::routes())
}

fn environment_recovery_routes() -> Router<AppState> {
    federation_logout_recovery::routes()
}

pub fn router(mgmt: ManagementState) -> Router<AppState> {
    let cors = build_management_cors_layer(&mgmt);

    Router::new()
        .merge(core_routes())
        .merge(api_keys::routes())
        .merge(super::installation_inventory::routes())
        .merge(tenant_routes())
        .merge(environment_identity_routes())
        .merge(dcr_bearer_tokens::routes())
        .merge(clients::routes())
        .merge(super::lti::routes())
        .merge(client_secrets::routes())
        .merge(runtime_keys::routes())
        .merge(key_stores::routes())
        .merge(users::routes())
        .merge(user_credentials::routes())
        .merge(user_inventory::routes())
        .merge(environment_recovery_routes())
        .merge(account_link::routes())
        .merge(federation::routes())
        .merge(operations::routes())
        .merge(audit_events::routes())
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            mgmt.clone(),
            management_security_middleware,
        ))
        .merge(super::organizations::routes(mgmt))
}
