//! Explicit Organizations configuration. Business access remains disabled by
//! bootstrap; operator sessions cannot be exchanged for membership authority.
mod audit;
mod audit_delivery;
pub(in crate::web::management) mod boundary;
mod client_reads;
mod mutations;
mod object_reads;
mod read;
mod snapshot;

use super::{http_boundary::management_security_middleware, AppState, ManagementState};
use axum::{
    middleware,
    routing::{get, patch, post},
    Router,
};

pub(super) fn routes(mgmt: ManagementState) -> Router<AppState> {
    let cors = super::http_boundary::build_management_cors_layer(&mgmt);
    let snapshots = Router::new()
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/snapshot",
            get(snapshot::export),
        )
        .layer(middleware::from_fn_with_state(
            mgmt.clone(),
            management_security_middleware,
        ))
        .layer(middleware::from_fn(boundary::snapshot));
    let ordinary = Router::new()
        .route("/teams/:team/environments/:environment/organization-domains/:domain/audit-events/pending",get(audit_delivery::pending))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/audit-events/acknowledgments",post(audit_delivery::acknowledge))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/audit-events",get(audit::list))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/support-policy",get(mutations::read_support_policy).put(mutations::configure_support_policy))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations/:organization/administrator-recovery", post(mutations::prepare_administrator_recovery))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/identity-policy",get(mutations::read_identity_policy).put(mutations::configure_identity_policy))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/invitation-delivery",get(mutations::read_delivery).put(mutations::configure_delivery))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations/:organization/invitations", post(mutations::issue_invitation))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/invitations/:invitation", get(mutations::read_invitation))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/role-policy", get(mutations::read_role_policy).put(mutations::replace_role_policy))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations", post(mutations::create_organization).get(object_reads::list))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations/:organization", get(mutations::read_organization))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/targets/introspection-recipients/replace", post(mutations::replace_recipients))
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/enable",
            post(mutations::enable_domain),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/clients",
            post(mutations::create_client).get(client_reads::list),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/clients/:binding",
            patch(mutations::update_client),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/default",
            post(mutations::bootstrap),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain",
            get(mutations::configuration),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/targets",
            post(mutations::register_target),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/operators",
            post(mutations::create).get(read::operators),
        )
        .route(
            "/teams/:team/environments/:environment/organization-domains/:domain/operators/:grant",
            patch(mutations::update),
        )
        .layer(middleware::from_fn_with_state(
            mgmt.clone(),
            management_security_middleware,
        ))
        .layer(middleware::from_fn(boundary::ordinary));
    let revoke = Router::new()
        .route("/teams/:team/environments/:environment/organization-domains/:domain/support-policy/disable",post(mutations::disable_support_policy))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/identity-policy/disable",post(mutations::disable_identity_policy))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/invitation-delivery/disable",post(mutations::disable_delivery))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/invitations/:invitation/revoke", post(mutations::revoke_invitation))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations/:organization/suspend", post(mutations::suspend_organization))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/organizations/:organization/delete", post(mutations::delete_organization))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/targets/introspection-recipients/revoke", post(mutations::revoke_recipients))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/disable", post(mutations::disable_domain))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/clients/:binding/revoke", post(mutations::revoke_client))
        .route("/teams/:team/environments/:environment/organization-domains/:domain/operators/:grant/revoke", post(mutations::revoke))
        .layer(middleware::from_fn_with_state(mgmt, management_security_middleware))
        .layer(middleware::from_fn(boundary::revocation));
    ordinary.merge(revoke).merge(snapshots).layer(cors)
}
