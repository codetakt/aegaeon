use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

mod audit;
mod mutation;
mod policy;
mod read;
mod scope;
mod store;

use mutation::{issue_client_secret, revoke_all_client_secrets, revoke_client_secret};
use read::list_client_secrets;

#[cfg(test)]
pub(in crate::web::management) use store::{
    LIST_CLIENT_SECRET_ROWS_SQL, REVOKE_ALL_CLIENT_SECRETS_ROWS_SQL, REVOKE_CLIENT_SECRET_ROW_SQL,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/clients/:clientId/clientSecrets",
            get(list_client_secrets).post(issue_client_secret),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/clients/:clientId/clientSecrets/:clientSecretId/revoke",
            post(revoke_client_secret),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/clients/:clientId/clientSecrets/revokeAll",
            post(revoke_all_client_secrets),
        )
}
