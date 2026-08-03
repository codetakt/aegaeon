use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

mod environment;
mod import_csv;
mod invitation;
mod policy;
mod read;
mod recovery_issuance;
mod responses;
mod revocation;
use import_csv::import_users_csv;
use invitation::invite_user;
use read::get_user_credentials;
use recovery_issuance::{issue_activation_token, issue_password_reset_token};
use revocation::{revoke_user_password_credential, revoke_user_recovery_token};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/credentials",
            get(get_user_credentials),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/activationTokens",
            post(issue_activation_token),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/passwordResetTokens",
            post(issue_password_reset_token),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/credentials/password/revoke",
            post(revoke_user_password_credential),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/recoveryTokens/:tokenId/revoke",
            post(revoke_user_recovery_token),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/invitations",
            post(invite_user),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/importCsv",
            post(import_users_csv),
        )
}
