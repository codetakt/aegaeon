mod audit;
mod list;
mod mutation;
mod profile;
mod read;
mod store;

use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

#[cfg(test)]
pub(super) use store::{
    load_user_for_status_sql_for_test, update_user_status_sql_for_test, LIST_USER_ROWS_SQL,
    UPDATE_USER_FIELDS_ROW_SQL,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/users",
            get(list::list_users).post(mutation::create_user),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId",
            get(read::get_user)
                .patch(mutation::update_user)
                .delete(mutation::delete_user),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/profile",
            get(profile::get_user_profile).patch(profile::update_user_profile_handler),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/restore",
            post(mutation::restore_user),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/suspend",
            post(mutation::suspend_user),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/unsuspend",
            post(mutation::unsuspend_user),
        )
}
