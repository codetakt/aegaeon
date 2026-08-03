use super::account_link_conflict::{preview_account_link_conflict, resolve_account_link_conflict};
use super::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};

mod mutation;
mod read;
mod relink;

use mutation::{create_account_link, delete_account_link};
use read::list_account_links;
use relink::{bulk_relink_account_links, relink_account_link};

#[cfg(test)]
pub(in crate::web::management) use read::LIST_ACCOUNT_LINK_ROWS_SQL;
#[cfg(test)]
pub(in crate::web::management) use relink::LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_SQL;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks",
            get(list_account_links).post(create_account_link),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks/conflictPreview",
            post(preview_account_link_conflict),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks/resolveConflict",
            post(resolve_account_link_conflict),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks/bulkRelink",
            post(bulk_relink_account_links),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks/:accountLinkId",
            delete(delete_account_link),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/accountLinks/:accountLinkId/relink",
            post(relink_account_link),
        )
}
