mod grants;
mod refresh_tokens;
mod sessions;

use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/sessions",
            get(sessions::list_user_sessions),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/sessions/:sessionId/revoke",
            post(sessions::revoke_user_session),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/grants",
            get(grants::list_user_grants),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/grants/:grantId/revoke",
            post(grants::revoke_user_grant),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/refreshTokens",
            get(refresh_tokens::list_user_refresh_tokens),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/refreshTokens/:refreshTokenId/revoke",
            post(refresh_tokens::revoke_user_refresh_token_inventory),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/invalidateSessions",
            post(sessions::invalidate_user_sessions),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/users/:userId/revokeRefreshTokens",
            post(refresh_tokens::revoke_user_refresh_tokens),
        )
}
