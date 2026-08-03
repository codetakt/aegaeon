use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_users::sync_upstream_profile_projection;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use crate::oidc::IdToken;
use crate::upstream::{project_upstream_attribute_mappings, UpstreamAuthRequest};

pub(in crate::web) async fn sync_upstream_callback_projection(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    local_end_user_id: Option<uuid::Uuid>,
    id_token: &IdToken,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(end_user_id) = local_end_user_id else {
        return Ok(());
    };
    if request.attribute_mappings.is_empty() {
        return Ok(());
    }
    let projection = project_upstream_attribute_mappings(&request.attribute_mappings, id_token)
        .map_err(|message| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some(&message),
                issuer_base,
            )
        })?;
    sync_upstream_profile_projection(tx, end_user_id, &projection)
        .await
        .map_err(|message| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some(&message),
                issuer_base,
            )
        })
}
