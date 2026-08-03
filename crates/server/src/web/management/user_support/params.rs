use axum::response::Response;
use uuid::Uuid;

use super::super::{TeamEnvironmentUserScopedPath, TeamEnvironmentUserTokenPath};

pub(in crate::web::management) fn require_user_id_param<P>(
    params: &P,
    request_id: &str,
) -> Result<Uuid, Response>
where
    P: TeamEnvironmentUserScopedPath,
{
    crate::web::management::parse_uuid_param(params.user_id_raw(), "userId", request_id)
}

pub(in crate::web::management) fn require_token_id_param(
    params: &TeamEnvironmentUserTokenPath,
    request_id: &str,
) -> Result<Uuid, Response> {
    let (_, _, _, token_id) = params.ids(request_id)?;
    Ok(token_id)
}
