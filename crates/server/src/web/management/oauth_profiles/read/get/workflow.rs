use crate::management::types::OAuthProfile;
use crate::web::management::oauth_profile_store::{load_oauth_profile, oauth_profile_not_found};
use crate::web::management::state::ManagementSession;
use crate::web::management::{ensure_team_visible_as, parse_team_environment_oauth_profile_scope};
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management) async fn get_oauth_profile_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentOAuthProfilePath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<OAuthProfile, Response> {
    let (team_id, environment_id, oauth_profile_id) =
        parse_team_environment_oauth_profile_scope(params, request_id)?;
    ensure_team_visible_as(pool, team_id, session, request_id, oauth_profile_not_found).await?;

    let Some(profile) =
        load_oauth_profile(pool, team_id, environment_id, oauth_profile_id, request_id).await?
    else {
        return Err(oauth_profile_not_found(request_id));
    };

    Ok(profile)
}
