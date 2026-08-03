use super::{
    load_management_environment_record, management_internal_error, parse_team_environment_scope,
    require_team_lifecycle_role, state::ManagementSession, ManagementEnvironmentRecord,
    TeamEnvironmentScopedPath,
};
use crate::key_encryption::{
    encrypt_key_handle, load_key_encryption_key, KeyEncryptionKeyLoadError,
    KeyHandleEncryptionContext,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) fn encrypt_key_handle_required(
    plaintext: &str,
    context: KeyHandleEncryptionContext<'_>,
    request_id: &str,
) -> Result<String, Response> {
    let kek = load_key_encryption_key().map_err(|error| {
        tracing::error!(
            target: "management",
            request_id,
            ?error,
            "key encryption key configuration is unavailable"
        );
        management_internal_error(
            request_id,
            match error {
                KeyEncryptionKeyLoadError::Missing => "Key encryption key is not configured",
                KeyEncryptionKeyLoadError::Empty
                | KeyEncryptionKeyLoadError::NonUnicode
                | KeyEncryptionKeyLoadError::InvalidEncoding
                | KeyEncryptionKeyLoadError::InvalidLength(_) => {
                    "Key encryption key is misconfigured"
                }
            },
        )
    })?;
    encrypt_key_handle(plaintext, &kek, context)
        .map_err(|_| management_internal_error(request_id, "Key handle encryption failed"))
}

pub(super) fn generate_random_kid() -> String {
    aegaeon_crypto::rand::random_base64url(16)
}

pub(super) async fn load_key_management_environment<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementEnvironmentRecord, Response>
where
    P: TeamEnvironmentScopedPath,
{
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_team_lifecycle_role(pool, team_id, session, request_id, forbidden_message).await?;
    load_management_environment_record(pool, team_id, environment_id, request_id).await
}
