use super::super::super::oauth_profile_store::RetirableOAuthProfile;
use super::super::super::oauth_profiles_support::OAuthProfileInput;
use super::context::OAuthProfileAuditContext;
use super::snapshot::{oauth_profile_audit_snapshot, oauth_profile_input_audit_snapshot};
use super::writer::write_oauth_profile_audit_event;
use crate::management::types::OAuthProfile;
use axum::response::Response;
use sqlx::{Postgres, Transaction};

pub(in crate::web::management::oauth_profiles) async fn write_oauth_profile_created_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: OAuthProfileAuditContext<'_>,
    input: &OAuthProfileInput,
) -> Result<(), Response> {
    write_oauth_profile_audit_event(
        tx,
        audit_context,
        "management.oauthProfile.created.v1",
        audit_context.oauth_profile_id.to_string(),
        serde_json::json!({
            "oauthProfileId": audit_context.oauth_profile_id.to_string(),
            "configurationVersionId": audit_context.configuration_version_id.to_string(),
            "profileType": &input.profile_type,
            "isDefault": input.is_default,
        }),
    )
    .await
}

pub(in crate::web::management::oauth_profiles) async fn write_oauth_profile_updated_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: OAuthProfileAuditContext<'_>,
    existing_profile: &OAuthProfile,
    input: &OAuthProfileInput,
) -> Result<(), Response> {
    write_oauth_profile_audit_event(
        tx,
        audit_context,
        "management.oauthProfile.updated.v1",
        audit_context.oauth_profile_id.to_string(),
        serde_json::json!({
            "oauthProfileId": audit_context.oauth_profile_id.to_string(),
            "configurationVersionId": audit_context.configuration_version_id.to_string(),
            "previous": oauth_profile_audit_snapshot(existing_profile),
            "current": oauth_profile_input_audit_snapshot(input),
        }),
    )
    .await
}

pub(in crate::web::management::oauth_profiles) async fn write_oauth_profile_deleted_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: OAuthProfileAuditContext<'_>,
    profile: &RetirableOAuthProfile,
) -> Result<(), Response> {
    write_oauth_profile_audit_event(
        tx,
        audit_context,
        "management.oauthProfile.deleted.v1",
        profile.profile_id.to_string(),
        serde_json::json!({
            "oauthProfileId": profile.profile_id.to_string(),
            "configurationVersionId": profile.configuration_version_id.to_string(),
            "name": &profile.name,
            "profileType": &profile.profile_type,
            "isDefault": profile.is_default,
            "expiresAt": &profile.expires_at,
        }),
    )
    .await
}
