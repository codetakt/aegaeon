use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    ensure_user_profile_update_requested, error_response, invalid_email_response,
    load_managed_user_identity_for_update, management_internal_error, normalize_email,
    user_profile_from_record, user_profile_not_found, write_user_management_audit_event,
    EndUserAuditEvent, UserManagementContext,
};
use crate::end_user_profiles;
use crate::management::types::{UpdateUserProfileRequest, UserProfile};

pub(super) async fn update_user_profile_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    body: UpdateUserProfileRequest,
    request_id: &str,
) -> Result<UserProfile, Response> {
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let _identity = load_managed_user_identity_for_update(
        &mut tx,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;
    ensure_user_profile_update_requested(&body, request_id)?;
    let normalized_email = match body.email {
        Some(Some(raw)) => normalize_email(&raw)
            .map(|normalized| Some(Some(normalized)))
            .ok_or_else(|| invalid_email_response(request_id))?,
        Some(None) => Some(None),
        None => None,
    };
    let normalized_display_name = match body.display_name {
        Some(Some(raw)) => Some(end_user_profiles::normalize_display_name(&raw)),
        Some(None) => Some(None),
        None => None,
    };
    let (previous, updated) = end_user_profiles::update_user_profile_with_previous(
        &mut tx,
        user_id,
        body.base_version,
        normalized_email,
        body.email_verified,
        normalized_display_name,
        body.custom_claims,
    )
    .await
    .map_err(|err| match err {
        end_user_profiles::UpdateProfileError::NotFound => user_profile_not_found(request_id),
        end_user_profiles::UpdateProfileError::VersionMismatch { current_version } => {
            error_response(
                StatusCode::CONFLICT,
                "base_version_mismatch",
                "Profile baseVersion does not match current version",
                Some(serde_json::json!({ "currentVersion": current_version })),
                Some(request_id),
            )
        }
        end_user_profiles::UpdateProfileError::InvalidCustomClaims(message) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message,
            None,
            Some(request_id),
        ),
        end_user_profiles::UpdateProfileError::Database(_) => {
            management_internal_error(request_id, "Failed to update user profile")
        }
    })?;

    write_user_management_audit_event(
        &mut tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.profile.updated.v1",
            target_id: user_id,
            data: serde_json::json!({
                "userId": updated.user_id,
                "previous": {
                    "email": previous.email,
                    "emailVerified": previous.email_verified,
                    "displayName": previous.display_name,
                    "customClaims": previous.custom_claims,
                    "version": previous.version,
                },
                "current": {
                    "email": updated.email,
                    "emailVerified": updated.email_verified,
                    "displayName": updated.display_name,
                    "customClaims": updated.custom_claims,
                    "version": updated.version,
                },
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(user_profile_from_record(updated))
}
