use super::super::{error_response, parse_optional_uuid_param};
use axum::{http::StatusCode, response::Response};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FederationLogoutRecoveryIncidentListQuery {
    pub(super) page_size: Option<u32>,
    pub(super) page_token: Option<String>,
    pub(super) connection_id: Option<String>,
    pub(super) status: Option<String>,
    pub(super) recovery_policy: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct FederationLogoutRecoveryIncidentFilters {
    pub(super) connection_id: Option<Uuid>,
    pub(super) status: Option<String>,
    pub(super) recovery_policy: Option<String>,
}

pub(in crate::web::management) fn normalize_federation_logout_recovery_status_filter(
    value: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    match value {
        "pending" | "completed" | "expired" | "callback_rejected" | "operator_cleared" => {
            Ok(Some(value.to_string()))
        }
        _ => Err(
            "Invalid status filter; expected one of pending, completed, expired, callback_rejected, operator_cleared",
        ),
    }
}

pub(in crate::web::management) fn normalize_federation_logout_recovery_policy_filter(
    value: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    match value {
        "force_prompt_login" | "disable_connection" => Ok(Some(value.to_string())),
        _ => Err(
            "Invalid recoveryPolicy filter; expected one of force_prompt_login or disable_connection",
        ),
    }
}

pub(super) fn parse_federation_logout_recovery_incident_filters(
    query: &FederationLogoutRecoveryIncidentListQuery,
    request_id: &str,
) -> Result<FederationLogoutRecoveryIncidentFilters, Response> {
    let connection_id =
        parse_optional_uuid_param(query.connection_id.as_deref(), "connectionId", request_id)?;
    let status = normalize_federation_logout_recovery_status_filter(query.status.as_deref())
        .map_err(|message| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                None,
                Some(request_id),
            )
        })?;
    let recovery_policy =
        normalize_federation_logout_recovery_policy_filter(query.recovery_policy.as_deref())
            .map_err(|message| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                    None,
                    Some(request_id),
                )
            })?;

    Ok(FederationLogoutRecoveryIncidentFilters {
        connection_id,
        status,
        recovery_policy,
    })
}
