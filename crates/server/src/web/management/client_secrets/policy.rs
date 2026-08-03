use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::config::valid_client_secret_expiration_days;

use super::super::{
    configuration_version_store::load_environment_policy_document_in_transaction, error_response,
    management_internal_error,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClientSecretExpirationPolicy {
    default_days: u32,
    max_days: u32,
}

impl ClientSecretExpirationPolicy {
    fn new(default_days: u32, max_days: u32) -> Option<Self> {
        let default_valid = valid_client_secret_expiration_days(u64::from(default_days));
        let max_valid = valid_client_secret_expiration_days(u64::from(max_days));
        (default_valid && max_valid && default_days <= max_days).then_some(Self {
            default_days,
            max_days,
        })
    }

    pub(super) fn resolve_requested_days(
        self,
        requested_days: Option<u32>,
        request_id: &str,
    ) -> Result<i32, Response> {
        let days = requested_days.unwrap_or(self.default_days);
        if days == 0 || days > self.max_days {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expiresInDays is out of range",
                None,
                Some(request_id),
            ));
        }
        i32::try_from(days).map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expiresInDays is too large",
                None,
                Some(request_id),
            )
        })
    }
}

pub(super) async fn load_client_secret_expiration_policy_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<ClientSecretExpirationPolicy, Response> {
    let policy =
        load_environment_policy_document_in_transaction(tx, environment_id, request_id).await?;
    ClientSecretExpirationPolicy::new(
        policy.client_secret_default_expiration_days,
        policy.client_secret_max_expiration_days,
    )
    .ok_or_else(|| {
        management_internal_error(
            request_id,
            "Environment client secret lifecycle policy is invalid",
        )
    })
}
