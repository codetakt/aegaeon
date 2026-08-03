use std::time::Duration;

use aegaeon_jose::RequestObjectClaims;

use crate::authcode::store::RequestObjectJtiAuthorizationCodeCommit;
use crate::request_object_store::{RequestObjectJtiStore, RequestObjectReplayError};

use super::super::super::now_epoch_secs;
use super::error::RequestObjectResolutionError;
use super::types::{RequestObjectAuthorizeDeps, RequestObjectReplayPolicy};

pub(super) fn require_request_object_jti(
    claims: &RequestObjectClaims,
) -> Result<&str, RequestObjectResolutionError> {
    claims
        .jti
        .as_deref()
        .filter(|jti| !jti.trim().is_empty())
        .ok_or_else(|| RequestObjectResolutionError::invalid_request("Request Object jti required"))
}

pub(in crate::web) fn request_object_jti_retention(
    store: &RequestObjectJtiStore,
    claims: &RequestObjectClaims,
    leeway_secs: u64,
) -> Result<Duration, RequestObjectResolutionError> {
    let exp = claims.exp.ok_or_else(|| {
        RequestObjectResolutionError::invalid_request("Request Object exp required")
    })?;
    let now = now_epoch_secs().map_err(|err| {
        RequestObjectResolutionError::internal_error(format!(
            "failed to read request object clock: {err}"
        ))
    })?;
    let replay_window_secs = store.replay_window().as_secs();
    let validity_secs = exp.checked_sub(now).ok_or_else(|| {
        RequestObjectResolutionError::invalid_request("Request Object exp must be in the future")
    })?;
    if validity_secs > replay_window_secs {
        return Err(RequestObjectResolutionError::invalid_request(
            "Request Object exp exceeds jti replay window",
        ));
    }

    let retention_secs = exp
        .checked_add(leeway_secs)
        .ok_or_else(|| {
            RequestObjectResolutionError::invalid_request(
                "Request Object exp plus leeway cannot be represented",
            )
        })?
        .checked_sub(now)
        .ok_or_else(|| {
            RequestObjectResolutionError::invalid_request(
                "Request Object exp must be in the future",
            )
        })?
        .max(1);
    Ok(Duration::from_secs(retention_secs))
}

pub(in crate::web) fn enforce_request_object_jti(
    deps: &RequestObjectAuthorizeDeps<'_>,
    client_id: &str,
    claims: &RequestObjectClaims,
) -> Result<(), RequestObjectResolutionError> {
    let jti = require_request_object_jti(claims)?;
    let retention =
        request_object_jti_retention(deps.request_object_jti_store, claims, deps.jwt_leeway_secs)?;

    match deps
        .request_object_jti_store
        .check_and_store_for(client_id, jti, retention)
    {
        Ok(()) => Ok(()),
        Err(RequestObjectReplayError::Replay) => Err(
            RequestObjectResolutionError::invalid_request("Request Object jti replay detected"),
        ),
        Err(RequestObjectReplayError::RetentionOverflow) => Err(
            RequestObjectResolutionError::invalid_request("Request Object jti retention invalid"),
        ),
        Err(RequestObjectReplayError::BackendUnavailable(err)) => {
            Err(RequestObjectResolutionError::internal_error(format!(
                "Request Object replay store unavailable: {err}"
            )))
        }
    }
}

pub(in crate::web) fn request_object_jti_authorization_code_commit_context(
    deps: &RequestObjectAuthorizeDeps<'_>,
    client_id: &str,
    claims: &RequestObjectClaims,
) -> Result<Option<RequestObjectJtiAuthorizationCodeCommit>, RequestObjectResolutionError> {
    let jti = require_request_object_jti(claims)?;
    let retention =
        request_object_jti_retention(deps.request_object_jti_store, claims, deps.jwt_leeway_secs)?;

    match deps
        .request_object_jti_store
        .authorization_code_commit_context_for(client_id, jti, retention)
    {
        Ok(context) => Ok(context),
        Err(RequestObjectReplayError::Replay) => Err(
            RequestObjectResolutionError::invalid_request("Request Object jti replay detected"),
        ),
        Err(RequestObjectReplayError::RetentionOverflow) => Err(
            RequestObjectResolutionError::invalid_request("Request Object jti retention invalid"),
        ),
        Err(RequestObjectReplayError::BackendUnavailable(err)) => {
            Err(RequestObjectResolutionError::internal_error(format!(
                "Request Object replay store unavailable: {err}"
            )))
        }
    }
}

pub(super) fn apply_request_object_replay_policy(
    deps: &RequestObjectAuthorizeDeps<'_>,
    client_id: &str,
    claims: &RequestObjectClaims,
    policy: RequestObjectReplayPolicy,
) -> Result<(), RequestObjectResolutionError> {
    match policy {
        RequestObjectReplayPolicy::Consume => enforce_request_object_jti(deps, client_id, claims),
        RequestObjectReplayPolicy::Defer => require_request_object_jti(claims).map(|_| ()),
    }
}
