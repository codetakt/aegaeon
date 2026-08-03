use serde_json::Value;

use crate::upstream::{UpstreamLogoutPolicy, UpstreamLogoutRecoveryPolicy};

/// # Errors
///
/// Returns an error when `configurationDocument.federation.logout` contains
/// invalid types or unsupported values.
pub fn parse_upstream_logout_policy(
    federation: Option<&Value>,
) -> Result<Option<UpstreamLogoutPolicy>, String> {
    let Some(federation) = federation else {
        return Ok(None);
    };
    let Some(logout) = federation.get("logout") else {
        return Ok(None);
    };
    let logout = logout
        .as_object()
        .ok_or_else(|| "configurationDocument.federation.logout must be an object".to_string())?;

    let back_channel = logout
        .get("backChannel")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            "configurationDocument.federation.logout.backChannel must be a boolean".to_string()
        })?;

    let session_hint_claim = match logout.get("sessionHintClaim") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .ok_or_else(|| {
                    "configurationDocument.federation.logout.sessionHintClaim must be a non-empty string when present".to_string()
                })?
                .to_string(),
        ),
    };

    let recovery_policy = match logout.get("recoveryPolicy") {
        None => UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        Some(value) => UpstreamLogoutRecoveryPolicy::parse(
            value
                .as_str()
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .ok_or_else(|| {
                    "configurationDocument.federation.logout.recoveryPolicy must be a non-empty string when present".to_string()
                })?,
        )
        .map_err(|_| {
            "configurationDocument.federation.logout.recoveryPolicy must be force_prompt_login or disable_connection".to_string()
        })?,
    };

    Ok(Some(UpstreamLogoutPolicy {
        back_channel,
        session_hint_claim,
        recovery_policy,
    }))
}
