use super::*;

pub(super) fn validate_loaded_runtime_version(
    state: &AppState,
    link: &UpstreamRefreshLink,
    issuer_base: &str,
) -> Result<(), Response> {
    let loaded = state.runtime_authority.revision().map_err(|_| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("runtime configuration is unavailable"),
            issuer_base,
        )
    })?;
    // Admission can precede activation; a fresh database link must not make the
    // process's older runtime policy appear current.
    if loaded.active_configuration_version_id() != link.configuration_version_id {
        return Err(json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_grant",
            Some("upstream runtime configuration is no longer current"),
            issuer_base,
        ));
    }
    Ok(())
}
