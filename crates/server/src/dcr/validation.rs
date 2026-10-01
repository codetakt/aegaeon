use prometheus::{register_int_counter_vec, Opts};
use std::collections::HashSet;
use std::hash::BuildHasher;

use super::registration::ClientRegistration;
use crate::metrics_support::{metric_or_local, OptionalCounterVec};

mod error;
pub(crate) use error::RegistrationValidationError;

mod config;
mod grant_policy;
mod jwks;
mod metadata;
mod sender_methods;
mod sender_policy;
mod uris;

pub use config::{DcrValidationConfig, SoftwareStatementValidationConfig};
pub(crate) use sender_methods::{
    runtime_supported_sender_constrained_method, RUNTIME_SUPPORTED_DCR_SENDER_METHODS,
};
pub use uris::validate_redirect_uris;
pub(crate) use uris::{validate_jwks_uri, validate_server_callback_uri};

pub(in crate::dcr::validation) static REG_BCP_NONCOMPLIANT: std::sync::LazyLock<
    OptionalCounterVec,
> = std::sync::LazyLock::new(|| {
    OptionalCounterVec::new(metric_or_local(
        register_int_counter_vec!(
            "dcr_bcp_noncompliant_total",
            "DCR BCP noncompliance by reason",
            &["reason"]
        ),
        "dcr_bcp_noncompliant_total",
        || {
            prometheus::IntCounterVec::new(
                Opts::new(
                    "dcr_bcp_noncompliant_total",
                    "DCR BCP noncompliance by reason",
                ),
                &["reason"],
            )
        },
    ))
});

pub(in crate::dcr::validation) fn record_bcp_noncompliance(reason: &'static str) {
    REG_BCP_NONCOMPLIANT.with_label_values(&[reason]).inc();
}

pub(in crate::dcr::validation) fn reject_bcp<T>(
    reason: &'static str,
    message: impl Into<String>,
) -> Result<T, String> {
    record_bcp_noncompliance(reason);
    Err(message.into())
}

pub(in crate::dcr::validation) fn with_bcp_metric(
    reason: &'static str,
    result: Result<(), String>,
) -> Result<(), String> {
    result.inspect_err(|_| {
        record_bcp_noncompliance(reason);
    })
}

/// Validate a client registration against DCR policy, JOSE requirements, and supported methods.
///
/// # Errors
///
/// Returns an error when the registration violates BCP constraints, JOSE policy, or local
/// operator requirements.
pub fn validate_registration<S: BuildHasher>(
    meta: &ClientRegistration,
    require_kid: bool,
    allowed_algs: &HashSet<String, S>,
) -> Result<(), String> {
    validate_registration_with_config(
        meta,
        require_kid,
        allowed_algs,
        &DcrValidationConfig::default(),
    )
}

/// Validate a client registration against an immutable DCR policy snapshot.
///
/// # Errors
///
/// Returns an error when the registration violates BCP constraints, JOSE policy, or local
/// operator requirements.
pub fn validate_registration_with_config<S: BuildHasher>(
    meta: &ClientRegistration,
    require_kid: bool,
    allowed_algs: &HashSet<String, S>,
    config: &DcrValidationConfig,
) -> Result<(), String> {
    validate_registration_with_config_detailed(meta, require_kid, allowed_algs, config)
        .map_err(|error| error.to_string())
}

pub(crate) fn validate_registration_with_config_detailed<S: BuildHasher>(
    meta: &ClientRegistration,
    require_kid: bool,
    allowed_algs: &HashSet<String, S>,
    config: &DcrValidationConfig,
) -> Result<(), RegistrationValidationError> {
    let raw_method = meta
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let method = raw_method.trim();
    let method_normalized = method.to_ascii_lowercase();

    metadata::validate_registration_uris(meta)?;
    metadata::validate_registration_scope(meta).map_err(RegistrationValidationError::Metadata)?;
    metadata::validate_client_key_material(meta, require_kid, allowed_algs, &method_normalized)
        .map_err(RegistrationValidationError::Metadata)?;
    sender_policy::validate_sender_constraint_policy(meta, &method_normalized, config)
        .map_err(RegistrationValidationError::Metadata)?;
    metadata::validate_id_token_signed_response_alg(meta)
        .map_err(RegistrationValidationError::Metadata)?;
    grant_policy::validate_grant_response_policy(meta, config)
        .map_err(RegistrationValidationError::Metadata)
}
