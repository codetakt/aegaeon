use ffi::dcr;
use std::collections::HashSet;

use super::super::registration::ClientRegistration;
use super::config::DcrValidationConfig;
use super::sender_methods::{
    build_sender_methods_mask, runtime_supported_sender_constrained_method,
    runtime_supported_token_endpoint_auth_method, LABEL_SENDER_METHOD_UNIMPLEMENTED,
    LABEL_SENDER_METHOD_UNKNOWN, LABEL_TOKEN_METHOD_UNIMPLEMENTED, LABEL_TOKEN_METHOD_UNKNOWN,
    MAX_SENDER_METHODS,
};
use super::{record_bcp_noncompliance, reject_bcp};

struct DeclaredSenderMethods {
    sorted: Vec<String>,
}

impl DeclaredSenderMethods {
    fn from_registration(meta: &ClientRegistration) -> Self {
        let mut declared: HashSet<String> = meta
            .sender_constrained_methods
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| !m.is_empty())
            .collect();
        if meta.require_dpop == Some(true) {
            declared.insert("dpop".into());
        }
        if meta.require_mtls == Some(true) {
            declared.insert("mtls".into());
        }

        let mut sorted = declared.into_iter().collect::<Vec<_>>();
        sorted.sort();
        sorted.truncate(MAX_SENDER_METHODS);
        Self { sorted }
    }

    fn is_declared(&self) -> bool {
        !self.sorted.is_empty()
    }
}

fn token_method_tag_or_reject(method_normalized: &str) -> Result<dcr::TokenMethodTag, String> {
    dcr::TokenMethodTag::from_label(method_normalized).ok_or_else(|| {
        record_bcp_noncompliance(LABEL_TOKEN_METHOD_UNKNOWN);
        format!("token_endpoint_auth_method '{method_normalized}' is not supported")
    })
}

fn validate_runtime_token_method(method_normalized: &str) -> Result<(), String> {
    if runtime_supported_token_endpoint_auth_method(method_normalized) {
        Ok(())
    } else {
        reject_bcp(
            LABEL_TOKEN_METHOD_UNIMPLEMENTED,
            format!(
                "token_endpoint_auth_method '{method_normalized}' is not implemented by this server"
            ),
        )
    }
}

fn sender_methods_mask_or_reject(
    declared: &DeclaredSenderMethods,
) -> Result<dcr::SenderMethodsMask, String> {
    build_sender_methods_mask(&declared.sorted).inspect_err(|_| {
        record_bcp_noncompliance(LABEL_SENDER_METHOD_UNKNOWN);
    })
}

fn reject_unimplemented_sender_registration(
    declared: &DeclaredSenderMethods,
) -> Result<(), String> {
    if let Some(unimplemented) = declared
        .sorted
        .iter()
        .find(|method| !runtime_supported_sender_constrained_method(method))
    {
        reject_bcp(
            LABEL_SENDER_METHOD_UNIMPLEMENTED,
            format!(
                "sender-constrained dynamic client registration method '{unimplemented}' is not implemented by this server"
            ),
        )
    } else {
        Ok(())
    }
}

fn allowed_sender_mask_or_reject(
    config: &DcrValidationConfig,
) -> Result<dcr::SenderMethodsMask, String> {
    build_sender_methods_mask(&config.allowed_sender_methods).inspect_err(|_| {
        record_bcp_noncompliance(LABEL_SENDER_METHOD_UNKNOWN);
    })
}

fn validate_lowstar_dcr_policy(
    meta: &ClientRegistration,
    config: &DcrValidationConfig,
    token_method_tag: dcr::TokenMethodTag,
    declared: &DeclaredSenderMethods,
    sender_methods_mask: dcr::SenderMethodsMask,
    allowed_sender_mask: dcr::SenderMethodsMask,
) -> Result<(), String> {
    dcr::validate_metadata(
        token_method_tag,
        meta.pkce_required.is_some(),
        meta.pkce_required == Some(true),
        meta.require_sender_constrained_tokens.is_some(),
        meta.require_sender_constrained_tokens == Some(true),
        declared.is_declared(),
        sender_methods_mask,
        config.require_pkce_for_public,
        config.require_pkce_for_confidential,
        config.require_sender_constrained,
        allowed_sender_mask,
    )
    .map_err(|policy_err| {
        record_bcp_noncompliance(policy_err.metric_label());
        policy_err.description().to_string()
    })
}

pub(super) fn validate_sender_constraint_policy(
    meta: &ClientRegistration,
    method_normalized: &str,
    config: &DcrValidationConfig,
) -> Result<(), String> {
    let declared = DeclaredSenderMethods::from_registration(meta);
    let token_method_tag = token_method_tag_or_reject(method_normalized)?;
    validate_runtime_token_method(method_normalized)?;
    let sender_methods_mask = sender_methods_mask_or_reject(&declared)?;
    reject_unimplemented_sender_registration(&declared)?;
    let allowed_sender_mask = allowed_sender_mask_or_reject(config)?;
    validate_lowstar_dcr_policy(
        meta,
        config,
        token_method_tag,
        &declared,
        sender_methods_mask,
        allowed_sender_mask,
    )
}
