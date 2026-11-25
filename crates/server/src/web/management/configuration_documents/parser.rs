mod key_store;
mod policy;
mod scope;

use super::super::configuration_federation::{
    federation_configuration_audit_snapshot, validate_configuration_document_federation,
    validate_federation_policy_for_environment,
};
use super::super::error_response;
use super::{
    validate_patched_policy, ActivatedEnvironmentConfiguration, EnvironmentConfigurationState,
};
use axum::{http::StatusCode, response::Response};

use crate::runtime_configuration::parse_configuration_document_v1;
use key_store::parse_configuration_key_store;
pub(in crate::web::management) use policy::{
    load_policy_from_configuration_snapshot, parse_configuration_policy_document,
    require_configuration_policy_for_request,
};
pub(in crate::web::management) use scope::parse_configuration_scope_allowlist;

fn parse_configuration_document_shape(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<crate::runtime_configuration::ConfigurationDocumentV1, Response> {
    parse_configuration_document_v1(configuration_document).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument must be a strict schemaVersion=1 document",
            None,
            Some(request_id),
        )
    })
}

pub(in crate::web::management) fn validate_configuration_document_for_environment(
    configuration_document: &serde_json::Value,
    issuer_host: &str,
    issuer_url: &str,
    request_id: &str,
    mismatch_message: &str,
) -> Result<(), Response> {
    let document = parse_configuration_document_shape(configuration_document, request_id)?;
    if let Some(mapping) = &document.attribute_mapping {
        mapping.validate().map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.attributeMapping is invalid",
                None,
                Some(request_id),
            )
        })?;
    }
    crate::runtime_configuration::PresentationDocument::settings(document.presentation.as_ref())
        .map_err(|message| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                None,
                Some(request_id),
            )
        })?;
    if document.schema_version != 1
        || document.issuer_host != issuer_host
        || document.issuer_url != issuer_url
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            mismatch_message,
            None,
            Some(request_id),
        ));
    }

    let policy = parse_configuration_policy_document(configuration_document, request_id)?;
    validate_patched_policy(&policy, request_id)?;
    validate_federation_policy_for_environment(&policy, issuer_url, request_id)?;
    let _ = parse_configuration_scope_allowlist(configuration_document, request_id)?;
    let _ = parse_configuration_key_store(configuration_document, request_id)?;
    validate_configuration_document_federation(configuration_document, request_id)
}

pub(in crate::web::management) fn validate_configuration_version_document(
    configuration_document: &serde_json::Value,
    issuer_host: &str,
    issuer_url: &str,
    request_id: &str,
) -> Result<(), Response> {
    validate_configuration_document_for_environment(
        configuration_document,
        issuer_host,
        issuer_url,
        request_id,
        "configurationDocument must match schemaVersion=1 and the environment issuer fields",
    )
}

pub(in crate::web::management) fn parse_activated_environment_configuration(
    configuration_document: serde_json::Value,
    issuer_host: &str,
    issuer_url: &str,
    request_id: &str,
) -> Result<ActivatedEnvironmentConfiguration, Response> {
    validate_configuration_document_for_environment(
        &configuration_document,
        issuer_host,
        issuer_url,
        request_id,
        "configurationDocument issuer fields did not match the environment",
    )?;
    let policy = parse_configuration_policy_document(&configuration_document, request_id)?;
    validate_patched_policy(&policy, request_id)?;
    validate_federation_policy_for_environment(&policy, issuer_url, request_id)?;
    let scope_allowlist = parse_configuration_scope_allowlist(&configuration_document, request_id)?;
    let (key_store_type, key_store_configuration, key_store_redacted) =
        parse_configuration_key_store(&configuration_document, request_id)?;
    let audit_snapshot = federation_configuration_audit_snapshot(&configuration_document);

    Ok(ActivatedEnvironmentConfiguration {
        configuration_document,
        state: EnvironmentConfigurationState {
            policy,
            scope_allowlist,
            key_store_type,
            key_store_configuration,
            key_store_redacted,
        },
        audit_snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(presentation: Option<serde_json::Value>) -> serde_json::Value {
        let mut document = serde_json::json!({
            "schemaVersion": 1,
            "issuerHost": "auth.example.com",
            "issuerUrl": "https://auth.example.com",
            "policy": super::super::default_policy_document(),
            "scopeAllowlist": ["openid", "profile"],
            "keyStore": {"type": "databaseEncrypted", "configuration": {}, "redacted": true},
        });
        if let Some(presentation) = presentation {
            document["presentation"] = presentation;
        }
        document
    }

    fn validate(document: &serde_json::Value) -> Result<(), Response> {
        validate_configuration_version_document(
            document,
            "auth.example.com",
            "https://auth.example.com",
            "request-1",
        )
    }

    #[test]
    fn presentation_is_optional_and_validated_before_activation() {
        assert!(validate(&document(None)).is_ok());
        assert!(validate(&document(Some(
            serde_json::json!({"serviceName": "Example School", "defaultLocale": "ja"})
        )))
        .is_ok());
        for invalid in [
            serde_json::json!({"defaultLocale": "fr"}),
            serde_json::json!({"serviceName": "Example\n"}),
            serde_json::json!({"serviceName": "Example", "logoUrl": "https://x.test/l.svg"}),
        ] {
            let response = validate(&document(Some(invalid.clone())))
                .expect_err("invalid presentation must be refused");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{invalid}");
        }
    }
}
