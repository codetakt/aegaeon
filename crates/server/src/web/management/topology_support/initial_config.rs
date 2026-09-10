use super::super::configuration_documents::{
    default_policy_document, parse_activated_environment_configuration,
    prepare_configuration_document,
};
use super::super::ManagementTenantScope;
use super::{CreateEnvironmentInput, InitialEnvironmentConfiguration};
use axum::response::Response;

pub(in crate::web::management) fn build_initial_environment_configuration(
    issuer_base_domain: &str,
    scope: &ManagementTenantScope,
    input: &CreateEnvironmentInput,
    request_id: &str,
) -> Result<InitialEnvironmentConfiguration, Response> {
    let issuer_host = format!(
        "{env}.{tenant}.{region}.{base}",
        env = input.slug,
        tenant = scope.slug,
        region = scope.region,
        base = issuer_base_domain
    );
    let issuer_url = format!("https://{issuer_host}");

    let document = serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": issuer_host.clone(),
        "issuerUrl": issuer_url.clone(),
        "policy": default_policy_document(),
        "scopeAllowlist": ["openid", "profile"],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true,
        },
    });
    let prepared_document = prepare_configuration_document(&document, request_id)?;
    let state =
        parse_activated_environment_configuration(document, &issuer_host, &issuer_url, request_id)?
            .state;

    Ok(InitialEnvironmentConfiguration {
        issuer_host,
        issuer_url,
        prepared_document,
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_environment_document_is_strict_and_fail_closed() {
        let scope = ManagementTenantScope {
            team: uuid::Uuid::new_v4(),
            tenant: uuid::Uuid::new_v4(),
            slug: "primary".into(),
            region: "local".into(),
        };
        let input = CreateEnvironmentInput {
            name: "Development".into(),
            slug: "dev".into(),
        };
        let initial =
            build_initial_environment_configuration("aegaeon.test", &scope, &input, "test")
                .expect("the server must generate its own valid strict v1 document");
        assert_eq!(initial.issuer_host, "dev.primary.local.aegaeon.test");
        assert_eq!(initial.issuer_url, "https://dev.primary.local.aegaeon.test");
        let document: serde_json::Value =
            serde_json::from_str(&initial.prepared_document.document).unwrap();
        assert_eq!(document["policy"]["oidcEnabled"], false);
        assert!(document.get("clients").is_none());
        let mut invalid = document;
        invalid["clients"] = serde_json::json!([]);
        assert!(prepare_configuration_document(&invalid, "test").is_err());
    }
}
