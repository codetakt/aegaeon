#[test]
fn introspection_authentication_policy_is_effective_without_rewriting_legacy_value(
) -> Result<(), Box<dyn std::error::Error>> {
    for legacy in [false, true] {
        let policy = PolicyDocument {
            require_client_auth_introspection: legacy,
            require_client_auth_token: false,
            require_client_auth_revocation: false,
            ..PolicyDocument::default()
        };
        let document = serde_json::to_value(&policy)?;
        let runtime = ServerConfig::default().with_management_policy(&policy)?;
        assert!(runtime.require_client_auth_introspection);
        assert!(!runtime.require_client_auth_token);
        assert!(!runtime.require_client_auth_revocation);
        assert_eq!(serde_json::to_value(&policy)?, document);
        let decoded: PolicyDocument = serde_json::from_value(document.clone())?;
        assert_eq!(decoded.require_client_auth_introspection, legacy);
        assert_eq!(serde_json::to_value(decoded)?, document);
    }
    Ok(())
}
