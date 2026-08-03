use super::*;

#[test]
fn resource_metadata_required_field_present() {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    assert_eq!(meta.resource, "https://as.example.com/resource");
}

#[test]
fn resource_metadata_links_to_authorization_server() -> TestResult {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    let servers = meta
        .authorization_servers
        .ok_or_else(|| io::Error::other("missing authorization servers"))?;
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0], "https://as.example.com");
    Ok(())
}

#[test]
fn resource_metadata_scopes_match_resource_endpoint() -> TestResult {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    let scopes = meta
        .scopes_supported
        .ok_or_else(|| io::Error::other("missing scopes"))?;
    assert!(scopes.contains(&"read".to_string()));
    Ok(())
}

#[test]
fn resource_metadata_bearer_methods_header_only() -> TestResult {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    let methods = meta
        .bearer_methods_supported
        .ok_or_else(|| io::Error::other("missing bearer methods"))?;
    assert_eq!(methods, vec!["header"]);
    Ok(())
}

#[test]
fn resource_metadata_dpop_algorithms_present() -> TestResult {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    let algs = meta
        .dpop_signing_alg_values_supported
        .ok_or_else(|| io::Error::other("missing DPoP algorithms"))?;
    assert_eq!(algs, vec!["EdDSA"]);
    Ok(())
}

#[test]
fn resource_metadata_serialization_round_trip() -> TestResult {
    let meta = ProtectedResourceMetadata::for_issuer("https://as.example.com");
    let json = serde_json::to_string(&meta)?;

    assert!(json.contains("\"resource\":\"https://as.example.com/resource\""));
    assert!(!json.contains("resource_tos_uri"));
    assert!(!json.contains("resource_policy_uri"));

    let parsed: ProtectedResourceMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.resource, meta.resource);
    assert_eq!(parsed.authorization_servers, meta.authorization_servers);
    Ok(())
}

#[test]
fn resource_metadata_mtls_reflects_runtime_snapshot() {
    let meta = ProtectedResourceMetadata::for_issuer_with_mtls("https://as.example.com", false);
    assert_eq!(meta.tls_client_certificate_bound_access_tokens, Some(false));

    let meta = ProtectedResourceMetadata::for_issuer_with_mtls("https://as.example.com", true);
    assert_eq!(meta.tls_client_certificate_bound_access_tokens, Some(true));
}
