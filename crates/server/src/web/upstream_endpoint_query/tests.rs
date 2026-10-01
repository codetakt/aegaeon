use super::*;

#[test]
fn endpoint_query_preserves_raw_vendor_bytes_and_reuses_equivalent_generated_value(
) -> Result<(), String> {
    let prefix = "vendor=%2f%2F&vendor=two+words&blank=&opaque=%FF&st%61te=same%20state";
    let mut url = Url::parse(&format!("https://issuer.example/authorize?{prefix}"))
        .map_err(|e| e.to_string())?;
    append_endpoint_parameters(
        &mut url,
        &[("state", "same state"), ("nonce", "nonce")],
        &[],
    )?;
    assert_eq!(url.query(), Some(format!("{prefix}&nonce=nonce").as_str()));
    for endpoint in [
        "https://issuer.example/authorize",
        "https://issuer.example/authorize?",
    ] {
        let mut url = Url::parse(endpoint).map_err(|e| e.to_string())?;
        append_endpoint_parameters(&mut url, &[("state", "state")], &[])?;
        assert_eq!(url.query(), Some("state=state"));
    }
    Ok(())
}

#[test]
fn endpoint_query_rejects_duplicates_conflicts_encoded_aliases_and_invalid_equality(
) -> Result<(), String> {
    for query in [
        "state=bad",
        "state=good&st%61te=good",
        "state=%FF",
        "state=%",
        "st%61te=%0G",
        "st%GGate=good",
        "%FF=good",
        "request=jwt",
        "request%5Furi=https%3A%2F%2Fissuer.example%2Fobject",
    ] {
        let mut url = Url::parse(&format!("https://issuer.example/authorize?{query}"))
            .map_err(|e| e.to_string())?;
        let original = url.clone();
        assert!(
            append_endpoint_parameters(
                &mut url,
                &[("nonce", "new"), ("state", "good")],
                &["request", "request_uri"]
            )
            .is_err(),
            "{query}"
        );
        assert_eq!(url, original, "error must not partially append");
    }
    Ok(())
}

#[test]
fn token_endpoint_query_rejects_every_body_field_including_encoded_names() {
    for field in TOKEN_FIELDS {
        for query in [
            format!("{field}=value"),
            format!("%{:02X}{}=value", field.as_bytes()[0], &field[1..]),
            format!("{field}="),
        ] {
            assert!(
                validate_token_endpoint_query(&format!("https://issuer.example/token?{query}"))
                    .is_err(),
                "{query}"
            );
        }
    }
    assert!(validate_token_endpoint_query(
        "https://issuer.example/token?vendor=%FF&vendor=&route=%2f"
    )
    .is_ok());
}

#[tokio::test]
async fn upstream_jwks_query_is_retained_on_transport_and_in_cache_identity() -> Result<(), String>
{
    use crate::web::upstream_metadata::{build_upstream_http_client, fetch_upstream_jwks_cached};
    let key = crate::oidc::OidcSigningKey::from_rsa_pem(
        "fixture".into(),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )),
    )
    .map_err(|e| e.to_string())?;
    let body = serde_json::to_string(&key.jwks()).map_err(|e| e.to_string())?;
    let mut fixture = super::http_fixture::EndpointFixture::start(body).await?;
    let client = build_upstream_http_client(&[])?;
    let cache = crate::upstream::NonAuthoritativeMetadataCache::default();
    for query in [
        "route=%2f&route=two+words&blank=",
        "route=%2F&route=two+words&blank=",
        "",
    ] {
        let endpoint = format!("{}/jwks?{query}", fixture.base);
        fetch_upstream_jwks_cached(&client, &endpoint, &cache, &[]).await?;
        let (target, body) = fixture.received().await?;
        assert_eq!(target, format!("/jwks?{query}"));
        assert!(body.is_empty());
        fetch_upstream_jwks_cached(&client, &endpoint, &cache, &[]).await?;
        fixture.assert_no_request();
    }
    Ok(())
}

#[test]
fn upstream_discovery_accepts_endpoint_queries_but_keeps_token_ambiguity_and_issuer_rules(
) -> Result<(), String> {
    use crate::web::upstream_metadata::validate_upstream_discovery;
    let issuer = "https://issuer.example";
    let mut discovery = crate::web::upstream_tests::base_discovery(issuer)?;
    let profile = crate::web::upstream_tests::base_profile();
    discovery
        .authorization_endpoint
        .push_str("?vendor=%2f&vendor=&client_id=client");
    discovery
        .token_endpoint
        .push_str("?route=%2F&route=&blank=");
    discovery.jwks_uri.push_str("?cache=1&cache=2");
    discovery.end_session_endpoint =
        Some("https://issuer.example/logout?vendor=%2f&vendor=".into());
    validate_upstream_discovery(&discovery, issuer, &profile, "none", &[])?;
    discovery.token_endpoint.push_str("&client%5Fid=client");
    assert!(validate_upstream_discovery(&discovery, issuer, &profile, "none", &[]).is_err());
    assert!(crate::web::validate_upstream_issuer("https://issuer.example?route=1").is_none());
    Ok(())
}

#[tokio::test]
async fn upstream_cached_discovery_and_federation_keep_exact_endpoint_query_identity(
) -> Result<(), String> {
    use crate::web::upstream_metadata::{
        fetch_upstream_discovery_cached, validate_upstream_discovery_matches_federation_metadata,
    };
    let issuer = "https://issuer.example";
    let cache = crate::upstream::NonAuthoritativeMetadataCache::default();
    let mut discovery = crate::web::upstream_tests::base_discovery(issuer)?;
    discovery.authorization_endpoint.push_str("?route=%2f");
    discovery.token_endpoint.push_str("?route=%2f");
    discovery.jwks_uri.push_str("?route=%2f");
    cache.try_insert(issuer, discovery.clone())?;
    let cached =
        fetch_upstream_discovery_cached(&reqwest::Client::new(), issuer, &cache, &[]).await?;
    let metadata = serde_json::json!({"issuer":issuer,"authorization_endpoint":discovery.authorization_endpoint,"token_endpoint":discovery.token_endpoint,"jwks_uri":discovery.jwks_uri});
    validate_upstream_discovery_matches_federation_metadata(&cached, issuer, &metadata)?;
    for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        let mut changed = metadata.clone();
        changed[field] = serde_json::json!(metadata[field]
            .as_str()
            .ok_or("endpoint")?
            .replace("%2f", "%2F"));
        assert!(
            validate_upstream_discovery_matches_federation_metadata(&cached, issuer, &changed)
                .is_err(),
            "{field}"
        );
    }
    Ok(())
}
