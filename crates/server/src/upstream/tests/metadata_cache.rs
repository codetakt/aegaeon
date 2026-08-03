#[test]
fn metadata_cache_unrepresentable_ttl_does_not_panic_or_insert() -> Result<(), String> {
    let cache = super::NonAuthoritativeMetadataCache::with_ttl_secs(u64::MAX);
    assert!(cache.try_insert("relay", "value".to_string()).is_err());

    assert!(cache.try_get("relay")?.is_none());
    assert!(cache.is_empty()?);
    Ok(())
}

#[test]
fn metadata_cache_explicit_ttl_is_bounded() -> Result<(), String> {
    let cache =
        super::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs_and_max_entries(
            "upstream_discovery_cache_ttl_seconds",
            60,
            "upstream_discovery_cache_max_entries",
            7,
        )
        .map_err(|err| format!("valid metadata cache ttl: {err}"))?;
    assert_eq!(cache.ttl(), std::time::Duration::from_secs(60));
    assert_eq!(cache.max_entries(), 7);

    assert!(
        super::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs(
            "upstream_discovery_cache_ttl_seconds",
            0,
        )
        .is_err()
    );
    assert!(
        super::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs(
            "upstream_discovery_cache_ttl_seconds",
            super::MAX_UPSTREAM_METADATA_CACHE_TTL_SECS + 1,
        )
        .is_err()
    );
    assert!(
        super::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs_and_max_entries(
            "upstream_discovery_cache_ttl_seconds",
            60,
            "upstream_discovery_cache_max_entries",
            0,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn metadata_cache_evicts_oldest_entry_when_capacity_is_reached() -> Result<(), String> {
    let cache = super::NonAuthoritativeMetadataCache::with_ttl_secs_and_max_entries(60, 2);

    cache.try_insert("a", "first".to_string())?;
    cache.try_insert("b", "second".to_string())?;
    cache.try_insert("c", "third".to_string())?;

    assert_eq!(cache.len()?, 2);
    assert!(cache.try_get("a")?.is_none());
    assert_eq!(cache.try_get("b")?, Some("second".to_string()));
    assert_eq!(cache.try_get("c")?, Some("third".to_string()));
    Ok(())
}

#[test]
fn metadata_cache_update_does_not_evict_another_entry() -> Result<(), String> {
    let cache = super::NonAuthoritativeMetadataCache::with_ttl_secs_and_max_entries(60, 2);

    cache.try_insert("a", "first".to_string())?;
    cache.try_insert("b", "second".to_string())?;
    cache.try_insert("a", "updated".to_string())?;

    assert_eq!(cache.len()?, 2);
    assert_eq!(cache.try_get("a")?, Some("updated".to_string()));
    assert_eq!(cache.try_get("b")?, Some("second".to_string()));
    Ok(())
}

#[test]
fn upstream_auth_request_expires_at_exact_boundary() {
    let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(60);
    let request = super::UpstreamAuthRequest {
        state: "state".to_string(),
        nonce: "nonce".to_string(),
        code_verifier: None,
        acr: None,
        issuer: "https://issuer.example".to_string(),
        client_id: "client".to_string(),
        client_secret: None,
        client_auth_method: "none".to_string(),
        context: super::UpstreamConnectionContext::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ),
        token_endpoint: "https://issuer.example/token".to_string(),
        jwks_uri: "https://issuer.example/jwks".to_string(),
        redirect_uri: "https://rp.example/callback".to_string(),
        return_to: None,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now - std::time::Duration::from_secs(60),
        expires_at: now,
    };

    assert!(!super::upstream_auth_request_is_fresh_at(&request, now));
    assert!(super::upstream_auth_request_is_fresh_at(
        &request,
        now - std::time::Duration::from_secs(1)
    ));
}
