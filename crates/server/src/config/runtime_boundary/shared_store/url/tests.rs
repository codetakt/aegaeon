use super::{redis_store_urls_reference_same_endpoint, RedisStoreUrl};

#[test]
fn shared_redis_store_url_requires_tls_for_non_loopback() {
    let err = RedisStoreUrl::from_env_value(
        "AEGAEON_PAR_REDIS_URL",
        "redis://redis.example/0".to_string(),
    )
    .expect_err("non-loopback redis:// must fail closed");

    assert!(matches!(
        err,
        crate::config::ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_PAR_REDIS_URL"
                && reason.contains("use rediss:// for non-loopback")
    ));
}

#[test]
fn shared_redis_store_url_allows_rediss_and_loopback_redis() -> Result<(), String> {
    assert_eq!(
        RedisStoreUrl::from_env_value(
            "AEGAEON_PAR_REDIS_URL",
            "rediss://redis.example/0".to_string(),
        )
        .map_err(|err| err.to_string())?
        .as_str(),
        "rediss://redis.example/0"
    );
    assert_eq!(
        RedisStoreUrl::from_env_value(
            "AEGAEON_PAR_REDIS_URL",
            "redis://127.0.0.1:6379/0".to_string(),
        )
        .map_err(|err| err.to_string())?
        .as_str(),
        "redis://127.0.0.1:6379/0"
    );
    Ok(())
}

#[test]
fn shared_redis_store_url_compares_canonical_endpoint_identity() -> Result<(), String> {
    let left = RedisStoreUrl::from_env_value(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        "rediss://writer:secret@REDIS.example/".to_string(),
    )
    .map_err(|err| err.to_string())?;
    let right = RedisStoreUrl::from_env_value(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        "rediss://reader:other@redis.example:6379/0".to_string(),
    )
    .map_err(|err| err.to_string())?;

    assert_ne!(left.as_str(), right.as_str());
    assert!(left.references_same_endpoint(&right));
    assert!(redis_store_urls_reference_same_endpoint(
        left.as_str(),
        right.as_str()
    ));
    Ok(())
}

#[test]
fn shared_redis_store_url_rejects_non_numeric_database_path() {
    let err = RedisStoreUrl::from_env_value(
        "AEGAEON_PAR_REDIS_URL",
        "rediss://redis.example/not-a-db".to_string(),
    )
    .expect_err("Redis database path must be numeric");

    assert!(matches!(
        err,
        crate::config::ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_PAR_REDIS_URL"
                && reason.contains("numeric database path")
    ));
}

#[test]
fn shared_redis_store_url_rejects_query_and_fragment_components() {
    for url in [
        "rediss://redis.example/0?protocol=resp3",
        "rediss://redis.example/0#runtime",
    ] {
        let err = RedisStoreUrl::from_env_value("AEGAEON_PAR_REDIS_URL", url.to_string())
            .expect_err("Redis URL query and fragment components must fail closed");

        assert!(matches!(
            err,
            crate::config::ConfigError::InvalidValue { key, reason, .. }
                if key == "AEGAEON_PAR_REDIS_URL"
                    && reason.contains("must not include query or fragment")
        ));
    }
    assert!(!redis_store_urls_reference_same_endpoint(
        "rediss://redis.example/0?protocol=resp3",
        "rediss://redis.example/0"
    ));
}

#[test]
fn shared_redis_store_url_requires_host() {
    let err = RedisStoreUrl::from_env_value("AEGAEON_PAR_REDIS_URL", "rediss:0".to_string())
        .expect_err("hostless Redis URLs must fail closed");

    assert!(matches!(
        err,
        crate::config::ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_PAR_REDIS_URL"
                && reason.contains("must include a host")
    ));
}
