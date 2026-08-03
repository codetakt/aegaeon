use super::*;

fn required_shared_runtime_store_literals() -> BTreeSet<&'static str> {
    const SOURCES: &[&str] = &[
        include_str!("../../../main.rs"),
        include_str!("../../../main/dpop.rs"),
        include_str!("../../../middleware/dpop.rs"),
        include_str!("../../../par.rs"),
        include_str!("../../../stepup.rs"),
        include_str!("../../../upstream.rs"),
        include_str!("../../../client_registry.rs"),
        include_str!("../../../client_registry/client_assertion_policy.rs"),
        include_str!("../../../client_registry/client_assertion_policy/replay.rs"),
        include_str!("../../../client_registry/jwks_runtime_state.rs"),
        include_str!("../../../request_object_store.rs"),
        include_str!("../../../request_object_store/config.rs"),
        include_str!("../../../device_authz.rs"),
        include_str!("../../../device_authz/store.rs"),
        include_str!("../../../device_authz/store/runtime.rs"),
        include_str!("../../../device_authz/csrf.rs"),
        include_str!("../../../device_authz/rate_limit.rs"),
        include_str!("../../../authcode/store.rs"),
        include_str!("../../../authcode/store/code_facade.rs"),
        include_str!("../../../oidc/session.rs"),
        include_str!("../../../oidc/session/standard.rs"),
        include_str!("../../../web/auth_session.rs"),
        include_str!("../../../web/management.rs"),
        include_str!("../../../web/management/state.rs"),
        include_str!("../../../web/management/state/session_store/configuration.rs"),
        include_str!("../../../upstream/store.rs"),
        include_str!("../../../web/upstream_logout_relay.rs"),
    ];
    SOURCES
        .iter()
        .flat_map(|source| shared_store_surface_literals(source))
        .collect()
}

fn shared_store_surface_literals(source: &str) -> Vec<&str> {
    const PATTERN: &str = "require_shared_runtime_store_url(";
    source
        .match_indices(PATTERN)
        .filter_map(|(start, _)| {
            let rest = source.get(start + PATTERN.len()..)?;
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('"')?;
            let value_end = rest.find('"')?;
            rest.get(..value_end)
        })
        .collect()
}

#[test]
fn required_shared_runtime_store_calls_are_covered_by_preflight() -> ConfigTestResult {
    let guarded_surfaces = required_shared_runtime_store_literals();
    let expected_surfaces = BTreeSet::from([
        "CSRF token store",
        "DPoP nonce store",
        "DPoP replay store",
        "JWKS runtime state",
        "OIDC logout/session store",
        "PAR request_uri store",
        "authorization-code/state/nonce store",
        "browser auth-session store",
        "client assertion replay store",
        "device-code store",
        "management session store",
        "request-object jti replay store",
        "step-up challenge store",
        "token/revocation store",
        "upstream auth state store",
        "upstream logout relay store",
        "verification rate limiter",
    ]);
    assert_eq!(
        guarded_surfaces, expected_surfaces,
        "required shared-store runtime-state surfaces must stay source-managed"
    );

    let cfg = ServerConfig {
        enable_private_key_jwt: true,
        enable_jwt_bearer_grant: true,
        enable_device_authz: true,
        ..ServerConfig::default()
    };
    let requirement_descriptions = cfg
        .shared_runtime_store_requirements(true)
        .map_err(|err| format!("shared-store requirements: {err:?}"))?
        .into_iter()
        .map(|requirement| requirement.describe())
        .collect::<BTreeSet<_>>();

    let expected_requirements = BTreeSet::from([
            "DPoP nonce store (AEGAEON_DPOP_NONCE_REDIS_URL)".to_string(),
            "DPoP replay store (AEGAEON_DPOP_REDIS_URL)".to_string(),
            "JWKS runtime state (AEGAEON_JWKS_REDIS_URL)".to_string(),
            "OIDC logout/session store (AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL)".to_string(),
            "PAR request_uri store (AEGAEON_PAR_REDIS_URL)".to_string(),
            "authorization-code/state/nonce store (AEGAEON_AUTH_CODE_REDIS_URL)".to_string(),
            "browser auth-session store (AEGAEON_AUTH_SESSION_REDIS_URL)".to_string(),
            "client assertion replay store (AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL)".to_string(),
            "device CSRF store (AEGAEON_DEVICE_CSRF_REDIS_URL)".to_string(),
            "device verification rate limiter (AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL)".to_string(),
            "device-code store (AEGAEON_DEVICE_CODE_REDIS_URL)".to_string(),
            "local auth CSRF store (AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL)".to_string(),
            "local login rate limiter (AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL)".to_string(),
            "management login rate limiter (AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL)".to_string(),
            "management session store (AEGAEON_MANAGEMENT_SESSION_REDIS_URL)".to_string(),
            "request-object jti replay store (AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL)".to_string(),
            "step-up challenge store (AEGAEON_STEPUP_REDIS_URL)".to_string(),
            "token/revocation store (AEGAEON_TOKEN_STORE_REDIS_URL)".to_string(),
            "upstream auth state store (AEGAEON_UPSTREAM_AUTH_REDIS_URL)".to_string(),
            "upstream logout relay store (AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL)".to_string(),
        ]);
    assert_eq!(
        requirement_descriptions, expected_requirements,
        "shared-store preflight must cover every required runtime-state surface"
    );
    Ok(())
}

#[test]
fn shared_runtime_store_inventory_tracks_runtime_redis_env_keys() -> ConfigTestResult {
    let inventory = shared_runtime_store_inventory_keys(&maximal_shared_runtime_store_config())?;
    let runtime_source = collect_runtime_source_redis_env_keys()?;

    assert_eq!(
        inventory, runtime_source,
        "shared-store preflight must track every runtime Redis-backed store"
    );
    Ok(())
}
