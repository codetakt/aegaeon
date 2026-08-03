use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MainEnvAuthority {
    SystemBootstrap,
    BootstrapSecret,
    HostLocalObservability,
    HostLocalTrustBundle,
    TestOnlyBootstrap,
    SharedRuntimeStore,
    RemovedRejected,
}

impl MainEnvAuthority {
    const fn is_allowed_with_management_database(self) -> bool {
        matches!(
            self,
            Self::SystemBootstrap
                | Self::BootstrapSecret
                | Self::HostLocalObservability
                | Self::HostLocalTrustBundle
                | Self::TestOnlyBootstrap
                | Self::SharedRuntimeStore
        )
    }
}

const MAIN_ENV_INVENTORY: &[(&str, MainEnvAuthority)] = &[
    (
        "AEGAEON_ALLOW_PROXY_CHAIN_LENGTH",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_AUTH_CODE_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_AUTH_SESSION_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    ("AEGAEON_DATABASE_URL", MainEnvAuthority::SystemBootstrap),
    (
        "AEGAEON_DB_ACQUIRE_TIMEOUT_SECS",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_DB_MAX_CONNECTIONS",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_DEVICE_CODE_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_DEVICE_CSRF_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_DPOP_NONCE_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_DPOP_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_ENFORCE_SECURE_PROTO",
        MainEnvAuthority::RemovedRejected,
    ),
    (
        "AEGAEON_FORWARD_HEADER_LOG_VALUES",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS",
        MainEnvAuthority::TestOnlyBootstrap,
    ),
    (
        "AEGAEON_JWKS_CA_BUNDLE",
        MainEnvAuthority::HostLocalTrustBundle,
    ),
    (
        "AEGAEON_JWKS_HISTOGRAM_BUCKETS",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_JWKS_INSECURE_SKIP_VERIFY",
        MainEnvAuthority::TestOnlyBootstrap,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE",
        MainEnvAuthority::HostLocalObservability,
    ),
    (
        "AEGAEON_KEY_ENCRYPTION_KEY",
        MainEnvAuthority::BootstrapSecret,
    ),
    (
        "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_MANAGEMENT_COOKIE_SECURE",
        MainEnvAuthority::RemovedRejected,
    ),
    (
        "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_PAR_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_POLICY_REQUIRE_TLS_VALIDATION",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_REQUIRE_MTLS_FROM_PROXY",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_REQUIRE_TLS_PROXY",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_RUNTIME_ISSUER_HOST",
        MainEnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_STEPUP_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    ("AEGAEON_TRUSTED_PROXIES", MainEnvAuthority::SystemBootstrap),
    (
        "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
        MainEnvAuthority::SharedRuntimeStore,
    ),
    ("BASE_URL", MainEnvAuthority::RemovedRejected),
];

fn main_env_inventory_map() -> BTreeMap<&'static str, MainEnvAuthority> {
    MAIN_ENV_INVENTORY.iter().copied().collect()
}

fn string_literals_in_call(source: &str, offset: usize) -> Vec<&str> {
    let Some(rest) = source.get(offset..) else {
        return Vec::new();
    };
    let mut literals = Vec::new();
    let bytes = rest.as_bytes();
    let mut index = 0usize;
    let mut paren_depth = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => {
                paren_depth = paren_depth.saturating_add(1);
                index += 1;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0 {
                    break;
                }
                index += 1;
            }
            b'"' => {
                let start = index + 1;
                index = start;
                let mut escaped = false;
                while index < bytes.len() {
                    match (bytes[index], escaped) {
                        (_, true) => {
                            escaped = false;
                            index += 1;
                        }
                        (b'\\', false) => {
                            escaped = true;
                            index += 1;
                        }
                        (b'"', false) => {
                            if let Some(literal) = rest.get(start..index) {
                                literals.push(literal);
                            }
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
            }
            _ => index += 1,
        }
    }
    literals
}

fn is_reviewed_env_literal(value: &str) -> bool {
    value == "BASE_URL" || value.starts_with("AEGAEON_")
}

fn constructor_mapped_env_reads(source: &str) -> BTreeSet<&'static str> {
    [
        (
            "std::env::var(KEY_ENCRYPTION_KEY_ENV)",
            &["AEGAEON_KEY_ENCRYPTION_KEY"][..],
        ),
        (
            "AuthSessionStore::try_from_management_policy(",
            &["AEGAEON_AUTH_SESSION_REDIS_URL"][..],
        ),
        (
            "ClientRegistry::from_shared_store_env_with_runtime_policy(",
            &[
                "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
                "AEGAEON_JWKS_REDIS_URL",
            ][..],
        ),
        (
            "JwksRuntimePolicy::try_from_management_policy(",
            &[
                "AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS",
                "AEGAEON_JWKS_CA_BUNDLE",
                "AEGAEON_JWKS_HISTOGRAM_BUCKETS",
                "AEGAEON_JWKS_INSECURE_SKIP_VERIFY",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE",
            ][..],
        ),
        (
            "DeviceCodeStore::try_from_shared_store_env_with_policy(",
            &["AEGAEON_DEVICE_CODE_REDIS_URL"][..],
        ),
        (
            "DpopMiddleware::try_from_shared_store_env(",
            &["AEGAEON_DPOP_REDIS_URL"][..],
        ),
        (
            "ManagementState::try_from_env_with_database(",
            &[
                "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
                "AEGAEON_MANAGEMENT_COOKIE_SECURE",
                "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
                "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
            ][..],
        ),
        (
            "OidcSessionStore::try_new_from_shared_store_env_with_ttl_secs(",
            &["AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL"][..],
        ),
        (
            "ParStore::try_new_from_shared_store_env_with_expires_in(",
            &["AEGAEON_PAR_REDIS_URL"][..],
        ),
        (
            "RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(",
            &["AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL"][..],
        ),
        (
            "StepUpStore::try_from_shared_store_env_with_ttl_secs(",
            &["AEGAEON_STEPUP_REDIS_URL"][..],
        ),
        (
            "TokenIssuer::try_from_shared_store_env_with_ttls(",
            &[
                "AEGAEON_AUTH_CODE_REDIS_URL",
                "AEGAEON_TOKEN_STORE_REDIS_URL",
            ][..],
        ),
        (
            "UpstreamAuthStore::try_new_from_shared_store_env_with_ttl_secs(",
            &["AEGAEON_UPSTREAM_AUTH_REDIS_URL"][..],
        ),
        (
            "UpstreamLogoutRelayStore::try_new_from_shared_store_env_with_ttl_secs(",
            &["AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL"][..],
        ),
    ]
    .into_iter()
    .filter(|(marker, _)| source.contains(marker))
    .flat_map(|(_, keys)| keys.iter().copied())
    .collect()
}

fn direct_production_env_reads(sources: &[&'static str]) -> BTreeSet<&'static str> {
    let markers = [
        "env::var(",
        "std::env::var(",
        "env_flag(",
        "env_num(",
        "env_num_impl(",
        "try_env_flag(",
        "try_env_ipnet_list(",
        "try_env_num(",
        "try_env_num_with(",
        "env_optional_non_empty(",
        "env_optional_trimmed(",
        "try_env_optional_string(",
        "try_required_env_flag(",
        "require_shared_runtime_store_url(",
        "RedisStoreUrl::optional_from_env(",
        "CsrfTokenStore::try_from_shared_store_env(",
        "VerificationRateLimiter::try_from_shared_store_env(",
    ];

    sources
        .iter()
        .flat_map(|source| {
            let production_source = source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(source);
            let direct = markers.into_iter().flat_map(move |marker| {
                let mut cursor = 0usize;
                std::iter::from_fn(move || {
                    let found = production_source.get(cursor..)?.find(marker)?;
                    let start = cursor + found + marker.len();
                    cursor = start;
                    Some(string_literals_in_call(production_source, start))
                })
                .flatten()
            });
            direct.chain(constructor_mapped_env_reads(production_source))
        })
        .filter(|value| is_reviewed_env_literal(value))
        .collect()
}

#[test]
fn direct_main_env_reads_are_classified() {
    let inventory = main_env_inventory_map();
    let direct_reads = direct_production_env_reads(&[
        include_str!("../../main.rs"),
        include_str!("../../config.rs"),
        include_str!("../../config/database.rs"),
        include_str!("../../config/environment.rs"),
        include_str!("../../config/transport.rs"),
        include_str!("../../key_encryption.rs"),
        include_str!("../app_state.rs"),
        include_str!("../bootstrap_env.rs"),
        include_str!("../browser_auth_runtime.rs"),
        include_str!("../client_runtime.rs"),
        include_str!("../dcr_runtime.rs"),
        include_str!("../device_runtime.rs"),
        include_str!("../dpop.rs"),
        include_str!("../federation_runtime.rs"),
        include_str!("../oidc_runtime.rs"),
        include_str!("../protocol_runtime.rs"),
        include_str!("../runtime_config.rs"),
        include_str!("../sync_runtime.rs"),
        include_str!("../token_runtime.rs"),
        include_str!("../upstream_runtime.rs"),
    ]);
    let classified = inventory.keys().copied().collect::<BTreeSet<_>>();

    assert_eq!(
        direct_reads, classified,
        "main.rs direct environment reads must be reviewed in MAIN_ENV_INVENTORY"
    );
}

#[test]
fn main_env_inventory_contains_no_legacy_startup_only_keys() {
    let inventory = main_env_inventory_map();
    assert!(!inventory.contains_key("AEGAEON_CLIENT_JWT_ALLOWED_ALGS"));
    assert!(!inventory.contains_key("AEGAEON_CLIENT_JWT_REQUIRE_KID"));
    assert!(!inventory.contains_key("AEGAEON_DCR_BEARER_TOKEN"));
    assert!(!inventory.contains_key("AEGAEON_ENABLE_TEST_CLIENTS"));
    assert!(!inventory.contains_key("AEGAEON_UPSTREAM_DISCOVERY_CACHE_TTL_SECS"));
    assert!(!inventory.contains_key("AEGAEON_UPSTREAM_JWKS_CACHE_TTL_SECS"));
}

#[test]
fn database_backed_runtime_env_reads_are_limited_to_bootstrap_or_shared_state() {
    let inventory = main_env_inventory_map();
    let allowed_with_database = inventory
        .iter()
        .filter_map(|(key, authority)| {
            authority
                .is_allowed_with_management_database()
                .then_some(*key)
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        inventory["AEGAEON_DPOP_REDIS_URL"],
        MainEnvAuthority::SharedRuntimeStore
    );
    assert_eq!(
        inventory["AEGAEON_DATABASE_URL"],
        MainEnvAuthority::SystemBootstrap
    );
    assert_eq!(inventory["BASE_URL"], MainEnvAuthority::RemovedRejected);
    assert_eq!(
        inventory["AEGAEON_MANAGEMENT_COOKIE_SECURE"],
        MainEnvAuthority::RemovedRejected
    );
    assert_eq!(
        allowed_with_database,
        BTreeSet::from([
            "AEGAEON_ALLOW_PROXY_CHAIN_LENGTH",
            "AEGAEON_AUTH_CODE_REDIS_URL",
            "AEGAEON_AUTH_SESSION_REDIS_URL",
            "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
            "AEGAEON_DATABASE_URL",
            "AEGAEON_DB_ACQUIRE_TIMEOUT_SECS",
            "AEGAEON_DB_MAX_CONNECTIONS",
            "AEGAEON_DEVICE_CODE_REDIS_URL",
            "AEGAEON_DEVICE_CSRF_REDIS_URL",
            "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
            "AEGAEON_DPOP_NONCE_REDIS_URL",
            "AEGAEON_DPOP_REDIS_URL",
            "AEGAEON_FORWARD_HEADER_LOG_VALUES",
            "AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS",
            "AEGAEON_JWKS_CA_BUNDLE",
            "AEGAEON_JWKS_HISTOGRAM_BUCKETS",
            "AEGAEON_JWKS_INSECURE_SKIP_VERIFY",
            "AEGAEON_JWKS_LOG_SAMPLE_PERCENT",
            "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200",
            "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304",
            "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR",
            "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE",
            "AEGAEON_JWKS_REDIS_URL",
            "AEGAEON_KEY_ENCRYPTION_KEY",
            "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
            "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
            "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
            "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
            "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
            "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
            "AEGAEON_PAR_REDIS_URL",
            "AEGAEON_POLICY_REQUIRE_TLS_VALIDATION",
            "AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY",
            "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
            "AEGAEON_REQUIRE_MTLS_FROM_PROXY",
            "AEGAEON_REQUIRE_TLS_PROXY",
            "AEGAEON_RUNTIME_ISSUER_HOST",
            "AEGAEON_STEPUP_REDIS_URL",
            "AEGAEON_TOKEN_STORE_REDIS_URL",
            "AEGAEON_TRUSTED_PROXIES",
            "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
            "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
        ])
    );
}
