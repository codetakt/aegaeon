use std::fs;
use std::path::Path;

#[path = "support/source_guard.rs"]
mod source_guard;

use source_guard::{
    assert_ordered_markers, function_body, migrations_source, repo_source, repository_file,
    rust_sources, section_between, server_source, TestContext, TestResult,
};

fn environment_docs() -> Result<String, String> {
    let mut combined = String::new();
    for path in [
        "docs/configurations/environment/README.md",
        "docs/configurations/environment/core-system.md",
        "docs/configurations/environment/management-plane.md",
        "docs/configurations/environment/network-and-policy.md",
        "docs/configurations/environment/oauth-oidc-runtime.md",
        "docs/configurations/environment/federation-observability-and-test.md",
    ] {
        combined.push('\n');
        combined.push_str(&repository_file(
            path,
            "environment configuration split docs",
        )?);
    }
    Ok(combined)
}

#[test]
fn oidc_management_database_constructor_uses_managed_snapshot_key_material() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oidc_config_path = manifest_dir.join("src/oidc/config.rs");
    let source = fs::read_to_string(&oidc_config_path)
        .test_context("OIDC config source should be readable")?;

    assert!(
        !source.contains("from_management_policy("),
        "`OidcConfig::from_management_policy` is ambiguous: management-database authority must use a runtime-key snapshot, not startup environment key material"
    );

    let body = function_body(&source, "pub fn from_management_snapshot(")
        .test_context("OIDC management snapshot constructor should exist")?;

    assert!(
        body.contains("oidc_key_material_from_runtime_keys("),
        "management-database OIDC config must source key material from runtime_keys"
    );
    assert!(
        !body.contains("oidc_key_material_from_env("),
        "management-database OIDC config must not read startup environment key material"
    );
    Ok(())
}

#[test]
fn main_hydrates_oidc_from_management_snapshot_when_database_authority_is_active() -> TestResult {
    let source = server_source("src/main/runtime_config.rs", "runtime config source")?;
    let body = function_body(&source, "pub(super) async fn oidc_runtime_from_authority(")
        .test_context("OIDC runtime authority function should exist")?;

    assert!(
        body.contains("OidcConfig::from_management_snapshot_async("),
        "database-authority startup must hydrate OIDC from the management runtime snapshot"
    );
    assert!(
        !body.contains("legacy_startup_oidc_config(") && !body.contains("None =>"),
        "OIDC runtime authority must not retain a startup-environment fallback branch"
    );
    Ok(())
}

#[test]
fn oidc_startup_key_material_env_inventory_is_source_managed() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oidc_boundary_path = manifest_dir.join("src/config/oidc_boundary.rs");
    let source = fs::read_to_string(&oidc_boundary_path)
        .test_context("OIDC boundary source should be readable")?;
    assert!(
        source.contains("OIDC_STARTUP_POLICY_ENV_KEYS"),
        "OIDC startup policy env inventory should exist"
    );
    assert!(
        source.contains("OIDC_STARTUP_KEY_MATERIAL_ENV_KEYS"),
        "OIDC startup key-material env inventory should exist"
    );

    for key in [
        "AEGAEON_OIDC_ENABLED",
        "AEGAEON_OIDC_ISSUER",
        "AEGAEON_OIDC_ID_TOKEN_TTL",
        "AEGAEON_OIDC_ENABLE_DISCOVERY",
        "AEGAEON_OIDC_ENABLE_USERINFO",
        "AEGAEON_OIDC_REQUIRE_NONCE",
        "AEGAEON_OIDC_ENABLE_LOGOUT",
        "AEGAEON_OIDC_ENABLE_BACKCHANNEL_LOGOUT",
        "AEGAEON_OIDC_BACKCHANNEL_LOGOUT_TIMEOUT_SECS",
        "AEGAEON_OIDC_LOGOUT_SESSION_TTL_SECS",
    ] {
        assert!(
            source.contains(key),
            "OIDC startup policy env inventory must include `{key}`"
        );
    }

    for key in [
        "AEGAEON_OIDC_SIGNING_BACKEND",
        "AEGAEON_OIDC_SIGNING_KID",
        "AEGAEON_OIDC_SIGNING_KEY_PEM_FILE",
        "AEGAEON_OIDC_SIGNING_KEY_PEM",
        "AEGAEON_OIDC_SIGNING_AWS_REGION",
        "AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID",
        "AEGAEON_OIDC_JWKS_ADDITIONAL_FILE",
        "AEGAEON_OIDC_JWKS_ADDITIONAL",
        "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM_FILE",
        "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM",
        "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KID",
    ] {
        assert!(
            source.contains(key),
            "OIDC startup key-material env inventory must include `{key}`"
        );
    }

    let runtime_boundary_path = manifest_dir.join("src/config/runtime_boundary/key_material.rs");
    let runtime_source = fs::read_to_string(&runtime_boundary_path)
        .test_context("runtime boundary source should be readable")?;
    assert!(
        runtime_source.contains("validate_management_database_startup_environment_boundary"),
        "runtime boundary must explicitly reject startup OIDC env under management-database authority"
    );
    Ok(())
}

#[test]
fn startup_managed_policy_env_inventory_is_source_managed() -> TestResult {
    let source = server_source(
        "src/config/startup_policy_boundary.rs",
        "startup policy boundary source",
    )?;
    assert!(
        source.contains("STARTUP_MANAGED_POLICY_ENV_KEYS"),
        "startup managed-policy env inventory should exist"
    );

    for key in [
        "AEGAEON_DPOP_STRICT",
        "AEGAEON_POLICY_REQUIRE_PKCE",
        "AEGAEON_POLICY_SENDER_CONSTRAINT",
        "AEGAEON_REQUIRE_CLIENT_AUTH_TOKEN",
        "AEGAEON_ENABLE_PRIVATE_KEY_JWT",
        "AEGAEON_JWT_INTROSPECTION_EXP_SECS",
        "AEGAEON_ACR_VALUES_SUPPORTED",
        "AEGAEON_LOCAL_PASSWORD_ACR",
        "AEGAEON_UPSTREAM_DISCOVERY_CACHE_TTL_SECS",
        "AEGAEON_UPSTREAM_JWKS_CACHE_TTL_SECS",
        "AEGAEON_CLEANUP_INTERVAL_SECS",
        "AEGAEON_ACCESS_TOKEN_TTL_SECS",
        "AEGAEON_MTLS_ENABLED",
        "AEGAEON_FEDERATION_ENTITY_CACHE_TTL_SECS",
        "AEGAEON_FEDERATION_CHAIN_CACHE_TTL_SECS",
        "AEGAEON_FEDERATION_CACHE_MAX_ENTRIES",
        "AEGAEON_JWKS_ALLOW_KID_REUSE",
        "AEGAEON_JWKS_CIRCUIT_OPEN_FAILS",
        "AEGAEON_JWKS_CIRCUIT_RESET_SECS",
        "AEGAEON_JWKS_CACHE_TTL_SECS",
        "AEGAEON_JWKS_SHARED_CACHE_GC_INTERVAL_SECS",
        "AEGAEON_JWKS_HTTP_TIMEOUT_SECS",
        "AEGAEON_JWKS_REFRESH_SKEW_SECS",
        "AEGAEON_JWKS_SHARED_CACHE_MAX_AGE_SECS",
        "AEGAEON_JWKS_MAX_BODY_BYTES",
        "AEGAEON_JWKS_HTTP_RETRIES",
        "AEGAEON_CLIENT_JWT_ALLOWED_ALGS",
        "AEGAEON_DCR_REQUIRE_SENDER_CONSTRAINED",
        "AEGAEON_DCR_BEARER_TOKEN",
        "AEGAEON_SSA_JWT_PEM",
        "AEGAEON_MANAGEMENT_ALLOWED_ORIGINS",
        "AEGAEON_MANAGEMENT_ISSUER_BASE_DOMAIN",
        "AEGAEON_MANAGEMENT_SESSION_TTL_SECS",
        "AEGAEON_MANAGEMENT_MAX_SESSIONS",
        "AEGAEON_CRYPTO_PROFILE",
    ] {
        assert!(
            source.contains(key),
            "startup managed-policy env inventory must include `{key}`"
        );
    }

    for removed in [
        "AEGAEON_FEDERATION_OP_ENABLED",
        "AEGAEON_FEDERATION_ENTITY_EXP_SECS",
        "AEGAEON_FEDERATION_AUTHORITY_HINTS",
        "AEGAEON_JWKS_REQUIRE_PIN_ON_STALE",
        "AEGAEON_JWKS_SHARED_CACHE_PATH",
        "AEGAEON_JWKS_STALE_IF_ERROR_SECS",
        "AEGAEON_JWKS_STALE_MAX_GENERATIONS",
        "AEGAEON_JWKS_STALE_MEMORY_MAX_SECS",
        "AEGAEON_JWKS_STALE_SHARED_MAX_SECS",
        "AEGAEON_JWKS_STALE_PREFERENCE",
    ] {
        assert!(
            !source.contains(removed),
            "removed env `{removed}` must not be classified as an active DB-managed policy env"
        );
    }

    let removed_env_source = server_source("src/config/removed_env.rs", "removed env inventory")?;
    assert!(
        removed_env_source.contains("REMOVED_FEDERATION_OP_ENV_KEYS")
            && removed_env_source.contains("public OpenID Federation OP publication was removed")
            && removed_env_source.contains("AEGAEON_FEDERATION_AUTHORITY_HINTS"),
        "removed Federation OP envs must be explicit negative inventory"
    );
    assert!(
        removed_env_source.contains("REMOVED_JWKS_STALE_SERVING_ENV_KEYS")
            && removed_env_source.contains("REMOVED_JWKS_ON_DISK_CACHE_ENV_KEYS")
            && removed_env_source.contains("JWKS stale serving was removed")
            && removed_env_source.contains("on-disk JWKS body cache was removed"),
        "removed JWKS stale/on-disk cache envs must be explicit negative inventory"
    );
    Ok(())
}

#[test]
fn main_has_no_legacy_startup_environment_runtime_branch() -> TestResult {
    let main_source = server_source("src/main.rs", "main source")?;
    let runtime_config_source =
        server_source("src/main/runtime_config.rs", "runtime config source")?;
    let client_runtime_source =
        server_source("src/main/client_runtime.rs", "client runtime source")?;
    let federation_runtime_source = server_source(
        "src/main/federation_runtime.rs",
        "federation runtime source",
    )?;

    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/main/legacy_startup.rs")
            .exists(),
        "legacy startup runtime module must not be present"
    );
    let runtime_sources = [
        main_source.as_str(),
        runtime_config_source.as_str(),
        client_runtime_source.as_str(),
        federation_runtime_source.as_str(),
    ]
    .join("\n");
    for marker in [
        "legacy_startup_",
        "OidcConfig::from_legacy_startup_environment(",
        "ClientRegistry::from_legacy_startup_environment(",
        "AuthSessionStore::from_env(",
        "AuthSessionStore::try_from_env(",
        "AuthSessionStore::try_from_legacy_startup_environment(",
        "FederationCacheConfig::try_from_env(",
    ] {
        assert!(
            !runtime_sources.contains(marker),
            "runtime modules must not retain legacy startup constructor or branch marker `{marker}`"
        );
    }
    Ok(())
}

#[test]
fn main_token_issuer_uses_shared_store_constructor_without_runtime_policy_env() -> TestResult {
    let source = server_source("src/main/token_runtime.rs", "token runtime source")?;

    assert!(
        source.contains("TokenIssuer::try_from_shared_store_env_with_ttls("),
        "main must select token stores from shared-store env while taking TTL/policy from runtime config"
    );
    assert!(
        !source.contains("TokenIssuer::try_from_env_with_ttls("),
        "main must not use the token issuer constructor that rereads runtime policy env"
    );
    Ok(())
}

#[test]
fn main_runtime_state_stores_use_explicit_shared_store_constructors() -> TestResult {
    let client_runtime_source =
        server_source("src/main/client_runtime.rs", "client runtime source")?;
    let oidc_runtime_source = server_source("src/main/oidc_runtime.rs", "OIDC runtime source")?;
    let protocol_runtime_source =
        server_source("src/main/protocol_runtime.rs", "protocol runtime source")?;
    let upstream_runtime_source =
        server_source("src/main/upstream_runtime.rs", "upstream runtime source")?;
    let source = [
        client_runtime_source.as_str(),
        oidc_runtime_source.as_str(),
        protocol_runtime_source.as_str(),
        upstream_runtime_source.as_str(),
    ]
    .join("\n");

    for marker in [
        "ClientRegistry::from_shared_store_env_with_runtime_policy(",
        "OidcSessionStore::try_new_from_shared_store_env_with_ttl_secs(",
        "ParStore::try_new_from_shared_store_env_with_expires_in(",
        "UpstreamAuthStore::try_new_from_shared_store_env_with_ttl_secs(",
    ] {
        assert!(
            source.contains(marker),
            "main must use explicit shared-store constructor `{marker}`"
        );
    }
    Ok(())
}

#[test]
fn management_database_runtime_boundaries_are_revalidated_after_snapshot_hydration() -> TestResult {
    let main_source = server_source("src/main.rs", "main source")?;
    let runtime_config_source =
        server_source("src/main/runtime_config.rs", "runtime config source")?;

    let hydrate_body = function_body(
        &runtime_config_source,
        "pub(super) async fn hydrate_database_runtime_config(",
    )
    .test_context("database runtime hydration helper should exist")?;
    assert_ordered_markers(
        hydrate_body,
        &[
            "load_database_runtime_configuration(",
            "bootstrap_config.into_runtime_baseline()",
            "server_config.with_management_policy(",
            "Ok((server_config, runtime_config))",
        ],
        "database runtime hydration must derive the runtime config from the management policy snapshot before returning",
    )?;

    let runtime_authority_body = function_body(&main_source, "fn runtime_authority(")
        .test_context("runtime authority helper should exist")?;
    assert_ordered_markers(
        runtime_authority_body,
        &[
            "oidc_runtime_from_authority(",
            "validate_runtime_boundaries_for_authority(",
            "oidc_sessions_from_shared_env(",
        ],
        "runtime authority must validate the hydrated boundary before constructing runtime stores",
    )?;

    let build_body = function_body(&main_source, "async fn build_server_runtime(")
        .test_context("server runtime builder should exist")?;
    assert_ordered_markers(
        build_body,
        &[
            "BootstrapConfig::try_from_env()",
            "let (server_config, db_pool, database_runtime_config)",
            "hydrate_database_runtime(",
            "runtime_authority(",
            "protocol_runtime_stores_from_shared_env(",
        ],
        "server startup must hydrate DB policy and revalidate boundaries before shared store construction",
    )?;
    Ok(())
}

#[test]
fn production_startup_uses_bootstrap_config_not_server_config_env_constructor() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config_source = server_source("src/config.rs", "server config source")?;

    assert!(
        config_source.contains("#[cfg(any(test, kani))]\nimpl ServerConfig")
            && config_source.contains(
                "BootstrapConfig::try_from_env().map(BootstrapConfig::into_runtime_baseline)"
            ),
        "`ServerConfig::try_from_env` must remain a test/Kani compatibility shim over BootstrapConfig"
    );

    let mut findings = Vec::new();
    for path in rust_sources(&[manifest_dir.join("src")])? {
        let relative = path
            .strip_prefix(manifest_dir)
            .test_context("server source path should be under manifest dir")?;
        let relative = relative.to_string_lossy();
        if relative.contains("/tests/")
            || relative.contains("_tests/")
            || relative.ends_with("tests.rs")
            || relative == "src/config.rs"
        {
            continue;
        }
        let source = fs::read_to_string(&path).test_context(&format!(
            "server source should be readable: {}",
            path.display()
        ))?;
        if source.contains("ServerConfig::try_from_env(") {
            findings.push(relative.to_string());
        }
    }

    assert!(
        findings.is_empty(),
        "production startup/runtime sources must not call `ServerConfig::try_from_env`; use `BootstrapConfig::try_from_env` then DB hydration:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn refresh_grant_endpoint_uses_single_prepared_rotation_lookup() -> TestResult {
    let endpoint_source = server_source("src/web/token_refresh.rs", "token refresh endpoint")?;
    let load_body = function_body(&endpoint_source, "async fn load_refresh_token_for_client(")
        .test_context("refresh endpoint preparation helper should exist")?;
    let handle_body = function_body(
        &endpoint_source,
        "pub(super) async fn handle_token_refresh_grant(",
    )
    .test_context("refresh endpoint handler should exist")?;
    let issuer_source = server_source(
        "src/authcode/token/refresh_grant.rs",
        "refresh grant issuer",
    )?;
    let prepared_issuer_body = function_body(
        &issuer_source,
        "pub(crate) async fn refresh_prepared_access_token_bound_async(",
    )
    .test_context("prepared refresh issuer helper should exist")?;

    assert!(
        endpoint_source.contains("struct ValidatedRefreshGrant")
            && load_body.contains(".prepare_refresh_rotation_async(")
            && load_body.contains("refresh_sender_binding_violation("),
        "refresh endpoint must load the refresh grant once and validate client/sender binding against that loaded grant"
    );
    assert!(
        handle_body.contains(".refresh_prepared_access_token_bound_async(")
            && !handle_body.contains(".refresh_access_token_bound_async("),
        "refresh endpoint must pass the loaded grant to the prepared issuer path instead of triggering a second prepare"
    );
    assert!(
        prepared_issuer_body.contains("previous_refresh_token.as_str() != refresh.token.as_str()")
            && prepared_issuer_body.contains("Self::prepare_loaded_refresh_grant(")
            && !prepared_issuer_body.contains("prepare_refresh_rotation")
            && !prepared_issuer_body.contains("prepare_refresh_grant_async"),
        "prepared issuer path must bind the loaded refresh token to the previous-token commit key without performing another lookup"
    );
    Ok(())
}

#[test]
fn dpop_runtime_store_selection_is_isolated_from_main_body() -> TestResult {
    let main_source = server_source("src/main.rs", "main source")?;
    let dpop_source = server_source("src/main/dpop.rs", "DPoP runtime source")?;
    let middleware_source = server_source("src/middleware/dpop.rs", "DPoP middleware source")?;
    let build_runtime_body = function_body(&main_source, "async fn build_server_runtime(")
        .test_context("server runtime builder should exist")?;
    let middleware_body = function_body(&dpop_source, "fn dpop_middleware_from_shared_store_env(")
        .test_context("DPoP shared-store helper should exist")?;
    let replay_constructor_body =
        function_body(&middleware_source, "pub fn try_from_shared_store_env(")
            .test_context("DPoP replay-store constructor should exist")?;
    let nonce_body = function_body(&dpop_source, "fn dpop_nonce_store_from_shared_store_env(")
        .test_context("DPoP nonce-store helper should exist")?;

    assert!(
        build_runtime_body.contains("dpop_middleware_from_shared_store_env("),
        "server runtime builder should delegate DPoP runtime-store construction to the shared-store helper"
    );
    for marker in [
        "RedisReplayStore::new(",
        "InMemoryReplayStore::new(",
        "DpopNonceStore::redis(",
        "DpopNonceStore::new_process_local(",
    ] {
        assert!(
            !build_runtime_body.contains(marker),
            "server runtime builder must not inline DPoP runtime-store constructor `{marker}`"
        );
    }
    assert!(
        middleware_body.contains("DpopMiddleware::try_from_shared_store_env(")
            && middleware_body.contains("dpop_nonce_store_from_shared_store_env("),
        "DPoP middleware helper must use the Redis-only middleware constructor and narrow nonce helper"
    );
    assert!(
        replay_constructor_body.contains("RedisReplayStore::new(")
            && replay_constructor_body
                .contains("require_shared_runtime_store_url(\"DPoP replay store\""),
        "DPoP replay constructor must require shared Redis runtime state"
    );
    assert!(
        nonce_body.contains("DpopNonceStore::redis(")
            && nonce_body.contains("require_shared_runtime_store_url(")
            && nonce_body.contains("\"DPoP nonce store\""),
        "DPoP helper must require shared Redis runtime state"
    );
    Ok(())
}

#[test]
fn federation_op_signing_manager_is_not_part_of_production_runtime_state() -> TestResult {
    let runtime_key_manager_source = server_source(
        "src/main/runtime_key_managers.rs",
        "runtime key managers source",
    )?;
    let app_state_source = server_source("src/main/app_state.rs", "main app state source")?;
    let web_state_source = server_source("src/web/state.rs", "web state source")?;

    assert!(
        !runtime_key_manager_source.contains("runtime_federation_key_manager(")
            && !runtime_key_manager_source.contains("disabled_federation_key_manager("),
        "production runtime key manager selection must not carry a dormant Federation OP signing selector"
    );
    assert!(
        !app_state_source.contains("federation_key_manager")
            && !web_state_source.contains("pub federation: Arc<dyn FederationKeyManager>"),
        "production AppState must not store a Federation OP signing key manager"
    );
    assert!(
        !web_state_source.contains("use crate::kms::{FederationKeyManager"),
        "web state must not import Federation OP signing capability in production"
    );
    Ok(())
}

#[test]
fn federation_op_public_routes_are_not_part_of_production_router() -> TestResult {
    let router_source = server_source("src/web/router.rs", "web router source")?;
    let web_mod_source = server_source("src/web/mod.rs", "web module source")?;

    for route in [
        "\"/.well-known/openid-federation\"",
        "\"/.well-known/openid-federation/fetch\"",
        "\"/.well-known/openid-federation/list\"",
        "\"/.well-known/openid-federation/resolve\"",
        "\"/federation/fetch\"",
        "\"/federation/list\"",
        "\"/federation/resolve\"",
    ] {
        assert!(
            !router_source.contains(route),
            "production router must not expose deferred Federation OP publication route {route}"
        );
    }
    assert!(
        web_mod_source.contains("#[cfg(test)]\nmod openid_federation;"),
        "Federation OP structural helpers must stay test-only until OP publication is reactivated"
    );
    Ok(())
}

#[test]
fn device_authorization_routes_are_mounted_only_when_enabled() -> TestResult {
    let router_source = server_source("src/web/router.rs", "web router source")?;
    let build_router_body = function_body(&router_source, "pub fn build_router(")
        .test_context("build_router body should be readable")?;
    assert!(
        build_router_body.contains("mount_device_routes_if_enabled(router, &state)"),
        "production router must mount device authorization routes through the policy gate"
    );
    for route in [
        "\"/device_authorization\"",
        "\"/device\"",
        "\"/device/approve\"",
        "\"/device/deny\"",
    ] {
        assert!(
            !build_router_body.contains(route),
            "device authorization route {route} must not be mounted unconditionally"
        );
    }

    let device_mount_body = function_body(&router_source, "fn mount_device_routes_if_enabled(")
        .test_context("device route mount helper should be readable")?;
    assert!(
        device_mount_body.contains("if !state.cfg.grant_runtime().device_authorization_enabled()")
            && device_mount_body.contains("return router;"),
        "device authorization routes must fail closed when the runtime policy disables device_code"
    );
    for route in [
        "\"/device_authorization\"",
        "\"/device\"",
        "\"/device/approve\"",
        "\"/device/deny\"",
    ] {
        assert!(
            device_mount_body.contains(route),
            "device authorization route {route} must remain inside the policy-gated mount helper"
        );
    }
    Ok(())
}

#[test]
fn public_docs_do_not_advertise_legacy_oidc_startup_environment() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .test_context("server crate should live under crates/server")?;
    let checked_docs = [
        "README.md",
        "docs/performance/README.md",
        "examples/minimal-rp/README.md",
        "docs/program-management/roadmaps/summary/current-program-summary.md",
        "docs/program-management/roadmaps/active/current-execution-plan.md",
        "docs/program-management/roadmaps/summary/program-master-plan.md",
        "docs/program-management/roadmaps/active/oidc-spec-coverage-roadmap.md",
        "docs/program-management/roadmaps/future/external-conformance-and-beta-plan.md",
        "docs/verification/runbooks/runtime-linkage.md",
        "docs/verification/claims/assurance-case/README.md",
        "docs/verification/claims/crypto-claim-mapping.md",
        "docs/verification/claims/crypto-allowlist.md",
    ];
    let forbidden = [
        "AEGAEON_OIDC_ENABLED=1",
        "behind `AEGAEON_OIDC_ENABLED",
        "-e AEGAEON_OIDC_ENABLED=1",
        "AEGAEON_OIDC_ENABLED",
        "AEGAEON_OIDC_SIGNING_KEY_PEM",
        "AEGAEON_OIDC_SIGNING_KEY_PEM_FILE",
        "AEGAEON_ENABLE_JWT_ACCESS_TOKENS",
        "AEGAEON_ENABLE_DEVICE_AUTHZ",
        "AEGAEON_ENABLE_JWT_BEARER_GRANT",
        "AEGAEON_ENABLE_TOKEN_EXCHANGE",
        "AEGAEON_REQUIRE_DPOP_NONCE",
        "AEGAEON_DPOP_NONCE_TTL_SECS",
        "AEGAEON_POLICY_REQUIRE_PKCE",
        "AEGAEON_DPOP_STRICT",
        "AEGAEON_CLIENT_JWT_ALLOWED_ALGS",
        "AEGAEON_FEDERATION_ENTITY_CACHE_TTL_SECS",
        "AEGAEON_STEPUP_CHALLENGE_TTL_SECS",
        "AEGAEON_CRYPTO_PROFILE",
    ];
    let mut findings = Vec::new();

    for relative_path in checked_docs {
        let path = repo_root.join(relative_path);
        let source = fs::read_to_string(&path).test_context(&format!(
            "public documentation should be readable: {}",
            path.display()
        ))?;
        for token in forbidden {
            if source.contains(token) {
                findings.push(format!(
                    "{relative_path}: forbidden legacy OIDC env `{token}`"
                ));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "public docs must describe the PostgreSQL-backed management runtime, not legacy OIDC startup env:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn legacy_admin_api_key_environment_is_removed_negative_inventory() -> TestResult {
    let config_source = server_source("src/config.rs", "server config source")?;
    let removed_env_source = server_source("src/config/removed_env.rs", "removed env inventory")?;
    let environment_source = server_source("src/config/environment.rs", "environment source")?;
    let docs = environment_docs()?;

    assert!(
        !config_source.contains("admin_api_key_sha256")
            && !environment_source.contains("admin_api_key_sha256_from_env"),
        "legacy process-env admin API key field/reader must not remain in ServerConfig"
    );
    assert!(
        removed_env_source.contains("REMOVED_ADMIN_API_KEY_ENV")
            && removed_env_source.contains("AEGAEON_ADMIN_API_KEY")
            && removed_env_source
                .contains("legacy /admin API key environment variable was removed"),
        "legacy admin API key env must be rejected as removed negative inventory"
    );
    assert!(
        docs.contains("`AEGAEON_ADMIN_API_KEY` | _removed_")
            && docs.contains("Startup fails closed if this variable is present")
            && !docs
                .contains("SHA-256 of the raw admin API key used to protect `/admin/*` endpoints"),
        "environment docs must not advertise a non-functional /admin API key runtime"
    );
    Ok(())
}

#[test]
fn legacy_deployment_mode_environment_is_removed_negative_inventory() -> TestResult {
    let authority_source = server_source(
        "src/config/runtime_boundary/authority.rs",
        "runtime boundary authority source",
    )?;
    let docs = environment_docs()?;

    assert!(
        authority_source.contains("reject_removed_deployment_mode_env")
            && authority_source.contains("deployment mode selector was removed")
            && !authority_source.contains("try_deployment_mode_from_env"),
        "legacy deployment mode selector must be rejected instead of parsed"
    );
    assert!(
        docs.contains("`AEGAEON_DEPLOYMENT_MODE` | _removed_")
            && docs.contains("all supported deployments require PostgreSQL plus DB/Redis-backed shared runtime state"),
        "environment docs must not advertise single-node or multi-node runtime modes"
    );
    Ok(())
}

#[test]
fn runtime_configuration_docs_do_not_reintroduce_deployment_modes_or_optional_jwks_state(
) -> TestResult {
    let docs = repository_file(
        "docs/operations/runtime-configuration.md",
        "runtime configuration docs",
    )?;
    let always_required_section = section_between(
        &docs,
        "currently covers these always-required stores:",
        "Feature-gated shared stores",
    )
    .test_context("always-required shared-store section should exist")?;
    let feature_gated_section = section_between(
        &docs,
        "Feature-gated shared stores",
        "The implementation and test inventory",
    )
    .test_context("feature-gated shared-store section should exist")?;

    assert!(
        docs.contains("There is no server deployment-mode selector")
            && !docs.contains("`multi-node` and `single-node` deployment modes"),
        "runtime configuration docs must not describe removed server deployment modes"
    );
    assert!(
        always_required_section.contains("JWKS runtime state")
            && always_required_section.contains("AEGAEON_JWKS_REDIS_URL"),
        "runtime configuration docs must list JWKS Redis state as always required"
    );
    assert!(
        !feature_gated_section.contains("JWKS runtime state")
            && !feature_gated_section.contains("AEGAEON_JWKS_REDIS_URL"),
        "runtime configuration docs must not describe JWKS Redis state as feature-gated"
    );
    Ok(())
}

#[test]
fn upstream_metadata_caches_are_explicitly_non_authoritative() -> TestResult {
    let upstream_runtime_source =
        server_source("src/main/upstream_runtime.rs", "upstream runtime source")?;

    assert!(
        upstream_runtime_source
            .contains("NonAuthoritativeMetadataCache::try_new_non_authoritative_with_ttl_secs_and_max_entries("),
        "upstream discovery/JWKS caches must use the explicit non-authoritative snapshot constructor"
    );
    assert!(
        upstream_runtime_source.contains("\"upstream_discovery_cache_ttl_seconds\""),
        "upstream discovery cache TTL must come from the management policy snapshot"
    );
    assert!(
        upstream_runtime_source.contains("\"upstream_jwks_cache_ttl_seconds\""),
        "upstream JWKS cache TTL must come from the management policy snapshot"
    );
    assert!(
        upstream_runtime_source.contains("\"upstream_discovery_cache_max_entries\""),
        "upstream discovery cache capacity must come from the management policy snapshot"
    );
    assert!(
        upstream_runtime_source.contains("\"upstream_jwks_cache_max_entries\""),
        "upstream JWKS cache capacity must come from the management policy snapshot"
    );

    let upstream_source = server_source(
        "src/upstream/metadata_cache.rs",
        "upstream metadata cache source",
    )?;
    let body = function_body(
        &upstream_source,
        "pub fn try_new_non_authoritative_with_ttl_secs_and_max_entries(",
    )
    .test_context("non-authoritative cache constructor should exist")?;

    assert!(
        !body.contains("try_process_local_runtime_state_allowed("),
        "non-authoritative metadata caches must not be promoted into runtime-state preflight"
    );
    Ok(())
}

#[test]
fn federation_pg_cache_repositories_apply_managed_capacity_policy() -> TestResult {
    let runtime_source = server_source("src/main/federation_runtime.rs", "federation runtime")?;
    let runtime_body = function_body(
        &runtime_source,
        "pub(super) fn federation_runtime_for_authority(",
    )
    .test_context("federation runtime builder should exist")?;
    assert_ordered_markers(
        runtime_body,
        &[
            "FederationCacheConfig::try_from_management_policy(policy)?",
            "pg_federation_repositories(db_pool, &cache_config)",
        ],
        "federation runtime must derive cache capacity from the management policy before constructing PostgreSQL repositories",
    )?;
    for marker in [
        "PgEntityCacheRepository::with_max_entries(",
        "PgTrustChainCacheRepository::with_max_entries(",
        "cache_config.cache_max_entries",
    ] {
        assert!(
            runtime_source.contains(marker),
            "federation runtime must include managed cache capacity marker `{marker}`"
        );
    }

    for (path, order_column) in [
        (
            "src/federation/repositories/postgres/entity_cache.rs",
            "fetched_at DESC, id DESC",
        ),
        (
            "src/federation/repositories/postgres/trust_chains.rs",
            "resolved_at DESC, id DESC",
        ),
    ] {
        let source = server_source(path, "federation PostgreSQL cache repository")?;
        for marker in [
            "max_entries: usize",
            "SELECT e.id FROM aegaeon.environments e WHERE e.id = $1 FOR UPDATE OF e",
            "fn prune_to_max_entries_in_tx(",
            "retention_rank > $2",
        ] {
            assert!(
                source.contains(marker),
                "{path} must retain managed capacity marker `{marker}`"
            );
        }
        assert!(
            source.contains(order_column),
            "{path} must prune the oldest cache rows with deterministic ordering"
        );
    }

    let config_source = server_source(
        "src/federation/repositories/config.rs",
        "federation cache config",
    )?;
    assert!(
        config_source.contains("Maximum number of entries per environment"),
        "federation cache config docs must describe production PostgreSQL capacity, not only in-memory tests"
    );

    let cache_source = server_source(
        "src/federation/repositories/cache/fetcher.rs",
        "federation cache fetcher wrapper",
    )?;
    let fetcher_source = format!(
        "{}\n{}",
        server_source(
            "src/federation/fetcher/types.rs",
            "federation fetcher types"
        )?,
        server_source("src/federation/fetcher/http.rs", "federation HTTP fetcher")?,
    );
    assert!(
        cache_source.contains("fetch_entity_configuration_with_jws(")
            && cache_source.contains("entity_configuration_jws")
            && !cache_source.contains("JWS not stored separately"),
        "federation cache wrapper must preserve raw entity-configuration JWS when the fetcher provides it"
    );
    assert!(
        fetcher_source.contains("pub struct FetchedEntityConfiguration")
            && fetcher_source.contains("fn fetch_entity_configuration_with_jws<'a>(")
            && fetcher_source.contains("FetchedEntityConfiguration::with_jws(statement, jws)"),
        "federation HTTP fetcher must expose verified statements with raw JWS retention for persistent caches"
    );
    Ok(())
}

#[test]
fn upstream_secret_envelopes_use_centralized_key_encryption_env_boundary() -> TestResult {
    let key_encryption_source = server_source("src/key_encryption.rs", "key encryption source")?;
    assert!(
        key_encryption_source.contains("std::env::var(KEY_ENCRYPTION_KEY_ENV)"),
        "key_encryption must remain the single OS-secret env admission point"
    );

    for (path, description) in [
        (
            "src/upstream/client_secret.rs",
            "upstream client secret envelope source",
        ),
        (
            "src/web/upstream_refresh_token_envelope.rs",
            "upstream refresh token envelope source",
        ),
        (
            "src/oidc/config/runtime_keys.rs",
            "OIDC runtime key material source",
        ),
        ("src/kms/managed.rs", "managed key manager source"),
    ] {
        let source = server_source(path, description)?;
        assert!(
            source.contains("load_key_encryption_key()"),
            "{path} must load KEK material through key_encryption"
        );
        for forbidden in [
            "std::env::var(KEY_ENCRYPTION_KEY_ENV)",
            "std::env::var(\"AEGAEON_KEY_ENCRYPTION_KEY\")",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not directly read key-encryption env via `{forbidden}`"
            );
        }
    }
    Ok(())
}

#[test]
fn cross_server_host_local_env_admission_points_are_source_managed() -> TestResult {
    let backchannel_source =
        server_source("src/web/backchannel_logout.rs", "backchannel logout source")?;
    let backchannel_body = function_body(
        &backchannel_source,
        "fn allow_http_loopback_backchannel_logout_for_tests()",
    )
    .test_context("backchannel logout loopback flag helper should exist")?;
    assert!(
        backchannel_source.contains("BACKCHANNEL_LOGOUT_HOST_LOCAL_BOOTSTRAP_ENV_KEYS")
            && backchannel_source.contains("BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV")
            && backchannel_source
                .contains("AEGAEON_BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS"),
        "backchannel logout test-only transport env must be source-managed inventory"
    );
    assert_ordered_markers(
        backchannel_body,
        &[
            "test_runtime_helpers_allowed_by_build()",
            "try_env_flag(BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV, false)",
        ],
        "backchannel logout loopback env must remain build-gated before it can affect URI admission",
    )?;

    let jwks_policy_source = server_source(
        "src/client_registry/jwks_policy.rs",
        "JWKS runtime policy source",
    )?;
    assert!(
        jwks_policy_source.contains("JWKS_HOST_LOCAL_BOOTSTRAP_ENV_KEYS")
            && jwks_policy_source.contains("JWKS_HISTOGRAM_BUCKETS_ENV")
            && jwks_policy_source.contains("JWKS_CA_BUNDLE_ENV")
            && jwks_policy_source.contains("JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV")
            && jwks_policy_source.contains("JWKS_INSECURE_SKIP_VERIFY_ENV"),
        "JWKS host-local observability/trust/test envs must remain explicitly inventoried"
    );
    let test_only_body = function_body(&jwks_policy_source, "fn try_test_only_env_flag(")
        .test_context("JWKS test-only env guard helper should exist")?;
    assert!(
        test_only_body.contains("test_runtime_helpers_allowed_by_build()"),
        "JWKS test-only env overrides must remain unavailable in release builds"
    );

    let key_encryption_source = server_source("src/key_encryption.rs", "key encryption source")?;
    assert!(
        key_encryption_source.contains("pub const KEY_ENCRYPTION_KEY_ENV")
            && key_encryption_source.contains("AEGAEON_KEY_ENCRYPTION_KEY")
            && key_encryption_source.contains("std::env::var(KEY_ENCRYPTION_KEY_ENV)"),
        "KEK env admission must remain centralized and named as bootstrap secret material"
    );
    Ok(())
}

#[test]
fn startup_policy_env_readers_are_removed_from_runtime_paths() -> TestResult {
    let dcr_runtime_source = server_source("src/main/dcr_runtime.rs", "DCR runtime source")?;
    let client_runtime_source =
        server_source("src/main/client_runtime.rs", "client runtime source")?;
    let web_metadata_source = server_source("src/web/metadata.rs", "web metadata source")?;
    let bcp_validator_source =
        server_source("src/bcp_policy/validator.rs", "BCP validator source")?;

    let runtime_sources = [
        dcr_runtime_source.as_str(),
        client_runtime_source.as_str(),
        web_metadata_source.as_str(),
        bcp_validator_source.as_str(),
    ]
    .join("\n");

    for marker in [
        "DcrValidationConfig::try_from_env(",
        "ClientAssertionRuntimePolicy::try_from_env(",
        "try_client_jwt_allowed_algorithm_names_from_env(",
        "MetadataRuntimeConfig::try_from_startup_environment(",
        "try_advertised_client_jwt_algs(",
    ] {
        assert!(
            !runtime_sources.contains(marker),
            "runtime paths and policy validators must not read removed startup policy env via `{marker}`"
        );
    }

    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/main/legacy_startup.rs")
            .exists(),
        "legacy startup policy reader module must not be present"
    );
    Ok(())
}

#[test]
fn structural_self_check_policy_is_database_backed_negative_env_inventory() -> TestResult {
    let removed_env_source = server_source("src/config/removed_env.rs", "removed env inventory")?;
    let environment_source = server_source("src/config/environment.rs", "environment source")?;
    let dcr_runtime_source = server_source("src/main/dcr_runtime.rs", "DCR runtime source")?;
    let runtime_config_source =
        server_source("src/main/runtime_config.rs", "runtime config source")?;
    let docs = environment_docs()?;
    let runtime_linkage = repository_file(
        "docs/verification/runbooks/runtime-linkage.md",
        "runtime linkage documentation",
    )?;

    for key in [
        "AEGAEON_DCR_EVERPARSE_RUNTIME",
        "AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME",
    ] {
        assert!(
            removed_env_source.contains(key),
            "removed structural self-check env `{key}` must remain in negative inventory"
        );
        assert!(
            !environment_source.contains(key)
                && !dcr_runtime_source.contains(key)
                && !runtime_config_source.contains(key),
            "runtime startup paths must not read removed structural self-check env `{key}`"
        );
        assert!(
            docs.contains(&format!("`{key}` | _removed_")),
            "environment docs must document removed structural self-check env `{key}`"
        );
    }

    for policy_field in [
        "policy.dcrEverparseRuntimeEnabled",
        "policy.requestObjectEverparseRuntimeEnabled",
    ] {
        assert!(
            runtime_linkage.contains(policy_field),
            "runtime linkage docs must name database-backed structural policy field `{policy_field}`"
        );
    }
    Ok(())
}

#[test]
fn jose_header_length_policy_is_database_backed_negative_env_inventory() -> TestResult {
    let removed_env_source = server_source("src/config/removed_env.rs", "removed env inventory")?;
    let environment_source = server_source("src/config/environment.rs", "environment source")?;
    let docs = environment_docs()?;
    let jose_policy_doc = repository_file(
        "docs/policies/jose-header-policy.md",
        "JOSE header policy docs",
    )?;

    assert!(
        removed_env_source.contains("AEGAEON_JOSE_HEADER_MAXLEN"),
        "removed JOSE header length env must remain in negative inventory"
    );
    assert!(
        !environment_source.contains("AEGAEON_JOSE_HEADER_MAXLEN"),
        "runtime startup paths must not read removed JOSE header length env"
    );
    assert!(
        docs.contains("`AEGAEON_JOSE_HEADER_MAXLEN` | _removed_"),
        "environment docs must document removed JOSE header length env"
    );
    assert!(
        jose_policy_doc.contains("policy.joseHeaderMaxLen"),
        "JOSE policy docs must name the active database policy field"
    );
    Ok(())
}

#[test]
fn management_path_extractor_does_not_leak_generic_hash_map_boundary() -> TestResult {
    let management_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/management");
    let scope_source = [
        "src/web/management/scope/parsing.rs",
        "src/web/management/scope/parsing/traits.rs",
        "src/web/management/scope/parsing/core_paths.rs",
        "src/web/management/scope/parsing/environment_paths.rs",
        "src/web/management/scope/parsing/user_paths.rs",
    ]
    .into_iter()
    .map(|path| server_source(path, "management scope"))
    .collect::<Result<Vec<_>, _>>()?
    .join("\n");
    assert!(
        scope_source.contains("trait TeamScopedPath")
            && scope_source.contains("trait TeamEnvironmentScopedPath")
            && scope_source.contains("TeamEnvironmentPath")
            && scope_source.contains("TeamEnvironmentUserPath"),
        "management scope parser must expose typed path traits and concrete path extractors"
    );
    assert!(
        !scope_source.contains("ManagementPath")
            && !scope_source.contains("HashMap<String, String>")
            && !scope_source.contains("fn get(&self, key: &str)"),
        "management scope parser must not retain the legacy generic path wrapper"
    );

    let mut findings = Vec::new();
    for path in rust_sources(&[management_root])? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "management source should be readable: {}",
            path.display()
        ))?;
        for forbidden in [
            "ManagementPath",
            "params: &HashMap<String, String>",
            "params: HashMap<String, String>",
            "Path<HashMap<String, String>>",
            "Path<std::collections::HashMap",
        ] {
            if source.contains(forbidden) {
                findings.push(format!("{}: forbidden `{forbidden}`", path.display()));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "management route path parameters must use concrete typed path extractors:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn management_api_key_schema_enforces_persistent_invariants() -> TestResult {
    let schema = repo_source("db/schema.sql", "database schema")?;
    let migration = migrations_source()?;

    for required in [
        "api_keys_name_normalized",
        "api_keys_key_prefix_shape",
        "api_keys_key_hash_sha256_length",
        "api_keys_expires_after_created",
        "api_keys_last_used_after_created",
        "api_keys_revocation_state_consistent",
    ] {
        assert!(
            schema.contains(required),
            "database schema must retain management API key constraint `{required}`"
        );
        assert!(
            migration.contains(required),
            "management API key migration must define constraint `{required}`"
        );
    }

    for required_expression in [
        "octet_length(key_hash) = 32",
        "key_prefix ~ '^aeg_[A-Za-z0-9_-]{8}$'",
        "status = 'ACTIVE'",
        "status = 'REVOKED'",
    ] {
        assert!(
            schema.contains(required_expression)
                || migration.contains(&required_expression.replace("key_hash", "\"key_hash\""))
                || migration.contains(&required_expression.replace("key_prefix", "\"key_prefix\"")),
            "management API key persistent invariant expression is missing: `{required_expression}`"
        );
    }

    Ok(())
}

#[test]
fn high_risk_management_mutations_require_human_sessions() -> TestResult {
    let lifecycle_roles_source = server_source(
        "src/web/management/scope/roles.rs",
        "management role scope source",
    )?;
    let lifecycle_body = function_body(
        &lifecycle_roles_source,
        "pub(in crate::web::management) async fn require_team_lifecycle_role(",
    )
    .test_context("team lifecycle role helper should exist")?;
    assert!(
        lifecycle_body.contains("load_principal_team_access("),
        "team lifecycle role checks must use the principal-aware access loader"
    );
    let lifecycle_predicate = function_body(&lifecycle_roles_source, "fn allows_lifecycle(&self)")
        .test_context("principal lifecycle predicate should exist")?;
    assert!(
        lifecycle_predicate.contains("Self::Service { .. } => false"),
        "team lifecycle role checks must reject service-principal administrators"
    );

    for path in [
        "src/web/management/client_secrets/mutation/issue.rs",
        "src/web/management/client_secrets/mutation/revoke.rs",
        "src/web/management/client_secrets/mutation/revoke_all.rs",
        "src/web/management/api_keys/handlers/create.rs",
        "src/web/management/api_keys/handlers/revoke.rs",
        "src/web/management/clients/mutation/delete.rs",
        "src/web/management/configuration_versions/mutation/activate.rs",
        "src/web/management/configuration_versions/mutation/archive.rs",
        "src/web/management/configuration_versions/mutation/create.rs",
        "src/web/management/configuration_versions/policy.rs",
        "src/web/management/dcr_bearer_tokens/handlers/delete.rs",
        "src/web/management/dcr_bearer_tokens/handlers/set.rs",
        "src/web/management/key_stores/mutation.rs",
        "src/web/management/runtime_keys/create.rs",
        "src/web/management/runtime_keys/lifecycle.rs",
        "src/web/management/topology_environment/mutation/delete.rs",
    ] {
        let source = server_source(path, "high-risk management handler source")?;
        assert!(
            source.contains("require_human_management_session_async"),
            "{path} must require an interactive management session"
        );
        assert!(
            !source.contains("require_management_session_async"),
            "{path} must not admit management API-key sessions"
        );
    }
    Ok(())
}

#[test]
fn management_database_schema_enforces_active_configuration_invariants() -> TestResult {
    let schema = repo_source("db/schema.sql", "database schema")?;
    let migration = migrations_source()?;

    for source in [&schema, &migration] {
        assert!(
            source.contains("configuration_versions_one_active_per_environment"),
            "configuration schema must enforce at most one ACTIVE configuration version per environment"
        );
        assert!(
            source.contains("configuration_versions_environment_id_id_unique"),
            "configuration schema must expose a composite environment/version key"
        );
        assert!(
            source.contains("environments_active_configuration_version_same_environment_fkey"),
            "environment active_configuration_version_id must be constrained to the same environment"
        );
    }

    assert!(
        !migration.contains("environments_active_configuration_version_fkey\""),
        "the migration inventory must not reintroduce the ambiguous single-column active configuration FK"
    );
    Ok(())
}

#[test]
fn environment_scoped_configuration_and_runtime_foreign_keys_are_database_invariants() -> TestResult
{
    let schema = repo_source("db/schema.sql", "database schema")?;
    let migration = migrations_source()?;

    // NOTE: names longer than PostgreSQL's 63-byte identifier limit are
    // silently truncated at creation; the markers below are the stored names.
    for marker in [
        "configuration_versions_base_configuration_version_same_environm",
        "environment_policies_configuration_version_same_environment_fke",
        "environment_scope_allowlist_configuration_version_same_environm",
        "environment_key_stores_configuration_version_same_environment_f",
        "oauth_profiles_configuration_version_same_environment_fkey",
        "connections_configuration_version_same_environment_fkey",
        "clients_configuration_version_same_environment_fkey",
        "client_secrets_configuration_version_same_environment_fkey",
        "runtime_keys_configuration_version_same_environment_fkey",
        "dynamic_client_registrations_client_same_environment_fkey",
        "environment_revoked_client_secrets_secret_same_environment_fkey",
    ] {
        assert!(
            schema.contains(marker),
            "final schema must retain environment-scoped invariant `{marker}`"
        );
        assert!(
            migration.contains(marker),
            "migration must introduce environment-scoped invariant `{marker}`"
        );
    }

    for marker in [
        "configuration_version_id uuid NOT NULL REFERENCES aegaeon.configuration_versions (id)",
        "client_id uuid NOT NULL REFERENCES aegaeon.clients (id)",
        "client_id uuid REFERENCES aegaeon.clients (id)",
        "oauth_profile_id uuid REFERENCES aegaeon.oauth_profiles (id)",
        "client_secret_id uuid NOT NULL REFERENCES aegaeon.client_secrets (id)",
    ] {
        assert!(
            !schema.contains(marker),
            "final schema must not retain ambiguous single-column scoped FK marker `{marker}`"
        );
    }
    Ok(())
}

#[test]
fn topology_lifecycle_invariants_are_enforced_at_database_and_api_boundaries() -> TestResult {
    let schema = repo_source("db/schema.sql", "database schema")?;
    let migration = migrations_source()?;

    for source in [&schema, &migration] {
        for marker in [
            "enforce_team_lifecycle_invariants",
            "teams_no_active_tenants_when_deleted",
            "enforce_tenant_lifecycle_invariants",
            "tenants_parent_team_active",
            "tenants_no_active_environments_when_deleted",
            "enforce_environment_lifecycle_invariants",
            "environments_parent_tenant_team_active",
            "FOR UPDATE",
        ] {
            assert!(
                source.contains(marker),
                "topology lifecycle DB boundary must contain `{marker}`"
            );
        }
    }

    let lifecycle_workflows: &[(&str, &str, &[&str], &str)] = &[
        (
            "src/web/management/topology/teams/mutation/delete/workflow.rs",
            "pub(super) async fn delete_team_inner(",
            &[
                "begin_management_transaction(pool, request_id).await?",
                "lock_team_lifecycle_row(",
                "team_has_active_tenants(",
                "delete_team_row(",
                "commit_management_transaction(",
            ],
            "team delete must hold one lifecycle transaction across lock/check/delete",
        ),
        (
            "src/web/management/topology/tenants/delete/workflow.rs",
            "pub(super) async fn delete_tenant_inner(",
            &[
                "begin_management_transaction(pool, request_id).await?",
                "lock_tenant_lifecycle_row(",
                "tenant_has_active_environments(",
                "delete_tenant_row(",
                "commit_management_transaction(",
            ],
            "tenant delete must hold one lifecycle transaction across lock/check/delete",
        ),
        (
            "src/web/management/topology/tenants/create/workflow.rs",
            "pub(super) async fn create_tenant_inner(",
            &[
                "begin_management_transaction(pool, request_id).await?",
                "lock_active_team_for_tenant_creation(",
                "insert_tenant_row(",
                "commit_management_transaction(",
            ],
            "tenant create must lock the active parent team before inserting",
        ),
    ];
    for (path, signature, markers, context) in lifecycle_workflows {
        let source = server_source(path, "topology lifecycle workflow source")?;
        let body = function_body(&source, signature)
            .test_context(&format!("workflow function should exist in {path}"))?;
        assert_ordered_markers(body, markers, context)?;
    }

    let environment_source = server_source(
        "src/web/management/topology_environment/mutation/create.rs",
        "environment create workflow source",
    )?;
    let environment_body = function_body(
        &environment_source,
        "pub(in crate::web::management) async fn create_environment(",
    )
    .test_context("environment create workflow should exist")?;
    assert_ordered_markers(
        environment_body,
        &[
            "begin_management_transaction(pool, &ctx.request_id).await",
            "lock_environment_creation_parent(",
            "build_initial_environment_configuration(",
            "create_environment_with_initial_configuration(",
            "commit_management_transaction(",
        ],
        "environment create must lock the active parent tenant before building and inserting the initial configuration",
    )?;

    let environment_parent_source = server_source(
        "src/web/management/topology_support/environment_creation/persistence/environment.rs",
        "environment parent lock source",
    )?;
    assert!(
        environment_parent_source.contains("FOR UPDATE OF team, t"),
        "environment creation must lock the active team and tenant parent rows"
    );

    Ok(())
}

#[test]
fn public_docs_do_not_advertise_removed_process_local_jwks_stale_policy() -> TestResult {
    let monitoring_doc = repo_source(
        "docs/operations/monitoring/README.md",
        "monitoring documentation",
    )?;
    assert!(
        monitoring_doc.contains("Stale JWKS serving")
            && monitoring_doc.contains("has been removed from the production runtime"),
        "monitoring docs must describe the production removal of JWKS stale serving"
    );
    for forbidden in [
        "policy.jwksStaleMemoryMaxSeconds",
        "policy.jwksStaleMaxGenerations",
        "policy.jwksRequirePinOnStale",
        "jwks_stale_served_total",
        "jwks_stale_refused_total",
        "stale_return",
    ] {
        assert!(
            !monitoring_doc.contains(forbidden),
            "monitoring docs must not advertise removed JWKS stale surface `{forbidden}`"
        );
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema = repo_source("db/schema.sql", "database schema")?;
    for forbidden in [
        "jwks_stale_if_error_seconds",
        "jwksStaleIfErrorSeconds",
        "jwks_stale_memory_max_seconds",
        "jwksStaleMemoryMaxSeconds",
        "jwks_stale_max_generations",
        "jwksStaleMaxGenerations",
        "jwks_stale_shared_max_seconds",
        "jwksStaleSharedMaxSeconds",
        "jwks_prefer_shared_stale_cache",
        "jwksPreferSharedStaleCache",
        "jwks_require_pin_on_stale",
        "jwksRequirePinOnStale",
    ] {
        assert!(
            !schema.contains(forbidden),
            "database schema must not retain removed JWKS stale policy field `{forbidden}`"
        );
    }
    for marker in [
        "jwks_cache_gc_interval_seconds",
        "jwks_shared_state_max_age_seconds",
    ] {
        assert!(
            schema.contains(marker),
            "database schema must use current JWKS shared-state policy column `{marker}`"
        );
    }
    for old_name in [
        "jwks_shared_cache_gc_interval_seconds",
        "jwks_shared_cache_max_age_seconds",
    ] {
        assert!(
            !schema.contains(old_name),
            "database schema must not retain old JWKS shared-cache policy column `{old_name}`"
        );
    }

    let migrations_dir = manifest_dir.join("../..").join("db/migrations");
    for entry in fs::read_dir(&migrations_dir).test_context(&format!(
        "database migrations should be readable at {}",
        migrations_dir.display()
    ))? {
        let entry = entry.test_context("database migration entry should be readable")?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }
        let source = fs::read_to_string(entry.path()).test_context(&format!(
            "database migration should be readable at {}",
            entry.path().display()
        ))?;
        for forbidden in [
            "jwks_stale_memory_max_seconds",
            "jwksStaleMemoryMaxSeconds",
            "jwks_stale_max_generations",
            "jwksStaleMaxGenerations",
            "jwks_stale_shared_max_seconds",
            "jwksStaleSharedMaxSeconds",
            "jwks_prefer_shared_stale_cache",
            "jwksPreferSharedStaleCache",
            "jwks_require_pin_on_stale",
            "jwksRequirePinOnStale",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} must not retain removed JWKS stale policy field `{forbidden}`",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[test]
fn management_database_schema_tracks_cleanup_interval_policy_migration() -> TestResult {
    let schema = repo_source("db/schema.sql", "database schema")?;
    let migration = migrations_source()?;

    for source in [&schema, &migration] {
        assert!(
            source.contains("cleanup_interval_seconds integer DEFAULT 60 NOT NULL"),
            "environment policy schema must define cleanup_interval_seconds with the managed default"
        );
        assert!(
            source.contains("cleanup_interval_seconds > 0")
                && source.contains("cleanup_interval_seconds <= 3600"),
            "environment policy schema must constrain cleanup_interval_seconds to the runtime bounds"
        );
    }
    Ok(())
}

#[test]
fn configuration_version_create_holds_environment_lock_across_base_check_and_numbering(
) -> TestResult {
    let source = server_source(
        "src/web/management/configuration_versions/mutation/create/workflow.rs",
        "configuration version create workflow source",
    )?;
    let body = function_body(
        &source,
        "pub(super) async fn create_configuration_version_inner(",
    )
    .test_context("configuration version create workflow should exist")?;

    assert_ordered_markers(
        body,
        &[
            "begin_management_transaction(pool, request_id).await?",
            "load_locked_environment_mutation_context(",
            "active_configuration_version_id != base_configuration_version_id",
            "load_next_configuration_version_number(",
            "insert_configuration_version_row(",
            "commit_management_transaction(",
        ],
        "configuration version create must hold the environment row lock from base-version validation through version-number allocation",
    )?;
    Ok(())
}

#[test]
fn configuration_version_archive_rechecks_lifecycle_and_locks_rows_before_state_change(
) -> TestResult {
    let workflow_source = server_source(
        "src/web/management/configuration_versions/mutation/archive/workflow.rs",
        "configuration version archive workflow source",
    )?;
    let audit_source = server_source(
        "src/web/management/configuration_versions/audit/archive.rs",
        "configuration version archive audit source",
    )?;
    let environment_lock_source = server_source(
        "src/web/management/row_mappers/environment_lock.rs",
        "environment mutation lock source",
    )?;
    let body = function_body(
        &workflow_source,
        "pub(super) async fn archive_configuration_version_inner(",
    )
    .test_context("configuration version archive workflow should exist")?;

    assert_ordered_markers(
        body,
        &[
            "begin_management_transaction(pool, request_id).await?",
            "require_team_lifecycle_role_in_transaction(",
            "load_locked_environment_mutation_context(",
            "load_configuration_version_status_for_update(",
            "Cannot archive the active configuration version",
            "SET status = 'ARCHIVED', archived_at = now()",
            "write_configuration_archive_audit(",
            "commit_management_transaction(",
        ],
        "configuration version archive must recheck lifecycle permission and hold environment/configuration locks before archiving",
    )?;
    assert!(
        workflow_source.contains("FOR UPDATE OF cv")
            && environment_lock_source.contains("FOR UPDATE OF e"),
        "configuration archive must lock both the target configuration version and environment rows"
    );
    assert!(
        audit_source.contains("CONFIGURATION_VERSION_ARCHIVED"),
        "configuration archive must emit a dedicated transition audit event"
    );
    Ok(())
}

#[test]
fn credential_login_revalidates_authority_rows_after_password_verification() -> TestResult {
    let local_source = server_source(
        "src/local_credentials/authentication.rs",
        "local credential authentication source",
    )?;
    let local_body = function_body(&local_source, "pub async fn authenticate_local_user(")
        .test_context("local credential authentication function should exist")?;
    assert_ordered_markers(
        local_body,
        &[
            "verify_password_or_dummy(password, Some(&password_hash))",
            "UPDATE aegaeon.end_user_password_credentials pc",
            "pc.password_hash = $2",
            "pc.status = 'ACTIVE'",
            "u.status = 'ACTIVE'",
            "RETURNING pc.id",
            "if !confirmed",
        ],
        "local credential login must revalidate credential hash/status and user status after password verification",
    )?;

    let management_source = server_source(
        "src/web/management/core/authentication/persistence.rs",
        "management authentication persistence source",
    )?;
    let management_body = function_body(
        &management_source,
        "pub(super) async fn update_management_login_state(",
    )
    .test_context("management login state update should exist")?;
    assert_ordered_markers(
        management_body,
        &[
            "UPDATE aegaeon.administrators",
            "password_hash = $2",
            "status = 'ACTIVE'",
            "RETURNING id",
            ".map(|row| row.is_some())",
        ],
        "management login must revalidate administrator status and password hash before session issuance",
    )?;

    let api_key_source = server_source(
        "src/web/management/session_support/api_key.rs",
        "management API key authentication source",
    )?;
    let api_key_auth_body = function_body(
        &api_key_source,
        "pub(super) async fn authenticate_management_api_key(",
    )
    .test_context("management API key authentication function should exist")?;
    let api_key_confirm_body = function_body(
        &api_key_source,
        "async fn confirm_api_key_active_and_touch_last_used(",
    )
    .test_context("management API key final confirmation should exist")?;
    assert!(
        api_key_auth_body.contains("confirm_api_key_active_and_touch_last_used(")
            && api_key_auth_body.contains("return Err(invalid_api_key(request_id));"),
        "management API key authentication must fail closed when final confirmation rejects the key"
    );
    assert_ordered_markers(
        api_key_confirm_body,
        &[
            "WITH active_key AS MATERIALIZED",
            "ak.status = 'ACTIVE'",
            "ak.key_hash = $3",
            "a.status = 'ACTIVE'",
            "a.kind = 'SERVICE'",
            "FOR UPDATE OF ak, a",
            "UPDATE aegaeon.api_keys ak",
            "SELECT EXISTS (SELECT 1 FROM active_key)",
        ],
        "management API key authentication must revalidate key hash, key status, and service administrator status under row locks",
    )?;
    Ok(())
}

#[test]
fn configuration_version_list_does_not_fetch_full_documents() -> TestResult {
    let source = server_source(
        "src/web/management/configuration_versions/read/persistence.rs",
        "configuration version read persistence source",
    )?;
    let list_body = function_body(
        &source,
        "pub(super) async fn fetch_configuration_version_rows(",
    )
    .test_context("configuration version list query function should exist")?;

    assert!(
        !list_body.contains("configuration_document"),
        "configuration version list must not fetch full configuration documents to compute summary hashes"
    );
    assert!(
        source.contains("FETCH_CONFIGURATION_VERSION_ROW_SQL")
            && source.contains("cv.configuration_document"),
        "single-version reads should still fetch the full configuration document"
    );
    Ok(())
}

#[test]
fn configuration_activation_validates_runtime_keys_against_new_policy() -> TestResult {
    let source = server_source(
        "src/web/management/configuration_versions/mutation/activate/workflow/persist.rs",
        "configuration activation persist source",
    )?;
    let body = function_body(&source, "pub(super) async fn persist_activation_state(")
        .test_context("configuration activation persist function should exist")?;

    assert_ordered_markers(
        body,
        &[
            "ensure_no_revocation_conflicts(",
            "ensure_runtime_keys_compatible_with_policy(",
            "persist_environment_configuration_state(",
            "switch_active_configuration_version(",
        ],
        "configuration activation must validate operational runtime keys before switching active policy",
    )?;
    assert!(
        source.contains("load_runtime_key_set_for_environment_in_tx(")
            && source.contains("validate_allowed_signing_algorithms("),
        "configuration activation must check active runtime keys against the candidate policy allowlist"
    );
    assert!(
        source.contains("ensure_required_runtime_keys_present(")
            && source.contains("required_runtime_key_usages(")
            && source.contains(".active_key(")
            && source.contains("\"missingRuntimeKeys\""),
        "configuration activation must reject policies that enable runtime features without ACTIVE runtime keys"
    );
    assert!(
        source.contains("ensure_runtime_constructors_accept_policy(")
            && source.contains("OidcConfig::from_management_snapshot_async(")
            && source.contains("ManagedJwtKeyManager::try_from_runtime_keys("),
        "configuration activation must prove the candidate policy and ACTIVE runtime keys are constructible before switching active state"
    );
    Ok(())
}

#[test]
fn configuration_activation_requires_security_downgrade_authorization() -> TestResult {
    let workflow_source = server_source(
        "src/web/management/configuration_versions/mutation/activate/workflow.rs",
        "configuration activation workflow source",
    )?;
    let load_source = server_source(
        "src/web/management/configuration_versions/mutation/activate/workflow/loading.rs",
        "configuration activation loading source",
    )?;
    let audit_source = server_source(
        "src/web/management/configuration_versions/audit/activation.rs",
        "configuration activation audit source",
    )?;
    let body = function_body(
        &workflow_source,
        "pub(super) async fn activate_configuration_version_inner(",
    )
    .test_context("configuration activation workflow should exist")?;

    assert_ordered_markers(
        body,
        &[
            "loading::load_activation_context(",
            "require_security_downgrade_authorization(",
            "persist::persist_activation_state(",
            "write_configuration_activation_audits(",
        ],
        "configuration activation must authorize security downgrades before persisting the candidate active snapshot",
    )?;
    assert!(
        load_source.contains("previous_policy: PolicyDocument")
            && load_source.contains("load_policy_from_configuration_snapshot(&previous_configuration_document"),
        "configuration activation must compare the candidate policy against the previously active policy"
    );
    assert!(
        body.contains("allowed: request.allow_security_downgrade == Some(true)")
            && body.contains("reason: request.reason.as_deref()"),
        "configuration activation must require both explicit acknowledgement and a non-empty reason for security downgrades"
    );
    assert!(
        audit_source.contains("\"securityDowngrade\"")
            && audit_source.contains("let activation_severity = if downgraded_fields.is_empty()"),
        "configuration activation audit must record downgrade decisions and raise severity for downgrades"
    );
    Ok(())
}

#[test]
fn runtime_configuration_loader_uses_one_repeatable_read_snapshot() -> TestResult {
    let source = server_source(
        "src/runtime_configuration.rs",
        "runtime configuration source",
    )?;
    let load_body = function_body(&source, "pub async fn load_database_runtime_configuration(")
        .test_context("database runtime configuration loader should exist")?;
    let revision_body = function_body(
        &source,
        "pub async fn load_active_runtime_configuration_revision_for_issuer_host(",
    )
    .test_context("database runtime revision loader should exist")?;

    assert!(
        source.contains("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"),
        "database runtime configuration load must use an explicit read-only repeatable-read snapshot"
    );
    assert_ordered_markers(
        load_body,
        &[
            "begin_runtime_configuration_snapshot(pool).await?",
            "ACTIVE_RUNTIME_CONFIGURATION_FOR_ISSUER_HOST",
            "load_active_runtime_configuration_revision_for_issuer_host_in_tx(",
            "load_runtime_key_set_for_issuer_host_in_tx(",
            "tx.commit()",
        ],
        "database runtime configuration must read policy, fingerprints, clients, and keys from one transaction snapshot",
    )?;
    assert!(
        !load_body.contains("load_active_runtime_configuration_revision_for_issuer_host(pool"),
        "database runtime configuration loader must not mix transactional and pool reads"
    );
    assert!(
        !load_body.contains("load_runtime_key_set_for_issuer_host(pool"),
        "database runtime configuration loader must not load runtime keys outside the snapshot"
    );
    assert_ordered_markers(
        revision_body,
        &[
            "begin_runtime_configuration_snapshot(pool).await?",
            "load_active_runtime_configuration_revision_for_issuer_host_in_tx(",
            "tx.commit()",
        ],
        "database runtime revision loader must read all revision fingerprints from one transaction snapshot",
    )?;
    assert!(
        !revision_body.contains("load_active_runtime_client_fingerprint_for_issuer_host(pool"),
        "database runtime revision loader must not mix pool reads into the transaction snapshot"
    );
    Ok(())
}

#[test]
fn runtime_key_projection_is_environment_scoped_operational_state() -> TestResult {
    let store_source = server_source("src/runtime_keys/store.rs", "runtime key store source")?;
    let configuration_source = server_source(
        "src/runtime_configuration.rs",
        "runtime configuration source",
    )?;
    let authority_query_source = server_source(
        "src/runtime_authority_queries.rs",
        "runtime authority query source",
    )?;
    let runtime_clients_source = server_source("src/runtime_clients.rs", "runtime clients source")?;

    for (source, description) in [
        (&store_source, "runtime key loader"),
        (&authority_query_source, "runtime key revision fingerprint"),
    ] {
        assert!(
            !source.contains("rk.configuration_version_id = e.active_configuration_version_id"),
            "{description} must not hide environment-scoped operational runtime keys after configuration activation"
        );
        assert!(
            source.contains("rk.retiring_expires_at > now()"),
            "{description} must stop projecting expired RETIRING runtime keys"
        );
    }
    assert!(
        configuration_source.contains("ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST")
            && authority_query_source.contains("'retiring_expires_at', rk.retiring_expires_at"),
        "runtime key revision fingerprint must include RETIRING expiry while the key remains projected"
    );
    assert!(
        !store_source.contains("pub async fn load_runtime_key_set_for_issuer_host("),
        "runtime key store must not expose a pool-read loader outside the runtime configuration snapshot"
    );
    assert!(
        !runtime_clients_source
            .contains("pub async fn load_active_runtime_client_fingerprint_for_issuer_host("),
        "runtime client fingerprint loader must not expose a pool-read API outside a transaction snapshot"
    );
    Ok(())
}

#[test]
fn runtime_key_retiring_overlap_is_bounded_and_expiring() -> TestResult {
    let lifecycle_source = server_source(
        "src/web/management/runtime_key_store/lifecycle.rs",
        "runtime key lifecycle store source",
    )?;
    let runtime_validation_source = server_source(
        "src/runtime_keys/validation.rs",
        "runtime key validation source",
    )?;
    let runtime_error_source =
        server_source("src/runtime_keys/error.rs", "runtime key error source")?;
    let schema = repository_file("db/schema.sql", "database schema")?;

    assert!(
        lifecycle_source.contains("runtime_key_retiring_retention_seconds(")
            && lifecycle_source.contains("retiring_expires_at = now()")
            && lifecycle_source.contains("policy.id_token_time_to_live_seconds")
            && lifecycle_source.contains("policy.jwt_leeway_seconds"),
        "runtime key lifecycle must assign RETIRING expiry from active policy TTLs"
    );
    assert!(
        runtime_validation_source.contains("MAX_RETIRING_KEYS_PER_USAGE")
            && runtime_validation_source.contains("reject_excess_retiring_keys(")
            && runtime_error_source.contains("TooManyRetiringKeys"),
        "runtime key projection must bound the number of RETIRING keys per usage"
    );
    assert!(
        schema.contains("retiring_expires_at timestamp with time zone")
            && schema.contains("runtime_keys_retiring_expiry_matches_status")
            && schema.contains("runtime_keys_retiring_expires_at"),
        "runtime key schema must enforce and index RETIRING expiry"
    );

    Ok(())
}

#[test]
fn active_configuration_mutations_revalidate_under_environment_lock() -> TestResult {
    for (path, signature, mutation_marker) in [
        (
            "src/web/management/clients/mutation/create/workflow.rs",
            "pub(in crate::web::management::clients::mutation::create) async fn create_client_workflow(",
            "insert_client_row(",
        ),
        (
            "src/web/management/clients/mutation/update/workflow.rs",
            "pub(in crate::web::management::clients::mutation::update) async fn update_client_workflow(",
            "update_client_row(",
        ),
        (
            "src/web/management/clients/mutation/delete/workflow.rs",
            "pub(super) async fn delete_client_inner(",
            "delete_client_row(",
        ),
        (
            "src/web/management/oauth_profiles/mutation/create/workflow.rs",
            "pub(super) async fn create_oauth_profile_inner(",
            "insert_oauth_profile_row(",
        ),
        (
            "src/web/management/oauth_profiles/mutation/update/workflow.rs",
            "pub(super) async fn update_oauth_profile_inner(",
            "update_oauth_profile_row(",
        ),
        (
            "src/web/management/connections/mutation/create/workflow.rs",
            "pub(super) async fn create_connection_inner(",
            "insert_connection_row(",
        ),
        (
            "src/web/management/connections/mutation/update/workflow.rs",
            "pub(super) async fn update_connection_inner(",
            "update_connection_row(",
        ),
        (
            "src/web/management/connections/mutation/delete/workflow.rs",
            "pub(super) async fn delete_connection_inner(",
            "retire_connection(",
        ),
        (
            "src/web/management/key_stores/mutation/workflow.rs",
            "pub(super) async fn update_key_store_inner(",
            "upsert_key_store(",
        ),
    ] {
        let source = server_source(path, "active configuration mutation source")?;
        let body = function_body(&source, signature)
            .test_context(&format!("workflow function should exist in {path}"))?;
        assert_ordered_markers(
            body,
            &[
                "begin_management_transaction(pool, request_id).await?",
                "load_management_environment_record_for_update(",
                "ensure_base_configuration_matches(",
                mutation_marker,
            ],
            &format!(
                "{path} must revalidate the base configuration under an environment row lock before mutation"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn dcr_database_mutations_revalidate_registration_under_lock() -> TestResult {
    let source = server_source("src/dcr_persistence.rs", "DCR persistence source")?;
    let mutation_source = server_source("src/dcr_persistence/mutation.rs", "DCR mutation source")?;
    let stored_source = server_source(
        "src/dcr_persistence/stored_client.rs",
        "DCR stored client source",
    )?;

    let create_body = function_body(&source, "pub async fn create_dynamic_registration(")
        .test_context("DCR create function should exist")?;
    assert_ordered_markers(
        create_body,
        &[
            "pool.begin().await?",
            "load_active_environment_for_update(",
            "insert_client_row(",
        ],
        "DCR create must bind active environment inside the write transaction",
    )?;

    let update_body = function_body(&source, "pub async fn update_dynamic_registration(")
        .test_context("DCR update function should exist")?;
    assert_ordered_markers(
        update_body,
        &[
            "pool.begin().await?",
            "lock_current_dynamic_registration(",
            "update_client_row(",
            "update_dynamic_registration_row(",
        ],
        "DCR update must lock and revalidate the stored registration before mutation",
    )?;

    let delete_body = function_body(&source, "pub async fn delete_dynamic_registration(")
        .test_context("DCR delete function should exist")?;
    assert_ordered_markers(
        delete_body,
        &[
            "pool.begin().await?",
            "lock_current_dynamic_registration(",
            "delete_dynamic_registration_row(",
            "mark_client_deleted(",
        ],
        "DCR delete must lock and revalidate the stored registration before deleting persisted rows",
    )?;

    assert!(
        stored_source.contains("registration_access_token_hash: String"),
        "DCR stored clients must carry the authenticated registration token hash for locked mutation revalidation"
    );
    assert!(
        mutation_source.contains("registration_access_token_hash = $13")
            && mutation_source.matches("rows_affected()").count() >= 2,
        "DCR update statements must bind the authenticated registration token hash and check row counts"
    );
    for helper in [
        "pub(super) async fn delete_dynamic_registration_row(",
        "pub(super) async fn mark_client_deleted(",
    ] {
        let helper_body = function_body(&mutation_source, helper)
            .test_context(&format!("DCR mutation helper should exist: {helper}"))?;
        assert!(
            helper_body.contains(".map(|result| result.rows_affected())")
                && helper_body.contains(".and_then(expect_single_affected_row)"),
            "DCR mutation helper `{helper}` must fail closed unless exactly one row is affected"
        );
    }
    assert!(
        mutation_source.contains("fn expect_single_affected_row(rows: u64)")
            && mutation_source.contains("DcrDatabaseError::ConcurrentModification"),
        "DCR mutation helpers must map unexpected affected-row counts to concurrent modification"
    );
    Ok(())
}

#[test]
fn runtime_client_snapshot_loader_uses_one_repeatable_read_snapshot() -> TestResult {
    let source = [
        server_source("src/runtime_clients.rs", "runtime client facade source")?,
        server_source(
            "src/runtime_clients/error.rs",
            "runtime client error source",
        )?,
        server_source(
            "src/runtime_clients/projection.rs",
            "runtime client projection source",
        )?,
        server_source(
            "src/runtime_clients/repository.rs",
            "runtime client repository source",
        )?,
        server_source("src/runtime_clients/row.rs", "runtime client row source")?,
        server_source(
            "src/runtime_clients/snapshot.rs",
            "runtime client snapshot source",
        )?,
    ]
    .join("\n");
    let body = function_body(
        &source,
        "async fn load_active_runtime_client_snapshot_for_issuer_host_guarded(",
    )
    .test_context("runtime client snapshot loader should exist")?;

    assert!(
        source.contains("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"),
        "runtime client snapshot load must use an explicit read-only repeatable-read snapshot"
    );
    assert_ordered_markers(
        body,
        &[
            "begin_runtime_client_snapshot(pool).await?",
            "validate_runtime_authority_revision_in_tx(",
            "let fingerprint_before = authority_revision",
            ".active_runtime_client_fingerprint()",
            "active_runtime_clients_for_issuer_host()",
            "tx.commit()",
        ],
        "runtime client snapshot must read fingerprint and rows from one transaction snapshot",
    )?;
    assert!(
        !body.contains("fingerprint_after"),
        "runtime client snapshot loader must not rely on before/after pool reads for consistency"
    );
    assert!(
        source.contains("pub async fn load_runtime_client_projection_from_database_guarded(")
            && source.contains("RuntimeRevisionMismatch"),
        "runtime client projection load must expose a guarded path that rejects policy/key/DCR revision drift"
    );
    assert!(
        source.contains(
            "pub(crate) async fn load_active_runtime_client_fingerprint_for_issuer_host_in_tx("
        ) && !source
            .contains("pub async fn load_active_runtime_client_fingerprint_for_issuer_host_in_tx("),
        "runtime client fingerprint aggregate loader must stay crate-private because it is safe only after active authority-row validation"
    );
    assert!(
        !source.contains("pub fn try_new(") && !source.contains("pub fn try_new_with_fingerprint("),
        "runtime client snapshots must not expose public constructors that bypass the database projection fingerprint"
    );
    assert!(
        source.contains("#[cfg(test)]\n    pub(super) fn try_new("),
        "the client-id-only runtime snapshot constructor must remain test-only"
    );

    let background_source = [
        server_source("src/main/background_tasks.rs", "background task source")?,
        server_source(
            "src/main/background_tasks/runtime_config.rs",
            "runtime config background task source",
        )?,
        server_source(
            "src/main/background_tasks/runtime_config/monitor.rs",
            "runtime config monitor task source",
        )?,
        server_source(
            "src/main/background_tasks/runtime_config/notifications.rs",
            "runtime config notification task source",
        )?,
    ]
    .join("\n");
    assert!(
        background_source.contains("try_synchronize_client_projection_from_database_from(")
            && background_source.contains("runtime_authority")
            && background_source.contains(
                "self.advance_runtime_authority_revision_or_request_restart(",
            )
            && background_source.contains(
                "runtime client projection changed but synchronization failed; requesting graceful restart to avoid serving stale client state",
            )
            && background_source.contains(
                "RuntimeRestartRequest::runtime_client_projection_sync_failure",
            )
            && background_source.contains("pub(super) fn spawn_supervised_runtime_task(")
            && background_source.contains("handle.await")
            && background_source.contains(
                "runtime background task failed; requesting graceful restart",
            )
            && background_source.contains(
                "RuntimeRestartRequest::runtime_authority_unavailable",
            ),
        "runtime configuration monitoring must advance authority state when the registry is already current, request restart when runtime-client projection refresh fails, and supervise task failure"
    );
    let request_guard_source = server_source(
        "src/web/runtime_authority_guard.rs",
        "runtime authority request-admission guard source",
    )?;
    assert!(
        request_guard_source.contains("ensure_runtime_authority_snapshot_is_current(")
            && request_guard_source
                .contains("current_database_runtime_authority_revision_or_request_restart(")
            && request_guard_source
                .contains("load_active_runtime_configuration_revision_for_issuer_host(")
            && request_guard_source
                .contains("try_synchronize_client_projection_from_database_from(")
            && request_guard_source.contains("request_restart_after_database_runtime_authority_drift(")
            && !request_guard_source.contains("load_runtime_client_projection_from_database_guarded(")
            && !request_guard_source.contains("replace_runtime_clients_from_database_guarded(")
            && request_guard_source.contains("try_runtime_snapshot_fingerprint()")
            && request_guard_source.contains(
                "runtime client projection is inconsistent during request admission; requesting graceful restart to avoid serving stale client state",
            )
            && request_guard_source.contains("RuntimeRestartRequest::runtime_authority_drift"),
        "request admission must revalidate the database runtime-authority revision through the bounded cache, synchronize client-only projection drift, and fail closed on runtime-critical drift"
    );

    let authority_query_source = server_source(
        "src/runtime_authority_queries.rs",
        "runtime authority query source",
    )?;
    let runtime_configuration_source = server_source(
        "src/runtime_configuration.rs",
        "runtime configuration source",
    )?;
    let runtime_client_query_source = server_source(
        "src/runtime_clients/queries.rs",
        "runtime client query source",
    )?;
    assert!(
        authority_query_source
            .contains("pub(crate) const ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST")
            && runtime_configuration_source.contains(
                "crate::runtime_authority_queries::ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST",
            )
            && source.contains(
                "crate::runtime_authority_queries::ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST",
            )
            && !runtime_configuration_source
                .contains("const ACTIVE_RUNTIME_CONFIGURATION_REVISION_FOR_ISSUER_HOST")
            && !runtime_client_query_source
                .contains("ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST"),
        "stable runtime authority revision SQL must have one shared source of truth"
    );
    assert!(
        runtime_client_query_source.contains("const ACTIVE_RUNTIME_CLIENT_PROJECTION_CTE")
            && runtime_client_query_source
                .matches("WITH active_runtime_client_projection AS (")
                .count()
                == 1
            && runtime_client_query_source
                .contains("pub(super) fn active_runtime_clients_for_issuer_host() -> String")
            && runtime_client_query_source.contains(
                "pub(super) fn active_runtime_client_fingerprint_for_issuer_host() -> String",
            )
            && runtime_client_query_source
                .contains("row_json::text AS runtime_client_projection_row_json")
            && runtime_client_query_source.contains("jsonb_agg(row_json ORDER BY"),
        "runtime client rows and fingerprint must derive from one canonical SQL projection CTE"
    );
    Ok(())
}

#[test]
fn request_admission_revalidates_runtime_client_projection_before_serving() -> TestResult {
    let router_source = server_source("src/web/router.rs", "router source")?;
    assert!(
        router_source.contains("runtime_authority_guard_middleware")
            && router_source.contains("from_fn_with_state("),
        "the server router must run the runtime authority guard during request admission"
    );

    let guard_source = server_source(
        "src/web/runtime_authority_guard.rs",
        "runtime authority request-admission guard source",
    )?;
    for marker in [
        "ensure_runtime_authority_snapshot_is_current(",
        "current_database_runtime_authority_revision_or_request_restart(",
        "load_active_runtime_configuration_revision_for_issuer_host(",
        "try_synchronize_client_projection_from_database_from(",
        "request_restart_after_database_runtime_authority_drift(",
        "try_runtime_snapshot_fingerprint()",
        "active_runtime_client_fingerprint()",
        "request_restart_after_runtime_client_projection_mismatch(",
        "runtime client projection is inconsistent during request admission",
        "RuntimeRestartRequest::runtime_authority_drift",
    ] {
        assert!(
            guard_source.contains(marker),
            "runtime authority guard must include marker `{marker}`"
        );
    }
    assert!(
        !guard_source.contains("readiness.current_revision()")
            && !guard_source.contains("readiness.store_revision(")
            && !guard_source.contains("RUNTIME_AUTHORITY_DATABASE_REVISION_CACHE_TTL"),
        "request admission must not reuse readiness revision cache; protected requests must re-read the database authority revision"
    );
    assert!(
        !guard_source.contains("load_runtime_client_projection_from_database_guarded(")
            && !guard_source.contains("replace_runtime_clients_from_database_guarded("),
        "request admission may use the typed runtime-authority revision loader and client projection synchronizer, but must not expose raw projection replacement"
    );
    assert!(
        guard_source.contains("matches!(path, \"/health\" | \"/ready\")"),
        "only health and readiness should remain available without request-admission side effects"
    );
    Ok(())
}

#[test]
fn post_commit_runtime_client_projection_sync_failures_fail_closed() -> TestResult {
    let dcr_runtime_source = server_source(
        "src/web/dcr_runtime.rs",
        "DCR runtime client synchronization source",
    )?;
    assert!(
        dcr_runtime_source.contains("database_committed = true")
            && dcr_runtime_source.contains("fn committed_runtime_sync_failure_response(")
            && dcr_runtime_source.contains("\"temporarily_unavailable\"")
            && dcr_runtime_source
                .contains("Err(committed_runtime_sync_failure_response(issuer_base))"),
        "DCR database mutations must not report success when committed runtime-client projection synchronization fails"
    );

    let management_snapshot_source = server_source(
        "src/web/management/runtime_clients/snapshot.rs",
        "management runtime client synchronization source",
    )?;
    assert!(
        management_snapshot_source.contains("database_committed = true")
            && management_snapshot_source
                .contains("fn committed_runtime_client_sync_failure_response(")
            && management_snapshot_source.contains("StatusCode::SERVICE_UNAVAILABLE")
            && management_snapshot_source
                .contains("Err(committed_runtime_client_sync_failure_response(request_id))"),
        "management database mutations must not report success when committed runtime-client projection synchronization fails"
    );
    Ok(())
}

#[test]
fn app_state_keeps_runtime_authority_as_single_typed_context() -> TestResult {
    let state_source = server_source("src/web/state.rs", "web app state source")?;
    let runtime_authority_source =
        server_source("src/runtime_authority.rs", "runtime authority state source")?;
    assert!(
        runtime_authority_source.contains("pub struct RuntimeAuthorityState")
            && runtime_authority_source.contains("issuer_host: Arc<String>")
            && runtime_authority_source.contains("revision: Arc<RwLock<RuntimeAuthorityRevision>>")
            && runtime_authority_source.contains("pub fn from_database_revision(")
            && runtime_authority_source
                .contains("pub async fn try_synchronize_client_projection_from_database(")
            && runtime_authority_source
                .contains("pub(crate) fn try_replace_client_projection_from(")
            && runtime_authority_source.contains("projection: RuntimeClientProjectionCommit")
            && runtime_authority_source.contains("try_runtime_projection_write()")
            && runtime_authority_source.contains("projection.commit_to(&mut registry_projection)")
            && !runtime_authority_source.contains("FnOnce()")
            && runtime_authority_source
                .contains("pub fn try_advance_client_projection_revision_from(")
            && runtime_authority_source.contains("StaleClientProjectionUpdate")
            && state_source.contains("pub runtime_authority: RuntimeAuthorityState")
            && state_source.contains("pub(super) struct RuntimeAuthorityServices")
            && state_source.contains("pub(super) fn runtime_authority_services(&self)"),
        "AppState must keep runtime issuer host and authority revision paired as RuntimeAuthorityState"
    );
    assert!(
        !state_source.contains("pub runtime_issuer_host:")
            && !state_source.contains("pub runtime_client_projection_guard:")
            && !state_source.contains("pub fn advance_client_projection_revision(")
            && !state_source.contains(
                "pub fn new(issuer_host: Arc<String>, revision: RuntimeAuthorityRevision)"
            ),
        "AppState must not expose runtime issuer host/projection guard as independent fields or retain ambiguous RuntimeAuthorityState mutation constructors"
    );

    let app_state_source = server_source("src/main/app_state.rs", "main app state assembly")?;
    assert!(
        app_state_source.contains("runtime_authority")
            && !app_state_source.contains("runtime_issuer_host,")
            && !app_state_source.contains("runtime_client_projection_guard,"),
        "main AppState assembly must pass the typed runtime authority context"
    );
    let router_source = server_source("src/web/router.rs", "router source")?;
    assert!(
        router_source.contains("runtime authority client projection is stale")
            && router_source.contains("loaded_revision.active_runtime_client_fingerprint()")
            && router_source.contains("current_revision.active_runtime_client_fingerprint()"),
        "readiness must reject a stale RuntimeAuthorityState client projection, not only stale registry projection"
    );
    let sync_source = server_source("src/main/sync_runtime.rs", "runtime sync plan source")?;
    assert!(
        !sync_source.contains("pub(super) authority_revision: RuntimeAuthorityRevision")
            && sync_source.contains("hydrate_runtime_clients_for_authority("),
        "startup runtime sync must delegate to the authority-owned projection coordinator without carrying a duplicate revision field"
    );
    let main_source = server_source("src/main.rs", "main server bootstrap source")?;
    assert_ordered_markers(
        &main_source,
        &[
            "let runtime_authority_revision = database_runtime_config.authority_revision()?",
            "RuntimeAuthorityState::from_database_revision(",
            "let runtime_sync = prepare_runtime_sync_for_authority(",
        ],
        "main startup must initialize RuntimeAuthorityState before using the authority-owned runtime-client sync coordinator",
    )?;
    Ok(())
}

#[test]
fn management_parent_keeps_import_facade_isolated() -> TestResult {
    let management_source = server_source("src/web/management.rs", "management module source")?;
    let prelude_source = server_source(
        "src/web/management/prelude.rs",
        "management import facade source",
    )?;

    assert!(
        management_source.contains("mod prelude;")
            && management_source.contains("use prelude::*;")
            && prelude_source.contains("pub(super) use super::http_errors::{")
            && prelude_source.contains("pub(super) use super::scope::{")
            && prelude_source.contains("pub(super) use super::transactions::{"),
        "management parent must keep child-facing imports in the dedicated prelude facade"
    );

    for forbidden in [
        "use account_link_support::{",
        "use environment_support::{",
        "use http_errors::{",
        "use row_mappers::{",
        "use scope::{",
        "use transactions::{",
        "use user_support::{",
    ] {
        assert!(
            !management_source.contains(forbidden),
            "management parent must not regain broad child-facing import `{forbidden}`"
        );
    }
    Ok(())
}

#[test]
fn runtime_authority_changes_are_notified_across_database_backed_nodes() -> TestResult {
    let background_source = [
        server_source("src/main/background_tasks.rs", "background task source")?,
        server_source(
            "src/main/background_tasks/runtime_config.rs",
            "runtime config background task source",
        )?,
        server_source(
            "src/main/background_tasks/runtime_config/monitor.rs",
            "runtime config monitor task source",
        )?,
        server_source(
            "src/main/background_tasks/runtime_config/notifications.rs",
            "runtime config notification task source",
        )?,
    ]
    .join("\n");
    for marker in [
        "reconnect_runtime_authority_listener(&database_url, &monitor).await",
        "aegaeon_runtime_authority_changed",
        "spawn_runtime_authority_notification_listener_task(",
        "listener",
        ".listen(RUNTIME_AUTHORITY_NOTIFICATION_CHANNEL)",
        "runtime_config_notifications",
        "monitor.check_revision().await",
        "notification_matches_issuer(",
        "runtime authority change notification ignored for unrelated issuer",
        "reconnecting while polling monitor remains authoritative",
        "spawn_supervised_runtime_task(",
    ] {
        assert!(
            background_source.contains(marker),
            "runtime authority listener must include marker `{marker}`"
        );
    }

    let main_source = server_source("src/main.rs", "main server bootstrap source")?;
    assert_ordered_markers(
        &main_source,
        &[
            "spawn_runtime_config_monitor_task(",
            "spawn_runtime_authority_notification_listener_task(",
            ".await?",
        ],
        "main startup must register PostgreSQL runtime authority notifications in addition to the polling monitor",
    )?;

    let schema = repository_file("db/schema.sql", "database schema")?;
    for marker in [
        "CREATE FUNCTION aegaeon.notify_runtime_authority_changed()",
        "pg_notify(",
        "aegaeon_runtime_authority_changed",
        "'environmentIds'",
        "'issuerHosts'",
        "FOR EACH ROW",
        "CREATE TRIGGER runtime_authority_notify_configuration_versions",
        "CREATE TRIGGER runtime_authority_notify_environment_policies",
        "CREATE TRIGGER runtime_authority_notify_clients",
        "CREATE TRIGGER runtime_authority_notify_runtime_keys",
        "CREATE TRIGGER runtime_authority_notify_environment_dcr_bearer_tokens",
    ] {
        assert!(
            schema.contains(marker),
            "database schema must include runtime authority notification marker `{marker}`"
        );
    }
    assert!(
        !schema.contains("runtime_authority_notify_environment_revoked_client_secrets"),
        "client-secret revocation ledger is a configuration activation conflict ledger, not the live runtime credential projection"
    );
    let runtime_client_query_source = server_source(
        "src/runtime_clients/queries.rs",
        "runtime client projection query source",
    )?;
    assert!(
        runtime_client_query_source.contains("cs.status = 'ACTIVE'")
            && !runtime_client_query_source.contains("environment_revoked_client_secrets"),
        "live runtime client projection must use client_secrets.status as the credential authority"
    );
    Ok(())
}

#[test]
fn runtime_authority_revision_uses_typed_stable_and_client_projection_boundary() -> TestResult {
    let source = server_source(
        "src/runtime_configuration.rs",
        "runtime configuration source",
    )?;
    let revision_source = server_source(
        "src/runtime_configuration/revision.rs",
        "runtime authority revision source",
    )?;
    for marker in [
        "struct StableRuntimeAuthorityRevision",
        "struct RuntimeClientProjectionRevision",
        "pub struct RuntimeAuthorityRevision",
        "stable: StableRuntimeAuthorityRevision",
        "client_projection: RuntimeClientProjectionRevision",
        "active_configuration_document_fingerprint",
        "pub(crate) fn try_new(",
        "pub fn authority_revision(&self) -> Result<RuntimeAuthorityRevision, RuntimeFingerprintError>",
        "RuntimeFingerprintError",
        "try_from_database_projection(",
    ] {
        assert!(
            revision_source.contains(marker)
                || (marker
                    == "pub fn authority_revision(&self) -> Result<RuntimeAuthorityRevision, RuntimeFingerprintError>"
                    && source.contains(marker)),
            "runtime authority revision must include marker `{marker}`"
        );
    }
    assert!(
        source.contains(
            "pub use self::revision::{RuntimeAuthorityRevision, RuntimeFingerprintError}"
        ),
        "runtime configuration loader must re-export the typed authority revision boundary"
    );
    let revision_body = function_body(&revision_source, "pub struct RuntimeAuthorityRevision")
        .test_context("RuntimeAuthorityRevision struct body should be readable")?;
    let stable_body = function_body(&revision_source, "struct StableRuntimeAuthorityRevision")
        .test_context("StableRuntimeAuthorityRevision struct body should be readable")?;
    let client_projection_body =
        function_body(&revision_source, "struct RuntimeClientProjectionRevision")
            .test_context("RuntimeClientProjectionRevision struct body should be readable")?;
    let authority_revision_boundary =
        [revision_body, stable_body, client_projection_body].join("\n");
    for forbidden in [
        "pub active_runtime_key_set_fingerprint: String",
        "pub active_runtime_client_fingerprint: String",
        "pub active_dcr_bearer_token_fingerprint: String",
        "pub active_configuration_document_fingerprint: String",
    ] {
        assert!(
            !authority_revision_boundary.contains(forbidden),
            "runtime authority revision must not expose raw public field `{forbidden}`"
        );
    }
    assert!(
        revision_source.contains("value.len() == 64")
            && revision_source.contains("byte.is_ascii_hexdigit()"),
        "runtime authority fingerprints decoded from PostgreSQL must be validated as SHA-256 hex"
    );
    Ok(())
}

#[test]
fn runtime_client_sync_interval_policy_is_retired() -> TestResult {
    let retired_field = "runtime_client_sync_interval_seconds";
    let retired_json_field = "runtimeClientSyncIntervalSeconds";
    for (source, description) in [
        (
            repo_source("db/schema.sql", "database schema")?,
            "db/schema.sql",
        ),
        (migrations_source()?, "db/migrations"),
    ] {
        assert!(
            !source.contains(retired_field),
            "{description} must not retain the obsolete standalone runtime-client sync policy column"
        );
        assert!(
            !source.contains(retired_json_field),
            "{description} must not retain the obsolete standalone runtime-client sync JSON policy field"
        );
    }

    for (path, description) in [
        (
            "src/management/types/policy/document.rs",
            "policy document type",
        ),
        ("src/management/types/policy/patch.rs", "policy patch type"),
        (
            "src/web/management/configuration_documents/policy_sql.rs",
            "policy update SQL",
        ),
        (
            "src/web/management/configuration_version_store/policy/query.rs",
            "policy select SQL",
        ),
        (
            "src/web/management/configuration_policy_rows/runtime.rs",
            "policy row projection",
        ),
        (
            "src/web/management/policy_patch/runtime.rs",
            "policy patch application",
        ),
        (
            "src/runtime_configuration/document/tests.rs",
            "runtime configuration document fixture",
        ),
    ] {
        let source = server_source(path, description)?;
        assert!(
            !source.contains(retired_field),
            "{path} must not expose the obsolete standalone runtime-client sync policy API"
        );
        assert!(
            !source.contains(retired_json_field),
            "{path} must not expose the obsolete standalone runtime-client sync JSON policy API"
        );
    }
    Ok(())
}

#[test]
fn client_runtime_projection_mutation_api_is_not_public_database_bypass() -> TestResult {
    let runtime_clients_source = [
        server_source("src/runtime_clients.rs", "runtime client facade source")?,
        server_source(
            "src/runtime_clients/projection.rs",
            "runtime client projection source",
        )?,
        server_source(
            "src/runtime_clients/repository.rs",
            "runtime client repository source",
        )?,
        server_source(
            "src/runtime_clients/snapshot.rs",
            "runtime client snapshot source",
        )?,
    ]
    .join("\n");
    for signature in [
        "pub struct RuntimeClientSnapshotEntry",
        "pub struct RuntimeClientSnapshot",
        "pub fn try_replace_runtime(",
        "pub fn try_register_runtime(",
        "pub async fn load_active_runtime_clients_for_issuer_host_guarded(",
    ] {
        assert!(
            !runtime_clients_source.contains(signature),
            "runtime client snapshots must not expose `{signature}` as a production DB-bypass API"
        );
    }
    assert!(
        runtime_clients_source
            .contains("pub async fn load_runtime_client_projection_from_database_guarded(")
            && runtime_clients_source.contains("pub(crate) struct RuntimeClientProjectionCommit")
            && runtime_clients_source.contains("pub(crate) fn into_commit(self)")
            && !runtime_clients_source
                .contains("pub async fn replace_runtime_clients_from_database_guarded("),
        "runtime clients must expose only a guarded database load facade; authority-owned code performs the commit"
    );

    let registry_source = server_source(
        "src/client_registry/registry_store.rs",
        "client registry projection source",
    )?;
    for signature in [
        "pub fn try_register(",
        "pub fn try_register_client_secret_credentials(",
        "pub fn try_clear_client_secret_credentials(",
        "pub fn try_replace_all_clients(",
        "pub fn try_replace_all_clients_with_fingerprint(",
        "pub fn try_update(",
        "pub fn try_delete(",
    ] {
        let index = registry_source.find(signature).test_context(&format!(
            "client registry must retain test helper signature `{signature}`"
        ))?;
        let prefix = &registry_source[..index];
        let last_lines = prefix.lines().rev().take(4).collect::<Vec<_>>().join("\n");
        assert!(
            last_lines.contains("#[cfg(test)]"),
            "`{signature}` must be test-gated and must not expose a production DB-bypass mutation API"
        );
    }
    let client_types_source = server_source(
        "src/client_registry/client_types.rs",
        "client registry client type source",
    )?;
    let to_par_client_index = client_types_source
        .find("pub fn to_par_client(")
        .test_context("client registry must retain test-only PAR conversion helper")?;
    let to_par_client_prefix = &client_types_source[..to_par_client_index];
    let to_par_client_last_lines = to_par_client_prefix
        .lines()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        to_par_client_last_lines.contains("#[cfg(test)]"),
        "`RegisteredClient::to_par_client` must stay test-gated and must not expose a production PAR projection adapter"
    );

    let par_module_source = server_source("src/par.rs", "PAR module source")?;
    assert!(
        par_module_source.contains("#[cfg(test)]\nmod client_registry;"),
        "PAR process-local client projection module must be test-gated"
    );
    let par_client_registry_source = server_source(
        "src/par/client_registry.rs",
        "PAR runtime projection source",
    )?;
    assert!(
        !par_client_registry_source.contains("#![cfg(test)]"),
        "PAR process-local client projection implementation should rely on the parent module gate"
    );

    let par_endpoint_source = server_source("src/par/endpoint.rs", "PAR endpoint source")?;
    for signature in [
        "fn register_client(",
        "fn register_client_secret_credentials(",
        "fn clear_client_secret_credentials(",
        "fn replace_clients(",
        "fn deregister_client(",
    ] {
        let index = par_endpoint_source.find(signature).test_context(&format!(
            "PAR endpoint must retain test helper signature `{signature}`"
        ))?;
        let prefix = &par_endpoint_source[..index];
        let last_lines = prefix.lines().rev().take(4).collect::<Vec<_>>().join("\n");
        assert!(
            last_lines.contains("#[cfg(test)]"),
            "`{signature}` must be test-gated and must not expose a production DB-bypass projection API"
        );
    }

    let par_http_source = server_source("src/web/par_endpoint.rs", "PAR HTTP handler source")?;
    assert!(
        !par_http_source.contains(".try_register_client(")
            && !par_http_source.contains(".register_client("),
        "PAR HTTP handler must not copy DB-managed clients into a process-local PAR projection"
    );

    Ok(())
}

#[test]
fn committed_runtime_client_sync_failures_request_restart_instead_of_serving_stale_projection(
) -> TestResult {
    for (path, description) in [
        (
            "src/web/dcr_runtime.rs",
            "DCR runtime synchronization source",
        ),
        (
            "src/web/management/runtime_clients/snapshot.rs",
            "management runtime client synchronization source",
        ),
    ] {
        let source = server_source(path, description)?;
        assert!(
            source.contains("database_committed = true"),
            "{path} must log that the database mutation was already committed"
        );
        assert!(
            source.contains("try_synchronize_client_projection_from_database("),
            "{path} must use the authority-owned runtime-client projection synchronization coordinator"
        );
        assert!(
            source.contains("requesting graceful restart before serving stale client state"),
            "{path} must request a graceful restart after a committed runtime-client synchronization failure"
        );
        assert!(
            source.contains("RuntimeRestartRequest::runtime_client_projection_sync_failure"),
            "{path} must record a typed runtime restart request"
        );
        assert!(
            !source.contains("keeps its previous runtime projection"),
            "{path} must not continue serving a previous runtime projection after a committed mutation"
        );
    }
    Ok(())
}

#[test]
fn committed_runtime_critical_management_mutations_request_restart_for_current_issuer() -> TestResult
{
    let guard_source = server_source(
        "src/web/management/runtime_restart.rs",
        "runtime critical mutation guard source",
    )?;
    assert!(
        guard_source.contains("database_committed = true")
            && guard_source
                .contains("runtime-critical management mutation committed for current issuer")
            && guard_source
                .contains("requesting graceful restart before serving the new runtime state")
            && guard_source.contains("RuntimeRestartRequest::runtime_critical_mutation")
            && guard_source.contains("request_restart_if_current_issuer_was_mutated")
            && !guard_source.contains("terminate_if_current_environment_changed")
            && !guard_source.contains("load_environment_issuer_host"),
        "runtime-critical committed management mutations must request restart using the pre-commit issuer scope instead of a post-commit lookup"
    );

    for (path, mutation_marker) in [
        (
            "src/web/management/configuration_versions/mutation/activate.rs",
            "configuration_version_activate",
        ),
        (
            "src/web/management/configuration_versions/policy.rs",
            "configuration_policy_patch",
        ),
        (
            "src/web/management/runtime_keys/create.rs",
            "runtime_key_create_active",
        ),
        (
            "src/web/management/runtime_keys/lifecycle.rs",
            "runtime_key_activate_next",
        ),
        (
            "src/web/management/runtime_keys/lifecycle.rs",
            "runtime_key_revoke",
        ),
        (
            "src/web/management/dcr_bearer_tokens/handlers/set.rs",
            "dcr_bearer_token_set",
        ),
        (
            "src/web/management/dcr_bearer_tokens/handlers/delete.rs",
            "dcr_bearer_token_delete",
        ),
    ] {
        let source = server_source(path, "runtime-critical management mutation handler")?;
        assert!(
            source.contains("RuntimeCriticalMutationGuard::from_state(&state)")
                && source.contains("request_restart_if_current_issuer_was_mutated(")
                && source.contains(mutation_marker),
            "{path} must invoke the committed runtime-critical mutation guard for {mutation_marker}"
        );
    }

    for path in [
        "src/web/management/dcr_bearer_tokens/handlers/set.rs",
        "src/web/management/dcr_bearer_tokens/handlers/delete.rs",
    ] {
        let source = server_source(path, "DCR bearer token mutation handler")?;
        assert!(
            source.contains("require_environment_lifecycle_scope_with_issuer_by_ids")
                && source.contains("let issuer_host = scoped_issuer.issuer_host")
                && source.contains("&issuer_host")
                && !source.contains("terminate_if_current_environment_changed"),
            "{path} must use the issuer host captured with the authorized environment scope"
        );
    }

    Ok(())
}

#[test]
fn management_user_runtime_commands_have_strict_execution_state_invariants() -> TestResult {
    let schema = repository_file("db/schema.sql", "database schema")?;
    for marker in [
        "CREATE TYPE aegaeon.management_runtime_command_status AS ENUM",
        "'executing'",
        "'failed_terminal'",
        "'failed_unconfirmed'",
        "status aegaeon.management_runtime_command_status DEFAULT 'requested'::aegaeon.management_runtime_command_status NOT NULL",
        "execution_started_at timestamp with time zone",
        "CREATE UNIQUE INDEX tenants_id_team_id_unique",
        "CREATE UNIQUE INDEX environments_id_tenant_id_unique",
        "CONSTRAINT management_user_runtime_commands_tenant_team_fkey",
        "CONSTRAINT management_user_runtime_commands_environment_tenant_fkey",
        "CONSTRAINT management_user_runtime_commands_end_user_environment_fkey",
        "CONSTRAINT management_user_runtime_commands_actor_team_membership_fkey",
        "status = 'requested'",
        "status = 'executing'",
        "status <> ALL (ARRAY['requested'::aegaeon.management_runtime_command_status, 'executing'::aegaeon.management_runtime_command_status])",
        "CREATE INDEX management_user_runtime_commands_active_execution",
        "WHERE (status = ANY (ARRAY['requested'::aegaeon.management_runtime_command_status, 'executing'::aegaeon.management_runtime_command_status]))",
    ] {
        assert!(
            schema.contains(marker),
            "management runtime command schema must include marker `{marker}`"
        );
    }
    for retired_marker in [
        "failed_retryable",
        "CONSTRAINT management_user_runtime_commands_status_valid",
    ] {
        assert!(
            !schema.contains(retired_marker),
            "management runtime command schema must not retain retired marker `{retired_marker}`"
        );
    }

    let audit_source = server_source(
        "src/web/management/user_support/audit.rs",
        "user audit support",
    )?;
    assert!(
        audit_source.contains("enum EndUserRuntimeCommandStatus")
            && audit_source.contains("Self::Executing => \"executing\"")
            && audit_source.contains("Self::FailedTerminal => \"failed_terminal\"")
            && audit_source.contains("Self::FailedUnconfirmed => \"failed_unconfirmed\"")
            && audit_source.contains("mark_user_management_runtime_command_executing")
            && audit_source.contains("AND status = 'requested'")
            && audit_source.contains("AND status = 'executing'")
            && !audit_source.contains("failed_retryable"),
        "Rust command state writer must use typed requested/executing/terminal transitions and avoid retryable wording"
    );

    let reconciler_source = server_source(
        "src/management/runtime_commands.rs",
        "management runtime command reconciler",
    )?;
    for marker in [
        "FOR UPDATE OF command SKIP LOCKED",
        "'failed_unconfirmed'",
        "'requested'::aegaeon.management_runtime_command_status",
        "'executing'::aegaeon.management_runtime_command_status",
        "management.user.runtimeCommand.reconciledStale.v1",
        "SELECT count(*)::bigint FROM audit",
    ] {
        assert!(
            reconciler_source.contains(marker),
            "management runtime command reconciler must include marker `{marker}`"
        );
    }
    Ok(())
}

#[test]
fn management_user_runtime_command_payloads_use_inventory_identifiers() -> TestResult {
    for (path, expected_markers) in [
        (
            "src/web/management/user_inventory/sessions/workflows/invalidate.rs",
            &["\"userId\": user_id.to_string()"][..],
        ),
        (
            "src/web/management/user_inventory/refresh_tokens/workflows/revoke_all.rs",
            &["\"userId\": user_id.to_string()"][..],
        ),
        (
            "src/web/management/user_inventory/sessions/workflows/revoke.rs",
            &[
                "\"userId\": user_id.to_string()",
                "\"sessionId\": session_inventory_id",
            ][..],
        ),
        (
            "src/web/management/user_inventory/refresh_tokens/workflows/revoke_one.rs",
            &[
                "\"userId\": user_id.to_string()",
                "\"refreshTokenId\": refresh_token_id",
            ][..],
        ),
        (
            "src/web/management/user_inventory/grants/workflows/revoke.rs",
            &[
                "\"userId\": user_id.to_string()",
                "\"grantId\": grant_id",
                "\"source\": target.source",
            ][..],
        ),
    ] {
        let source = server_source(path, "management user runtime workflow source")?;
        let payload = section_between(
            &source,
            "let command_payload = serde_json::json!({",
            "});\n    let mut tx",
        )
        .test_context(&format!("{path} command payload should be readable"))?;
        for marker in expected_markers {
            assert!(
                payload.contains(marker),
                "{path} command payload must include inventory marker `{marker}`"
            );
        }
        for forbidden_marker in [
            "\"subject\"",
            "raw_session_id",
            "raw_refresh_token",
            "raw_token_id",
        ] {
            assert!(
                !payload.contains(forbidden_marker),
                "{path} command payload must not persist runtime lookup marker `{forbidden_marker}`"
            );
        }
    }
    Ok(())
}

#[test]
fn federation_postgres_sql_uses_schema_managed_table_names() -> TestResult {
    let schema = repository_file("db/schema.sql", "database schema")?;
    for table in [
        "CREATE TABLE aegaeon.federation_trust_anchors",
        "CREATE TABLE aegaeon.federation_entity_cache",
        "CREATE TABLE aegaeon.federation_trust_chains",
    ] {
        assert!(
            schema.contains(table),
            "federation schema must define source-managed table `{table}`"
        );
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = rust_sources(&[manifest_dir.join("src"), manifest_dir.join("tests")])?;
    for path in sources {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        for retired_name in [
            ["aegaeon", "federation", "entity_cache"],
            ["aegaeon", "federation", "trust_anchors"],
            ["aegaeon", "federation", "trust_chains"],
        ]
        .map(|parts| parts.join("."))
        {
            assert!(
                !source.contains(&retired_name),
                "{} must not reference retired PostgreSQL table name `{retired_name}`",
                path.display()
            );
        }
    }

    Ok(())
}

#[test]
fn legacy_signing_key_schema_is_not_in_final_database_schema() -> TestResult {
    let schema = repository_file("db/schema.sql", "database schema")?;
    for marker in [
        "signing_key_status",
        "CREATE TABLE aegaeon.signing_keys",
        "CREATE TABLE aegaeon.environment_revoked_signing_keys",
    ] {
        assert!(
            !schema.contains(marker),
            "legacy signing key schema marker must not remain in final schema: {marker}"
        );
    }
    assert!(
        schema.contains("CREATE TABLE aegaeon.runtime_keys"),
        "runtime_keys must remain the sole runtime key material inventory"
    );

    Ok(())
}
