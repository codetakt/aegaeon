use serde_json::{json, Value};

use super::*;
use crate::runtime_configuration::RuntimeConfigurationError;

fn valid_policy() -> Result<Value, String> {
    serde_json::from_str(
        r#"{
            "pkceRequired": true,
            "dcrEnabled": false,
            "dcrEverparseRuntimeEnabled": false,
            "requireStateParameter": true,
            "strictAuthorizeRedirect": true,
            "requireClientAuthToken": true,
            "requireClientAuthPar": true,
            "requireClientAuthIntrospection": true,
            "requireClientAuthRevocation": true,
            "senderConstraint": "dpop",
            "requireScopeSubset": true,
            "requireAudienceMatch": true,
            "retainRefreshChain": true,
            "enforceRefreshSenderBinding": true,
            "dpopStrict": true,
            "dpopIatWindowSeconds": 300,
            "dpopRequireNonce": true,
            "dpopNonceTtlSeconds": 300,
            "requirePushedAuthorizationRequests": false,
            "parExpiresInSeconds": 90,
            "deviceCodeTtlSeconds": 600,
            "deviceCodePollIntervalSeconds": 5,
            "activationTokenDefaultTtlSeconds": 86400,
            "passwordResetTokenDefaultTtlSeconds": 3600,
            "recoveryTokenMaxTtlSeconds": 604800,
            "clientSecretDefaultExpirationDays": 90,
            "clientSecretMaxExpirationDays": 365,
            "privateKeyJwtEnabled": false,
            "clientJwtAllowedAlgs": ["RS256"],
            "clientJwtRequireKid": false,
            "jwtLeewaySeconds": 60,
            "pkjwtJtiWindowSeconds": 300,
            "joseHeaderMaxLen": 4096,
            "jwksAllowKidReuse": false,
            "jwksCircuitOpenFails": 3,
            "jwksCircuitResetSeconds": 30,
            "jwksCacheTtlSeconds": 300,
            "jwksCacheGcIntervalSeconds": 600,
            "jwksLocalCacheMaxEntries": 4096,
            "jwksHttpTimeoutSeconds": 5,
            "jwksRefreshSkewSeconds": 10,
            "jwksSharedStateMaxAgeSeconds": 86400,
            "jwksMaxBodyBytes": 65536,
            "jwksHttpRetries": 2,
            "jwtBearerAllowClientSubject": false,
            "jwtBearerJtiWindowSeconds": 300,
            "requestObjectJtiTtlSeconds": 600,
            "requestObjectEverparseRuntimeEnabled": false,
            "jwtAccessTokensEnabled": false,
            "jwtIntrospectionEnabled": false,
            "jwtIntrospectionExpSeconds": 60,
            "authorizationDetailsTypesSupported": [],
            "acrValuesSupported": [],
            "defaultAcr": null,
            "localPasswordAcr": null,
            "dcrRequirePkceForPublic": false,
            "dcrRequirePkceForConfidential": false,
            "dcrRequireSenderConstrained": false,
            "dcrAllowedSenderMethods": ["dpop"],
            "ssaLeewaySeconds": 120,
            "oidcEnabled": false,
            "oidcEnableDiscovery": true,
            "oidcEnableUserinfo": true,
            "oidcEnableLogout": false,
            "oidcEnableBackchannelLogout": false,
            "oidcLogoutSessionTtlSeconds": 600,
            "oidcBackchannelLogoutTimeoutSeconds": 2,
            "oidcRequireNonce": false,
            "mtlsEnabled": false,
            "mtlsAliasParEnabled": false,
            "federationOutboundAllowedDomains": [],
            "upstreamOutboundAllowedDomains": [],
            "federationEntityCacheTtlSeconds": 1800,
            "federationTrustChainCacheTtlSeconds": 3600,
            "federationCacheMaxEntries": 1000,
            "cryptoProfile": "verified",
            "allowedSigningAlgorithms": ["RS256", "EdDSA"],
            "allowedGrantTypes": ["authorization_code", "refresh_token"],
            "accessTokenTimeToLiveSeconds": 3600,
            "idTokenTimeToLiveSeconds": 3600,
            "refreshTokenTimeToLiveSeconds": 2592000,
            "authorizationCodeTimeToLiveSeconds": 300,
            "authSessionTtlSeconds": 28800,
            "authMaxSessions": 10000,
            "stepupChallengeTtlSeconds": 300,
            "upstreamAuthTtlSeconds": 300,
            "upstreamLogoutRelayTtlSeconds": 300,
            "upstreamDiscoveryCacheTtlSeconds": 300,
            "upstreamDiscoveryCacheMaxEntries": 4096,
            "upstreamJwksCacheTtlSeconds": 300,
            "upstreamJwksCacheMaxEntries": 4096,
            "cleanupIntervalSeconds": 60,
            "runtimeConfigMonitorIntervalSeconds": 30
        }"#,
    )
    .map_err(|err| format!("valid runtime policy fixture: {err}"))
}

fn valid_document() -> Result<Value, String> {
    Ok(json!({
        "schemaVersion": 1,
        "issuerHost": "auth.example.com",
        "issuerUrl": "https://auth.example.com",
        "policy": valid_policy()?,
        "scopeAllowlist": ["openid", "profile"],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true
        }
    }))
}

#[test]
fn parses_valid_runtime_configuration_document() -> Result<(), String> {
    let state = parse_runtime_configuration_document(
        &valid_document()?,
        "auth.example.com",
        "https://auth.example.com",
    )
    .map_err(|err| format!("valid runtime config: {err}"))?;

    assert!(state.policy.pkce_required);
    assert_eq!(
        state.policy.jose_header_max_len,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN as u32
    );
    assert_eq!(state.scope_allowlist, vec!["openid", "profile"]);
    assert_eq!(state.key_store.key_store_type, "databaseEncrypted");
    Ok(())
}

#[test]
fn rejects_unknown_top_level_runtime_configuration_field() -> Result<(), String> {
    let mut document = valid_document()?;
    document["unexpected"] = json!(true);

    let result = parse_runtime_configuration_document(
        &document,
        "auth.example.com",
        "https://auth.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocumentShape(_))
    ));
    Ok(())
}

#[test]
fn rejects_unknown_runtime_key_store_field() -> Result<(), String> {
    let mut document = valid_document()?;
    document["keyStore"]["typo"] = json!(true);

    let result = parse_runtime_configuration_document(
        &document,
        "auth.example.com",
        "https://auth.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocumentShape(_))
    ));
    Ok(())
}

#[test]
fn rejects_issuer_mismatch() -> Result<(), String> {
    let result = parse_runtime_configuration_document(
        &valid_document()?,
        "other.example.com",
        "https://other.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocument(reason))
            if reason.contains("issuerHost")
    ));
    Ok(())
}

#[test]
fn rejects_retired_federation_op_policy_fields() -> Result<(), String> {
    for (field, value) in [
        ("federationOpEnabled", json!(false)),
        ("federationEntityExpSeconds", json!(86400)),
        (
            "federationAuthorityHints",
            json!(["https://auth.example.com"]),
        ),
    ] {
        let mut document = valid_document()?;
        document["policy"][field] = value;

        let result = parse_runtime_configuration_document(
            &document,
            "auth.example.com",
            "https://auth.example.com",
        );

        assert!(matches!(
            result,
            Err(RuntimeConfigurationError::InvalidDocumentShape(err))
                if err.to_string().contains(field)
        ));
    }
    Ok(())
}

#[test]
fn rejects_policy_missing_required_runtime_field() -> Result<(), String> {
    let mut document = valid_document()?;
    let policy = document
        .get_mut("policy")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| "valid document policy object".to_string())?;
    policy.remove("cleanupIntervalSeconds");

    let result = parse_runtime_configuration_document(
        &document,
        "auth.example.com",
        "https://auth.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocumentShape(err))
            if err.to_string().contains("cleanupIntervalSeconds")
    ));
    Ok(())
}

#[test]
fn rejects_sensitive_key_store_public_config() -> Result<(), String> {
    let mut document = valid_document()?;
    document["keyStore"]["configuration"] = json!({"apiKey": "redacted"});

    let result = parse_runtime_configuration_document(
        &document,
        "auth.example.com",
        "https://auth.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocument(reason))
            if reason.contains("secret material")
    ));
    Ok(())
}

#[test]
fn rejects_non_empty_database_encrypted_key_store_configuration() -> Result<(), String> {
    let mut document = valid_document()?;
    document["keyStore"]["configuration"] = json!({"rotationPolicy": "manual"});

    let result = parse_runtime_configuration_document(
        &document,
        "auth.example.com",
        "https://auth.example.com",
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigurationError::InvalidDocument(reason))
            if reason.contains("empty for databaseEncrypted")
    ));
    Ok(())
}
