use super::*;
use crate::authcode::token::AccessTokenAudiencePolicy;
use std::{sync::Arc, time::Duration};

const CLIENT: &str = "device-audience-client";
const SUBJECT: &str = "device-audience-user";
const TARGET: &str = "https://resource.example/api";
const USERINFO: &str = "https://issuer.example/userinfo";

fn stores(
    redis: bool,
    ttl: u64,
    interval: u64,
) -> Result<(DeviceCodeStore, DeviceCodeStore), String> {
    if !redis {
        let store =
            DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(ttl, interval);
        return Ok((store.clone(), store));
    }
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")
        .map_err(|_| "AEGAEON_TEST_REDIS_URL is required".to_string())?;
    let prefix: Arc<str> = format!("device-audience:v2:{{{}}}", uuid::Uuid::new_v4()).into();
    let make = || -> Result<DeviceCodeStore, String> {
        Ok(DeviceCodeStore {
            backend: DeviceCodeStoreBackend::Redis(
                RedisDeviceCodeStoreBackend::new_with_prefix(&url, Arc::clone(&prefix))
                    .map_err(|_| "owned Redis fixture is unavailable".to_string())?,
            ),
            ttl: Duration::from_secs(ttl),
            default_interval_secs: interval,
        })
    };
    Ok((make()?, make()?))
}

fn create(
    store: &DeviceCodeStore,
    client: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<DeviceAuthorizationResponse, String> {
    store
        .try_create_with_resource(
            client,
            scope,
            resource,
            None,
            "https://issuer.example/device",
        )
        .ok_or_else(|| "device grant allocation failed".to_string())
}

fn approved(
    store: &DeviceCodeStore,
    client: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<DeviceAuthorizationResponse, String> {
    let grant = create(store, client, scope, resource)?;
    assert!(store.try_approve(&grant.user_code, SUBJECT)?);
    Ok(grant)
}

async fn poll(
    store: &DeviceCodeStore,
    grant: &DeviceAuthorizationResponse,
    client: &str,
    requested: Option<&str>,
    policy: AccessTokenAudiencePolicy,
    asynchronous: bool,
) -> Result<DevicePollResult, String> {
    if asynchronous {
        store
            .try_poll_for_token_async(
                grant.device_code.clone(),
                client.into(),
                None,
                requested.map(str::to_owned),
                policy,
            )
            .await
    } else {
        store.try_poll_for_token(&grant.device_code, client, None, requested, &policy)
    }
}

fn assert_approved(
    result: DevicePollResult,
    client: &str,
    expected_scope: Option<&str>,
    expected_resource: Option<&str>,
) -> DeviceTestResult {
    let DevicePollResult::Approved {
        user_id,
        scope,
        resource,
        client_id,
    } = result
    else {
        return Err(format!("expected an approved device grant, got {result:?}"));
    };
    assert_eq!(user_id, SUBJECT);
    assert_eq!(client_id, client);
    assert_eq!(scope.as_deref(), expected_scope);
    assert_eq!(resource.as_deref(), expected_resource);
    Ok(())
}

async fn admission_scenarios(redis: bool) -> DeviceTestResult {
    for asynchronous in [false, true] {
        let (writer, reader) = stores(redis, 60, 0)?;
        for scope in [None, Some("read"), Some("openid")] {
            let grant = approved(&writer, CLIENT, scope, None)?;
            let before = writer.try_active_count()?;
            assert!(matches!(
                poll(
                    &reader,
                    &grant,
                    CLIENT,
                    None,
                    AccessTokenAudiencePolicy::new(true, None),
                    asynchronous
                )
                .await?,
                DevicePollResult::InvalidTarget
            ));
            assert_eq!(
                writer.try_active_count()?,
                before,
                "rejection must retain the code"
            );
            assert_approved(
                poll(
                    &reader,
                    &grant,
                    CLIENT,
                    None,
                    AccessTokenAudiencePolicy::new(false, None),
                    asynchronous,
                )
                .await?,
                CLIENT,
                scope,
                None,
            )?;
            assert!(matches!(
                poll(
                    &writer,
                    &grant,
                    CLIENT,
                    None,
                    AccessTokenAudiencePolicy::new(false, None),
                    asynchronous
                )
                .await?,
                DevicePollResult::ExpiredToken
            ));
        }

        // A URI client identifier is still a valid explicitly captured resource.
        for client in [CLIENT, TARGET] {
            for requested in [None, Some(TARGET)] {
                let grant = approved(&writer, client, Some("read"), Some(TARGET))?;
                assert!(matches!(
                    poll(
                        &reader,
                        &grant,
                        client,
                        Some("https://resource.example/other"),
                        AccessTokenAudiencePolicy::new(true, None),
                        asynchronous
                    )
                    .await?,
                    DevicePollResult::InvalidTarget
                ));
                assert_approved(
                    poll(
                        &reader,
                        &grant,
                        client,
                        requested,
                        AccessTokenAudiencePolicy::new(true, None),
                        asynchronous,
                    )
                    .await?,
                    client,
                    Some("read"),
                    Some(TARGET),
                )?;
            }
        }
        let grant = approved(&writer, TARGET, Some("read"), None)?;
        assert!(matches!(
            poll(
                &reader,
                &grant,
                TARGET,
                Some(TARGET),
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::InvalidTarget
        ));
        assert_approved(
            poll(
                &reader,
                &grant,
                TARGET,
                None,
                AccessTokenAudiencePolicy::new(false, None),
                asynchronous,
            )
            .await?,
            TARGET,
            Some("read"),
            None,
        )?;

        for scope in ["openid", "openid profile"] {
            let grant = approved(&writer, CLIENT, Some(scope), None)?;
            assert_approved(
                poll(
                    &reader,
                    &grant,
                    CLIENT,
                    None,
                    AccessTokenAudiencePolicy::new(true, Some(USERINFO.into())),
                    asynchronous,
                )
                .await?,
                CLIENT,
                Some(scope),
                None,
            )?;
        }
        for scope in [
            None,
            Some("read"),
            Some("OpenId"),
            Some("openidish"),
            Some(""),
            Some("openid  profile"),
            Some("openid\tprofile"),
            Some("openid openid"),
            Some(" openid"),
            Some("openid "),
            Some("openid\u{a0}profile"),
        ] {
            let grant = approved(&writer, CLIENT, scope, None)?;
            let before = writer.try_active_count()?;
            assert!(
                matches!(
                    poll(
                        &reader,
                        &grant,
                        CLIENT,
                        None,
                        AccessTokenAudiencePolicy::new(true, Some(USERINFO.into())),
                        asynchronous
                    )
                    .await?,
                    DevicePollResult::InvalidTarget
                ),
                "scope {scope:?} must not acquire the OIDC default"
            );
            assert_eq!(writer.try_active_count()?, before);
        }
    }
    Ok(())
}

async fn state_scenarios(redis: bool) -> DeviceTestResult {
    for asynchronous in [false, true] {
        let (writer, reader) = stores(redis, 60, 5)?;
        let pending = create(&writer, CLIENT, Some("read"), None)?;
        assert!(matches!(
            poll(
                &reader,
                &pending,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::AuthorizationPending
        ));
        assert!(writer.try_approve(&pending.user_code, SUBJECT)?);
        assert!(matches!(
            poll(
                &reader,
                &pending,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::SlowDown
        ));
        let invalid_target = approved(&writer, CLIENT, Some("read"), None)?;
        assert!(matches!(
            poll(
                &reader,
                &invalid_target,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::InvalidTarget
        ));
        assert!(matches!(
            poll(
                &reader,
                &invalid_target,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(false, None),
                asynchronous
            )
            .await?,
            DevicePollResult::SlowDown
        ));
        let denied = create(&writer, CLIENT, Some("read"), None)?;
        assert!(writer.try_deny(&denied.user_code)?);
        assert!(matches!(
            poll(
                &reader,
                &denied,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::AccessDenied
        ));
        let (expiring, expired_reader) = stores(redis, 1, 0)?;
        let expired = approved(&expiring, CLIENT, Some("read"), None)?;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(matches!(
            poll(
                &expired_reader,
                &expired,
                CLIENT,
                None,
                AccessTokenAudiencePolicy::new(true, None),
                asynchronous
            )
            .await?,
            DevicePollResult::ExpiredToken
        ));
    }
    Ok(())
}

#[tokio::test]
async fn device_token_audience_memory_preserves_approved_resource_authority() -> DeviceTestResult {
    admission_scenarios(false).await
}

#[tokio::test]
#[ignore = "requires owned AEGAEON_TEST_REDIS_URL"]
async fn device_token_audience_redis_preserves_approved_resource_authority() -> DeviceTestResult {
    admission_scenarios(true).await
}

#[tokio::test]
async fn device_token_audience_memory_preserves_pending_terminal_and_backoff_states(
) -> DeviceTestResult {
    state_scenarios(false).await
}

#[tokio::test]
#[ignore = "requires owned AEGAEON_TEST_REDIS_URL"]
async fn device_token_audience_redis_preserves_pending_terminal_and_backoff_states(
) -> DeviceTestResult {
    state_scenarios(true).await
}
