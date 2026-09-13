//! Deterministic publication-boundary controls for legacy same-audience exchange.
use crate::authcode::store::{validate_exchange_subject, ExchangeCommitError, TokenStore};
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, RefreshToken, RefreshTokenInput,
    SenderBinding,
};
use crate::web::{persist_access_with_meta_async, AccessTokenPersistence};
use std::time::Duration;

fn fixture(
    store: &TokenStore,
    has_parent: bool,
) -> Result<(RefreshToken, BearerTokenMeta), String> {
    let client = "legacy-exchange-client";
    let user = "legacy-exchange-user";
    let parent = RefreshToken::with_ttl(
        RefreshTokenInput {
            scope: Some("read write".into()),
            ..RefreshTokenInput::new(client.into(), user.into())
        },
        600,
    );
    let access = AccessToken::new(client.into(), user.into(), Some("read write".into()), 300);
    let subject = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: client.into(),
        user_id: user.into(),
        granted_scopes: vec!["read".into(), "write".into()],
        audience: client.into(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(access.expires_in),
        refresh_parent: has_parent.then(|| parent.token.clone()),
    });
    assert!(parent.exchange_grant.is_none());
    assert!(subject.exchange_grant.is_none());
    store.store_issued_grant(access, has_parent.then(|| parent.clone()), subject.clone())?;
    let validated_access = store
        .try_verify_access_token(&subject.token_id)?
        .ok_or("subject must be valid before the publication race")?;
    let validated_subject = store
        .try_get_bearer_meta(&subject.token_id)?
        .ok_or("subject metadata must exist before the publication race")?;
    validate_exchange_subject(&validated_access, &validated_subject).map_err(str::to_owned)?;
    Ok((parent, validated_subject))
}

async fn commit_legacy_output(
    store: &TokenStore,
    subject: &BearerTokenMeta,
    retain: bool,
    strengthen: bool,
) -> (String, Result<(), ExchangeCommitError>) {
    let output = AccessToken::new(
        subject.client_id.clone(),
        subject.user_id.clone(),
        Some("read".into()),
        120,
    );
    let token = output.token.clone();
    let result = persist_access_with_meta_async(
        store,
        output,
        AccessTokenPersistence {
            application_grant: None,
            audience: subject.audience.clone(),
            refresh_parent: retain.then(|| subject.refresh_parent.clone()).flatten(),
            sender_binding: if strengthen {
                Some(SenderBinding::DPoP {
                    jkt: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".into(),
                })
            } else {
                subject.sender_binding.clone()
            },
            authorization_details: subject.authorization_details.clone(),
            exchange_grant: subject.exchange_grant.clone(),
            // Every exchange binds the validated subject, including historical grants.
            exchange_subject: subject.clone(),
            auth_time_epoch_secs: subject.auth_time_epoch_secs,
            acr: subject.acr.clone(),
        },
    )
    .await;
    (token, result)
}

#[tokio::test]
async fn token_exchange_legacy_live_subject_commit_control() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let (_, subject) = fixture(&store, true)?;
    let (output, result) = commit_legacy_output(&store, &subject, true, false).await;
    result?;
    assert!(store.try_verify_access_token(&output)?.is_some());
    Ok(())
}

#[tokio::test]
async fn token_exchange_legacy_subject_revoked_before_commit_is_rejected() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let (parent, validated_subject) = fixture(&store, true)?;
    // Fix the interleaving without threads or sleeps: validation completes,
    // only its subject is revoked, then publication uses the saved validation.
    store.try_revoke_token_for_client(
        &validated_subject.token_id,
        Some(&validated_subject.client_id),
    )?;
    assert!(store
        .try_verify_access_token(&validated_subject.token_id)?
        .is_none());
    let live_parent = store
        .try_get_refresh_token(&parent.token)?
        .ok_or("subject revocation must leave the refresh parent live")?;
    assert!(!live_parent.rotated);
    assert!(!store.try_is_refresh_revoked(&parent.token)?);

    let (output, result) = commit_legacy_output(&store, &validated_subject, true, false).await;
    assert!(
        result.is_err(),
        "exchange must reject a revoked subject despite its still-live refresh parent"
    );
    assert!(store.try_verify_access_token(&output)?.is_none());
    Ok(())
}

async fn optional_lineage_cases(store: &TokenStore) -> Result<(), String> {
    for has_parent in [false, true] {
        for retain in [false, true] {
            for strengthen in [false, true] {
                let (_, subject) = fixture(store, has_parent)?;
                let (id, result) = commit_legacy_output(store, &subject, retain, strengthen).await;
                result?;
                let output = store
                    .try_verify_access_token(&id)?
                    .ok_or("legacy output missing")?;
                assert_eq!(output.cnf.is_some(), strengthen);
                assert_eq!(
                    output.token_type,
                    if strengthen { "DPoP" } else { "Bearer" }
                );
                let saved = store.try_get_bearer_meta(&id)?.ok_or("output metadata")?;
                assert_eq!(
                    saved.refresh_parent,
                    if retain {
                        subject.refresh_parent.clone()
                    } else {
                        None
                    }
                );
                // The original subject remains usable after successful exchange.
                assert!(store.try_verify_access_token(&subject.token_id)?.is_some());
                store.try_revoke_token_for_client(&subject.token_id, Some(&subject.client_id))?;
                let (rejected, result) =
                    commit_legacy_output(store, &subject, retain, strengthen).await;
                let error = result.expect_err("revoked subject must not publish");
                assert!(matches!(error, ExchangeCommitError::Rejected(_)));
                assert_eq!(
                    super::super::response::token_exchange_commit_error(error).status(),
                    axum::http::StatusCode::BAD_REQUEST
                );
                assert!(store.try_verify_access_token(&rejected)?.is_none());
            }
        }
    }
    // Historical parent references may be missing when retention is disabled.
    let (_, mut subject) = fixture(store, false)?;
    subject.refresh_parent = Some("historical-missing-parent".into());
    store.try_replace_bearer_meta_record(subject.clone())?;
    let (_, result) = commit_legacy_output(store, &subject, false, true).await;
    result?;
    let (id, result) = commit_legacy_output(store, &subject, true, false).await;
    assert!(matches!(result, Err(ExchangeCommitError::Rejected(_))));
    assert!(store.try_verify_access_token(&id)?.is_none());
    Ok(())
}

#[tokio::test]
async fn token_exchange_legacy_optional_lineage_and_sender_strengthening() -> Result<(), String> {
    optional_lineage_cases(&TokenStore::new_process_local_for_tests()).await
}

#[tokio::test]
#[ignore = "requires private Redis"]
async fn redis_token_exchange_legacy_optional_lineage_and_sender_strengthening(
) -> Result<(), String> {
    let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
        "legacy-exchange-{}",
        uuid::Uuid::new_v4()
    ));
    let store = TokenStore::try_from_shared_store_env(&namespace).map_err(|e| e.to_string())?;
    optional_lineage_cases(&store).await
}
