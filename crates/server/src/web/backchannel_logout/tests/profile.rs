use super::*;

#[tokio::test]
async fn logout_profile_local_sync_and_async_signatures() -> TestResult {
    let cfg = config(local_key()?);
    for sub in [None, Some("subject")] {
        let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let sync = build_backchannel_logout_token(&cfg, "client", "session", sub, "logout-event")
            .map_err(anyhow::Error::msg)?;
        let asynchronous =
            build_backchannel_logout_token_async(&cfg, "client", "session", sub, "logout-event")
                .await
                .map_err(anyhow::Error::msg)?;
        let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        for token in [sync, asynchronous] {
            let claims = verify_logout(&cfg.signing_key, &token, "client", sub)?;
            let iat = claims["iat"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("iat"))?;
            assert!((before..=after).contains(&iat));
        }
    }
    Ok(())
}

#[test]
fn logout_profile_numericdate_boundaries_fail_closed() -> TestResult {
    let cfg = config(local_key()?);
    let last_iat = u64::try_from(i64::MAX - 300)?;
    for seconds in [0, 1_700_000_000, last_iat] {
        let time = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| anyhow::anyhow!("fixture time unavailable"))?;
        let claims = build_backchannel_logout_claims_at(
            &cfg,
            "client",
            "session",
            None,
            "logout-event",
            time,
        )
        .map_err(anyhow::Error::msg)?;
        assert_eq!(claims["iat"], seconds);
        assert_eq!(claims["exp"], seconds + 300);
    }
    for seconds in [last_iat + 1, u64::try_from(i64::MAX)?] {
        let time = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| anyhow::anyhow!("fixture time unavailable"))?;
        assert!(build_backchannel_logout_claims_at(
            &cfg,
            "client",
            "session",
            None,
            "logout-event",
            time
        )
        .is_err());
    }
    assert!(logout_token_dates(u64::try_from(i64::MAX)? + 1).is_err());
    assert!(logout_token_dates(u64::MAX).is_err());
    let pre_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_nanos(1))
        .ok_or_else(|| anyhow::anyhow!("pre-epoch fixture unavailable"))?;
    assert!(build_backchannel_logout_claims_at(
        &cfg,
        "client",
        "session",
        None,
        "logout-event",
        pre_epoch
    )
    .is_err());
    Ok(())
}

#[tokio::test]
async fn logout_profile_rejects_blank_identity_claims() -> TestResult {
    let cfg = config(local_key()?);
    for (client, sid, sub, jti) in [
        (" ", "session", None, "logout-event"),
        ("client", " ", None, "logout-event"),
        ("client", "session", Some(" "), "logout-event"),
        ("client", "session", None, " "),
    ] {
        assert!(build_backchannel_logout_token(&cfg, client, sid, sub, jti).is_err());
        assert!(
            build_backchannel_logout_token_async(&cfg, client, sid, sub, jti)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn logout_profile_keeps_id_token_type_and_claims() -> TestResult {
    let key = local_key()?;
    let token = crate::oidc::IdTokenBuilder::try_new(
        ISSUER.to_string(),
        "subject".to_string(),
        "client".to_string(),
    )
    .map_err(anyhow::Error::msg)?
    .nonce("login-nonce".to_string())
    .build();
    let claims = serde_json::to_value(&token.claims)?;
    for signed in [
        key.sign_rs256_jwt(&token.claims)?,
        key.sign_rs256_jwt_async(&token.claims).await?,
    ] {
        assert_eq!(verify_token(&key, &signed, "JWT")?, claims);
    }
    Ok(())
}
