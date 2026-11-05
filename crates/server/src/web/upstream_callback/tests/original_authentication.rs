use super::*;

async fn session(f: &Fixture, claims: Value) -> TestResult<crate::web::auth_session::AuthSession> {
    let exchange = f.signed_exchange(&f.request, claims)?;
    let response =
        persist_bound_upstream_callback(&f.state, &f.request, &exchange, "original-authentication")
            .await;
    f.success_session(response).await
}

fn claims(f: &Fixture, subject: &str, now: u64) -> Value {
    json!({"iss":f.request.issuer,"sub":subject,"aud":"client","iat":now,
        "exp":now+3600,"auth_time":now-30,"nonce":"nonce",
        "acr":"urn:example:two-factors","amr":["pwd","otp"]})
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_organizations_original_authentication_retains_signed_facts_and_exact_owner(
) -> TestResult {
    let f = Fixture::new().await?;
    let now = now_epoch_secs()?;
    let session = session(&f, claims(&f, "private-upstream-subject", now)).await?;
    let evidence = session.original_authentication.ok_or("original evidence")?;
    let owner = f.owner(&f.request, "private-upstream-subject").await?;
    assert_eq!(evidence.user_id, owner.0);
    assert_eq!(evidence.subject, owner.1);
    assert_eq!(evidence.context, f.request.context);
    assert_eq!(evidence.issuer, f.request.issuer);
    assert_eq!(evidence.upstream_client_id, f.request.client_id);
    assert_eq!(evidence.account_link_provenance, owner.2);
    assert_eq!(evidence.account_link_revision, owner.3);
    assert_eq!(evidence.auth_time, i64::try_from(now - 30)?);
    assert_eq!(evidence.acr.as_deref(), Some("urn:example:two-factors"));
    assert_eq!(evidence.amr, Some(vec!["pwd".into(), "otp".into()]));
    assert!(evidence.matches_session(
        &session.user_id,
        i64::try_from(session.auth_time_epoch_secs)?,
        i64::try_from(session.created_at_epoch_secs)?
    ));
    let serialized = serde_json::to_string(&evidence)?;
    assert!(!serialized.contains("private-upstream-subject"));
    assert!(!serialized.contains("access-token"));
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_organizations_original_authentication_never_uses_requested_acr_or_iat_fallback(
) -> TestResult {
    let mut f = Fixture::new().await?;
    f.request.acr = Some("urn:example:two-factors".into());
    let now = now_epoch_secs()?;
    let mut absent = claims(&f, "no-assurance", now);
    absent.as_object_mut().ok_or("claims")?.remove("acr");
    absent.as_object_mut().ok_or("claims")?.remove("amr");
    assert!(
        f.signed_exchange(&f.request, absent.clone()).is_err(),
        "requested ACR already requires a corresponding signed claim"
    );
    f.request.acr = None;
    std::sync::Arc::make_mut(&mut f.state.cfg).default_acr = Some("urn:example:two-factors".into());
    let ordinary = session(&f, absent).await?;
    assert_eq!(
        ordinary.acr, f.state.cfg.default_acr,
        "existing configured ACR behavior"
    );
    let evidence = ordinary
        .original_authentication
        .ok_or("explicit signed time")?;
    assert_eq!(evidence.acr, None, "configured ACR is not evidence");
    assert_eq!(evidence.amr, None);
    let mut no_time = claims(&f, "no-auth-time", now);
    no_time.as_object_mut().ok_or("claims")?.remove("auth_time");
    let ordinary = session(&f, no_time).await?;
    assert_eq!(
        ordinary.auth_time_epoch_secs, now,
        "ordinary legacy compatibility"
    );
    assert!(
        ordinary.original_authentication.is_none(),
        "iat cannot become signed auth_time evidence"
    );
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_organizations_original_authentication_bounds_optional_assurance_claims() -> TestResult {
    let f = Fixture::new().await?;
    let now = now_epoch_secs()?;
    for (index, amr) in [
        json!(["pwd", "pwd"]),
        json!([]),
        json!(["pwd\n"]),
        json!(["x".repeat(129)]),
        json!((0..17).map(|i| format!("method{i}")).collect::<Vec<_>>()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut raw = claims(&f, &format!("bounded-{index}"), now);
        raw["amr"] = amr;
        assert!(session(&f, raw).await?.original_authentication.is_none());
    }
    let mut oversized = claims(&f, "oversized-acr", now);
    oversized["acr"] = json!("x".repeat(257));
    assert!(session(&f, oversized)
        .await?
        .original_authentication
        .is_none());
    f.cleanup().await
}
