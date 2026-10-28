//! Real restricted-PostgreSQL and public-router launch boundary tests.
mod dpop;
mod failures;
mod fixture;
use crate::lti::{model::Lifecycle, store};
use axum::http::StatusCode;
use fixture::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_resource_launch_signs_owned_claims_and_consumes_once() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let url = format!("/lti/authorize?{request}");
    let (a, b) = tokio::join!(
        fixture.send("GET", &url, true, None, None),
        fixture.send("GET", &url, true, None, None)
    );
    let a = body(a?).await?;
    let b = body(b?).await?;
    let issued = [&a, &b]
        .into_iter()
        .filter(|value| value.1.contains("name=\"id_token\""))
        .collect::<Vec<_>>();
    assert_eq!(issued.len(), 1, "one competing request must win");
    let token = hidden(&issued[0].1, "id_token")?;
    let claims = fixture.verify(&token).await?;
    assert_eq!(claims["sub"], "lti-user");
    assert_eq!(claims["nonce"], " opaque + nonce ");
    assert_eq!(claims["nickname"], "Mapped local nickname");
    assert_eq!(
        claims["https://purl.imsglobal.org/spec/lti/claim/message_type"],
        "LtiResourceLinkRequest"
    );
    assert_eq!(
        claims["https://purl.imsglobal.org/spec/lti/claim/resource_link"]["id"],
        "resource-1"
    );
    assert!(!claims
        .as_object()
        .ok_or("claims object")?
        .contains_key("email"));
    assert!(issued[0].1.contains("state"));
    assert_eq!(
        claims["exp"].as_i64().ok_or("exp")? - claims["iat"].as_i64().ok_or("iat")?,
        60
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='lti.launch.issued.v1'").bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
    assert_eq!(count, 1);
    let audit: String = sqlx::query_scalar(
        "SELECT jsonb_agg(data)::text FROM aegaeon.audit_events WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert!(!audit.contains("Mapped local nickname"));
    assert!(!audit.contains(&token));
    let replay = body(fixture.send("GET", &url, true, None, None).await?).await?;
    assert!(!replay.1.contains("name=\"id_token\""));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_consent_and_post_continuation_preserve_request_binding() -> Result {
    let fixture = Fixture::new(true, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, true).await?;
    let response = fixture
        .send(
            "POST",
            "/lti/authorize",
            false,
            Some("application/x-www-form-urlencoded"),
            Some(request.clone()),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let continuation = response.headers()["location"].to_str()?.to_string();
    let mut altered = request.clone();
    altered.push_str("&nonce=second");
    let refused = body(
        fixture
            .send(
                "POST",
                "/lti/authorize",
                true,
                Some("application/x-www-form-urlencoded"),
                Some(altered),
            )
            .await?,
    )
    .await?;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    let resumed = fixture.send("GET", &continuation, true, None, None).await?;
    assert_eq!(resumed.headers()["cache-control"], "no-store");
    let response = body(resumed).await?;
    let token = hidden(&response.1, "id_token")?;
    assert_eq!(fixture.verify(&token).await?["nonce"], " opaque + nonce ");
    assert!(
        !body(fixture.send("GET", &continuation, true, None, None).await?)
            .await?
            .1
            .contains("name=\"id_token\"")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_admission_rejects_stale_configuration_inactive_owner_and_wrong_redirect() -> Result
{
    let mut fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let wrong = request.replace("tool.example%2Flaunch", "attacker.example%2Flaunch");
    let response = body(
        fixture
            .send("GET", &format!("/lti/authorize?{wrong}"), true, None, None)
            .await?,
    )
    .await?;
    assert_eq!(response.0, StatusCode::FORBIDDEN);
    assert!(!response.1.contains("<form"));
    sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1")
        .bind(fixture.user)
        .execute(&fixture.state.db_pool)
        .await?;
    let denied = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert_eq!(denied.0, StatusCode::FORBIDDEN);
    sqlx::query("UPDATE aegaeon.end_users SET status='ACTIVE' WHERE id=$1")
        .bind(fixture.user)
        .execute(&fixture.state.db_pool)
        .await?;
    fixture.config.status = Lifecycle::Disabled;
    fixture.replace(1).await?;
    let denied = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert_eq!(denied.0, StatusCode::FORBIDDEN);
    assert!(!denied.1.contains("name=\"id_token\""));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_secure_defaults_stage_activation_and_require_dpop() -> Result {
    let fixture = Fixture::new(true, true).await?;
    let mut tx = fixture.state.db_pool.begin().await?;
    assert!(
        store::load(&mut tx, fixture.state.environment_id, "tool", true)
            .await?
            .is_none()
    );
    store::activate(&mut tx, fixture.state.environment_id, "tool", 1).await?;
    tx.commit().await?;
    let response = fixture.create_response().await?;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "unbound producer token must not pass secure default"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_revision_cas_and_permanent_placement_identity_hold() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let attempt = || async {
        let mut tx = fixture.state.db_pool.begin().await?;
        let result = store::replace(
            &mut tx,
            fixture.state.environment_id,
            "tool",
            1,
            &fixture.config,
            fixture.author,
        )
        .await;
        if result.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(result)
    };
    let (a, b) = tokio::join!(attempt(), attempt());
    assert_eq!(usize::from(a?.is_ok()) + usize::from(b?.is_ok()), 1);
    let mut tx = fixture.state.db_pool.begin().await?;
    let mut changed = fixture.config.clone();
    changed.deployments[0].resource_links[0].context.id = "reused-context".into();
    assert!(store::replace(
        &mut tx,
        fixture.state.environment_id,
        "tool",
        2,
        &changed,
        fixture.author
    )
    .await
    .is_err());
    tx.rollback().await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.lti_registration_revisions v JOIN aegaeon.lti_registrations r ON r.id=v.registration_id WHERE r.environment_id=$1").bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
    assert_eq!(count, 2);
    Ok(())
}
