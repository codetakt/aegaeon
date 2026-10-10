use super::*;
use crate::upstream::{
    UpstreamConnectionContext, UpstreamJitProvisioningCollisionPolicy as Collision,
    UpstreamJitProvisioningInitialStatus as Initial, UpstreamJitProvisioningPolicy,
};
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_pg_pool, TestEnvironment,
    TestResult,
};
use sqlx::PgPool;
use std::time::{Duration, SystemTime};

fn response_error(response: Response) -> std::io::Error {
    std::io::Error::other(format!("unexpected JIT response: {}", response.status()))
}

async fn request(pool: &PgPool, env: &TestEnvironment) -> TestResult<UpstreamAuthRequest> {
    let version: uuid::Uuid = sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    let issuer = format!("https://upstream.example/{}", "path".repeat(100));
    let connection: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,status) VALUES ($1,$2,'subject-test','subject-test',$3,'client','ACTIVE') RETURNING id",
    )
    .bind(env.environment_id)
    .bind(version)
    .bind(&issuer)
    .fetch_one(pool)
    .await?;
    Ok(UpstreamAuthRequest {
        browser_binding_digest: None,
        state: "state".into(),
        nonce: "nonce".into(),
        code_verifier: None,
        acr: None,
        issuer,
        client_id: "client".into(),
        client_secret: None,
        client_auth_method: "none".into(),
        context: UpstreamConnectionContext::new(
            connection,
            env.team_id,
            env.tenant_id,
            env.environment_id,
            version,
        ),
        token_endpoint: "https://upstream.example/token".into(),
        jwks_uri: "https://upstream.example/jwks".into(),
        redirect_uri: "https://issuer.example/callback".into(),
        return_to: None,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: Some(UpstreamJitProvisioningPolicy {
            enabled: true,
            require_verified_email: false,
            domain_allowlist: Vec::new(),
            collision_policy: Collision::RejectExistingEmail,
            initial_status: Initial::Active,
        }),
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: SystemTime::now(),
        expires_at: SystemTime::now() + Duration::from_secs(300),
    })
}

fn token(request: &UpstreamAuthRequest) -> TestResult<IdToken> {
    Ok(crate::oidc::IdTokenBuilder::try_new(
        request.issuer.clone(),
        "X".repeat(255),
        request.client_id.clone(),
    )?
    .build())
}

async fn cleanup(pool: &PgPool, env: &TestEnvironment) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM aegaeon.account_links WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM aegaeon.connections WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    cleanup_test_environment(pool, env).await
}

async fn snapshot(pool: &PgPool, env: &TestEnvironment) -> TestResult<(i64, i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1),(SELECT count(*) FROM aegaeon.account_links WHERE environment_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1),(SELECT count(*) FROM aegaeon.end_user_profiles p JOIN aegaeon.end_users u ON u.id=p.end_user_id WHERE u.environment_id=$1)").bind(env.environment_id).fetch_one(pool).await?)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn oidc_subject_format_jit_creation_links_email_and_collision() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("database required")?;
    let env = setup_test_environment(&pool).await?;
    let result: TestResult = async {
        let mut request = request(&pool, &env).await?;
        let mut token = token(&request)?;
        let mut tx = pool.begin().await?;
        let result = resolve_provisioned_upstream_callback_user(
            &mut tx,
            &request,
            &token,
            "first",
            &env.issuer_url,
            "subject-first",
        )
        .await;
        let (subject, id) = match result {
            Ok(value) => value,
            Err(response) => {
                let body = axum::body::to_bytes(response.into_body(), 65536).await?;
                return Err(std::io::Error::other(format!(
                    "JIT creation response: {}",
                    String::from_utf8_lossy(&body)
                ))
                .into());
            }
        };
        assert_eq!(subject.len(), 45);
        assert_eq!(
            uuid::Uuid::parse_str(subject.strip_prefix("upstream:").ok_or("prefix")?)?
                .get_version_num(),
            4
        );
        assert!(!subject.contains(&request.issuer));
        tx.commit().await?;
        let mut tx = pool.begin().await?;
        let linked = super::super::account_link::resolve_linked_upstream_callback_user(
            &mut tx,
            &request,
            "first",
            &env.issuer_url,
            "subject-linked",
        )
        .await
        .map_err(response_error)?
        .ok_or("link")?;
        assert_eq!(linked.subject, subject);
        assert_eq!(Some(linked.end_user_id), id);
        tx.commit().await?;
        sqlx::query("UPDATE aegaeon.end_users SET email='same@example.com' WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await?;
        token
            .claims
            .additional_claims
            .insert("email".into(), serde_json::json!("same@example.com"));
        let before = snapshot(&pool, &env).await?;
        let mut tx = pool.begin().await?;
        assert!(resolve_provisioned_upstream_callback_user(
            &mut tx,
            &request,
            &token,
            "reject-email",
            &env.issuer_url,
            "subject-reject"
        )
        .await
        .is_err());
        tx.rollback().await?;
        assert_eq!(snapshot(&pool, &env).await?, before);
        request
            .jit_provisioning_policy
            .as_mut()
            .ok_or("policy")?
            .collision_policy = Collision::ReuseExistingEmail;
        let mut tx = pool.begin().await?;
        let reused = resolve_provisioned_upstream_callback_user(
            &mut tx,
            &request,
            &token,
            "reuse",
            &env.issuer_url,
            "subject-reuse",
        )
        .await
        .map_err(response_error)?;
        assert_eq!(reused, (subject.clone(), id));
        tx.commit().await?;
        let before = snapshot(&pool, &env).await?;
        let mut tx = pool.begin().await?;
        // Deterministic candidate exercises the real insert-only collision boundary.
        assert!(select_or_provision_upstream_user(
            &mut tx,
            &request,
            env.environment_id,
            &subject,
            UpstreamCallbackEmail {
                value: None,
                verified: false
            },
            &env.issuer_url,
            "subject-collision"
        )
        .await
        .is_err());
        tx.rollback().await?;
        assert_eq!(snapshot(&pool, &env).await?, before);
        check_policy_refusals(&pool, &env, &request).await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup(&pool, &env).await)
}

async fn check_policy_refusals(
    pool: &PgPool,
    env: &TestEnvironment,
    request: &UpstreamAuthRequest,
) -> TestResult {
    for kind in 0..4 {
        let mut request = request.clone();
        let policy = request.jit_provisioning_policy.as_mut().ok_or("policy")?;
        match kind {
            0 => policy.enabled = false,
            1 => policy.require_verified_email = true,
            2 => policy.domain_allowlist = vec!["allowed.example".into()],
            _ => policy.initial_status = Initial::Blocked,
        }
        let token = token(&request)?;
        let before = snapshot(pool, env).await?;
        let mut tx = pool.begin().await?;
        let response = resolve_provisioned_upstream_callback_user(
            &mut tx,
            &request,
            &token,
            "policy",
            &env.issuer_url,
            "subject-policy",
        )
        .await
        .err()
        .ok_or("policy allowed")?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        tx.rollback().await?;
        assert_eq!(snapshot(pool, env).await?, before);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn oidc_subject_format_jit_concurrent_link_conflict_rolls_back() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("database required")?;
    let env = setup_test_environment(&pool).await?;
    let result: TestResult=async {
        let request=request(&pool,&env).await?;
        let token=token(&request)?;
        let mut winner=pool.begin().await?;
        let winner_pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *winner).await?;
        let first=resolve_provisioned_upstream_callback_user(&mut winner,&request,&token,"race",&env.issuer_url,"subject-winner").await.map_err(response_error)?;
        let (send,recv)=tokio::sync::oneshot::channel();
        let loser_pool=pool.clone();let issuer=env.issuer_url.clone();
        let request2=request.clone();
        let loser=tokio::spawn(async move {
            let mut tx=loser_pool.begin().await.map_err(|e|e.to_string())?;
            let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
            send.send(pid).map_err(|_|"pid receiver")?;
            let result=resolve_provisioned_upstream_callback_user(&mut tx,&request2,&token,"race",&issuer,"subject-loser").await;
            tx.rollback().await.map_err(|e|e.to_string())?;
            Ok::<_,String>(result.err().map(|r|r.status()))
        });
        let loser_pid=recv.await?;
        let blocked=tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                // Both pool connections belong to the concurrent transactions.
                // Observe from the idle winner instead of waiting for a third connection.
                let pids:Vec<i32>=sqlx::query_scalar("SELECT pg_blocking_pids($1)").bind(loser_pid).fetch_one(&mut *winner).await?;
                if pids.contains(&winner_pid) {return Ok::<_,sqlx::Error>(());}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        // Release even when the lock observation failed, so no spawned transaction is stranded.
        winner.commit().await?;
        let response=tokio::time::timeout(Duration::from_secs(5),loser).await???;
        blocked??;assert_eq!(response,Some(StatusCode::FORBIDDEN));
        let counts=snapshot(&pool,&env).await?;assert_eq!(counts.0,1);assert_eq!(counts.1,1);assert_eq!(counts.3,0);
        let loser_audit:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND request_id='subject-loser'").bind(env.environment_id).fetch_one(&pool).await?;assert_eq!(loser_audit,0);
        let mut tx=pool.begin().await?;
        let linked=super::super::account_link::resolve_linked_upstream_callback_user(&mut tx,&request,"race",&env.issuer_url,"subject-after-race").await.map_err(response_error)?.ok_or("link")?;
        assert_eq!((linked.subject,Some(linked.end_user_id)),first);tx.rollback().await?;
        Ok(())
    }.await;
    finish_test(result, cleanup(&pool, &env).await)
}
