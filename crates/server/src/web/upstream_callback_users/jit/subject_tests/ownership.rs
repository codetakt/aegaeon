async fn assert_jit_owner(
    runtime: &PgPool,
    env: &TestEnvironment,
    owner: uuid::Uuid,
    expected: &[&str],
) -> TestResult {
    let admin = crate::web::test_support::test_admin_pool(runtime).await?;
    let owners: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT environment_id FROM aegaeon.end_user_identity_owners WHERE owner_id=$1",
    )
    .bind(owner)
    .fetch_all(&admin)
    .await?;
    assert_eq!(owners, vec![env.environment_id]);
    let mut subjects:Vec<String>=sqlx::query_scalar("SELECT subject FROM aegaeon.end_user_subject_reservations WHERE environment_id=$1 AND owner_id=$2").bind(env.environment_id).bind(owner).fetch_all(&admin).await?;
    subjects.sort();
    let mut expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(subjects, expected);
    Ok(())
}

async fn check_jit_historical_subject(
    pool: &PgPool,
    env: &TestEnvironment,
    request: &UpstreamAuthRequest,
    owner: uuid::Uuid,
    subject: &str,
) -> TestResult {
    let renamed = format!("jit-renamed-{owner}");
    sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1")
        .bind(owner)
        .bind(&renamed)
        .execute(pool)
        .await?;
    let current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2",
    )
    .bind(env.environment_id)
    .bind(subject)
    .fetch_one(pool)
    .await?;
    assert_eq!(current, 0);
    let before = snapshot(pool, env).await?;
    let mut tx = pool.begin().await?;
    let response = select_or_provision_upstream_user(
        &mut tx,
        request,
        env.environment_id,
        subject,
        UpstreamCallbackEmail {
            value: None,
            verified: false,
        },
        &env.issuer_url,
        "jit-historical-candidate",
    )
    .await
    .err()
    .ok_or("JIT adopted formerly owned subject")?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    let error: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(error["error"], "server_error");
    let text = String::from_utf8(body.to_vec())?;
    assert!(!text.contains(&owner.to_string()));
    assert!(!text.contains(subject));
    tx.rollback().await?;
    assert_eq!(snapshot(pool, env).await?, before);
    sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1")
        .bind(owner)
        .bind(subject)
        .execute(pool)
        .await?;
    assert_jit_owner(pool, env, owner, &[subject, &renamed]).await
}

struct JitAuditFailure {
    admin: PgPool,
    name: String,
}
impl JitAuditFailure {
    async fn install(runtime: &PgPool, env: &TestEnvironment) -> TestResult<Self> {
        let admin = crate::web::test_support::test_admin_pool(runtime).await?;
        let name = format!("jit_ownership_witness_{}", env.environment_id.simple());
        // A test-only nontransactional sequence witnesses that both provisional authority
        // rows existed inside the real runtime transaction before the later audit failure.
        // The trigger only reads permanent tables; it does not disable/replace their guards.
        let sql = format!(
            r#"
CREATE SEQUENCE aegaeon.{name};
CREATE FUNCTION aegaeon.{name}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
    IF NEW.environment_id='{environment}'::uuid
       AND NEW.request_id='jit-late-audit-failure'
       AND NEW.event_type='upstream.account_link.upsert.authorized.v1' THEN
        IF (
            SELECT count(*) FROM aegaeon.end_users u
            JOIN aegaeon.end_user_identity_owners o
              ON o.owner_id=u.id AND o.environment_id=u.environment_id
            JOIN aegaeon.end_user_subject_reservations r
              ON r.owner_id=u.id AND r.environment_id=u.environment_id
             AND r.subject=u.subject
            WHERE u.environment_id=NEW.environment_id AND u.subject=NEW.actor_id
        )=1 THEN
            PERFORM pg_catalog.nextval('aegaeon.{name}'::regclass);
        END IF;
        RAISE EXCEPTION 'injected late JIT audit refusal';
    END IF;
    RETURN NEW;
END;
$body$;
REVOKE ALL ON FUNCTION aegaeon.{name}() FROM PUBLIC;
CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events
FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}();
"#,
            environment = env.environment_id,
        );
        sqlx::raw_sql(&sql).execute(&admin).await?;
        Ok(Self { admin, name })
    }
    async fn witnessed(&self) -> TestResult {
        let called: bool =
            sqlx::query_scalar(&format!("SELECT is_called FROM aegaeon.{}", self.name))
                .fetch_one(&self.admin)
                .await?;
        assert!(
            called,
            "failure control must observe provisional user, owner and reservation"
        );
        Ok(())
    }
    async fn remove(&self) -> TestResult {
        sqlx::raw_sql(&format!("DROP TRIGGER {} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{}(); DROP SEQUENCE aegaeon.{};",self.name,self.name,self.name)).execute(&self.admin).await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and AEGAEON_TEST_ADMIN_DATABASE_URL failure control"]
async fn permanent_subject_jit_late_audit_failure_rolls_back_provisional_authority() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let request = request(&pool, &env).await?;
    let token = token(&request)?;
    let failure = JitAuditFailure::install(&pool, &env).await?;
    let before = snapshot(&pool, &env).await?;
    let result: TestResult = async {
        let mut tx = pool.begin().await?;
        let response = resolve_provisioned_upstream_callback_user(
            &mut tx,
            &request,
            &token,
            "audit-failed-link",
            &env.issuer_url,
            "jit-late-audit-failure",
        )
        .await
        .err()
        .ok_or("injected late audit failure was accepted")?;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        tx.rollback().await?;
        failure.witnessed().await?;
        assert_eq!(snapshot(&pool, &env).await?, before);
        Ok(())
    }
    .await;
    // Remove only owned test controls, even if the measured operation returned an error.
    let removed = failure.remove().await;
    match (result, removed) {
        (Err(operation), Err(cleanup)) => {
            return Err(format!("operation: {operation}; control removal: {cleanup}").into());
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    let mut tx = pool.begin().await?;
    let (subject, owner) = resolve_provisioned_upstream_callback_user(
        &mut tx,
        &request,
        &token,
        "audit-failed-link",
        &env.issuer_url,
        "jit-after-audit-control",
    )
    .await
    .map_err(response_error)?;
    tx.commit().await?;
    assert_jit_owner(&pool, &env, owner.ok_or("committed owner")?, &[&subject]).await?;
    let after = snapshot(&pool, &env).await?;
    for key in ["users", "links", "owners", "reservations"] {
        assert_eq!(
            after[key].as_array().ok_or("committed row")?.len(),
            1,
            "{key}"
        );
    }
    Ok(())
}

async fn check_jit_current_collision(
    pool: &PgPool,
    env: &TestEnvironment,
    request: &UpstreamAuthRequest,
    subject: &str,
) -> TestResult {
    let before = snapshot(pool, env).await?;
    let mut tx = pool.begin().await?;
    assert!(select_or_provision_upstream_user(
        &mut tx,
        request,
        env.environment_id,
        subject,
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
    assert_eq!(snapshot(pool, env).await?, before);
    Ok(())
}
