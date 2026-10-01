use super::*;

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_old_delimiter_and_local_subject_are_not_identity_authority() -> TestResult {
    let f = Fixture::new().await?;
    let first = f.with_issuer("https://issuer.example").await?;
    let second = f.with_issuer("https://issuer.example:443").await?;
    // Both tuples formerly produced upstream:https://issuer.example:443:b.
    let old = "upstream:https://issuer.example:443:b";
    let local = f.local(old, None).await?;
    let a = f
        .success_subject(f.callback(&first, "443:b", None).await?)
        .await?;
    let b = f
        .success_subject(f.callback(&second, "b", None).await?)
        .await?;
    assert_ne!(a, b);
    assert_ne!(a, old);
    assert_ne!(b, old);
    for (request, sub) in [(&first, "443:b"), (&second, "b")] {
        let (id, subject, provenance, revision) = f.owner(request, sub).await?;
        assert_ne!(id, local);
        assert!(subject.starts_with("upstream:v2:"));
        assert_eq!(subject.len(), 55);
        assert_eq!(provenance, "jit_v2");
        assert_eq!(revision, 1);
        let name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM aegaeon.end_user_profiles WHERE end_user_id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(name.as_deref(), Some("Projected Name"));
    }
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_email_collision_never_reuses_old_or_other_subject() -> TestResult {
    let f = Fixture::new().await?;
    f.local(
        "upstream:https://issuer.example:old",
        Some("same@example.com"),
    )
    .await?;
    f.rejected(&f.request, "old", Some("same@example.com"))
        .await?;
    f.rejected(&f.request, "different", Some("SAME@example.com"))
        .await?;
    // A preexisting old spelling with an unrelated email is also never adopted.
    f.local(
        "upstream:https://issuer.example:new",
        Some("unrelated@example.com"),
    )
    .await?;
    let subject = f
        .success_subject(
            f.callback(&f.request, "new", Some("new@example.com"))
                .await?,
        )
        .await?;
    assert_ne!(subject, "upstream:https://issuer.example:new");
    f.rejected(&f.request, "another-identity", Some("new@example.com"))
        .await?;
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_admitted_policies_refuse_without_side_effects() -> TestResult {
    let f = Fixture::new().await?;
    let mut request = f.request.clone();
    request.jit_provisioning_policy = None;
    f.rejected(&request, "missing", None).await?;
    request = f.request.clone();
    request
        .jit_provisioning_policy
        .as_mut()
        .ok_or("policy")?
        .enabled = false;
    f.rejected(&request, "disabled", None).await?;
    request = f.request.clone();
    request
        .jit_provisioning_policy
        .as_mut()
        .ok_or("policy")?
        .collision_policy = Collision::ReuseExistingEmail;
    f.rejected(&request, "legacy", Some("verified@example.com"))
        .await?;
    request = f.request.clone();
    request
        .jit_provisioning_policy
        .as_mut()
        .ok_or("policy")?
        .require_verified_email = true;
    f.rejected(&request, "missing-email", None).await?;
    request = f.request.clone();
    request
        .jit_provisioning_policy
        .as_mut()
        .ok_or("policy")?
        .domain_allowlist = vec!["allowed.example".into()];
    f.rejected(&request, "wrong-domain", Some("verified@example.com"))
        .await?;
    request = f.request.clone();
    request
        .jit_provisioning_policy
        .as_mut()
        .ok_or("policy")?
        .initial_status = Initial::Blocked;
    f.rejected(&request, "blocked", None).await?;
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_exact_link_repeat_and_wrong_connection_preserve_authority() -> TestResult {
    let f = Fixture::new().await?;
    let first = f
        .success_subject(f.callback(&f.request, "repeat", None).await?)
        .await?;
    let owner = f.owner(&f.request, "repeat").await?;
    // Historical enforcement is separate: exact-link lookup precedes JIT policy.
    sqlx::query("UPDATE aegaeon.account_links SET binding_provenance='legacy_unreviewed' WHERE environment_id=$1").bind(f.env.environment_id).execute(&f.pool).await?;
    let mut request = f.request.clone();
    request.jit_provisioning_policy = None;
    assert_eq!(
        f.success_subject(f.callback(&request, "repeat", None).await?)
            .await?,
        first
    );
    let current = f.owner(&request, "repeat").await?;
    assert_eq!(current.0, owner.0);
    assert_eq!(current.2, "legacy_unreviewed");
    assert_eq!(current.3, 1);
    let c = request.managed_connection_context();
    request.context = crate::upstream::UpstreamConnectionContext::new(
        Uuid::new_v4(),
        c.team_id,
        c.tenant_id,
        c.environment_id,
        c.configuration_version_id,
    );
    f.rejected(&request, "repeat", None).await?;
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_concurrent_same_and_different_identities_have_no_orphans() -> TestResult {
    let f = Fixture::new().await?;
    for (a, b, expected) in [("same", "same", 1_i64), ("distinct-a", "distinct-b", 3_i64)] {
        let (one, two) = tokio::join!(
            f.callback(&f.request, a, None),
            f.callback(&f.request, b, None)
        );
        let one = one?;
        let two = two?;
        assert!(one.status().is_redirection() || two.status().is_redirection());
        for response in [one, two] {
            if response.status().is_redirection() {
                f.success_subject(response).await?;
            } else {
                assert!(response.headers().get(header::SET_COOKIE).is_none());
            }
        }
        let users: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1")
                .bind(f.env.environment_id)
                .fetch_one(&f.pool)
                .await?;
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.account_links WHERE environment_id=$1",
        )
        .bind(f.env.environment_id)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(users, expected);
        assert_eq!(links, expected);
    }
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_forced_local_subject_collision_aborts_callback_transaction() -> TestResult {
    let f = Fixture::new().await?;
    let subject = "upstream:v2:forced-test-collision";
    f.local(subject, Some("original@example.com")).await?;
    let trigger = format!("jit_subject_collision_{}", Uuid::new_v4().simple());
    // Force the actual INSERT boundary to collide in this environment only.
    // Production random generation and the complete callback remain unchanged.
    sqlx::query(&format!("CREATE FUNCTION aegaeon.{trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.subject := '{subject}'; RETURN NEW; END $$")).execute(&f.pool).await?;
    sqlx::query(&format!("CREATE TRIGGER {trigger} BEFORE INSERT ON aegaeon.end_users FOR EACH ROW WHEN (NEW.environment_id='{}'::uuid) EXECUTE FUNCTION aegaeon.{trigger}()",f.env.environment_id)).execute(&f.pool).await?;
    let result: TestResult = async {
        f.rejected(&f.request, "forced-collision", Some("attacker@example.com"))
            .await?;
        sqlx::query(
            "UPDATE aegaeon.end_users SET status='DELETED' WHERE environment_id=$1 AND subject=$2",
        )
        .bind(f.env.environment_id)
        .bind(subject)
        .execute(&f.pool)
        .await?;
        f.rejected(
            &f.request,
            "deleted-collision",
            Some("attacker@example.com"),
        )
        .await
    }
    .await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON aegaeon.end_users"))
        .execute(&f.pool)
        .await?;
    sqlx::query(&format!("DROP FUNCTION aegaeon.{trigger}()"))
        .execute(&f.pool)
        .await?;
    result?;
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_callback_audit_failure_rolls_back_user_link_and_profile() -> TestResult {
    let f = Fixture::new().await?;
    let constraint = format!("jit_audit_failure_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("ALTER TABLE aegaeon.audit_events ADD CONSTRAINT {constraint} CHECK (environment_id <> '{}'::uuid OR event_type <> 'upstream_auth') NOT VALID",f.env.environment_id)).execute(&f.pool).await?;
    let result = f.rejected(&f.request, "audit-failure", None).await;
    sqlx::query(&format!(
        "ALTER TABLE aegaeon.audit_events DROP CONSTRAINT {constraint}"
    ))
    .execute(&f.pool)
    .await?;
    result?;
    f.cleanup().await
}
