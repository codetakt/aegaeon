use super::*;

const ACTIVE: &str =
    r#"{"state":"active","roles":["admin"],"reason":"retain existing administrator"}"#;
const CHANGE: &str =
    r#"{"state":"active","roles":["admin","reader"],"reason":"assign additional existing role"}"#;
const SUSPEND: &str = r#"{"state":"suspended","roles":["admin"],"reason":"suspend membership"}"#;
const REMOVE: &str = r#"{"state":"removed","roles":[],"reason":"remove membership"}"#;

async fn counts(f: &Fixture) -> TestResult<(i64, i64, i64)> {
    let receipts = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND operation='set_existing_member'").bind(f.env.environment_id).fetch_one(&f.pool).await?;
    let events = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_authority_events WHERE environment_id=$1",
    )
    .bind(f.env.environment_id)
    .fetch_one(&f.pool)
    .await?;
    let outbox = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_outbox o JOIN aegaeon.organization_authority_events e ON e.id=o.event_id WHERE e.environment_id=$1").bind(f.env.environment_id).fetch_one(&f.pool).await?;
    Ok((receipts, events, outbox))
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_members_mutation_receipts_races_and_last_admin() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup_members(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let client = MemberClient::new(&f, &state, &key).await?;
        let path = format!("{}/{}", client.list, f.users[0]);
        let (_, first, tag) = client.get(&path).await?;
        let tag = tag.ok_or("etag")?;
        let before = counts(&f).await?;
        assert_eq!(
            client
                .request(
                    Method::PUT,
                    &path,
                    &client.read,
                    Some(&tag),
                    Some("forbidden"),
                    ACTIVE
                )
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .request(
                    Method::PUT,
                    &path,
                    &client.write,
                    None,
                    Some("missing"),
                    ACTIVE
                )
                .await?
                .0,
            StatusCode::PRECONDITION_REQUIRED
        );
        for body in [
            r#"{"state":"active","state":"removed","roles":[],"reason":"duplicate"}"#,
            r#"{"state":"active","roles":["admin","admin"],"reason":"duplicate"}"#,
            r#"{"state":"active","roles":[],"reason":"unknown","bypass":true}"#,
            r#"{"state":"invited","roles":[],"reason":"cannot invite"}"#,
        ] {
            assert_eq!(
                client.put(&path, &tag, "bad-input", body).await?.0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(counts(&f).await?, before);
        let (left, right) = tokio::join!(
            client.put(&path, &tag, "race-a", CHANGE),
            client.put(&path, &tag, "race-b", CHANGE)
        );
        let (left, right) = (left?, right?);
        assert!([left.0, right.0].contains(&StatusCode::OK));
        assert!([left.0, right.0].contains(&StatusCode::PRECONDITION_FAILED));
        let (winner, key) = if left.0 == StatusCode::OK {
            (left, "race-a")
        } else {
            (right, "race-b")
        };
        assert_eq!(
            winner.1["revision"].as_i64().ok_or("revision")?,
            first["revision"].as_i64().ok_or("revision")? + 1
        );
        let committed = counts(&f).await?;
        assert_eq!(committed, (before.0 + 1, before.1 + 1, before.2 + 1));
        let replay = client.put(&path, &tag, key, CHANGE).await?;
        assert_eq!(replay, winner);
        assert_eq!(counts(&f).await?, committed);
        assert_eq!(
            client.put(&path, &tag, key, SUSPEND).await?.0,
            StatusCode::CONFLICT
        );
        let current_tag = winner.2.ok_or("winner etag")?;
        let removed = client.put(&path, &current_tag, "remove", REMOVE).await?;
        assert_eq!(removed.0, StatusCode::OK, "{}", removed.1);
        assert_eq!(removed.1["state"], "removed");
        assert_eq!(
            client.put(&path, &current_tag, "remove", REMOVE).await?,
            removed
        );
        assert_eq!(
            client
                .put(
                    &path,
                    removed.2.as_deref().ok_or("removed etag")?,
                    "revive",
                    ACTIVE
                )
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
        let self_path = format!("{}/{}", client.list, f.users[1]);
        let self_tag = client.get(&self_path).await?.2.ok_or("self tag")?;
        let after = counts(&f).await?;
        assert_eq!(
            client
                .put(&self_path, &self_tag, "last-admin", REMOVE)
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(counts(&f).await?, after);
        let unknown = format!("{}/{}", client.list, Uuid::new_v4());
        assert_eq!(
            client.put(&unknown, &tag, "create", ACTIVE).await?.0,
            StatusCode::FORBIDDEN
        );
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1")
            .bind(f.users[1])
            .execute(&f.pool)
            .await?;
        assert_eq!(
            client.put(&path, &current_tag, "remove", REMOVE).await?.0,
            StatusCode::UNAUTHORIZED,
            "replay rechecks actor"
        );
        assert_eq!(counts(&f).await?, after);
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_members_current_assignable_roles_and_invited_refusal(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup_members(&f).await?;
    let result = async {
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET assignable_roles='[\"reader\"]',version=version+1 WHERE environment_id=$1 AND role_key='reader'").bind(state.environment_id).execute(&f.pool).await?;
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let client = MemberClient::new(&f, &state, &key).await?;
        let path = format!("{}/{}", client.list, f.users[0]);
        let tag = client.get(&path).await?.2.ok_or("etag")?;
        let before = counts(&f).await?;
        assert_eq!(client.put(&path, &tag, "strip-stronger", REMOVE).await?.0, StatusCode::FORBIDDEN);
        let self_path = format!("{}/{}", client.list, f.users[1]);
        let self_tag = client.get(&self_path).await?.2.ok_or("etag")?;
        assert_eq!(client.put(&self_path, &self_tag, "escalate", ACTIVE).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(counts(&f).await?, before);
        sqlx::query("UPDATE aegaeon.organization_memberships SET state='invited',roles='[\"reader\"]',revision=revision+1 WHERE environment_id=$1 AND end_user_id=$2").bind(state.environment_id).bind(f.users[0]).execute(&f.pool).await?;
        let tag = client.get(&path).await?.2.ok_or("invited etag")?;
        assert_eq!(client.put(&path, &tag, "skip-invitation", r#"{"state":"active","roles":["reader"],"reason":"not acceptance"}"#).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(counts(&f).await?, before);
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_members_receipt_capacity_reserves_real_reductions() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup_members(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let client = MemberClient::new(&f, &state, &key).await?;
        let path = format!("{}/{}", client.list, f.users[0]);
        let tag = client.get(&path).await?.2.ok_or("etag")?;
        let registration: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2").bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'member',$4,$5,'set_existing_member','retained-' || n::text,decode(repeat('00',32),'hex'),'{}'::jsonb FROM generate_series(1,$6) n")
            .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(f.users[1]).bind(OWNER).bind(registration)
            .bind(crate::organizations::commands::capacity::MAX_MEMBER_RECEIPTS).execute(&f.pool).await?;
        let before = counts(&f).await?;
        assert_eq!(client.put(&path, &tag, "noop", ACTIVE).await?.0, StatusCode::CONFLICT);
        assert_eq!(counts(&f).await?, before);
        let suspended = client.put(&path, &tag, "restrict", SUSPEND).await?;
        assert_eq!(suspended.0, StatusCode::OK, "{}", suspended.1);
        assert_eq!(client.put(&path, &tag, "restrict", SUSPEND).await?, suspended);
        let current = suspended.2.as_deref().ok_or("suspended etag")?;
        assert_eq!(client.put(&path, current, "noop-suspended", SUSPEND).await?.0, StatusCode::CONFLICT);
        assert_eq!(client.put(&path, current, "widen", ACTIVE).await?.0, StatusCode::CONFLICT);
        assert_eq!(client.put(&path, current, "remove", REMOVE).await?.0, StatusCode::OK);
        assert_eq!(counts(&f).await?, (before.0 + 2, before.1 + 2, before.2 + 2));
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis; observed primary waits"]
async fn shared_redis_organizations_members_atomic_store_failure_and_lost_response() -> TestResult {
    use std::time::Duration;
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup_members(&f).await?;
    // The restricted runtime cannot lock append-only receipts against writes.
    // Only this owned fault controller uses the fixture administrator; the
    // mounted handler and all authority assertions retain runtime credentials.
    let controller = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let client = MemberClient::new(&f, &state, &key).await?;
        let path = format!("{}/{}", client.list, f.users[0]);
        let original = client.get(&path).await?;
        let tag = original.2.as_deref().ok_or("etag")?;
        let before = counts(&f).await?;
        // The actual receipt INSERT waits after state/audit/outbox writes. Its
        // bounded SQL failure must roll back every pending effect.
        let mut block_receipt = controller.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_authority_receipts IN SHARE MODE").execute(&mut *block_receipt).await?;
        assert_eq!(client.put(&path, tag, "storage-failure", CHANGE).await?.0, StatusCode::SERVICE_UNAVAILABLE);
        block_receipt.rollback().await?;
        assert_eq!(client.get(&path).await?, original);
        assert_eq!(counts(&f).await?, before);
        // Observe the owned request waiting at the actual domain lock, then
        // lose only the caller. It may complete once the blocker is released.
        let signed = proof(&state, &key, &client.write, "PUT", json!({"htu":format!("{}{path}",state.issuer)}))?;
        let mut request = Request::builder().method(Method::PUT).uri(&path)
            .header(header::AUTHORIZATION, format!("DPoP {}", client.write))
            .header("DPoP", signed).header(header::CONTENT_TYPE,"application/json")
            .header(header::IF_MATCH, tag).header("Idempotency-Key","lost-response")
            .body(Body::from(CHANGE))?;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127,0,0,1],12543))));
        let mut blocker = f.pool.begin().await?;
        crate::organizations::repository::lock_domain(&mut blocker, f.organization.scope).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        let router = crate::web::build_router(state.clone());
        let caller = tokio::spawn(async move { router.oneshot(request).await });
        tokio::time::timeout(Duration::from_millis(800), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a WHERE $1 = ANY(pg_catalog.pg_blocking_pids(a.pid)))")
                    .bind(pid).fetch_one(&f.pool).await?;
                if waiting { return Ok::<(),sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await??;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        blocker.rollback().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if counts(&f).await?.0 == before.0 + 1 { return Ok::<(),Box<dyn std::error::Error>>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let replay = client.put(&path, tag, "lost-response", CHANGE).await?;
        assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
        assert_eq!(client.get(&path).await?, replay);
        assert_eq!(counts(&f).await?, (before.0 + 1, before.1 + 1, before.2 + 1));
        Ok(())
    }.await;
    controller.close().await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
