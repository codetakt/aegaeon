use super::*;
use crate::organizations::repository_tests::Fixture;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual credential locks and post-lock expiry"]
async fn pg_machine_audit_key_lock_serializes_revocation_and_rechecks_expiry_after_wait(
) -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new().await?;
    let service = Uuid::new_v4();
    let key = Uuid::new_v4();
    let raw = format!("aeg_{}", Uuid::new_v4().simple());
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {raw}").parse()?);
    let session = ManagementSession::api_key(
        service,
        1,
        key,
        f.env.team_id,
        vec![ApiKeyCapability::OrganizationAuditExport],
    );
    let result = async {
        sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind) VALUES($1,$2,'disabled-service-login','SERVICE')")
            .bind(service).bind(format!("{service}@machine.example")).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.api_keys(id,team_id,service_administrator_id,name,key_prefix,key_hash) VALUES($1,$2,$3,'audit fixture',$4,$5)")
            .bind(key).bind(f.env.team_id).bind(service).bind(&raw[..12]).bind(sha256_array(raw.as_bytes()).as_slice()).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.api_key_capabilities(api_key_id,capability) VALUES($1,'ORGANIZATION_AUDIT_EXPORT')")
            .bind(key).execute(&f.pool).await?;
        let mut reading = f.pool.begin().await?;
        lock_current(&mut reading, &session, &headers, f.env.team_id, "valid-key").await
            .map_err(|r| format!("valid credential refused: {}",r.status()))?;
        // Both the credential and its capability remain locked through commit.
        for query in ["UPDATE aegaeon.api_keys SET expires_at=clock_timestamp()+interval '1 day' WHERE id=$1",
            "DELETE FROM aegaeon.api_key_capabilities WHERE api_key_id=$1"] {
            let mut concurrent = f.pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *concurrent).await?;
            let blocked = sqlx::query(query).bind(key).execute(&mut *concurrent).await;
            concurrent.rollback().await?;
            assert!(matches!(blocked, Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("55P03")));
        }
        reading.rollback().await?;
        sqlx::query("UPDATE aegaeon.api_keys SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1")
            .bind(key).execute(&f.pool).await?;
        let mut barrier = f.pool.begin().await?;
        sqlx::query("SELECT id FROM aegaeon.api_keys WHERE id=$1 FOR UPDATE").bind(key).fetch_one(&mut *barrier).await?;
        let mut waiting = f.pool.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *waiting).await?;
        let team = f.env.team_id;
        let worker = tokio::spawn(async move {
            let result = lock_current(&mut waiting, &session, &headers, team, "post-lock-expiry").await;
            waiting.rollback().await.unwrap();
            result
        });
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (blocked, expired): (bool,bool) = sqlx::query_as("SELECT cardinality(pg_blocking_pids($1))>0,clock_timestamp()>expires_at FROM aegaeon.api_keys WHERE id=$2")
                    .bind(pid).bind(key).fetch_one(&f.pool).await?;
                if blocked && expired { return Ok::<_,sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        barrier.rollback().await?;
        let outcome = tokio::time::timeout(Duration::from_secs(3),worker).await??;
        observed??;
        assert_eq!(outcome.unwrap_err().status(),StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    sqlx::query("DELETE FROM aegaeon.api_keys WHERE id=$1")
        .bind(key)
        .execute(&f.pool)
        .await?;
    sqlx::query("DELETE FROM aegaeon.administrators WHERE id=$1")
        .bind(service)
        .execute(&f.pool)
        .await?;
    f.cleanup(result).await
}
