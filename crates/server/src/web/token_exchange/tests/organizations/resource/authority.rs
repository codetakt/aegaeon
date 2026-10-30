use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis; observed primary lock wait"]
async fn shared_redis_organizations_current_read_refuses_cleanup_closure_during_primary_wait(
) -> TestResult {
    use crate::organizations::request_work::Admission;
    use std::time::Duration;
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = issue(&f, &state, &key, PRIVILEGE).await?;
        let meta = state.tokens.store.try_get_bearer_meta(&token)?.ok_or("metadata")?;
        // Real issuers/stores supply the authority. Each case has an isolated
        // admission class; the process-wide budget is never closed or reset.
        for close in [false, true] {
            let admission = Admission::isolated_for_test()?;
            let closing = admission.clone();
            let mut blocker = f.pool.begin().await?;
            crate::organizations::repository::lock_domain(&mut blocker, f.organization.scope).await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker).await?;
            let reading_state = state.clone();
            let reading_meta = meta.clone();
            let reader = tokio::spawn(async move {
                crate::web::organization_authority::current_for_resource(
                    &reading_state, &reading_meta, &admission,
                ).await.map_err(|response| response.status())
            });
            tokio::time::timeout(Duration::from_millis(800), async {
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a WHERE $1 = ANY(pg_catalog.pg_blocking_pids(a.pid)))",
                    ).bind(blocker_pid).fetch_one(&f.pool).await?;
                    if waiting { return Ok::<(), sqlx::Error>(()); }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await??;
            if close { closing.close_until_restart(); }
            blocker.rollback().await?;
            let outcome = tokio::time::timeout(Duration::from_secs(5), reader).await??;
            if close {
                assert_eq!(outcome, Err(StatusCode::SERVICE_UNAVAILABLE),
                    "a read pending at class closure must not publish positive authority");
            } else {
                assert_eq!(outcome, Ok(true));
            }
        }
        // An independent live class and the mounted authenticated route remain
        // usable; the test does not manufacture a process-wide reopening.
        inspect_context(&state, &key, &token, StatusCode::OK).await?;
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

async fn inspect_context(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
    expected: StatusCode,
) -> TestResult {
    let signed = proof(state, key, token, "GET", json!({}))?;
    let (status, body) = get(
        state,
        Method::GET,
        PATH,
        Some(&format!("DPoP {token}")),
        Some(&signed),
        "",
    )
    .await?;
    assert_eq!(status, expected, "{body}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_identity_resume_never_revives_selected_authority() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = issue(&f, &state, &key, PRIVILEGE).await?;
        inspect_context(&state, &key, &token, StatusCode::OK).await?;
        for status in ["SUSPENDED", "ACTIVE"] {
            // The existing management lifecycle commits these same status
            // transitions. Store authentication and DPoP remain fully real.
            sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status,updated_at=now() WHERE id=$1")
                .bind(f.users[1]).bind(status).execute(&f.pool).await?;
            inspect_context(&state, &key, &token, StatusCode::UNAUTHORIZED).await?;
        }
        // A fresh root based on the old authentication is also refused.
        assert!(fixture::parent(&f, &state, &key).await.is_err());
        // This issuer fixture supplies an authentication time ten seconds ago.
        // Advance beyond that fixed age; the real issuer/root/DPoP checks remain.
        tokio::time::sleep(std::time::Duration::from_secs(11)).await;
        let (_, fresh) = issue(&f, &state, &key, PRIVILEGE).await?;
        inspect_context(&state, &key, &fresh, StatusCode::OK).await?;
        inspect_context(&state, &key, &token, StatusCode::UNAUTHORIZED).await?;
        // No observer need see the intermediate suspended state for revocation.
        let mut tx = f.pool.begin().await?;
        for status in ["SUSPENDED", "ACTIVE"] {
            sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status WHERE id=$1")
                .bind(f.users[1]).bind(status).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        inspect_context(&state, &key, &fresh, StatusCode::UNAUTHORIZED).await?;
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_own_resource_rejects_foreign_targets_and_inconsistent_metadata(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result=async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_,token)=issue(&f,&state,&key,PRIVILEGE).await?;
        inspect_context(&state,&key,&token,StatusCode::OK).await?;
        let original=state.tokens.store.try_get_bearer_meta(&token)?.ok_or("meta")?;
        for field in ["selected","original","details","authentication"]{
            let mut changed=original.clone();
            match field {
                "selected"=>changed.selected_organization=None,
                "original"=>changed.exchange_grant=None,
                "details"=>changed.authorization_details=None,
                _=>changed.auth_time_epoch_secs=Some(1),
            }
            state.tokens.store.try_replace_bearer_meta_record(changed)?;
            inspect_context(&state,&key,&token,StatusCode::UNAUTHORIZED).await?;
        }
        state.tokens.store.try_replace_bearer_meta_record(original)?;
        inspect_context(&state,&key,&token,StatusCode::OK).await?;
        let parent=fixture::parent(&f,&state,&key).await?;
        let (status,external)=select(&state,parent["access_token"].as_str().ok_or("parent")?,&key,IDENTIFIER).await?;
        assert_eq!(status,StatusCode::OK,"{external}");
        inspect_context(&state,&key,external["access_token"].as_str().ok_or("external")?,StatusCode::UNAUTHORIZED).await?;
        let signed=proof(&state,&key,&token,"GET",json!({"htu":format!("{}/resource",state.issuer)}))?;
        assert_eq!(get(&state,Method::GET,"/resource",Some(&format!("DPoP {token}")),Some(&signed),"").await?.0,StatusCode::UNAUTHORIZED);
        // The selected token is otherwise unchanged; a matching audience alone
        // cannot supply the separately required current management target flag.
        sqlx::query("UPDATE aegaeon.authorization_domain_targets SET management=false WHERE environment_id=$1 AND audience=$2")
            .bind(state.environment_id).bind(format!("{}/organizations",state.issuer)).execute(&f.pool).await?;
        inspect_context(&state,&key,&token,StatusCode::UNAUTHORIZED).await?;
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
