use super::*;
use axum::{body::to_bytes, http::header};

pub(super) async fn reject_without_secrets(response: Response) -> ResultTest {
    assert!(!response.status().is_success());
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()?
        .contains("no-store"));
    let bytes = to_bytes(response.into_body(), 8192).await?;
    let body = std::str::from_utf8(&bytes)?;
    for value in [
        "private-subject",
        "private-access-token",
        "private-refresh",
        "changed-private-nonce",
    ] {
        assert!(!body.contains(value));
    }
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_captures_and_preserves_two_rotations() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let first = f.load().await.map_err(error)?;
            let original = first.original_authentication.clone();
            let (bytes, generation) = f.stored().await?;
            assert_eq!(generation, 1);
            for value in ["private-refresh-original", "private-subject", "nonce"] {
                assert!(!std::str::from_utf8(&bytes)?.contains(value));
            }
            let mut refreshed = claims.clone();
            refreshed.as_object_mut().ok_or("object")?.remove("nonce");
            refreshed
                .as_object_mut()
                .ok_or("object")?
                .remove("auth_time");
            f.refresh(&first, Some(&refreshed), Some("private-refresh-second"))
                .await
                .map_err(error)?;
            let second = f.load().await.map_err(error)?;
            assert_eq!(second.upstream_refresh_token_generation, 2);
            assert!(second.original_authentication == original);
            f.refresh(&second, None, Some("private-refresh-third"))
                .await
                .map_err(error)?;
            let third = f.load().await.map_err(error)?;
            assert_eq!(third.upstream_refresh_token_generation, 3);
            assert!(third.original_authentication == original);
            let before = f.stored().await?;
            f.refresh(&third, None, None).await.map_err(error)?;
            assert_eq!(before, f.stored().await?);
            let mut request = f.request.clone();
            request.nonce = "changed-private-nonce".into();
            let mut new_claims = claims.clone();
            new_claims["nonce"] = json!(request.nonce);
            new_claims["auth_time"] = json!(crate::web::now_epoch_secs()? - 5);
            let callback = f.callback_with_request(&new_claims, None, &request)?;
            f.store_callback(&callback).await.map_err(error)?;
            assert_eq!(before, f.stored().await?);
            let grant = open_upstream_refresh_token(
                &before.0,
                f.env.environment_id,
                &f.request.issuer,
                &f.subject_hash,
                f.request.context.connection_id,
                3,
            )
            .map_err(|e| format!("{e:?}"))?;
            assert!(grant.original == original);
            assert_eq!(grant.refresh_token, "private-refresh-third");
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_rejects_changed_signed_original_claims() -> ResultTest {
    run(true, |rt, f| {
        rt.block_on(async {
            let mut claims = f.claims()?;
            claims["aud"] = json!(["client", "other"]);
            claims["azp"] = json!("client");
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let link = f.load().await.map_err(error)?;
            let before = f.stored().await?;
            for (field, value) in [
                ("sub", json!("different-private-subject")),
                ("iss", json!("https://other.example")),
                ("aud", json!("client")),
                ("aud", json!(["client", "untrusted"])),
                ("nonce", json!("changed-private-nonce")),
                ("auth_time", json!(1)),
            ] {
                let mut next = claims.clone();
                next[field] = value;
                let response = match f
                    .refresh(&link, Some(&next), Some("private-refresh-rejected"))
                    .await
                {
                    Ok(_) => return Err(format!("accepted changed {field}").into()),
                    Err(r) => r,
                };
                reject_without_secrets(response).await?;
                assert_eq!(before, f.stored().await?);
            }
            let mut equivalent = claims.clone();
            equivalent["aud"] = json!(["other", "client", "other"]);
            f.refresh(&link, Some(&equivalent), None)
                .await
                .map_err(error)?;
            assert_eq!(before, f.stored().await?);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_rejects_added_auth_time_and_accepts_singleton_audience() -> ResultTest
{
    run(false, |rt, f| {
        rt.block_on(async {
            let mut original = f.claims()?;
            original
                .as_object_mut()
                .ok_or("object")?
                .remove("auth_time");
            f.store_callback(&f.callback(&original, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let link = f.load().await.map_err(error)?;
            let before = f.stored().await?;
            let mut added = original.clone();
            added["auth_time"] = json!(crate::web::now_epoch_secs()? - 1);
            let rejected = f
                .refresh(&link, Some(&added), Some("private-refresh-rejected"))
                .await
                .err()
                .ok_or("new auth_time accepted")?;
            reject_without_secrets(rejected).await?;
            assert_eq!(before, f.stored().await?);
            original["aud"] = json!(["client"]);
            original["azp"] = json!("client");
            f.refresh(&link, Some(&original), None)
                .await
                .map_err(error)?;
            assert_eq!(before, f.stored().await?);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_rejects_legacy_corrupt_and_changed_client_before_exchange(
) -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
        f.store_callback(&f.callback(&f.claims()?,Some("private-refresh-original"))?).await.map_err(error)?;
        let before=f.stored().await?;
        for bytes in [b"aeg-upstream-refresh-token-v2.legacy".to_vec(),b"aeg-upstream-refresh-token-v3.malformed".to_vec(),{let mut b=before.0.clone();let n=b.len();b[n-5]^=1;b}] {
            sqlx::query("UPDATE aegaeon.account_links SET upstream_refresh_token_encrypted=$1 WHERE id=$2").bind(&bytes).bind(f.link_id).execute(&f.pool).await?;
            // This is the production pre-exchange loader. It must not yield a
            // refresh token to the network stage for any inadmissible envelope.
            let response=f.load().await.err().ok_or("corrupt/legacy envelope admitted")?;reject_without_secrets(response).await?;
            assert_eq!(f.stored().await?.0,bytes);
        }
        sqlx::query("UPDATE aegaeon.account_links SET upstream_refresh_token_encrypted=$1 WHERE id=$2").bind(&before.0).bind(f.link_id).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.connections SET client_id='other-client' WHERE id=$1")
            .bind(f.request.context.connection_id).execute(&f.pool).await?;
        reject_without_secrets(f.load().await.err().ok_or("changed client admitted")?).await?;
        sqlx::query("UPDATE aegaeon.connections SET client_id='client' WHERE id=$1")
            .bind(f.request.context.connection_id).execute(&f.pool).await?;
        // The schema already refuses issuer rewrites; do not bypass that boundary.
        assert!(sqlx::query("UPDATE aegaeon.connections SET issuer_url='https://different.example' WHERE id=$1")
            .bind(f.request.context.connection_id).execute(&f.pool).await.is_err());
        sqlx::query("UPDATE aegaeon.account_links SET upstream_refresh_token_generation=2 WHERE id=$1").bind(f.link_id).execute(&f.pool).await?;
        reject_without_secrets(f.load().await.err().ok_or("wrong generation admitted")?).await?;
        sqlx::query("UPDATE aegaeon.account_links SET upstream_refresh_token_generation=1 WHERE id=$1").bind(f.link_id).execute(&f.pool).await?;
        std::env::set_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,URL_SAFE_NO_PAD.encode([0x52;32]));
        reject_without_secrets(f.load().await.err().ok_or("wrong key admitted")?).await?;
        std::env::set_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,URL_SAFE_NO_PAD.encode([0x51;32]));
        assert_eq!(before,f.stored().await?);Ok(())
    })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_callback_replacement_wins_stale_rotation() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let old = f.load().await.map_err(error)?;
            let replacement = f.callback(&claims, Some("private-refresh-replacement"))?;
            let mut tx = f.pool.begin().await?;
            persist_upstream_callback_refresh_token(
                &mut tx,
                &f.request,
                &replacement,
                &f.env.issuer_url,
            )
            .await
            .map_err(error)?;
            let pool = f.pool.clone();
            let issuer = f.env.issuer_url.clone();
            let profile = f.profile.clone();
            let (started, received) = tokio::sync::oneshot::channel();
            let mut pending = tokio::spawn(async move {
                let _ = started.send(());
                persist_upstream_refresh_exchange(
                    &pool,
                    &old,
                    &Fixture::response(None, Some("private-refresh-stale")),
                    &profile,
                    &issuer,
                )
                .await
            });
            received.await?;
            assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut pending)
                    .await
                    .is_err()
            );
            tx.commit().await?;
            let response = pending
                .await?
                .err()
                .ok_or("stale rotation overwritten callback")?;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            reject_without_secrets(response).await?;
            let current = f.load().await.map_err(error)?;
            assert_eq!(
                current.upstream_refresh_token,
                "private-refresh-replacement"
            );
            assert_eq!(current.upstream_refresh_token_generation, 2);
            // Stale no-rotation last-use update has the same generation predicate.
            let mut stale = current;
            stale.upstream_refresh_token_generation = 1;
            let before = f.stored().await?;
            assert!(persist_upstream_refresh_exchange(
                &f.pool,
                &stale,
                &Fixture::response(None, None),
                &f.profile,
                &f.env.issuer_url
            )
            .await
            .is_err());
            assert_eq!(before, f.stored().await?);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_preserves_grant_on_storage_failure_and_bad_capture() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let before = f.stored().await?;
            let link = f.load().await.map_err(error)?;
            let mut bad = f.callback(&claims, Some("private-refresh-bad"))?;
            bad.id_token.claims.sub = "unlinked-subject".into();
            assert!(f.store_callback(&bad).await.is_err());
            assert_eq!(before, f.stored().await?);
            let closed = sqlx::postgres::PgPoolOptions::new()
                .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
                .await?;
            closed.close().await;
            let rejected = persist_upstream_refresh_exchange(
                &closed,
                &link,
                &Fixture::response(None, Some("private-refresh-unwritten")),
                &f.profile,
                &f.env.issuer_url,
            )
            .await
            .err()
            .ok_or("closed pool accepted")?;
            reject_without_secrets(rejected).await?;
            assert_eq!(before, f.stored().await?);
            Ok(())
        })
    })
}
