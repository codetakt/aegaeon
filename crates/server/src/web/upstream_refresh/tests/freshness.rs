use super::cases::reject_without_secrets;
use super::*;

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_rejects_old_signed_token_before_persistence() -> ResultTest {
    run(true, |rt, f| {
        rt.block_on(async {
            let mut original = f.claims()?;
            let now = crate::web::now_epoch_secs()?;
            // Still unexpired and accepted at initial authentication, but too old for refresh.
            original["iat"] = json!(now - 600);
            f.store_callback(&f.callback(&original, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let link = f.load().await.map_err(error)?;
            let before = f.stored().await?;
            for rotation in [None, Some("private-refresh-rejected")] {
                let response = f
                    .refresh(&link, Some(&original), rotation)
                    .await
                    .err()
                    .ok_or("old signed ID token accepted")?;
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                reject_without_secrets(response).await?;
                assert_eq!(before, f.stored().await?);
            }
            let mut fresh = original.clone();
            fresh["iat"] = json!(crate::web::now_epoch_secs()?);
            f.refresh(&link, Some(&fresh), None).await.map_err(error)?;
            // Existing upper-time and expiry checks remain conjunctive.
            for (field, value) in [("iat", now + 600), ("exp", now - 600)] {
                let mut invalid = fresh.clone();
                invalid[field] = json!(value);
                reject_without_secrets(
                    f.refresh(&link, Some(&invalid), Some("private-refresh-rejected"))
                        .await
                        .err()
                        .ok_or("invalid time accepted")?,
                )
                .await?;
                assert_eq!(before, f.stored().await?);
            }
            // An absent ID Token has no iat requirement and still preserves context.
            f.refresh(&link, None, Some("private-refresh-next"))
                .await
                .map_err(error)?;
            assert!(
                f.load().await.map_err(error)?.original_authentication
                    == link.original_authentication
            );
            Ok(())
        })
    })
}
