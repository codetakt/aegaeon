use super::cases::reject_without_secrets;
use super::currentness::{snapshot, wait_for_blocker};
use super::*;

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_revalidates_secret_and_effective_profile() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
        let claims=f.claims()?;
        f.store_callback(&f.callback(&claims,Some("private-refresh-original"))?).await.map_err(error)?;
        let link=f.load().await.map_err(error)?;
        let profile_id=Uuid::parse_str(&f.profile.id)?;
        let alternative:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed) SELECT environment_id,configuration_version_id,'alternate','UPSTREAM',false,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed FROM aegaeon.oauth_profiles WHERE id=$1 RETURNING id")
            .bind(profile_id).fetch_one(&f.pool).await?;
        for rotation in [None,Some("private-refresh-rejected")] {
            for (table,id,change,restore) in [
                ("connections",link.upstream_connection_id,"client_secret_encrypted=decode('01','hex')","client_secret_encrypted=NULL"),
                ("oauth_profiles",profile_id,"allowed_grant_types=ARRAY['authorization_code']","allowed_grant_types=ARRAY['authorization_code','refresh_token']"),
                ("oauth_profiles",profile_id,"expires_at=now()-interval '1 second'","expires_at=NULL"),
                ("oauth_profiles",profile_id,"status='RETIRED'","status='ACTIVE'"),
            ] {
                sqlx::query(&format!("UPDATE aegaeon.{table} SET {change} WHERE id=$1")).bind(id).execute(&f.pool).await?;
                let before=snapshot(f).await?;
                let rejected=f.refresh(&link,None,rotation).await.err().ok_or("stale credential/policy accepted")?;
                assert_eq!(rejected.status(),StatusCode::CONFLICT);
                reject_without_secrets(rejected).await?;
                assert_eq!(before,snapshot(f).await?);
                sqlx::query(&format!("UPDATE aegaeon.{table} SET {restore} WHERE id=$1")).bind(id).execute(&f.pool).await?;
            }
            // Explicit reassignment and changing the effective default both reject,
            // even if the replacement currently has equivalent policy fields.
            for default_switch in [false,true] {
                let mut tx=f.pool.begin().await?;
                if default_switch {
                    sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=false WHERE id=$1").bind(profile_id).execute(&mut *tx).await?;
                    sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=true WHERE id=$1").bind(alternative).execute(&mut *tx).await?;
                } else {
                    sqlx::query("UPDATE aegaeon.connections SET oauth_profile_id=$1 WHERE id=$2").bind(alternative).bind(link.upstream_connection_id).execute(&mut *tx).await?;
                }
                tx.commit().await?;
                let before=snapshot(f).await?;
                let rejected=f.refresh(&link,None,rotation).await.err().ok_or("profile replacement accepted")?;
                assert_eq!(rejected.status(),StatusCode::CONFLICT);
                reject_without_secrets(rejected).await?;
                assert_eq!(before,snapshot(f).await?);
                let mut tx=f.pool.begin().await?;
                sqlx::query("UPDATE aegaeon.connections SET oauth_profile_id=NULL WHERE id=$1").bind(link.upstream_connection_id).execute(&mut *tx).await?;
                sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=false WHERE id=$1").bind(alternative).execute(&mut *tx).await?;
                sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=true WHERE id=$1").bind(profile_id).execute(&mut *tx).await?;
                tx.commit().await?;
            }
        }
        Ok(())
    })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_serializes_effective_profile_updates() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
        let claims=f.claims()?;
        f.store_callback(&f.callback(&claims,Some("private-refresh-original"))?).await.map_err(error)?;
        let profile_id=Uuid::parse_str(&f.profile.id)?;
        for rotation in [None,Some("private-refresh-next")] {
            let link=f.load().await.map_err(error)?;
            let before=snapshot(f).await?;
            let mut change=f.pool.begin().await?;
            let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *change).await?;
            sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code'] WHERE id=$1").bind(profile_id).execute(&mut *change).await?;
            let pool=f.pool.clone(); let issuer=f.env.issuer_url.clone();let profile=f.profile.clone();
            let pending=tokio::spawn(async move { persist_upstream_refresh_exchange(&pool,&link,&Fixture::response(None,rotation),&profile,&issuer).await });
            wait_for_blocker(&f.pool,blocker).await?;
            change.commit().await?;
            let rejected=pending.await?.err().ok_or("concurrent policy change accepted")?;
            assert_eq!(rejected.status(),StatusCode::CONFLICT);reject_without_secrets(rejected).await?;
            assert_eq!(before,snapshot(f).await?);
            sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code','refresh_token'] WHERE id=$1").bind(profile_id).execute(&f.pool).await?;

            let link=f.load().await.map_err(error)?;
            let mut refresh=f.pool.begin().await?;
            let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *refresh).await?;
            super::super::persistence::lock_current_connection(&mut refresh,&link,&f.profile,&f.env.issuer_url).await.map_err(error)?;
            let pool=f.pool.clone();
            let pending=tokio::spawn(async move {sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code'] WHERE id=$1").bind(profile_id).execute(&pool).await});
            wait_for_blocker(&f.pool,blocker).await?;
            super::super::persistence::persist_locked_upstream_refresh_exchange(&mut refresh,&link,&Fixture::response(None,rotation),&f.env.issuer_url).await.map_err(error)?;
            refresh.commit().await?; assert_eq!(pending.await??.rows_affected(),1);
            assert_eq!(snapshot(f).await?.1,link.upstream_refresh_token_generation+i64::from(rotation.is_some()));
            sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code','refresh_token'] WHERE id=$1").bind(profile_id).execute(&f.pool).await?;
        }
        Ok(())
    })
    })
}
