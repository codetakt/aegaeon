use super::*;

async fn bounded(entity: bool) -> TestResult {
    let f = Fixture::new().await?;
    let table = if entity {
        "federation_entity_cache"
    } else {
        "federation_trust_chains"
    };
    let result:TestResult=async {
        for env in [f.own.environment_id,f.foreign.environment_id] {
            let query=if entity {
                "INSERT INTO aegaeon.federation_entity_cache(environment_id,entity_id,entity_configuration_jws,parsed_statement,expires_at) SELECT $1,'https://expired.example/'||i,'expired','{}',now()-interval '1 hour' FROM generate_series(1,101) i"
            } else {
                "INSERT INTO aegaeon.federation_trust_chains(environment_id,leaf_entity_id,anchor_entity_id,chain_jwts,resolved_at,expires_at) SELECT $1,'https://expired.example/'||i,'https://anchor.example','[\"expired-fixture-jws\"]',now()-interval '2 hours',now()-interval '1 hour' FROM generate_series(1,101) i"
            };
            sqlx::query(query).bind(env).execute(&f.pool).await?;
        }
        let before=f.snapshot(f.foreign.environment_id).await?;
        let now=crate::federation::repositories::clock::current_unix_epoch_secs()?;
        let removed=f.witness.run(async {
            if entity {PgEntityCacheRepository::new(f.pool.clone()).cleanup_expired(now).await}
            else {PgTrustChainCacheRepository::new(f.pool.clone()).cleanup_expired(now).await}
        }).await??;
        if removed!=100 {return Err(format!("cleanup removed {removed} rows, expected bounded100").into());}
        let remaining:i64=sqlx::query_scalar(&format!("SELECT count(*) FROM aegaeon.{table} WHERE environment_id=$1 AND expires_at <= to_timestamp($2::bigint)")).bind(f.own.environment_id).bind(now).fetch_one(&f.pool).await?;
        if remaining!=1 || before!=f.snapshot(f.foreign.environment_id).await? {return Err("cleanup crossed scope or lost remainder".into());}
        let removed=if entity {PgEntityCacheRepository::new(f.pool.clone()).cleanup_expired(now).await?}
            else {PgTrustChainCacheRepository::new(f.pool.clone()).cleanup_expired(now).await?};
        if removed!=102 {return Err("ordinary unscoped cleanup behavior changed".into());}
        Ok(())
    }.await;
    f.finish(result).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; bounded scoped federation cache expiry"]
async fn pg_organizations_federation_entity_cleanup_scope_bound() -> TestResult {
    bounded(true).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; bounded scoped federation cache expiry"]
async fn pg_organizations_federation_chain_cleanup_scope_bound() -> TestResult {
    bounded(false).await
}
