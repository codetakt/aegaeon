use super::*;
use crate::federation::{
    EntityCacheRepository, FederationError, TrustAnchorRepository, TrustChainCacheRepository,
};
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod cleanup;
mod ownership;

const ENTITY: &str = "https://entity.example/fixture";
const ANCHOR: &str = "https://anchor.example/fixture";

#[derive(Clone, Copy, Debug)]
enum Call {
    AnchorList,
    AnchorGet,
    AnchorUpsert,
    AnchorDelete,
    EntityGet,
    EntityUpsert,
    ChainGet,
    ChainUpsert,
}
impl Call {
    async fn run(self, pool: &PgPool, env: Uuid) -> Result<(), FederationError> {
        let anchor = PgTrustAnchorRepository::new(pool.clone());
        let entity = PgEntityCacheRepository::with_max_entries(pool.clone(), 200);
        let chain = PgTrustChainCacheRepository::with_max_entries(pool.clone(), 200);
        let now = crate::federation::repositories::clock::current_unix_epoch_secs()?;
        let exists = match self {
            Self::AnchorList => anchor.list_for_environment(env).await?.len() == 1,
            Self::AnchorGet => anchor.get(env, ANCHOR).await?.is_some(),
            Self::AnchorUpsert => {
                anchor
                    .upsert(env, ANCHOR, &json!({"keys":[],"fixture":"updated"}), None)
                    .await?;
                true
            }
            Self::AnchorDelete => {
                anchor.delete(env, ANCHOR).await?;
                true
            }
            Self::EntityGet => entity.get(env, ENTITY, now).await?.is_some(),
            Self::EntityUpsert => {
                entity
                    .upsert(
                        env,
                        ENTITY,
                        "updated-jws",
                        &json!({"updated":true}),
                        now + 3600,
                    )
                    .await?;
                true
            }
            Self::ChainGet => chain.get(env, ENTITY, ANCHOR, now).await?.is_some(),
            Self::ChainUpsert => {
                chain
                    .upsert(env, ENTITY, ANCHOR, &json!(["updated-chain"]), now + 3600)
                    .await?;
                true
            }
        };
        if exists {
            Ok(())
        } else {
            Err(FederationError::Validation("fixture record absent".into()))
        }
    }
}

struct Fixture {
    pool: PgPool,
    own: TestEnvironment,
    foreign: TestEnvironment,
    witness: CallerFixture,
}
impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let own = setup_test_environment(&pool).await?;
        let foreign = setup_test_environment(&pool).await?;
        let witness = CallerFixture::new(own.environment_id).await?;
        let fixture = Self {
            pool,
            own,
            foreign,
            witness,
        };
        fixture.seed().await?;
        Ok(fixture)
    }
    async fn seed(&self) -> TestResult {
        for env in [self.own.environment_id, self.foreign.environment_id] {
            sqlx::query("INSERT INTO aegaeon.federation_trust_anchors(environment_id,entity_id,jwks) VALUES($1,$2,$3) ON CONFLICT(environment_id,entity_id) DO UPDATE SET jwks=EXCLUDED.jwks")
                .bind(env).bind(ANCHOR).bind(json!({"keys":[]})).execute(&self.pool).await?;
            sqlx::query("INSERT INTO aegaeon.federation_entity_cache(environment_id,entity_id,entity_configuration_jws,parsed_statement,expires_at) VALUES($1,$2,'initial-jws',$3,now()+interval '1 hour') ON CONFLICT(environment_id,entity_id) DO UPDATE SET entity_configuration_jws=EXCLUDED.entity_configuration_jws,parsed_statement=EXCLUDED.parsed_statement")
                .bind(env).bind(ENTITY).bind(json!({})).execute(&self.pool).await?;
            sqlx::query("INSERT INTO aegaeon.federation_trust_chains(environment_id,leaf_entity_id,anchor_entity_id,chain_jwts,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour') ON CONFLICT(environment_id,leaf_entity_id,anchor_entity_id) DO UPDATE SET chain_jwts=EXCLUDED.chain_jwts")
                .bind(env).bind(ENTITY).bind(ANCHOR).bind(json!(["initial-chain"])).execute(&self.pool).await?;
        }
        Ok(())
    }
    async fn snapshot(&self, env: Uuid) -> Result<Value, sqlx::Error> {
        sqlx::query_scalar("SELECT jsonb_build_array((SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM aegaeon.federation_trust_anchors a WHERE environment_id=$1),(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM aegaeon.federation_entity_cache e WHERE environment_id=$1),(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM aegaeon.federation_trust_chains c WHERE environment_id=$1))")
            .bind(env).fetch_one(&self.pool).await
    }
    async fn finish(self, result: TestResult) -> TestResult {
        let owner_cleanup = self.witness.finish().await.map_err(Into::into);
        let mut cleanup = Ok(());
        for env in [&self.own, &self.foreign] {
            for table in [
                "federation_trust_chains",
                "federation_entity_cache",
                "federation_trust_anchors",
            ] {
                let outcome = sqlx::query(&format!(
                    "DELETE FROM aegaeon.{table} WHERE environment_id=$1"
                ))
                .bind(env.environment_id)
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(Into::into);
                cleanup = cleanup.and(outcome);
            }
            cleanup = cleanup.and(
                cleanup_test_environment(&self.pool, env)
                    .await
                    .map_err(Into::into),
            );
        }
        self.pool.close().await;
        result.and(owner_cleanup).and(cleanup)
    }
}
async fn scoped(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        call.run(&f.pool, f.own.environment_id).await?;
        call.run(&f.pool, f.foreign.environment_id).await?;
        f.seed().await?;
        f.witness
            .run(call.run(&f.pool, f.own.environment_id))
            .await??;
        let before = f.snapshot(f.foreign.environment_id).await?;
        if f.witness
            .run(call.run(&f.pool, f.foreign.environment_id))
            .await?
            .is_ok()
        {
            return Err(format!("{call:?} accepted a foreign Environment").into());
        }
        if before != f.snapshot(f.foreign.environment_id).await? {
            return Err("foreign federation state changed".into());
        }
        if f.witness.pending().await? != 0 {
            return Err("completed repository call remains pending".into());
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}
macro_rules! scope_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual federation scope"]
        async fn $name() -> TestResult {
            scoped(Call::$case).await
        }
    };
}
scope_test!(pg_organizations_federation_anchor_list_scope, AnchorList);
scope_test!(pg_organizations_federation_anchor_get_scope, AnchorGet);
scope_test!(
    pg_organizations_federation_anchor_upsert_scope,
    AnchorUpsert
);
scope_test!(
    pg_organizations_federation_anchor_delete_scope,
    AnchorDelete
);
scope_test!(pg_organizations_federation_entity_get_scope, EntityGet);
scope_test!(
    pg_organizations_federation_entity_upsert_scope,
    EntityUpsert
);
scope_test!(pg_organizations_federation_chain_get_scope, ChainGet);
scope_test!(pg_organizations_federation_chain_upsert_scope, ChainUpsert);
