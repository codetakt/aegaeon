use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, sample_registered_client, setup_test_environment, test_pg_pool,
    TestEnvironment, TestResult,
};
use serde_json::Value;

mod ownership;

const TOKEN: &str = "registration-owner-fixture-token";
#[derive(Clone, Copy, Debug)]
enum Call {
    Environment,
    Bearer,
    Read,
    Create,
    Update,
    Delete,
}
struct Record {
    client: RegisteredClient,
    stored: DcrStoredClient,
    token: String,
}
impl Call {
    async fn run(self, pool: &PgPool, env: &TestEnvironment, row: &Record) -> TestResult {
        match self {
            Self::Environment => {
                let found = environment::load_active_environment(pool, &env.issuer_host).await?;
                if found.environment_id != env.environment_id {
                    return Err("wrong Environment".into());
                }
            }
            Self::Bearer => {
                if load_dcr_bearer_token_hash_for_issuer_host(pool, &env.issuer_host)
                    .await?
                    .as_deref()
                    != Some(&dcr_bearer_token_hash(TOKEN))
                {
                    return Err("bearer hash absent".into());
                }
            }
            Self::Read => {
                load_dynamic_registration_by_token(
                    pool,
                    &env.issuer_host,
                    &row.client.client_id,
                    &row.token,
                )
                .await?
                .ok_or("registration absent")?;
            }
            Self::Create => {
                let client = sample_registered_client(&format!("created-{}", Uuid::new_v4()));
                create_dynamic_registration(
                    pool,
                    &env.issuer_host,
                    &client,
                    &["code".into()],
                    &format!("create-token-{}", Uuid::new_v4()),
                    "owned-create",
                )
                .await?;
            }
            Self::Update => {
                update_dynamic_registration(
                    pool,
                    &row.stored,
                    &row.client,
                    &["code".into()],
                    &row.token,
                    DcrClientSecretChange::Preserve,
                    None,
                    "owned-update",
                )
                .await?;
            }
            Self::Delete => {
                delete_dynamic_registration(pool, &row.stored, "owned-delete").await?;
            }
        }
        Ok(())
    }
}
struct Fixture {
    pool: PgPool,
    own: TestEnvironment,
    foreign: TestEnvironment,
    witness: CallerFixture,
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let own = setup_test_environment(&pool).await?;
        let foreign = setup_test_environment(&pool).await?;
        for env in [own.environment_id, foreign.environment_id] {
            sqlx::query("INSERT INTO aegaeon.environment_dcr_bearer_tokens(environment_id,token_hash,token_hash_algorithm) VALUES($1,$2,'sha256')").bind(env).bind(dcr_bearer_token_hash(TOKEN)).execute(&pool).await?;
        }
        let witness = CallerFixture::new(own.environment_id).await?;
        Ok(Self {
            pool,
            own,
            foreign,
            witness,
        })
    }
    async fn record(&self, env: &TestEnvironment) -> TestResult<Record> {
        let client = sample_registered_client(&format!("registered-{}", Uuid::new_v4()));
        let token = format!("record-token-{}", Uuid::new_v4());
        create_dynamic_registration(
            &self.pool,
            &env.issuer_host,
            &client,
            &["code".into()],
            &token,
            "owned-setup",
        )
        .await?;
        let stored = load_dynamic_registration_by_token(
            &self.pool,
            &env.issuer_host,
            &client.client_id,
            &token,
        )
        .await?
        .ok_or("registration setup absent")?;
        Ok(Record {
            client,
            stored,
            token,
        })
    }
    async fn snapshot(&self, env: Uuid) -> TestResult<Value> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c WHERE environment_id=$1),(SELECT jsonb_agg(to_jsonb(d) ORDER BY client_id) FROM aegaeon.dynamic_client_registrations d WHERE environment_id=$1),(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM aegaeon.client_secrets s WHERE environment_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1))").bind(env).fetch_one(&self.pool).await?)
    }
    async fn finish(self, result: TestResult) -> TestResult {
        let witness = self.witness.finish().await.map_err(Into::into);
        let own = cleanup_test_environment(&self.pool, &self.own)
            .await
            .map_err(Into::into);
        let foreign = cleanup_test_environment(&self.pool, &self.foreign)
            .await
            .map_err(Into::into);
        self.pool.close().await;
        result.and(witness).and(own).and(foreign)
    }
}
async fn scope(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        // Establish ordinary behavior with valid records in both Environments.
        for env in [&f.own, &f.foreign] {
            call.run(&f.pool, env, &f.record(env).await?).await?;
        }
        let own = f.record(&f.own).await?;
        let foreign = f.record(&f.foreign).await?;
        f.witness.run(call.run(&f.pool, &f.own, &own)).await??;
        let before = f.snapshot(f.foreign.environment_id).await?;
        if f.witness
            .run(call.run(&f.pool, &f.foreign, &foreign))
            .await?
            .is_ok()
        {
            return Err(format!("{call:?} accepted foreign registration authority").into());
        }
        if before != f.snapshot(f.foreign.environment_id).await? {
            return Err("foreign registration changed after refusal".into());
        }
        call.run(&f.pool, &f.foreign, &foreign).await?;
        if f.witness.pending().await? != 0 {
            return Err("finished registration remains pending".into());
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}
macro_rules! scope_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual registration Environment ownership"]
        async fn $name() -> TestResult {
            scope(Call::$case).await
        }
    };
}
scope_test!(pg_organizations_registration_environment_scope, Environment);
scope_test!(pg_organizations_registration_bearer_scope, Bearer);
scope_test!(pg_organizations_registration_read_scope, Read);
scope_test!(pg_organizations_registration_create_scope, Create);
scope_test!(pg_organizations_registration_update_scope, Update);
scope_test!(pg_organizations_registration_delete_scope, Delete);
