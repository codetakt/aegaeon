//! Actual authenticated API flows under retained data-store observations.
use super::*;
use crate::dcr_persistence::test_database::Database;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

struct ObservedFixture {
    database: Database,
    product: Fixture,
    state: AppState,
    witness: CallerFixture,
}
impl ObservedFixture {
    async fn new(resource: bool) -> TestResult<Self> {
        let database = Database::create(false).await?;
        let product = Fixture::with_pool(database.pool.clone(), IDENTIFIER).await?;
        let state = if resource {
            resource::setup(&product).await?
        } else {
            fixture::state(&product).await?
        };
        let options = state.db_pool.connect_options().as_ref().clone();
        let role = options.get_username().replace('"', r#""""#);
        sqlx::query(&format!(
            "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO \"{role}\""
        ))
        .execute(&database.admin)
        .await?;
        let token = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let witness =
            CallerFixture::with_observed_stores(state.environment_id, options, token).await?;
        Ok(Self {
            database,
            product,
            state,
            witness,
        })
    }
    async fn finish(self, result: TestResult) -> TestResult {
        let witness = self
            .witness
            .finish()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
        let state = fixture::finish(&self.state).await;
        if state.is_ok() {
            assert!(self.state.db_pool.is_closed());
            assert!(self
                .state
                .management
                .database
                .as_ref()
                .is_none_or(sqlx::PgPool::is_closed));
        }
        let product = self.product.cleanup(result.and(witness).and(state)).await;
        let database = self
            .database
            .cleanup()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
        product.and(database)
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual authenticated token flow under observed work"]
async fn shared_redis_organizations_observed_protocol_exchange_and_introspection() -> TestResult {
    let mut f = ObservedFixture::new(false).await?;
    let result = async {
        f.witness
            .run(Box::pin(happy::flow(&f.product, &f.state)))
            .await??;
        if f.witness.pending().await? != 0
            || f.witness.completed_observations().await? == 0
            || f.witness.completed_parent_generation().await? == 0
        {
            return Err("protocol completed without its store observation".into());
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual resource epoch retirement under observed work"]
async fn shared_redis_organizations_observed_protocol_resource_retirement() -> TestResult {
    let mut f = ObservedFixture::new(true).await?;
    let result = async {
        Box::pin(resource::route_epoch::exercise(
            &f.product,
            &f.state,
            &mut f.witness,
        ))
        .await?;
        if f.witness.pending().await? != 0
            || f.witness.completed_observations().await? == 0
            || f.witness.completed_parent_generation().await? == 0
        {
            return Err("protocol completed without its store observation".into());
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; complete mounted observed HTTP resource execution"]
async fn shared_redis_organizations_observed_protocol_http_response_completion() -> TestResult {
    let mut f = ObservedFixture::new(true).await?;
    let mut witness = Arc::new(f.witness);
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = witness
            .run(Box::pin(resource::issue(
                &f.product,
                &f.state,
                &key,
                "organization.context.read",
            )))
            .await??;
        for method in [axum::http::Method::GET, axum::http::Method::HEAD] {
            let previous = Arc::get_mut(&mut witness)
                .ok_or("retained HTTP fixture")?
                .observed_generation()
                .await?;
            let parent_previous = Arc::get_mut(&mut witness)
                .ok_or("retained HTTP fixture")?
                .completed_parent_generation()
                .await?;
            let signed = resource::proof(&f.state, &key, &token, method.as_str(), json!({}))?;
            let (status, body) = resource::get_admitted(
                &witness,
                &f.state,
                method.clone(),
                "/organizations/context",
                Some(&format!("DPoP {token}")),
                Some(&signed),
                "",
            )
            .await?;
            if status != StatusCode::OK {
                return Err(format!("observed HTTP refused: {status} {body}").into());
            }
            if method == axum::http::Method::GET
                && (body["organization"]["externalId"] != IDENTIFIER
                    || body["organization"]["id"] != f.product.organization.id.to_string())
            {
                return Err("observed HTTP changed exact identifiers".into());
            }
            if witness.pending().await? != 0
                || Arc::get_mut(&mut witness)
                    .ok_or("retained HTTP fixture")?
                    .observed_generation()
                    .await?
                    <= previous
                || Arc::get_mut(&mut witness)
                    .ok_or("retained HTTP fixture")?
                    .completed_parent_generation()
                    .await?
                    <= parent_previous
            {
                return Err("HTTP used an unobserved admission".into());
            }
        }
        Ok(())
    }
    .await;
    f.witness = Arc::try_unwrap(witness).map_err(|_| "retained observed fixture")?;
    f.finish(result).await
}
