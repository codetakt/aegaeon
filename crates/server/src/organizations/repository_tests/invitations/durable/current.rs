//! Real selected-generation admission for durable producer tests.
use super::*;
use crate::organizations::{
    lifecycle::{Limits, Runtime},
    request_work::CapacityClass,
};
use std::{future::Future, str::FromStr, sync::Arc, time::Duration};

pub(super) struct CurrentFixture {
    pub fixture: InvitationFixture,
    admin: PgPool,
    runtime: Arc<Runtime>,
}

impl CurrentFixture {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut fixture = InvitationFixture::new().await?;
        // CI supplies an ordinary runtime login. Lifecycle selection belongs
        // to the explicit fixture administrator, in the same
        // disposable database (the administrator URL may name a control DB).
        let original = fixture.base.pool.connect_options();
        let admin_options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var(
            "AEGAEON_TEST_ADMIN_DATABASE_URL",
        )?)?
        .database(
            original
                .get_database()
                .ok_or("fixture database is missing")?,
        );
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(admin_options)
            .await?;
        let mut setup = admin.begin().await?;
        let previous: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT deployment_id,generation FROM aegaeon_lifecycle.current WHERE singleton",
        )
        .fetch_optional(&mut *setup)
        .await?;
        let deployment = previous.map_or_else(Uuid::new_v4, |p| p.0);
        let selection = Selection::new(deployment, Uuid::new_v4())?;
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
            .bind(deployment)
            .bind(previous.map(|p| p.1))
            .bind(selection.generation())
            .bind(Uuid::new_v4())
            .execute(&mut *setup)
            .await?;
        setup.commit().await?;
        // Reuse the fixture's restricted, password-authenticated endpoint.
        // Runtime::checked validates its role and binds the selected generation;
        // no additional login, password-bearing DDL or grants are needed here.
        let runtime = Runtime::checked(
            selection,
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(2)),
            original.as_ref().clone(),
            vec![(
                fixture.base.env.environment_id,
                fixture.base.env.issuer_url.clone(),
            )],
            Limits {
                ordinary: 3,
                revocation: 1,
                snapshot: 1,
            },
        )
        .await;
        let runtime = match runtime {
            Ok(runtime) => runtime,
            Err(error) => {
                admin.close().await;
                fixture.base.pool.close().await;
                return Err(Box::new(error));
            }
        };
        fixture.base.pool.close().await;
        fixture.base.pool = runtime.pool().clone();
        Ok(Self {
            fixture,
            admin,
            runtime,
        })
    }

    pub async fn run(&self, future: impl Future<Output = TestResult>) -> TestResult {
        let owner = self.runtime.admit(
            CapacityClass::Ordinary,
            Some(self.fixture.base.env.environment_id),
        )?;
        let result = owner.store_scope(future).await;
        let cleanup = owner.completion_for_test().await;
        cleanup?;
        result?
    }

    pub async fn finish(mut self, result: TestResult) -> TestResult {
        self.runtime.close().await;
        self.fixture.base.pool = self.admin;
        self.fixture.base.cleanup(result).await
    }
}
