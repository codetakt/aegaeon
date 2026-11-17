//! Real selected-generation admission for durable producer tests.
use super::*;
use crate::organizations::{
    lifecycle::{Limits, Runtime},
    request_work::CapacityClass,
};
use std::{future::Future, sync::Arc, time::Duration};

pub(super) struct CurrentFixture {
    pub fixture: InvitationFixture,
    admin: PgPool,
    runtime: Arc<Runtime>,
    role: String,
}

impl CurrentFixture {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut fixture = InvitationFixture::new().await?;
        let admin = fixture.base.pool.clone();
        let previous: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT deployment_id,generation FROM aegaeon_lifecycle.current WHERE singleton",
        )
        .fetch_optional(&admin)
        .await?;
        let deployment = previous.map_or_else(Uuid::new_v4, |p| p.0);
        let selection = Selection::new(deployment, Uuid::new_v4())?;
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
            .bind(deployment)
            .bind(previous.map(|p| p.1))
            .bind(selection.generation())
            .bind(Uuid::new_v4())
            .execute(&admin)
            .await?;
        let role = format!("notification_fixture_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(&format!(
            "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
             GRANT USAGE ON SCHEMA aegaeon,aegaeon_lifecycle TO {role};
             GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA aegaeon TO {role};
             GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA aegaeon TO {role};
             GRANT SELECT ON aegaeon_lifecycle.current TO {role};"
        ))
        .execute(&admin)
        .await?;
        let runtime = Runtime::checked(
            selection,
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(2)),
            admin.connect_options().as_ref().clone().username(&role),
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
        .await?;
        fixture.base.pool = runtime.pool().clone();
        Ok(Self {
            fixture,
            admin,
            runtime,
            role,
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
        sqlx::raw_sql(&format!(
            "DROP OWNED BY {}; DROP ROLE {};",
            self.role, self.role
        ))
        .execute(&self.fixture.base.pool)
        .await?;
        self.fixture.base.cleanup(result).await
    }
}
