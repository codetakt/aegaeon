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
    role: String,
}

impl CurrentFixture {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut fixture = InvitationFixture::new().await?;
        // CI supplies an ordinary runtime login. Lifecycle selection and role
        // creation belong to the explicit fixture administrator, in the same
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
        let role = format!("notification_fixture_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        sqlx::raw_sql(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
             GRANT USAGE ON SCHEMA aegaeon,aegaeon_lifecycle TO {role};
             GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA aegaeon TO {role};
             GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA aegaeon TO {role};
             GRANT SELECT ON aegaeon_lifecycle.current TO {role};"
        ))
        .execute(&mut *setup)
        .await?;
        setup.commit().await?;
        let runtime = Runtime::checked(
            selection,
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(2)),
            original
                .as_ref()
                .clone()
                .username(&role)
                .password(&password),
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
                let cleanup = sqlx::raw_sql(&format!("DROP OWNED BY {role}; DROP ROLE {role};"))
                    .execute(&admin)
                    .await;
                admin.close().await;
                fixture.base.pool.close().await;
                cleanup?;
                return Err(Box::new(error));
            }
        };
        fixture.base.pool.close().await;
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
