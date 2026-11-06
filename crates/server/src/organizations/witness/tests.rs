use super::*;
use sqlx::{postgres::PgConnectOptions, Executor};

mod abandonment;
mod admission_execution;
mod attribution;
pub(crate) mod caller_fixture;
mod catalog_rules;
mod creation;
mod current_catalog;
mod deployment;
mod dispatch;
mod history;
mod http_execution;
mod maintenance;
mod observed_http;
mod observed_work;
mod parent_admission;
mod pending;
mod periodic;
mod primary_callers;
mod recovery;
pub(crate) mod scope_fixture;
mod startup_preflight;
mod store_continuity;
mod store_progress;
mod store_supplier;
mod token_work;
mod work;

type TestResult = anyhow::Result<()>;

struct Fixture {
    admin: PgConnection,
    owner: PgConnection,
    options: PgConnectOptions,
    database: String,
    runtime: String,
    maintenance: String,
    runtime_password: String,
    maintenance_password: String,
    control_store_supplier_installed: bool,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        Self::with_version(16).await
    }
    async fn with_version(version: usize) -> anyhow::Result<Self> {
        let options: PgConnectOptions =
            std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
        let mut admin = PgConnection::connect_with(&options).await?;
        let id = Uuid::new_v4().simple().to_string();
        let database = format!("organization_witness_{id}");
        let runtime = format!("witness_runtime_{id}");
        let maintenance = format!("witness_maintenance_{id}");
        admin
            .execute(format!("CREATE DATABASE {database}").as_str())
            .await?;
        let runtime_password = Uuid::new_v4().simple().to_string();
        let maintenance_password = Uuid::new_v4().simple().to_string();
        let options = options.database(&database);
        let mut owner = PgConnection::connect_with(&options).await?;
        let schemas = [
            include_str!("../../../../../db/organization-witness/schema-v1.sql"),
            include_str!("../../../../../db/organization-witness/schema-v2.sql"),
            include_str!("../../../../../db/organization-witness/schema-v3.sql"),
            include_str!("../../../../../db/organization-witness/schema-v4.sql"),
            include_str!("../../../../../db/organization-witness/schema-v5.sql"),
            include_str!("../../../../../db/organization-witness/schema-v6.sql"),
            include_str!("../../../../../db/organization-witness/schema-v7.sql"),
            include_str!("../../../../../db/organization-witness/schema-v8.sql"),
            include_str!("../../../../../db/organization-witness/schema-v9.sql"),
            include_str!("../../../../../db/organization-witness/schema-v10.sql"),
            include_str!("../../../../../db/organization-witness/schema-v11.sql"),
            include_str!("../../../../../db/organization-witness/schema-v12.sql"),
            include_str!("../../../../../db/organization-witness/schema-v13.sql"),
            include_str!("../../../../../db/organization-witness/schema-v14.sql"),
            include_str!("../../../../../db/organization-witness/schema-v15.sql"),
            include_str!("../../../../../db/organization-witness/schema-v16.sql"),
        ];
        anyhow::ensure!((1..=schemas.len()).contains(&version));
        for schema in &schemas[..version] {
            sqlx::raw_sql(schema).execute(&mut owner).await?;
        }
        sqlx::raw_sql(&format!("CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' IN ROLE aegaeon_organization_witness_runtime; CREATE ROLE {maintenance} LOGIN PASSWORD '{maintenance_password}' IN ROLE aegaeon_organization_witness_maintenance;")).execute(&mut owner).await?;
        Ok(Self {
            admin,
            owner,
            options,
            database,
            runtime,
            maintenance,
            runtime_password,
            maintenance_password,
            control_store_supplier_installed: false,
        })
    }
    async fn connect(&self, role: Role) -> Result<Control> {
        let (user, password) = match role {
            Role::Runtime => (&self.runtime, &self.runtime_password),
            Role::Maintenance => (&self.maintenance, &self.maintenance_password),
        };
        // Test-only isolated local supplier. Production connect always verifies TLS.
        let connection =
            PgConnection::connect_with(&self.options.clone().username(user).password(password))
                .await?;
        Control::checked(connection, role).await
    }
    async fn finish(mut self) -> TestResult {
        self.owner.close().await?;
        for _ in 0..100 {
            let remaining: i64 =
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
                    .bind(&self.database)
                    .fetch_one(&mut self.admin)
                    .await?;
            if remaining == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
                .bind(&self.database)
                .fetch_one(&mut self.admin)
                .await?;
        assert_eq!(remaining, 0, "all witness connections must actually finish");
        self.admin
            .execute(format!("DROP DATABASE {}", self.database).as_str())
            .await?;
        sqlx::raw_sql(&format!("DROP ROLE {},{},aegaeon_organization_witness_runtime,aegaeon_organization_witness_maintenance,aegaeon_organization_witness_owner",self.runtime,self.maintenance)).execute(&mut self.admin).await?;
        self.admin.close().await?;
        Ok(())
    }
}
// Explicit test setup, never a production registration fallback. Each fixture
// has one deployment; additional Environments use that same registered parent.
async fn register_parent(control: &mut Control, scope: Scope) -> TestResult {
    control
        .value(
            sqlx::query_scalar("SELECT organization_witness.deployment_initialize($1,$2)")
                .bind(scope.deployment_id)
                .bind(Uuid::new_v4()),
        )
        .await?;
    Ok(())
}
fn selection() -> Selection {
    Selection {
        epoch: Uuid::new_v4(),
        primary: Uuid::new_v4(),
        token_store: Uuid::new_v4(),
        source_sha256: "a".repeat(64),
        history_sha256: "b".repeat(64),
        acceptance_sha256: "c".repeat(64),
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis administrator; creates and removes its own control database and roles"]
async fn shared_redis_organizations_witness_serializes_fence_and_retains_uncertain_work(
) -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = exercise(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn exercise(f: &mut Fixture) -> TestResult {
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let mut second_maintenance = f.connect(Role::Maintenance).await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    let mut second_runtime = f.connect(Role::Runtime).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    assert!(runtime.initialize(scope, operation).await.is_err());
    assert!(
        maintenance.initialize(scope, operation).await.is_err(),
        "child requires an explicit parent"
    );
    register_parent(&mut maintenance, scope).await?;
    let created = maintenance.initialize(scope, operation).await?;
    assert!(created.is_drained_fence());
    assert!(maintenance.initialize(scope, Uuid::new_v4()).await.is_err());
    assert!(runtime
        .current(Scope {
            deployment_id: Uuid::new_v4(),
            ..scope
        })
        .await
        .is_err());
    let selected = selection();
    assert!(runtime
        .acquire(scope, &selected, Uuid::new_v4())
        .await
        .is_err());
    assert!(maintenance
        .activate(scope, operation, 1, &selected.acceptance_sha256)
        .await
        .is_err());
    let mut parent = parent_admission::Parent::from_fenced(f, scope, &selected).await?;
    let prepared = maintenance.prepare(scope, operation, 1, &selected).await?;
    assert_eq!(prepared.phase, "prepared");
    assert_eq!(
        maintenance
            .prepare(scope, operation, 1, &selected)
            .await?
            .revision,
        2
    );
    assert!(maintenance
        .prepare(scope, operation, 1, &selection())
        .await
        .is_err());
    parent.bind(f).await?;
    let active = maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    assert_eq!(active.phase, "active");
    assert_eq!(
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?
            .revision,
        3
    );
    assert!(
        maintenance.fence(scope, operation, 0).await.is_err(),
        "historical fence must not report current drain"
    );

    let worker = Uuid::new_v4();
    let mut concurrent = deployment::connect(f, Role::Runtime).await?;
    let (a, b) = tokio::join!(
        parent
            .control
            .acquire_child(&parent.admission, scope.environment_id, &selected, worker),
        concurrent.acquire_child(&parent.admission, scope.environment_id, &selected, worker)
    );
    concurrent.close().await?;
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "one pending admission must have exactly one executable owner"
    );
    let a = a.or(b)?;
    assert_eq!(maintenance.current(scope).await?.pending, 1);
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let (one, two) = tokio::join!(
        maintenance.fence(scope, first, 3),
        second_maintenance.fence(scope, second, 3)
    );
    assert_ne!(one.is_ok(), two.is_ok(), "one concurrent operation may win");
    let fenced = one.or(two)?;
    assert!(!fenced.is_drained_fence());
    assert!(parent.acquire().await.is_err());
    let next = selection();
    assert!(maintenance
        .prepare(scope, fenced.operation_id, fenced.revision, &next)
        .await
        .is_err());

    // Bypass the adapter precheck to exercise the actual fixed SQL boundary.
    let raw = sqlx::query("SELECT organization_witness.prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(scope.environment_id)
        .bind(scope.deployment_id)
        .bind(fenced.operation_id)
        .bind(fenced.revision)
        .bind(next.epoch)
        .bind(next.primary)
        .bind(next.token_store)
        .bind(&next.source_sha256)
        .bind(&next.history_sha256)
        .bind(&next.acceptance_sha256)
        .execute(maintenance.connection.as_mut().unwrap())
        .await;
    assert!(
        raw.is_err(),
        "actual SQL must refuse pending work before preparation"
    );

    // A real backend loss leaves the committed pending slot. There is no expiry
    // or connection-close cleanup that can turn this into a drained fence.
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(runtime.connection.as_mut().unwrap())
        .await?;
    sqlx::query("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .execute(&mut f.owner)
        .await?;
    assert!(runtime.current(scope).await.is_err());
    assert!(
        runtime.connection.is_none(),
        "terminated control connection must be discarded"
    );
    runtime.close().await?;
    assert_eq!(maintenance.current(scope).await?.pending, 1);
    // This component test started no primary/Redis work. Explicitly reconcile
    // that fact and complete the exact handle through another authenticated link.
    let drained = second_runtime.complete(&a).await?;
    assert!(drained.is_drained_fence());
    assert!(second_runtime.complete(&a).await?.is_drained_fence());
    assert!(
        maintenance
            .prepare(scope, fenced.operation_id, fenced.revision, &selected)
            .await
            .is_err(),
        "consumed epoch cannot return"
    );
    parent.close(true).await?;
    // A changed logical store selection also requires a fresh fenced parent.
    let deployment_id =
        crate::organizations::witness::deployment::DeploymentId::new(scope.deployment_id)?;
    let mut parent_maintenance = deployment::connect(f, Role::Maintenance).await?;
    let parent_state = parent_maintenance.current(deployment_id).await?;
    parent_maintenance
        .fence(deployment_id, Uuid::new_v4(), parent_state.revision)
        .await?;
    parent_maintenance.close().await?;
    let mut parent = parent_admission::Parent::from_fenced(f, scope, &next).await?;
    let prepared = maintenance
        .prepare(scope, fenced.operation_id, fenced.revision, &next)
        .await?;
    parent.bind(f).await?;
    assert!(maintenance
        .activate(
            scope,
            fenced.operation_id,
            prepared.revision,
            &"d".repeat(64)
        )
        .await
        .is_err());
    assert!(maintenance
        .activate(
            scope,
            fenced.operation_id,
            prepared.revision - 1,
            &next.acceptance_sha256
        )
        .await
        .is_err());
    let active = maintenance
        .activate(
            scope,
            fenced.operation_id,
            prepared.revision,
            &next.acceptance_sha256,
        )
        .await?;
    assert!(
        parent
            .control
            .acquire_child(
                &parent.admission,
                scope.environment_id,
                &selected,
                Uuid::new_v4()
            )
            .await
            .is_err(),
        "retired selection"
    );
    let mut wrong = next.clone();
    wrong.primary = Uuid::new_v4();
    assert!(parent
        .control
        .acquire_child(
            &parent.admission,
            scope.environment_id,
            &wrong,
            Uuid::new_v4()
        )
        .await
        .is_err());
    wrong = next.clone();
    wrong.token_store = Uuid::new_v4();
    assert!(parent
        .control
        .acquire_child(
            &parent.admission,
            scope.environment_id,
            &wrong,
            Uuid::new_v4()
        )
        .await
        .is_err());
    let new = parent.acquire().await?;
    assert_eq!(new.slot.slot, a.slot.slot);
    assert!(new.slot.generation > a.slot.generation);
    assert!(
        second_runtime.complete(&a).await.is_err(),
        "late completion cannot release reused slot"
    );
    assert_eq!(maintenance.current(scope).await?.pending, 1);
    second_runtime.complete(&new).await?;

    let mut leases = Vec::new();
    for _ in 0..64 {
        leases.push(parent.acquire().await?);
    }
    assert_eq!(maintenance.current(scope).await?.pending, 64);
    assert!(parent.acquire().await.is_err(), "finite admission limit");
    let fenced = maintenance
        .fence(scope, Uuid::new_v4(), active.revision)
        .await?;
    assert_eq!(fenced.pending, 64);
    for lease in &leases {
        second_runtime.complete(lease).await?;
    }
    assert!(maintenance.current(scope).await?.is_drained_fence());
    parent.close(true).await?;

    // Least privilege is enforced by PostgreSQL even when bypassing Rust methods.
    for query in ["SELECT * FROM organization_witness.authorities", "DELETE FROM organization_witness.slots", "SET ROLE aegaeon_organization_witness_owner", "SELECT organization_witness.initialize(gen_random_uuid(),gen_random_uuid(),gen_random_uuid())"] {
        assert!(sqlx::query(query).execute(second_runtime.connection.as_mut().unwrap()).await.is_err(),"{query}");
    }
    assert!(sqlx::query("SELECT organization_witness.acquire(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid())").execute(maintenance.connection.as_mut().unwrap()).await.is_err());
    maintenance.close().await?;
    second_maintenance.close().await?;
    second_runtime.close().await?;
    for (name, value) in [
        ("synchronous_commit", "off"),
        ("default_transaction_isolation", "repeatable read"),
        ("default_transaction_read_only", "on"),
    ] {
        let mut unsafe_connection = PgConnection::connect_with(
            &f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password),
        )
        .await?;
        sqlx::query("SELECT set_config($1,$2,false)")
            .bind(name)
            .bind(value)
            .execute(&mut unsafe_connection)
            .await?;
        assert!(
            Control::checked(unsafe_connection, Role::Runtime)
                .await
                .is_err(),
            "unsafe live control-store setting: {name}"
        );
    }
    sqlx::query(&format!(
        "GRANT SELECT ON organization_witness.slots TO {}",
        f.runtime
    ))
    .execute(&mut f.owner)
    .await?;
    assert!(
        f.connect(Role::Runtime).await.is_err(),
        "unexpected table privilege"
    );
    sqlx::query(&format!(
        "REVOKE SELECT ON organization_witness.slots FROM {}",
        f.runtime
    ))
    .execute(&mut f.owner)
    .await?;
    sqlx::query("ALTER FUNCTION organization_witness.acquire(uuid,uuid,uuid,uuid,uuid,uuid) SET search_path TO pg_catalog,public").execute(&mut f.owner).await?;
    assert!(
        f.connect(Role::Runtime).await.is_err(),
        "changed actual function catalog"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual FATAL response and durable pending work"]
async fn shared_redis_organizations_witness_fatal_response_discards_connection() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = fatal_response(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn fatal_response(f: &mut Fixture) -> TestResult {
    let (mut maintenance, scope, operation, selected, mut parent) =
        parent_admission::Parent::prepare(f).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    let admission = parent.acquire().await?;
    // The real server returns FATAL while this call awaits its own response;
    // this is distinct from a later write noticing an already closed socket.
    let error = runtime
        .value(sqlx::query_scalar(
            "SELECT to_jsonb(pg_terminate_backend(pg_backend_pid()))",
        ))
        .await
        .unwrap_err();
    let Error::Storage(sqlx::Error::Database(error)) = error else {
        panic!("expected actual server FATAL response")
    };
    let error = error
        .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
        .ok_or_else(|| anyhow::anyhow!("PostgreSQL error"))?;
    assert_eq!(error.severity(), sqlx::postgres::PgSeverity::Fatal);
    assert_eq!(error.code(), "57P01");
    let discarded = runtime.connection.is_none();
    assert!(
        matches!(runtime.current(scope).await, Err(Error::Refused)),
        "fatal client must not try another query"
    );
    runtime.close().await?;
    let state = maintenance.current(scope).await?;
    assert_eq!(
        state.pending, 1,
        "fatal transport cannot clear durable work"
    );
    assert!(!maintenance
        .fence(scope, Uuid::new_v4(), state.revision)
        .await?
        .is_drained_fence());
    drop(admission);
    parent.close(false).await?;
    maintenance.close().await?;
    assert!(
        discarded,
        "FATAL response must discard the control connection"
    );
    Ok(())
}

mod owned_request;
