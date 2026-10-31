macro_rules! ensure_test {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.into());
        }
    };
}
macro_rules! check_eq {
    ($left:expr, $right:expr $(,)?) => {
        if $left != $right {
            return Err(format!(
                "expected equality: {} and {}",
                stringify!($left),
                stringify!($right)
            )
            .into());
        }
    };
}

use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::upstream::UpstreamLogoutRecoveryPolicy;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    env: TestEnvironment,
    witness: CallerFixture,
    incident: UpstreamLogoutIncidentRecord,
    hash: String,
    connection: Uuid,
}

impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_owner(None).await
    }

    async fn with_owner(owner: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let env = setup_test_environment(&pool).await?;
        let connection = sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) SELECT id,active_configuration_version_id,$2,'logout fixture','https://issuer.example','client','none','ACTIVE' FROM aegaeon.environments WHERE id=$1 RETURNING id")
            .bind(env.environment_id).bind(Uuid::new_v4().to_string()).fetch_one(&pool).await?;
        let hash = hash_upstream_logout_secret(&Uuid::new_v4().to_string());
        sqlx::query("INSERT INTO aegaeon.federation_logout_recovery_incidents(team_id,tenant_id,environment_id,connection_id,upstream_issuer,recovery_policy,status,relay_token_hash,downstream_redirect_uri,request_id,expires_at) VALUES($1,$2,$3,$4,'https://issuer.example','disable_connection','pending',$5,'https://client.example/logout','logout-fixture',now()+interval '1 hour')")
            .bind(env.team_id).bind(env.tenant_id).bind(env.environment_id).bind(connection).bind(&hash).execute(&pool).await?;
        let incident = load_upstream_logout_incident_by_hash(&pool, &hash, &env.issuer_url)
            .await
            .map_err(|r| format!("load {}", r.status()))?
            .ok_or("incident absent")?;
        let witness = CallerFixture::new(owner.unwrap_or(env.environment_id)).await?;
        Ok(Self {
            pool,
            env,
            witness,
            incident,
            hash,
            connection,
        })
    }

    async fn status(&self) -> Result<String, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT status FROM aegaeon.federation_logout_recovery_incidents WHERE id=$1",
        )
        .bind(self.incident.id)
        .fetch_one(&self.pool)
        .await
    }

    async fn finish(self, result: TestResult) -> TestResult {
        let witness = self.witness.finish().await.map_err(Into::into);
        let incidents = sqlx::query(
            "DELETE FROM aegaeon.federation_logout_recovery_incidents WHERE environment_id=$1",
        )
        .bind(self.env.environment_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(Into::into);
        let env = cleanup_test_environment(&self.pool, &self.env).await;
        self.pool.close().await;
        result
            .and(witness)
            .and(incidents)
            .and(env.map_err(Into::into))
    }

    async fn response(
        &self,
        pool: &PgPool,
        incident: UpstreamLogoutIncidentRecord,
    ) -> Result<StatusCode, anyhow::Error> {
        Ok(self
            .witness
            .run(process_persisted_logout_incident(
                pool,
                incident,
                &self.env.issuer_url,
                "logout-test",
            ))
            .await?
            .status())
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual callback race and replay"]
async fn pg_organizations_logout_callback_consumes_once() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        let (a,b) = tokio::join!(f.response(&f.pool, f.incident.clone()), f.response(&f.pool, f.incident.clone()));
        let mut statuses = [a?.as_u16(), b?.as_u16()]; statuses.sort_unstable();
        if statuses != [302,400] { return Err(format!("concurrent callback statuses {statuses:?}").into()); }
        check_eq!(f.response(&f.pool, f.incident.clone()).await?, StatusCode::BAD_REQUEST);
        check_eq!(f.status().await?, "completed");
        let audits:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='federation.upstreamLogoutRelay.completed.v1'")
            .bind(f.env.environment_id).fetch_one(&f.pool).await?;
        check_eq!(audits,1);
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; expiry at actual transition"]
async fn pg_organizations_logout_callback_rechecks_expiry() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        sqlx::query("UPDATE aegaeon.federation_logout_recovery_incidents SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1")
            .bind(f.incident.id).execute(&f.pool).await?;
        check_eq!(f.response(&f.pool,f.incident.clone()).await?,StatusCode::BAD_REQUEST);
        check_eq!(f.status().await?,"pending");
        let response=f.witness.run(persisted_logout_incident_response_by_hash(&f.pool,&f.hash,&f.env.issuer_url,"expired-test")).await?
            .map_err(|r|format!("callback {}",r.status()))?.ok_or("incident absent")?;
        check_eq!(response.status(),StatusCode::BAD_REQUEST);
        check_eq!(f.status().await?,"expired");
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; mutation and audit rollback"]
async fn pg_organizations_logout_callback_audit_failure_rolls_back() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        let response = f
            .witness
            .run(process_persisted_logout_incident(
                &f.pool,
                f.incident.clone(),
                &f.env.issuer_url,
                "audit-fault\0",
            ))
            .await?;
        ensure_test!(
            response.status() == StatusCode::SERVICE_UNAVAILABLE,
            "actual PostgreSQL audit encoding fault was accepted"
        );
        check_eq!(f.status().await?, "pending");
        check_eq!(
            f.response(&f.pool, f.incident.clone()).await?,
            StatusCode::FOUND
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; no redirect after store failure"]
async fn pg_organizations_logout_callback_store_failure_refuses() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        let closed = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy_with(f.pool.connect_options().as_ref().clone());
        closed.close().await;
        check_eq!(
            f.response(&closed, f.incident.clone()).await?,
            StatusCode::SERVICE_UNAVAILABLE
        );
        check_eq!(f.status().await?, "pending");
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; exact owner for reads and mutations"]
async fn pg_organizations_logout_foreign_scope_refuses() -> TestResult {
    let f = Fixture::with_owner(Some(Uuid::new_v4())).await?;
    let result: TestResult = async {
        let read = f
            .witness
            .run(load_upstream_logout_incident_by_hash(
                &f.pool,
                &f.hash,
                &f.env.issuer_url,
            ))
            .await?
            .map_err(|r| format!("load {}", r.status()))?;
        if read.is_some() {
            return Err("foreign incident disclosed".into());
        }
        ensure_test!(
            f.witness
                .run(load_active_logout_recovery_policy_for_connection(
                    &f.pool,
                    f.connection
                ))
                .await?
                .is_err(),
            "foreign policy query accepted"
        );
        let response = f
            .witness
            .run(process_persisted_logout_incident(
                &f.pool,
                f.incident.clone(),
                &f.env.issuer_url,
                "foreign",
            ))
            .await?;
        check_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        check_eq!(f.status().await?, "pending");
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; bounded expiry preserves blocking policy"]
async fn pg_organizations_logout_expiry_is_bounded_and_audited() -> TestResult {
    let f = Fixture::new().await?;
    let result:TestResult=async {
        sqlx::query("INSERT INTO aegaeon.federation_logout_recovery_incidents(team_id,tenant_id,environment_id,connection_id,upstream_issuer,recovery_policy,status,relay_token_hash,downstream_redirect_uri,request_id,created_at,expires_at) SELECT $1,$2,$3,$4,'https://issuer.example','disable_connection','pending',$5||n::text,'https://client.example/logout','expiry-fixture',now()-interval '2 hours',now()-interval '1 hour' FROM generate_series(1,101) n")
            .bind(f.env.team_id).bind(f.env.tenant_id).bind(f.env.environment_id).bind(f.connection).bind(Uuid::new_v4().to_string()).execute(&f.pool).await?;
        let policy=f.witness.run(load_active_logout_recovery_policy_for_connection(&f.pool,f.connection)).await??;
        check_eq!(policy,Some(UpstreamLogoutRecoveryPolicy::DisableConnection));
        let expired:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.federation_logout_recovery_incidents WHERE environment_id=$1 AND status='expired'")
            .bind(f.env.environment_id).fetch_one(&f.pool).await?;
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='federation.upstreamLogoutRelay.expired.v1'")
            .bind(f.env.environment_id).fetch_one(&f.pool).await?;
        check_eq!((expired,audits),(100,100));
        check_eq!(f.witness.run(load_active_logout_recovery_policy_for_connection(&f.pool,f.connection)).await??,policy);
        Ok(())
    }.await;
    f.finish(result).await
}

mod ownership;
