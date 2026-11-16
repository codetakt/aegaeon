//! Hold a real PostgreSQL row lock until the mounted request is cancelled.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sqlx::{Postgres, Transaction};

pub(super) struct PgGate {
    pub(super) transaction: Transaction<'static, Postgres>,
    pid: i32,
    pub(super) route_pid: Option<i32>,
    pub(super) target_consent: Option<String>,
    expected_role: String,
    expected_database: String,
    expected_query: &'static str,
}

impl PgGate {
    pub(super) async fn create(
        f: &Fixture,
        state: &AppState,
        boundary: &str,
        token: Option<&str>,
    ) -> TestResult<Self> {
        // Require the actual route query, role, database and blocker. A merely
        // pending HTTP future does not establish that the store worker started.
        let expected_query = match boundary {
            "picker" => "SELECT enabled FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 AND import_operation_id IS NULL FOR SHARE",
            "selection" | "approval" => "UPDATE aegaeon.authorization_consents SET decision=$1,decided_at=now() WHERE id=$2 AND environment_id=$3 AND issuer=$4 AND subject=$5 AND session_sha256=$6 AND request_snapshot=$7 AND decision IS NULL AND expires_at > now()",
            _ => return Err("unexpected PostgreSQL cancellation boundary".into()),
        };
        let runtime_options = state.db_pool.connect_options();
        let fixture_options = f.pool.connect_options();
        let expected_role = runtime_options.get_username().to_owned();
        let expected_database = runtime_options
            .get_database()
            .ok_or("runtime database missing")?
            .to_owned();
        if fixture_options.get_username() != expected_role
            || fixture_options.get_database() != Some(expected_database.as_str())
            || state.environment_id != f.env.environment_id
        {
            return Err(
                "fixture observation differs from actual runtime role/database/environment".into(),
            );
        }
        let mut tx = f.pool.begin().await?;
        // The controller transaction is bounded too; product limits are untouched.
        sqlx::query("SELECT set_config('statement_timeout','5s',true), set_config('idle_in_transaction_session_timeout','10s',true)")
            .execute(&mut *tx).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        let target = if boundary == "picker" {
            let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 FOR UPDATE")
                .bind(f.env.environment_id).bind(f.organization.scope.domain_id)
                .fetch_one(&mut *tx).await?;
            assert_eq!(id, f.organization.scope.domain_id);
            None
        } else {
            let digest = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(
                token.ok_or("missing gate continuation")?.as_bytes(),
            ));
            let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.authorization_consents WHERE environment_id=$1 AND token_sha256=$2 AND decision IS NULL FOR UPDATE")
                .bind(f.env.environment_id).bind(digest).fetch_one(&mut *tx).await?;
            Some(id.to_string())
        };
        Ok(Self {
            transaction: tx,
            pid,
            route_pid: None,
            target_consent: target,
            expected_role,
            expected_database,
            expected_query,
        })
    }

    pub(super) async fn reached(&mut self, f: &Fixture, boundary: &str) -> TestResult {
        let row = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let rows: Vec<(i32,String,String,String)> = sqlx::query_as("SELECT pid,usename::text,query,datname::text FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='active' AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))")
                    .bind(self.pid).fetch_all(&f.pool).await?;
                if !rows.is_empty() {
                    if rows.len()!=1
                        || !rows[0].2.split_whitespace().eq(self.expected_query.split_whitespace())
                        || rows[0].1!=self.expected_role
                        || rows[0].3!=self.expected_database {
                        return Err::<(i32,String,String,String),Box<dyn std::error::Error>>("unexpected actual database waiter".into());
                    }
                    return Ok(rows.into_iter().next().unwrap());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await??;
        self.route_pid = Some(row.0);
        eprintln!(
            "discovery-cancellation {}",
            json!({"phase":"actual-pg-wait","boundary":boundary,
            "gate_pid":self.pid,"route_pid":row.0,"role":row.1,"database":row.3,"blocker_confirmed":true,
            "exact_source_query_confirmed":true,"runtime_role_database_confirmed":true,
            "query_sha256_base64url":URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(row.2.as_bytes()))})
        );
        Ok(())
    }
}
