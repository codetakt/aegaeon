use super::*;
use axum::{response::Response, Router};
use std::time::Duration;

pub(super) struct Probe {
    pub app: Router,
    pub pool: PgPool,
    pub path: String,
    pub session: String,
    pub team: Uuid,
    pub environment: Uuid,
}

impl Probe {
    fn request(&self) -> axum::http::Request<Body> {
        let mut req = request(
            &self.path,
            Value::Null,
            &self.session,
            "https://admin.aegaeon.test",
            true,
        );
        *req.method_mut() = Method::GET;
        req
    }

    pub async fn verify(&self) -> ManagementTestResult {
        self.compatible_read().await?;
        self.retained_authority().await?;
        sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1")
            .bind(self.team)
            .execute(&self.pool)
            .await?;
        assert_eq!(
            self.app.clone().oneshot(self.request()).await?.status(),
            StatusCode::FORBIDDEN,
            "a committed authority downgrade must stop export"
        );
        Ok(())
    }

    async fn compatible_read(&self) -> ManagementTestResult {
        let mut reader = self.pool.begin().await?;
        sqlx::query("SELECT m.team_id FROM aegaeon.team_memberships m JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.administrators a ON a.id=m.administrator_id WHERE m.team_id=$1 FOR SHARE OF m,t,a")
            .bind(self.team).fetch_all(&mut *reader).await?;
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            self.app.clone().oneshot(self.request()),
        )
        .await;
        reader.rollback().await?;
        let response = outcome.map_err(|_| "export blocked by a compatible authority read")??;
        Self::check_export(response).await
    }

    async fn retained_authority(&self) -> ManagementTestResult {
        let mut barrier = self.pool.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *barrier)
            .await?;
        sqlx::query("SELECT id FROM aegaeon.lti_registrations WHERE environment_id=$1 FOR UPDATE")
            .bind(self.environment)
            .fetch_all(&mut *barrier)
            .await?;
        let reading = tokio::spawn(self.app.clone().oneshot(self.request()));
        let checked = self.check_waiting_reader(pid).await;
        let release = barrier.rollback().await;
        let response = tokio::time::timeout(Duration::from_secs(3), reading).await;
        checked?;
        release?;
        Self::check_export(response???).await
    }

    async fn check_waiting_reader(&self, blocker: i32) -> ManagementTestResult {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM aegaeon.lti_registrations%' AND $1=ANY(pg_blocking_pids(pid)))")
                    .bind(blocker).fetch_one(&self.pool).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, sqlx::Error>(())
        }).await??;
        // The HTTP read has passed authorization and is waiting for its data.
        // Both authority and issuer rows must remain protected until it commits.
        for (query, id) in [
            (
                "SELECT team_id FROM aegaeon.team_memberships WHERE team_id=$1 FOR UPDATE NOWAIT",
                self.team,
            ),
            (
                "SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE NOWAIT",
                self.environment,
            ),
        ] {
            let mut writer = self.pool.begin().await?;
            let attempt = sqlx::query(query).bind(id).fetch_all(&mut *writer).await;
            writer.rollback().await?;
            assert_eq!(
                attempt
                    .err()
                    .and_then(|e| e
                        .as_database_error()
                        .and_then(|d| d.code())
                        .map(|s| s.into_owned()))
                    .as_deref(),
                Some("55P03")
            );
        }
        Ok(())
    }

    async fn check_export(response: Response) -> ManagementTestResult {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let exported: Value =
            serde_json::from_slice(&body::to_bytes(response.into_body(), 262144).await?)?;
        assert_eq!(exported["registration"]["activeRevision"], 1);
        Ok(())
    }
}
