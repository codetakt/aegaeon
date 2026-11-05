//! Frozen, verified transport configuration. Diagnostic links may precede
//! admission; application work always follows fresh parent/child admission.
use super::super::{
    connector::{no_ambient_postgres, pg_connect, Endpoint},
    Error, Result, Role, Selection,
};
use super::{dispatch::Environment, work::Work, DeploymentControl, DeploymentId};
use crate::organizations::{
    request_work::Admission,
    store_observation::{self, transport, Postgres, Redis},
};
use sqlx::postgres::PgConnectOptions;
use std::time::Duration;
use uuid::Uuid;

#[cfg(test)]
mod tests;

pub struct Connector {
    control: PgConnectOptions,
    primary: PgConnectOptions,
    token: redis::Client,
}

struct PreflightCapacity<'a> {
    local: &'a Admission,
    attempt: aegaeon_pure::organization_recovery::Preflight,
}

impl Drop for PreflightCapacity<'_> {
    fn drop(&mut self) {
        if self.attempt.requires_fence() {
            self.local.close_until_restart();
        }
    }
}

impl Connector {
    pub(super) fn primary_options(&self) -> PgConnectOptions {
        self.primary.clone()
    }

    pub fn new(control: Endpoint<'_>, primary: Endpoint<'_>, token: Endpoint<'_>) -> Result<Self> {
        no_ambient_postgres()?;
        let postgres = |endpoint: Endpoint<'_>| {
            let ca = transport::certificate(endpoint.root_cert).map_err(|_| Error::Refused)?;
            transport::postgres_options(endpoint.url, endpoint.root_cert, ca)
                .map_err(|_| Error::Refused)
        };
        let ca = transport::certificate(token.root_cert).map_err(|_| Error::Refused)?;
        Ok(Self {
            control: postgres(control)?,
            primary: postgres(primary)?,
            token: transport::redis_client(token.url, ca).map_err(|_| Error::Refused)?,
        })
    }

    async fn control(&self) -> Result<(DeploymentControl, store_observation::PostgresObservation)> {
        no_ambient_postgres()?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut control =
                DeploymentControl::checked(pg_connect(&self.control).await?, Role::Runtime).await?;
            let observed = store_observation::primary(
                control.control.connection.as_mut().ok_or(Error::Refused)?,
            )
            .await
            .map_err(|_| Error::Refused)?;
            Ok((control, observed))
        })
        .await
        .map_err(|_| Error::Deadline)?
    }

    async fn stores(
        &self,
        witness: &store_observation::PostgresObservation,
        child: Option<(Uuid, &str)>,
    ) -> Result<(Postgres, Redis)> {
        no_ambient_postgres()?;
        tokio::time::timeout(Duration::from_secs(20), async {
            let connection = pg_connect(&self.primary).await?;
            let primary = if let Some((environment, issuer)) = child {
                super::super::connector::primary::checked(connection, environment, issuer).await?
            } else {
                Postgres::observe(connection)
                    .await
                    .map_err(|_| Error::Refused)?
            };
            if !primary.observation().different_cluster(witness) {
                return Err(Error::Refused);
            }
            let config = redis::AsyncConnectionConfig::new()
                .set_connection_timeout(Duration::from_secs(5))
                .set_response_timeout(Duration::from_secs(5));
            let connection = tokio::time::timeout(
                Duration::from_secs(5),
                self.token
                    .get_multiplexed_async_connection_with_config(&config),
            )
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Refused)?;
            let token = Redis::observe(connection)
                .await
                .map_err(|_| Error::Refused)?;
            Ok((primary, token))
        })
        .await
        .map_err(|_| Error::Deadline)?
    }

    /// Startup diagnosis under the same finite owner and deadline as real
    /// startup. A drained, sealed restart can first update physical bindings.
    /// No durable work admission is allocated by either operation.
    pub(super) async fn startup_preflight(
        &self,
        local: &Admission,
        deployment: DeploymentId,
        parent: &Selection,
        child: &Environment,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let mut capacity = PreflightCapacity {
            local,
            attempt: Default::default(),
        };
        let mut control = None;
        let mut primary = None;
        let mut token = None;
        let inspected = tokio::time::timeout_at(deadline, async {
            let (connection, observed) = self.control().await?;
            control = Some(connection);
            // Validate both independent selections before any restart mutation.
            control
                .as_mut()
                .ok_or(Error::Refused)?
                .startup_preflight(deployment, parent, child.id, &child.selection)
                .await?;
            let (primary_connection, token_connection) = self
                .stores(&observed, Some((child.id, &child.issuer)))
                .await?;
            primary = Some(primary_connection);
            token = Some(token_connection);
            control
                .as_mut()
                .ok_or(Error::Refused)?
                .ensure_store_continuity(
                    deployment,
                    parent,
                    primary.as_mut().ok_or(Error::Refused)?,
                    token.as_mut().ok_or(Error::Refused)?,
                    &mut capacity.attempt,
                )
                .await?;
            let snapshot = control
                .as_mut()
                .ok_or(Error::Refused)?
                .startup_preflight(deployment, parent, child.id, &child.selection)
                .await?;
            snapshot
                .check(
                    primary.as_mut().ok_or(Error::Refused)?,
                    token.as_mut().ok_or(Error::Refused)?,
                )
                .await
        })
        .await
        .unwrap_or(Err(Error::Deadline));
        let cleaned = tokio::time::timeout_at(deadline, async {
            // Closing Redis retains the existing observer contract: dropping its
            // sole multiplexed connection is not a separate driver-join receipt.
            if let Some(connection) = token.take() {
                connection.close();
            }
            let primary_closed = match primary.take() {
                Some(connection) => connection.close().await.map_err(|_| Error::Refused),
                None => Ok(()),
            };
            let control_closed = match control.take() {
                Some(connection) => connection.close().await,
                None => Ok(()),
            };
            primary_closed?;
            control_closed
        })
        .await
        .unwrap_or(Err(Error::Deadline));
        if let Err(error) = &cleaned {
            tracing::error!(
                target: "organization_startup",
                stage = "preflight_cleanup",
                reason_code = error.reason_code(),
                "Organizations startup diagnostic cleanup incomplete"
            );
        }
        if inspected.is_ok() && cleaned.is_ok() {
            capacity.attempt.finish();
        }
        // Preserve the primary refusal when cleanup also fails. Only a possibly
        // mutating continuity update fences capacity; read-only diagnosis cannot
        // create application effects or durable admissions.
        inspected.and(cleaned)
    }

    /// Caller retains local capacity before this first network await. A complete
    /// request deadline must include this construction and later completion.
    pub async fn parent(
        &self,
        local: Admission,
        deployment: DeploymentId,
        selection: &Selection,
    ) -> Result<Work> {
        let mut preflight = PreflightCapacity {
            local: &local,
            attempt: Default::default(),
        };
        let (mut control, observed) = self.control().await?;
        let (mut primary, mut token) = self.stores(&observed, None).await?;
        control
            .ensure_store_continuity(
                deployment,
                selection,
                &mut primary,
                &mut token,
                &mut preflight.attempt,
            )
            .await?;
        preflight.attempt.finish();
        drop(preflight);
        // Reuse only these owned diagnostic links. Work::begin still acquires a
        // fresh durable slot and checks the freshly returned checkpoint.
        Work::begin(control, local, deployment, selection, || async move {
            Ok((primary, token))
        })
        .await
    }

    pub async fn child(
        &self,
        parent: &Work,
        environment: Uuid,
        issuer: &str,
        selection: &Selection,
    ) -> Result<super::super::work::Work> {
        self.child_admitted(parent.admission(), environment, issuer, selection)
            .await
    }

    pub(in crate::organizations::witness) async fn child_admitted(
        &self,
        parent: &Admission,
        environment: Uuid,
        issuer: &str,
        selection: &Selection,
    ) -> Result<super::super::work::Work> {
        if environment.is_nil() || issuer.is_empty() || issuer.len() > 16_384 {
            return Err(Error::Refused);
        }
        let (control, observed) = self.control().await?;
        Work::child_admitted(parent, control, environment, selection, || {
            self.stores(&observed, Some((environment, issuer)))
        })
        .await
    }
}
