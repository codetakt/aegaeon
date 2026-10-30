use super::{Item, Ready, PROGRESS};
use crate::organizations::{
    operators::{lock_operator_authority, Capability},
    request_work::Admission,
    snapshot::Reader,
    Scope,
};
use crate::web::management::{
    organizations::boundary::{failure, require_organization_management_session, storage_error},
    AppState,
};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::Connection;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity(Uuid, u64);

pub(super) struct Delivery {
    permit: mpsc::OwnedPermit<Item>,
    bytes: Vec<u8>,
}

pub(super) struct Worker {
    pub state: AppState,
    pub headers: HeaderMap,
    pub admission: Admission,
    pub team: Uuid,
    pub scope: Scope,
    pub request_id: String,
}

impl Worker {
    pub(super) fn unavailable(&self) -> Response {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &self.request_id,
        )
    }

    pub(super) async fn require_current_export_authority(
        &self,
        expected: Option<Identity>,
        delivery: Option<Delivery>,
    ) -> Result<Identity, Response> {
        let admission = self
            .admission
            .current_snapshot_authority()
            .map_err(|_| self.unavailable())?;
        let session = require_organization_management_session(
            &self.state,
            &self.headers,
            &admission,
            &self.request_id,
        )
        .await?;
        let identity = Identity(session.administrator_id, session.created_at_epoch_secs);
        if expected.is_some_and(|prior| prior != identity) {
            return Err(failure(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                &self.request_id,
            ));
        }
        let mut connection = admission
            .connection(&self.state.db_pool)
            .await
            .map_err(|_| self.unavailable())?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| self.unavailable())?
            .begin()
            .await
            .map_err(|_| self.unavailable())?;
        lock_operator_authority(
            &mut tx,
            self.scope,
            self.team,
            identity.0,
            Capability::Export,
        )
        .await
        .map_err(|e| storage_error(&e, &self.request_id))?;
        let current = require_organization_management_session(
            &self.state,
            &self.headers,
            &admission,
            &self.request_id,
        )
        .await?;
        if Identity(current.administrator_id, current.created_at_epoch_secs) != identity {
            return Err(failure(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                &self.request_id,
            ));
        }
        admission.admit_commit().map_err(|_| self.unavailable())?;
        tx.commit().await.map_err(|_| self.unavailable())?;
        // Capacity was reserved before the check. Do not await a slow receiver
        // or pool cleanup between successful authorization and page admission.
        if let Some(delivery) = delivery {
            delivery.permit.send(Ok(Bytes::from(delivery.bytes)));
        }
        connection.release().await;
        Ok(identity)
    }

    async fn emit(
        &self,
        sender: &mpsc::Sender<Item>,
        identity: Identity,
        bytes: Vec<u8>,
    ) -> Result<(), Response> {
        tokio::time::timeout(PROGRESS, async {
            let permit = sender
                .clone()
                .reserve_owned()
                .await
                .map_err(|_| self.unavailable())?;
            self.require_current_export_authority(Some(identity), Some(Delivery { permit, bytes }))
                .await?;
            Ok(())
        })
        .await
        .map_err(|_| self.unavailable())?
    }

    pub(super) async fn transfer(
        &self,
        sender: &mpsc::Sender<Item>,
        ready: &mut Option<Ready>,
    ) -> Result<(), Response> {
        let identity =
            tokio::time::timeout(PROGRESS, self.require_current_export_authority(None, None))
                .await
                .map_err(|_| self.unavailable())??;
        let mut connection = self
            .admission
            .connection(&self.state.db_pool)
            .await
            .map_err(|_| self.unavailable())?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| self.unavailable())?
            .begin()
            .await
            .map_err(|_| self.unavailable())?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| self.unavailable())?;
        let mut reader = Reader::start(&mut tx, self.scope)
            .await
            .map_err(|e| storage_error(&e, &self.request_id))?;
        self.emit(
            sender,
            identity,
            reader.header_line().map_err(|_| self.unavailable())?,
        )
        .await?;
        ready
            .take()
            .ok_or_else(|| self.unavailable())?
            .send(Ok(()))
            .map_err(|_| self.unavailable())?;
        let mut progress = tokio::time::Instant::now() + PROGRESS;
        loop {
            let lines = tokio::time::timeout_at(progress, reader.next(&mut tx))
                .await
                .map_err(|_| self.unavailable())?
                .map_err(|_| self.unavailable())?;
            let Some(lines) = lines else {
                break;
            };
            if !lines.is_empty() {
                tokio::time::timeout_at(progress, self.emit(sender, identity, lines.concat()))
                    .await
                    .map_err(|_| self.unavailable())??;
                progress = tokio::time::Instant::now() + PROGRESS;
            }
        }
        self.admission
            .admit_commit()
            .map_err(|_| self.unavailable())?;
        tokio::time::timeout_at(progress, tx.commit())
            .await
            .map_err(|_| self.unavailable())?
            .map_err(|_| self.unavailable())?;
        tokio::time::timeout_at(progress, connection.release())
            .await
            .map_err(|_| self.unavailable())?;
        tokio::time::timeout_at(
            progress,
            self.emit(
                sender,
                identity,
                reader.manifest_line().map_err(|_| self.unavailable())?,
            ),
        )
        .await
        .map_err(|_| self.unavailable())?
    }
}
