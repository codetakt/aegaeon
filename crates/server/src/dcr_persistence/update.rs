use sqlx::{Acquire, Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::{oneshot, OwnedSemaphorePermit};

use super::*;

pub(super) struct Update {
    pub pool: PgPool,
    pub stored: DcrStoredClient,
    pub client: RegisteredClient,
    pub response_types: Vec<String>,
    pub registration_access_token: String,
    pub secret_change: DcrClientSecretChange,
    pub client_secret_assertion: Option<String>,
    pub request_id: String,
}

pub(super) async fn execute(update: Update) -> Result<(), DcrDatabaseError> {
    crate::dcr::metadata_contract::validate_grant_response_relation(
        &update.client.allowed_grant_types,
        &update.response_types,
    )
    .map_err(DcrDatabaseError::MetadataRelation)?;
    let admission =
        credentials::admission::for_persistence(update.client_secret_assertion.is_some())?;
    let (cancel_on_drop, cancelled) = oneshot::channel();
    // Detaching this task on caller cancellation does not detach its cleanup:
    // the dropped sender selects rollback, and the task retains the connection
    // and admission until rollback and pool return have completed.
    let task = tokio::spawn(run(update, admission, cancelled));
    let result = task.await.map_err(|_| {
        DcrDatabaseError::CorruptRegistration("registration update task unavailable".into())
    })?;
    drop(cancel_on_drop);
    result
}

async fn run(
    update: Update,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<(), DcrDatabaseError> {
    let mut connection = tokio::select! {
        biased;
        _ = &mut cancelled => return Err(cancelled_update()),
        connection = update.pool.acquire() => connection?,
    };
    let result = run_transaction(&update, &mut connection, admission.clone(), &mut cancelled).await;
    // SQLx drains a pending rollback and checks the connection (or closes it)
    // before making it available again. Await that work while still admitted.
    connection.return_to_pool().await;
    drop(admission);
    result
}

async fn run_transaction(
    update: &Update,
    connection: &mut sqlx::pool::PoolConnection<Postgres>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    cancelled: &mut oneshot::Receiver<()>,
) -> Result<(), DcrDatabaseError> {
    let mut tx = connection.begin().await?;
    // Server-side cancellation bounds in-flight lock/statement waits even when
    // the caller disappears. Rollback and pool return still retain admission.
    sqlx::query("SELECT set_config('statement_timeout', LEAST(COALESCE(NULLIF(setting::bigint,0),5000),5000)::text, true) FROM pg_settings WHERE name='statement_timeout'")
        .execute(&mut *tx)
        .await?;
    let result = tokio::select! {
        biased;
        _ = cancelled => Err(cancelled_update()),
        result = apply(update, &mut tx, admission) => result,
    };
    match result {
        Ok(()) => tx.commit().await.map_err(Into::into),
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

fn cancelled_update() -> DcrDatabaseError {
    DcrDatabaseError::CorruptRegistration("registration update caller cancelled".into())
}

async fn apply(
    update: &Update,
    tx: &mut Transaction<'_, Postgres>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<(), DcrDatabaseError> {
    let stored = &update.stored;
    let client = &update.client;
    let response_types = &update.response_types;
    lock_current_dynamic_registration(tx, stored).await?;
    if let Some(assertion) = update.client_secret_assertion.as_deref() {
        let permit = admission.ok_or_else(|| {
            DcrDatabaseError::CorruptRegistration(
                "credential verification admission unavailable".into(),
            )
        })?;
        credentials::verify_current_client_secret(tx, stored, assertion, permit).await?;
    }
    update_client_row(tx, stored, client, response_types).await?;
    update_dynamic_registration_row(
        tx,
        stored,
        client,
        response_types,
        &update.registration_access_token,
    )
    .await?;
    match &update.secret_change {
        DcrClientSecretChange::Preserve => {}
        DcrClientSecretChange::ReplaceWithPlaintext(secret) => {
            revoke_active_client_secrets(tx, stored.environment_id, stored.database_client_id)
                .await?;
            replace_client_secret(tx, environment(stored), stored.database_client_id, secret)
                .await?;
        }
        DcrClientSecretChange::RevokeAll => {
            revoke_active_client_secrets(tx, stored.environment_id, stored.database_client_id)
                .await?;
        }
    }
    write_dcr_audit_event(
        tx,
        environment(stored),
        stored.database_client_id,
        "dcr.client.updated.v1",
        client,
        response_types,
        &update.request_id,
    )
    .await?;
    Ok(())
}

fn environment(stored: &DcrStoredClient) -> ActiveDcrEnvironment {
    ActiveDcrEnvironment {
        team_id: stored.team_id,
        tenant_id: stored.tenant_id,
        environment_id: stored.environment_id,
        configuration_version_id: stored.configuration_version_id,
    }
}

#[cfg(test)]
mod tests;
