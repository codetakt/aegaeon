use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::upstream::{seal_upstream_client_secret, upstream_client_auth_method_uses_secret};

use super::super::super::connections_support::{
    validate_preserved_connection_client_secret, ConnectionClientSecretAction,
};
use super::super::super::management_internal_error;
use super::super::read::connection_not_found;
use super::presence::connection_client_secret_present_in_transaction;

pub(in crate::web::management) async fn apply_connection_client_secret_action(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    environment_id: Uuid,
    client_auth_method: &str,
    action: &ConnectionClientSecretAction,
    request_id: &str,
) -> Result<(), Response> {
    let replacement = match action {
        ConnectionClientSecretAction::Preserve => {
            if upstream_client_auth_method_uses_secret(client_auth_method) {
                let client_secret_present = connection_client_secret_present_in_transaction(
                    tx,
                    environment_id,
                    connection_id,
                    request_id,
                )
                .await?;
                validate_preserved_connection_client_secret(
                    client_auth_method,
                    client_secret_present,
                    request_id,
                )?;
            }
            return Ok(());
        }
        ConnectionClientSecretAction::Clear => None,
        ConnectionClientSecretAction::Set(client_secret) => {
            Some(seal_connection_client_secret_required(
                client_secret,
                environment_id,
                connection_id,
                request_id,
            )?)
        }
    };

    let rows_affected = sqlx::query(
        r"
UPDATE aegaeon.connections
SET client_secret_encrypted = $3,
    updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(connection_id)
    .bind(environment_id)
    .bind(replacement)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(request_id, "Failed to update connection client secret")
    })?
    .rows_affected();

    if rows_affected == 0 {
        return Err(connection_not_found(request_id));
    }

    Ok(())
}

fn seal_connection_client_secret_required(
    client_secret: &str,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<Vec<u8>, Response> {
    seal_upstream_client_secret(client_secret, environment_id, connection_id).map_err(|_| {
        management_internal_error(request_id, "Connection client secret encryption failed")
    })
}
