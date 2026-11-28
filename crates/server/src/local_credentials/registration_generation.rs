//! Fence mailbox proofs across an explicit withdrawal. Never key ownership by this digest.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn address_digest(environment: Uuid, address: &str) -> [u8; 32] {
    let mut key = environment.as_bytes().to_vec();
    key.extend(address.bytes().map(|byte| byte.to_ascii_lowercase()));
    aegaeon_crypto::hash::sha256_digest(&key)
}

pub(crate) async fn current(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    address: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT generation FROM aegaeon.end_user_registration_generations
        WHERE environment_id=$1 AND address_digest=$2",
    )
    .bind(environment)
    .bind(address_digest(environment, address).as_slice())
    .fetch_optional(&mut **tx)
    .await
}

pub(crate) async fn advance(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    address: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO aegaeon.end_user_registration_generations(environment_id,address_digest,generation)
        VALUES ($1,$2,gen_random_uuid()) ON CONFLICT (environment_id,address_digest)
        DO UPDATE SET generation=EXCLUDED.generation")
        .bind(environment).bind(address_digest(environment, address).as_slice())
        .execute(&mut **tx).await?;
    Ok(())
}
