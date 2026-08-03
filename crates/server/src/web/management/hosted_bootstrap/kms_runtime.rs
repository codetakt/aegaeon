use anyhow::{anyhow, Context, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::key_encryption::{
    encrypt_key_handle, load_key_encryption_key, KeyHandleEncryptionContext,
};

use super::model::NormalizedHostedBootstrapInput;

pub(super) async fn insert_oidc_kms_runtime_key(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    let public_jwk = oidc_kms_public_jwk(input).await?;
    let kek = load_key_encryption_key()
        .map_err(|err| anyhow!("key encryption key is invalid: {err:?}"))?;
    let context = KeyHandleEncryptionContext::new(
        environment_id,
        "OIDC_ID_TOKEN_SIGNING",
        "awsKms",
        "RS256",
        &input.kms_kid,
    );
    let encrypted_key_handle = encrypt_key_handle(&input.kms_key_id, &kek, context)
        .context("failed to encrypt hosted bootstrap KMS key handle")?;
    sqlx::query_scalar(
        r#"
INSERT INTO aegaeon.runtime_keys (
  environment_id,
  configuration_version_id,
  usage,
  kid,
  algorithm,
  provider,
  status,
  public_jwk,
  key_handle,
  provider_configuration,
  activated_at
)
VALUES (
  $1,
  $2,
  'OIDC_ID_TOKEN_SIGNING',
  $3,
  'RS256',
  'awsKms',
  'ACTIVE',
  $4,
  $5,
  $6,
  now()
)
RETURNING id
        "#,
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(&input.kms_kid)
    .bind(public_jwk)
    .bind(encrypted_key_handle)
    .bind(serde_json::json!({ "region": input.kms_region }))
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap OIDC KMS runtime key")
}

#[cfg(feature = "kms-aws")]
async fn oidc_kms_public_jwk(input: &NormalizedHostedBootstrapInput) -> Result<serde_json::Value> {
    let signing_key = crate::oidc::OidcSigningKey::from_aws_kms_async(
        input.kms_region.clone(),
        input.kms_key_id.clone(),
        input.kms_kid.clone(),
    )
    .await
    .context("failed to initialize hosted bootstrap AWS KMS OIDC signing key")?;
    serde_json::to_value(
        signing_key
            .jwks()
            .keys
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("AWS KMS OIDC signing key did not expose a public JWK"))?,
    )
    .context("failed to serialize hosted bootstrap AWS KMS public JWK")
}

#[cfg(not(feature = "kms-aws"))]
async fn oidc_kms_public_jwk(_input: &NormalizedHostedBootstrapInput) -> Result<serde_json::Value> {
    anyhow::bail!(
        "hosted bootstrap with awsKms runtime keys requires the aegaeon-server kms-aws feature"
    )
}
