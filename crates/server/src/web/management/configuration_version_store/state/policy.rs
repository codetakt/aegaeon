mod bind;

use super::super::super::configuration_documents::UPDATE_ENVIRONMENT_POLICY_SQL;
use super::super::super::{i32_from_u32_field, management_internal_error};
use crate::management::types::PolicyDocument;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn update_environment_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_policies (
  environment_id,
  configuration_version_id,
  pkce_required,
  dcr_enabled,
  allowed_signing_algorithms,
  allowed_grant_types,
  access_token_time_to_live_seconds,
  id_token_time_to_live_seconds,
  refresh_token_time_to_live_seconds,
  authorization_code_time_to_live_seconds
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (environment_id) DO NOTHING
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(policy.pkce_required)
    .bind(policy.dcr_enabled)
    .bind(policy.allowed_signing_algorithms.clone())
    .bind(policy.allowed_grant_types.clone())
    .bind(i32_from_u32_field(
        "access_token_time_to_live_seconds",
        policy.access_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "id_token_time_to_live_seconds",
        policy.id_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "refresh_token_time_to_live_seconds",
        policy.refresh_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "authorization_code_time_to_live_seconds",
        policy.authorization_code_time_to_live_seconds,
        request_id,
    )?)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to prepare environment policy"))?;

    let result = bind::bind_policy_update_fields(
        sqlx::query(UPDATE_ENVIRONMENT_POLICY_SQL)
            .bind(environment_id)
            .bind(configuration_version_id),
        policy,
        request_id,
    )?
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment policy"))?;
    if result.rows_affected() != 1 {
        return Err(management_internal_error(
            request_id,
            "Environment policy projection is missing",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::test_support::*;

    #[tokio::test]
    #[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
    async fn token_exchange_target_policy_database_roundtrip() -> TestResult {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        let env = setup_test_environment(&pool).await?;
        let result = async {
            let version: Uuid = sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id = $1")
                .bind(env.environment_id).fetch_one(&pool).await?;
            let policy = PolicyDocument { token_exchange: serde_json::from_value(serde_json::json!({"version":1,
                "targets":[{"audience":"api","resourceAliases":["https://api.example/resource"]}],
                "rules":[{"clientId":"client","sourceAudience":"source","targetAudience":"api",
                    "scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]
            }))?, ..PolicyDocument::default() };
            let mut tx = pool.begin().await?;
            update_environment_policy_state(&mut tx, env.environment_id, version, &policy, "exchange-policy-test")
                .await.map_err(|response| format!("policy write: {}", response.status()))?;
            tx.commit().await?;
            let loaded = crate::web::management::configuration_version_store::load_environment_policy_document(
                &pool, env.environment_id, "exchange-policy-test").await
                .map_err(|response| format!("policy load: {}", response.status()))?;
            assert_eq!(loaded.token_exchange, policy.token_exchange);
            let mut config = crate::config::ServerConfig::default();
            config.apply_management_policy(&loaded)?;
            assert_eq!(config.token_exchange, policy.token_exchange);
            Ok(())
        }.await;
        finish_test(result, cleanup_test_environment(&pool, &env).await)
    }
}
