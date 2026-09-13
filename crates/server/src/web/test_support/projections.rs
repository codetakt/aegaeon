use super::{TestEnvironment, TestResult};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A persistence fixture with real identity rows. Authorization API tests use
/// the management handler instead, including its audit and revision checks.
pub(crate) async fn seed_test_projection(
    pool: &PgPool,
    env: &TestEnvironment,
    client: &str,
    subject: &str,
    audiences: Value,
    claims: Value,
) -> TestResult<(Uuid, Option<Uuid>)> {
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2 AND status='ACTIVE' AND deleted_at IS NULL")
        .bind(env.environment_id).bind(client).fetch_optional(pool).await?;
    let client_id = match existing {
        Some(id) => id,
        None => sqlx::query_scalar("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,$2,'projection fixture','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid','read'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1 RETURNING id")
            .bind(env.environment_id).bind(client).fetch_one(pool).await?,
    };
    let user_id = if client == subject {
        None
    } else {
        let existing = sqlx::query_scalar::<_, Uuid>("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 AND status='ACTIVE'")
            .bind(env.environment_id).bind(subject).fetch_optional(pool).await?;
        Some(match existing {
            Some(id) => id,
            None => sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,$2,'ACTIVE') RETURNING id")
                .bind(env.environment_id).bind(subject).fetch_one(pool).await?,
        })
    };
    sqlx::query("INSERT INTO aegaeon.application_authorizations(environment_id,client_id,subject,revision,authority,source_revision,audiences,claims,enabled,client_record_id,end_user_record_id) VALUES ($1,$2,$3,1,'operator',1,$4,$5,true,$6,$7)")
        .bind(env.environment_id).bind(client).bind(subject).bind(audiences).bind(claims)
        .bind(client_id).bind(user_id).execute(pool).await?;
    Ok((client_id, user_id))
}
