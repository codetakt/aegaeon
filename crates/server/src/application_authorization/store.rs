use super::inorii::{Claims, Grant};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub type PublicationGuard = sqlx::Transaction<'static, sqlx::Postgres>;

/// Hold the projection and its bound identities stable until token publication completes.
/// Shared identity locks permit concurrent publication and unrelated projection updates.
pub async fn lock_current(
    pool: &PgPool,
    environment: Uuid,
    issuer: &str,
    grant: &Grant,
) -> Result<Option<PublicationGuard>, sqlx::Error> {
    if grant.environment_id != environment || grant.issuer != issuer || grant.validate().is_err() {
        return Ok(None);
    }
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query("SELECT revision, audiences, claims, client_record_id, end_user_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1 AND client_id=$2 AND subject=$3 AND enabled FOR SHARE")
        .bind(environment).bind(&grant.client_id).bind(&grant.subject)
        .fetch_optional(&mut *transaction).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if !lock_identities(&mut transaction, grant, &row).await? {
        return Ok(None);
    }
    let mut current = grant.clone();
    current.revision = row.try_get("revision")?;
    current.selected_organization = None;
    current.audiences = serde_json::from_value(row.try_get("audiences")?)
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    current.claims = serde_json::from_value(row.try_get("claims")?)
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    Ok(grant.is_restriction_of(&current).then_some(transaction))
}

async fn lock_identities(
    transaction: &mut PublicationGuard,
    grant: &Grant,
    projection: &sqlx::postgres::PgRow,
) -> Result<bool, sqlx::Error> {
    let Some(client): Option<Uuid> = projection.try_get("client_record_id")? else {
        return Ok(false);
    };
    let client_exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.clients WHERE id=$1 AND environment_id=$2 AND client_identifier=$3 AND status='ACTIVE' AND deleted_at IS NULL FOR SHARE",
    ).bind(client).bind(grant.environment_id).bind(&grant.client_id)
        .fetch_optional(&mut **transaction).await?.is_some();
    if !client_exists {
        return Ok(false);
    }
    let user: Option<Uuid> = projection.try_get("end_user_record_id")?;
    if grant.subject == grant.client_id {
        return Ok(user.is_none());
    }
    let Some(user) = user else {
        return Ok(false);
    };
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.end_users WHERE id=$1 AND environment_id=$2 AND subject=$3 AND status='ACTIVE' FOR SHARE",
    ).bind(user).bind(grant.environment_id).bind(&grant.subject)
        .fetch_optional(&mut **transaction).await?.is_some())
}

/// Absence is the default deny-release policy. Reads always use authoritative PostgreSQL.
pub async fn capture(
    pool: &PgPool,
    environment: Uuid,
    issuer: &str,
    client: &str,
    subject: &str,
) -> Result<Option<Grant>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT a.revision, a.audiences, a.claims FROM aegaeon.application_authorizations a \
         JOIN aegaeon.clients c ON c.id=a.client_record_id AND c.environment_id=a.environment_id \
           AND c.client_identifier=a.client_id AND c.status='ACTIVE' AND c.deleted_at IS NULL \
         LEFT JOIN aegaeon.end_users u ON u.id=a.end_user_record_id AND u.environment_id=a.environment_id \
           AND u.subject=a.subject AND u.status='ACTIVE' \
         WHERE a.environment_id=$1 AND a.client_id=$2 AND a.subject=$3 AND a.enabled \
           AND ((a.subject=a.client_id AND a.end_user_record_id IS NULL) \
             OR (a.subject<>a.client_id AND u.id IS NOT NULL))",
    )
    .bind(environment)
    .bind(client)
    .bind(subject)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        let audiences: serde_json::Value = row.try_get("audiences")?;
        let claims: serde_json::Value = row.try_get("claims")?;
        let grant = Grant {
            version: 1,
            environment_id: environment,
            issuer: issuer.to_owned(),
            client_id: client.to_owned(),
            subject: subject.to_owned(),
            revision: row.try_get("revision")?,
            audiences: serde_json::from_value(audiences)
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
            selected_organization: None,
            claims: serde_json::from_value::<Claims>(claims)
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        };
        grant
            .validate()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        Ok(grant)
    })
    .transpose()
}

pub async fn is_current(
    pool: &PgPool,
    environment: Uuid,
    issuer: &str,
    grant: &Grant,
) -> Result<bool, sqlx::Error> {
    if grant.environment_id != environment || grant.issuer != issuer || grant.validate().is_err() {
        return Ok(false);
    }
    Ok(
        capture(pool, environment, issuer, &grant.client_id, &grant.subject)
            .await?
            .is_some_and(|current| grant.is_restriction_of(&current)),
    )
}
