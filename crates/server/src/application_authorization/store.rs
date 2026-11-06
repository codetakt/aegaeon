use super::inorii::{Claims, Grant};
use crate::{
    dcr_persistence::admitted_connection::AdmittedConnection,
    organizations::request_work::async_store,
};
use sqlx::{postgres::PgTransactionManager, PgConnection, PgPool, Row, TransactionManager};
use uuid::Uuid;

/// Holds publication locks and their admitted connection through protocol cleanup.
///
/// This opaque guard replaces the former `sqlx::Transaction` alias. Retain it
/// until publication completes, then drop it or explicitly call `rollback` or
/// `commit`. It deliberately provides no raw connection or `Deref` access.
pub struct PublicationGuard {
    connection: Option<AdmittedConnection>,
    environment: Uuid,
    owner: Option<crate::organizations::request_work::Admission>,
}

impl PublicationGuard {
    fn ensure_open(&self) -> Result<(), sqlx::Error> {
        if let Some(owner) = &self.owner {
            owner.ensure_open()?;
        }
        if let Some(current) = async_store::task_owner()? {
            if !self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.same_work(&current))
            {
                return Err(sqlx::Error::Protocol(
                    "missing or foreign Organizations publication owner".into(),
                ));
            }
        }
        async_store::ensure_environment_if_scoped(self.environment)
    }

    fn connection(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        self.ensure_open()?;
        self.connection
            .as_mut()
            .ok_or_else(|| sqlx::Error::Protocol("publication guard already released".into()))?
            .as_mut()
    }

    async fn begin(
        &mut self,
        statement: Option<std::borrow::Cow<'static, str>>,
    ) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        self.connection
            .as_mut()
            .ok_or_else(|| sqlx::Error::Protocol("publication guard already released".into()))?
            .begin_raw(statement)
            .await
    }

    /// Release publication locks and await the admitted connection's cleanup.
    ///
    /// # Errors
    /// Returns a transaction or admission error. Dropping an interrupted call
    /// still retains its owner through rollback and protocol cleanup.
    pub async fn rollback(mut self) -> Result<(), sqlx::Error> {
        PgTransactionManager::rollback(self.connection()?).await?;
        if let Some(connection) = self.connection.take() {
            connection.release().await;
        }
        self.ensure_open()
    }

    /// Complete the read-only publication lock transaction and await cleanup.
    ///
    /// # Errors
    /// Returns a transaction or admission error. This does not publish a token.
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        if let Some(owner) = &self.owner {
            owner.admit_commit()?;
        } else {
            async_store::admit_current_commit()?;
        }
        PgTransactionManager::commit(self.connection()?).await?;
        if let Some(connection) = self.connection.take() {
            connection.release().await;
        }
        self.ensure_open()
    }
}

/// Hold the projection and its bound identities stable until token publication completes.
/// Shared identity locks permit concurrent publication and unrelated projection updates.
pub async fn lock_current(
    pool: &PgPool,
    environment: Uuid,
    issuer: &str,
    grant: &Grant,
) -> Result<Option<PublicationGuard>, sqlx::Error> {
    async_store::ensure_environment_if_scoped(environment)?;
    // Construct before awaiting BEGIN. Dropping the retained admitted connection
    // always rolls back, including a BEGIN reply that SQLx has not observed.
    let mut guard = PublicationGuard {
        connection: Some(AdmittedConnection::acquire(pool).await?),
        environment,
        owner: async_store::task_owner()?,
    };
    guard.begin(None).await?;
    if lock_current_on_connection(guard.connection()?, environment, issuer, grant).await? {
        Ok(Some(guard))
    } else {
        guard.rollback().await?;
        Ok(None)
    }
}

/// Reuse an existing publication transaction; no second pool checkout is needed.
/// The caller retains this transaction until its protected publication completes.
pub(crate) async fn lock_current_in_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    environment: Uuid,
    issuer: &str,
    grant: &Grant,
) -> Result<bool, sqlx::Error> {
    async_store::ensure_environment_if_scoped(environment)?;
    lock_current_on_connection(transaction, environment, issuer, grant).await
}

async fn lock_current_on_connection(
    connection: &mut PgConnection,
    environment: Uuid,
    issuer: &str,
    grant: &Grant,
) -> Result<bool, sqlx::Error> {
    if grant.environment_id != environment || grant.issuer != issuer || grant.validate().is_err() {
        return Ok(false);
    }
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut *connection)
        .await?;
    let row = sqlx::query("SELECT revision, audiences, claims, client_record_id, end_user_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1 AND client_id=$2 AND subject=$3 AND enabled FOR SHARE")
        .bind(environment).bind(&grant.client_id).bind(&grant.subject)
        .fetch_optional(&mut *connection).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !lock_identities(connection, grant, &row).await? {
        return Ok(false);
    }
    let mut current = grant.clone();
    current.revision = row.try_get("revision")?;
    current.selected_organization = None;
    current.audiences = serde_json::from_value(row.try_get("audiences")?)
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    current.claims = serde_json::from_value(row.try_get("claims")?)
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    Ok(grant.is_restriction_of(&current))
}

async fn lock_identities(
    connection: &mut PgConnection,
    grant: &Grant,
    projection: &sqlx::postgres::PgRow,
) -> Result<bool, sqlx::Error> {
    let Some(client): Option<Uuid> = projection.try_get("client_record_id")? else {
        return Ok(false);
    };
    let client_exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.clients WHERE id=$1 AND environment_id=$2 AND client_identifier=$3 AND status='ACTIVE' AND deleted_at IS NULL FOR SHARE",
    ).bind(client).bind(grant.environment_id).bind(&grant.client_id)
        .fetch_optional(&mut *connection).await?.is_some();
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
        .fetch_optional(&mut *connection).await?.is_some())
}

/// Absence is the default deny-release policy. Reads always use authoritative PostgreSQL.
pub async fn capture(
    pool: &PgPool,
    environment: Uuid,
    issuer: &str,
    client: &str,
    subject: &str,
) -> Result<Option<Grant>, sqlx::Error> {
    async_store::ensure_environment_if_scoped(environment)?;
    let mut connection = AdmittedConnection::acquire(pool).await?;
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
    .fetch_optional(connection.as_mut()?)
    .await?;
    connection.release().await;
    async_store::ensure_environment_if_scoped(environment)?;
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

/// Bind a CC authorization to the identity already locked by `lock_current`.
/// This must use the same publication transaction: no second pool acquisition or
/// additional publication lock is needed, and the locked projection cannot be replaced.
pub(crate) async fn publication_client_identity_matches(
    guard: &mut PublicationGuard,
    grant: &Grant,
    expected_registration_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let identity: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT client_record_id FROM aegaeon.application_authorizations \
         WHERE environment_id=$1 AND client_id=$2 AND subject=$3 AND enabled",
    )
    .bind(grant.environment_id)
    .bind(&grant.client_id)
    .bind(&grant.subject)
    .fetch_optional(guard.connection()?)
    .await?;
    Ok(identity.flatten() == Some(expected_registration_id))
}

#[cfg(test)]
mod organization_epoch;
