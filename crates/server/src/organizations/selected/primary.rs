use super::*;
use operators::mutations::clients::ClientBinding;

pub(crate) async fn lock_primary_scope(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<(), RepositoryError> {
    scope.validate()?;
    let primary:bool=sqlx::query_scalar("SELECT NOT pg_catalog.pg_is_in_recovery() AND current_setting('transaction_read_only')='off'")
        .fetch_one(&mut **tx).await?;
    if !primary {
        return Err(
            sqlx::Error::Protocol("Organizations requires a writable primary".into()).into(),
        );
    }
    let found:Option<uuid::Uuid>=sqlx::query_scalar("SELECT e.id FROM aegaeon.environments e JOIN aegaeon.tenants n ON n.id=e.tenant_id JOIN aegaeon.teams t ON t.id=n.team_id WHERE e.id=$1 AND e.status='ACTIVE' AND n.status='ACTIVE' AND t.status='ACTIVE' FOR SHARE OF e,n,t")
        .bind(scope.environment_id).fetch_optional(&mut **tx).await?;
    require(found == Some(scope.environment_id))?;
    Ok(())
}

pub(crate) async fn current_client(
    tx: &mut Transaction<'_, Postgres>,
    original: &RootAuthority,
    audience: &str,
) -> Result<ClientBinding, RepositoryError> {
    let consent = &original.consent;
    lock_primary_scope(tx, consent.scope).await?;
    repo::lock_domain(tx, consent.scope).await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2",
    )
    .bind(consent.scope.environment_id)
    .bind(consent.scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    if revision != consent.domain_revision || revision == i64::MAX {
        return Err(AuthorityError::ReauthorizationRequired.into());
    }
    let client = consent::client(tx, consent.scope, &consent.client_id, audience).await?;
    if client.id != consent.client_binding_id
        || client.revision != consent.client_binding_revision
        || client.client_registration_id != consent.client_registration_id
    {
        return Err(AuthorityError::ReauthorizationRequired.into());
    }
    Ok(client)
}
