//! The current, dedicated registration is shared by issuer, BFF and delivery.
use super::*;

pub(crate) const HOSTED_SCOPES: &[&str] = &[
    "openid",
    "read",
    "offline_access",
    crate::organizations::invitations::recipient::PRIVILEGE,
];
pub(crate) const HOSTED_GRANTS: &[&str] = &[
    "authorization_code",
    "refresh_token",
    crate::policy::TOKEN_EXCHANGE_GRANT_TYPE,
];
pub(crate) const HOSTED_CLIENT_PREFIX: &str = "aegaeon-hosted-invitation-";
pub(crate) const HOSTED_CALLBACK: &str = "/organization-invitations/hosted/callback";

pub(crate) fn hosted_client_identifier(domain: Uuid) -> String {
    format!("{HOSTED_CLIENT_PREFIX}{domain}")
}

pub(crate) struct HostedRegistration {
    pub client_registration_id: Uuid,
    pub client_id: String,
    pub issuer: String,
    pub return_url: Option<String>,
}

pub(super) async fn registration(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    domain_revision: i64,
    id: Uuid,
    return_url: Option<String>,
) -> Result<HostedRegistration, RepositoryError> {
    use crate::organizations::{consent, invitations::recipient::PRIVILEGE};
    let client_id = hosted_client_identifier(scope.domain_id);
    let issuer: String = sqlx::query_scalar(r#"
        SELECT 'https://'||e.issuer_host FROM aegaeon.environments e
        JOIN aegaeon.tenants n ON n.id=e.tenant_id AND n.status='ACTIVE'
        JOIN aegaeon.teams t ON t.id=n.team_id AND t.status='ACTIVE'
        JOIN aegaeon.authorization_domains d ON d.environment_id=e.id
        JOIN aegaeon.clients c ON c.environment_id=e.id AND c.configuration_version_id=e.active_configuration_version_id
        WHERE e.id=$1 AND e.status='ACTIVE' AND d.id=$2 AND d.revision=$8 AND d.enabled AND d.import_operation_id IS NULL
          AND c.id=$3 AND c.client_identifier=$4 COLLATE "C" AND c.deleted_at IS NULL AND c.status='ACTIVE'
          AND c.client_type='CONFIDENTIAL' AND c.token_endpoint_authentication_method='client_secret_basic'
          AND c.dpop_bound_access_tokens AND c.redirect_uris=ARRAY['https://'||e.issuer_host||$7]
          AND c.allowed_grant_types @> $5::text[] AND c.allowed_grant_types <@ $5
          AND c.allowed_scopes @> $6::text[] AND c.allowed_scopes <@ $6
        FOR SHARE OF t,n,e,d,c"#)
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).bind(&client_id)
        .bind(HOSTED_GRANTS).bind(HOSTED_SCOPES).bind(HOSTED_CALLBACK).bind(domain_revision)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    // Issuer credential projection scopes ACTIVE Argon2id hashes to this exact
    // client UUID and Environment. Activating another policy revision preserves
    // existing credentials while moving the client's configuration_version_id.
    let credential: Option<Uuid> = sqlx::query_scalar("
        SELECT s.id FROM aegaeon.client_secrets s JOIN aegaeon.clients c ON c.id=s.client_id
         AND c.environment_id=s.environment_id
        WHERE c.id=$1 AND c.environment_id=$2 AND s.status='ACTIVE' AND s.revoked_at IS NULL
          AND s.secret_hash_algorithm='argon2id' AND s.expires_at>clock_timestamp() ORDER BY s.id LIMIT 1 FOR SHARE OF s"
    ).bind(id).bind(scope.environment_id).fetch_optional(&mut **tx).await?;
    require(credential.is_some())?;
    let policy: Option<serde_json::Value> = sqlx::query_scalar(
        "
        SELECT p.token_exchange FROM aegaeon.environment_policies p JOIN aegaeon.environments e
          ON e.id=p.environment_id AND e.active_configuration_version_id=p.configuration_version_id
        WHERE e.id=$1 AND p.retain_refresh_chain AND p.strict_authorize_redirect AND p.oidc_enabled
          AND p.enforce_refresh_sender_binding FOR SHARE OF p",
    )
    .bind(scope.environment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let exchange: crate::policy::token_exchange::TokenExchangePolicy =
        serde_json::from_value(policy.ok_or(AuthorityError::Forbidden)?)?;
    require(exchange.hosted_invitation_rule(&issuer, &client_id))?;
    let target = format!("{issuer}/organization-invitations");
    require(
        exchange
            .targets
            .iter()
            .any(|t| t.audience == target && t.resource_aliases.is_empty()),
    )?;
    let management: Option<bool> = sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&target).fetch_optional(&mut **tx).await?;
    let binding = consent::client(tx, scope, &client_id, &target).await?;
    require(
        management == Some(true)
            && binding.client_registration_id == id
            && matches!(binding.targets.as_slice(), [t] if t.audience == target && t.privileges.as_slice() == [PRIVILEGE]),
    )?;
    Ok(HostedRegistration {
        client_registration_id: id,
        client_id,
        issuer,
        return_url,
    })
}
