//! Subject-only membership projection. A page/cursor never carries authority.
use super::{
    model::require, repository as repo, selection, AuthorityError, AuthorizationCeiling, Scope,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use repo::RepositoryError;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

const PAGE_SIZE: i64 = 25;
mod reads;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub identifier: String,
    pub authority: super::MembershipCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Page {
    pub organizations: Vec<Entry>,
    pub next_cursor: Option<String>,
    pub binding: String,
}

pub(crate) struct Query<'a> {
    pub environment_id: Uuid,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub subject: &'a str,
    pub auth_time: i64,
    pub dpop_jkt: &'a str,
    pub audience: &'a str,
    pub privileges: Option<&'a [String]>,
    /// API tokens name their dedicated discovery target. The browser independently
    /// verifies that this client has such a target in the same domain.
    pub discovery_audience: Option<&'a str>,
    pub cursor: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    binding: String,
    after: Uuid,
}

fn position(cursor: Option<&str>, binding: &str) -> Result<Option<Uuid>, AuthorityError> {
    let Some(encoded) = cursor else {
        return Ok(None);
    };
    require(encoded.len() <= 512)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityError::Invalid)?;
    require(URL_SAFE_NO_PAD.encode(&bytes) == encoded)?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| AuthorityError::Invalid)?;
    require(cursor.version == 1 && cursor.binding == binding && !cursor.after.is_nil())?;
    Ok(Some(cursor.after))
}

/// Check a dedicated audience and explicit client permission on primary storage.
/// Ordinary login or a business token cannot satisfy this contract.
pub(crate) async fn token_permission(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
    audience: &str,
) -> Result<Scope, RepositoryError> {
    let domain: Option<Uuid> = sqlx::query_scalar("SELECT domain_id FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND audience=$2 COLLATE \"C\" AND membership_discovery AND NOT management")
        .bind(environment).bind(audience).fetch_optional(&mut **tx).await?;
    let scope = Scope {
        environment_id: environment,
        domain_id: domain.ok_or(AuthorityError::Forbidden)?,
    };
    super::selected::lock_primary_scope(tx, scope).await?;
    reads::lock_domain(tx, scope).await?;
    let binding = client_binding(tx, scope, client).await?;
    require(
        binding
            .targets
            .iter()
            .any(|t| t.audience == audience && t.privileges == [selection::DISCOVERY_SCOPE]),
    )?;
    Ok(scope)
}

async fn client_binding(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    client: &str,
) -> Result<super::operators::mutations::clients::ClientBinding, RepositoryError> {
    let row = sqlx::query("SELECT b.id,b.client_registration_id,b.client_identifier,b.active,b.revision,b.targets FROM aegaeon.organization_client_bindings b JOIN aegaeon.clients c ON c.id=b.client_registration_id AND c.environment_id=b.environment_id JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id WHERE b.environment_id=$1 AND b.domain_id=$2 AND b.client_identifier=$3 COLLATE \"C\" AND b.active AND c.client_identifier=b.client_identifier AND c.status='ACTIVE' AND c.deleted_at IS NULL AND c.dpop_bound_access_tokens AND 'authorization_code'=ANY(c.allowed_grant_types) AND 'organizations:discover'=ANY(c.allowed_scopes) FOR SHARE OF b,c")
        .bind(scope.environment_id).bind(scope.domain_id).bind(client).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let binding = super::operators::mutations::clients::decode(&row)?;
    let identifier = super::operators::mutations::clients::current_client(
        tx,
        scope,
        binding.client_registration_id,
        true,
    )
    .await?;
    require(identifier == binding.client_identifier)?;
    Ok(binding)
}

pub(crate) async fn page(
    tx: &mut Transaction<'_, Postgres>,
    query: &Query<'_>,
) -> Result<Page, RepositoryError> {
    require(!query.subject.is_empty() && !query.dpop_jkt.is_empty() && !query.issuer.is_empty())?;
    crate::util::validate_resource_indicator(query.audience)
        .map_err(|_| AuthorityError::Invalid)?;
    let domain: Option<Uuid> = sqlx::query_scalar("SELECT domain_id FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND audience=$2 COLLATE \"C\" AND NOT membership_discovery")
        .bind(query.environment_id).bind(query.audience).fetch_optional(&mut **tx).await?;
    let scope = Scope {
        environment_id: query.environment_id,
        domain_id: domain.ok_or(AuthorityError::Forbidden)?,
    };
    super::selected::lock_primary_scope(tx, scope).await?;
    reads::lock_domain(tx, scope).await?;
    let binding = client_binding(tx, scope, query.client_id).await?;
    let discovery: Vec<String> = sqlx::query_scalar("SELECT audience FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND membership_discovery AND NOT management ORDER BY audience COLLATE \"C\" LIMIT 33")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
    require(binding.targets.iter().any(|t| {
        discovery.contains(&t.audience)
            && query.discovery_audience.is_none_or(|a| a == t.audience)
            && t.privileges == [selection::DISCOVERY_SCOPE]
    }))?;
    let allowed: BTreeSet<String> = binding
        .targets
        .iter()
        .find(|t| t.audience == query.audience)
        .ok_or(AuthorityError::Forbidden)?
        .privileges
        .iter()
        .cloned()
        .collect();
    let requested: BTreeSet<String> = query
        .privileges
        .map_or_else(|| allowed.clone(), |v| v.iter().cloned().collect());
    require(!requested.is_empty() && requested.len() <= 256)?;
    let eligible: BTreeSet<_> = requested.intersection(&allowed).cloned().collect();
    let user: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 COLLATE \"C\" AND status='ACTIVE'")
        .bind(scope.environment_id).bind(query.subject).fetch_optional(&mut **tx).await?;
    let user = user.ok_or(AuthorityError::Forbidden)?;
    let identity =
        super::identity::revision(tx, scope, user, query.subject, query.auth_time).await?;
    let roles = repo::roles(tx, scope).await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    let owner = super::request_work::async_store::current_owner()?;
    let epoch = owner.epoch_binding()?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":1,"scope":scope,"issuer":query.issuer,"epoch":epoch,
        "subject":query.subject,"user":user,"identity":identity,"client":binding,
        "domain_revision":revision,"roles":roles,"audience":query.audience,"privileges":requested,
        "discovery_audience":query.discovery_audience,"auth_time":query.auth_time,"dpop_jkt":query.dpop_jkt}),
    )?;
    let tag = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(&bytes));
    let after = position(query.cursor, &tag)?;
    let authority = PageAuthority {
        scope,
        user,
        roles,
        eligible,
    };
    materialize_page(tx, &authority, after, tag, query.privileges.is_some()).await
}

struct PageAuthority {
    scope: Scope,
    user: Uuid,
    roles: std::collections::BTreeMap<String, super::RoleDefinition>,
    eligible: BTreeSet<String>,
}

async fn materialize_page(
    tx: &mut Transaction<'_, Postgres>,
    authority: &PageAuthority,
    after: Option<Uuid>,
    tag: String,
    browser: bool,
) -> Result<Page, RepositoryError> {
    // Subject-first partial index; scan at most one bounded page, including
    // memberships whose current role privileges cannot satisfy this request.
    let ids = membership_ids(tx, authority.scope, authority.user, after).await?;
    let mut organizations = Vec::new();
    let mut after_page = after;
    let mut more = ids.len() > PAGE_SIZE as usize;
    let rows = reads::memberships(
        tx,
        authority.scope,
        authority.user,
        &ids[..ids.len().min(PAGE_SIZE as usize)],
    )
    .await?;
    for (organization, member) in rows {
        let id = organization.id;
        if organization.state != super::OrganizationState::Active {
            after_page = Some(id);
            continue;
        }
        if member.state != super::MembershipState::Active {
            return Err(AuthorityError::Forbidden.into());
        }
        if !representable(&member, &authority.roles)? {
            after_page = Some(id);
            continue;
        }
        let mut ceiling =
            AuthorizationCeiling::capture_membership(&organization, &member, &authority.roles)?;
        let privileges: BTreeSet<_> = authority
            .eligible
            .intersection(&ceiling.privileges)
            .cloned()
            .collect();
        ceiling.privileges = privileges.clone();
        if !privileges.is_empty()
            && !push_entry(
                &mut organizations,
                Entry {
                    identifier: organization.external_id,
                    authority: ceiling,
                },
                browser,
            )?
        {
            more = true;
            break;
        }
        after_page = Some(id);
    }
    let next_cursor = if more {
        Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Cursor {
            version: 1,
            binding: tag.clone(),
            after: after_page.ok_or(AuthorityError::Invalid)?,
        })?))
    } else {
        None
    };
    Ok(Page {
        organizations,
        next_cursor,
        binding: tag,
    })
}

fn representable(
    member: &super::Membership,
    definitions: &std::collections::BTreeMap<String, super::RoleDefinition>,
) -> Result<bool, AuthorityError> {
    // Validate every referenced role before applying the projection bound. An
    // unknown/invalid later role must never be hidden by an earlier large union.
    let roles = super::model::roles_for(member, definitions)?;
    let mut privileges = BTreeSet::new();
    for privilege in roles.iter().flat_map(|role| &role.privileges) {
        privileges.insert(privilege);
        if privileges.len() > super::model::MAX_PRIVILEGES {
            return Ok(false);
        }
    }
    Ok(!privileges.is_empty())
}

fn push_entry(
    entries: &mut Vec<Entry>,
    entry: Entry,
    browser: bool,
) -> Result<bool, RepositoryError> {
    entries.push(entry);
    // Reserve half the existing 64 KiB continuation bound for immutable request
    // data. Large authority sets produce another page, not an unbounded picker.
    if browser && serde_json::to_vec(entries)?.len() > 32 * 1024 {
        entries.pop();
        if entries.is_empty() {
            return Err(AuthorityError::Exhausted.into());
        }
        return Ok(false);
    }
    Ok(true)
}

async fn membership_ids(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    user: Uuid,
    after: Option<Uuid>,
) -> Result<Vec<Uuid>, RepositoryError> {
    // Separate prepared shapes preserve a real range seek even when PostgreSQL
    // switches to a generic plan. An optional-parameter OR could scan old pages.
    let ids = if let Some(after) = after {
        sqlx::query_scalar("SELECT organization_id FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 AND end_user_id=$3 AND state='active' AND organization_id>$4 ORDER BY organization_id LIMIT $5")
            .bind(scope.environment_id).bind(scope.domain_id).bind(user).bind(after).bind(PAGE_SIZE+1).fetch_all(&mut **tx).await?
    } else {
        sqlx::query_scalar("SELECT organization_id FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 AND end_user_id=$3 AND state='active' ORDER BY organization_id LIMIT $4")
            .bind(scope.environment_id).bind(scope.domain_id).bind(user).bind(PAGE_SIZE+1).fetch_all(&mut **tx).await?
    };
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_reject_swapped_authority_and_noncanonical_encoding() {
        let id = Uuid::from_u128(1);
        let encoded = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Cursor {
                version: 1,
                binding: "actor-client-query-snapshot".into(),
                after: id,
            })
            .unwrap(),
        );
        assert_eq!(
            position(Some(&encoded), "actor-client-query-snapshot"),
            Ok(Some(id))
        );
        for other in [
            "other-actor",
            "other-client",
            "other-query",
            "new-authority",
        ] {
            assert!(position(Some(&encoded), other).is_err());
        }
        assert!(position(Some(&(encoded + "=")), "actor-client-query-snapshot").is_err());
    }
}
