//! A revision identifies one immutable adapter configuration. Selection only
//! controls issuance. Every subsequent operation resolves the invitation's pin.
use super::registration::registration;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature="openapi",schema(as=OrganizationInvitationDeliverySettings))]
#[serde(untagged)]
pub enum Settings {
    Profiles(Profiles),
    Custom(Channel),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature="openapi",schema(as=OrganizationInvitationDeliveryProfiles))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profiles {
    /// Absence suspends issuance. An enabled retained route may still deliver.
    pub default_revision: Option<i64>,
    /// Invitations issued before the catalog retain this custom adapter.
    pub legacy_revision: Option<i64>,
    pub routes: Vec<Route>,
    pub return_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature="openapi",schema(as=OrganizationInvitationDeliveryRoute))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Route {
    /// Immutable identity of the adapter endpoint and its recipient UI.
    pub revision: i64,
    /// Bump to the next domain revision when replacing transport credentials or
    /// encryption material. Old ciphertext is withheld until explicit reissue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_revision: Option<i64>,
    pub enabled: bool,
    #[cfg_attr(feature="openapi",schema(value_type=Option<String>,format="uuid"))]
    pub hosted_client_registration_id: Option<Uuid>,
    pub channel: Channel,
}

impl Settings {
    pub(crate) fn validate(&self, scope: Scope) -> Result<(), AuthorityError> {
        match self {
            Self::Custom(channel) => channel.validate(scope),
            Self::Profiles(p) => p.validate(scope),
        }
    }
}

impl Profiles {
    pub(super) fn find(&self, revision: i64) -> Option<&Route> {
        self.routes.iter().find(|r| r.revision == revision)
    }

    fn validate(&self, scope: Scope) -> Result<(), AuthorityError> {
        require(!self.routes.is_empty() && self.routes.len() <= 8)?;
        let mut revisions = BTreeSet::new();
        let mut hosted_client = None;
        for route in &self.routes {
            require(
                route.revision > 0
                    && revisions.insert(route.revision)
                    && route
                        .transport_revision
                        .is_none_or(|revision| revision > route.revision),
            )?;
            route.channel.validate(scope)?;
            if let Some(id) = route.hosted_client_registration_id {
                require(!id.is_nil() && route.channel.encryption.is_some())?;
                if route.enabled {
                    require(hosted_client.replace(id).is_none_or(|other| other == id))?;
                }
                // The reference adapter has ONE immutable recipient UI per endpoint.
                require(!self.routes.iter().any(|r| {
                    r.hosted_client_registration_id.is_none()
                        && r.channel.endpoint == route.channel.endpoint
                }))?;
            }
        }
        if let Some(revision) = self.default_revision {
            require(self.find(revision).is_some_and(|r| r.enabled))?;
        }
        if let Some(revision) = self.legacy_revision {
            require(
                self.find(revision)
                    .is_some_and(|r| r.hosted_client_registration_id.is_none()),
            )?;
        }
        if let Some(destination) = &self.return_url {
            let url = url::Url::parse(destination).map_err(|_| AuthorityError::Invalid)?;
            require(
                destination.len() <= 2048
                    && url.scheme() == "https"
                    && url.has_host()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
                    && url.as_str() == destination,
            )?;
        }
        Ok(())
    }

    pub(super) fn suspend(&mut self) {
        self.default_revision = None;
        for route in &mut self.routes {
            route.enabled = false;
        }
    }
}

/// Keep legacy invitations on their old endpoint without modifying retained
/// invitation authority or the authenticated context of already sealed mail.
pub(super) async fn transition(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    previous: &Configuration,
    submitted: Option<&Settings>,
    next_revision: i64,
) -> Result<Option<Settings>, RepositoryError> {
    let previous_profiles = match &previous.channel {
        Some(Settings::Profiles(p)) => Some(p),
        _ => None,
    };
    let Some(Settings::Profiles(next)) = submitted else {
        if let Some(old) = previous_profiles {
            if submitted.is_some() {
                return Err(AuthorityError::Conflict.into());
            }
            let mut suspended = old.clone();
            suspended.suspend();
            if suspended == *old {
                return Err(AuthorityError::Conflict.into());
            }
            return Ok(Some(Settings::Profiles(suspended)));
        }
        return Ok(submitted.cloned());
    };
    let old_legacy = match &previous.channel {
        Some(Settings::Custom(channel)) => {
            let route = next
                .find(previous.revision)
                .ok_or(AuthorityError::Conflict)?;
            require(
                route.enabled
                    && route.hosted_client_registration_id.is_none()
                    && route.channel == *channel
                    && route.transport_revision.is_none(),
            )?;
            Some(previous.revision)
        }
        Some(Settings::Profiles(old)) => old.legacy_revision,
        None => None,
    };
    require(next.legacy_revision == old_legacy)?;
    for route in &next.routes {
        if let Some(old) = previous_profiles.and_then(|p| p.find(route.revision)) {
            require(
                old.channel.endpoint == route.channel.endpoint
                    && old.channel.encryption.is_some() == route.channel.encryption.is_some()
                    && old.hosted_client_registration_id == route.hosted_client_registration_id,
            )?;
            let expected_transport = if old.channel == route.channel {
                old.transport_revision
            } else {
                Some(next_revision)
            };
            require(route.transport_revision == expected_transport)?;
        } else if Some(route.revision) != old_legacy {
            require(route.revision == next_revision && route.transport_revision.is_none())?;
        }
        if let Some(client) = route
            .hosted_client_registration_id
            .filter(|_| route.enabled)
        {
            if next.default_revision == Some(route.revision) {
                // Use authoritative wall time only when selecting this route.
                // A message already sealed before retirement can drain until
                // open_until under the existing worker-key contract.
                let now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                )
                .fetch_one(&mut **tx)
                .await?;
                let key = route
                    .channel
                    .encryption
                    .as_ref()
                    .ok_or(AuthorityError::Invalid)?;
                require(key.not_before <= now && now < key.seal_until)?;
            }
            registration(
                tx,
                scope,
                previous.revision,
                client,
                next.return_url.clone(),
            )
            .await?;
        }
    }
    if let Some(old) = previous_profiles {
        for removed in old
            .routes
            .iter()
            .filter(|r| next.find(r.revision).is_none())
        {
            // The scope lock serializes new invitations and the removal. Old
            // revisions cannot be reused, even after their final invitation expires.
            let live: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND state='pending' AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint AND authority->>'delivery_profile_revision'=$3)")
                .bind(scope.environment_id).bind(scope.domain_id).bind(removed.revision.to_string()).fetch_one(&mut **tx).await?;
            require(!live)?;
        }
    }
    Ok(submitted.cloned())
}

pub(crate) async fn hosted_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<HostedRegistration, RepositoryError> {
    let config = read_locked(tx, scope).await?;
    let Some(Settings::Profiles(p)) = config.channel else {
        return Err(AuthorityError::Forbidden.into());
    };
    let id = p
        .routes
        .iter()
        .filter(|r| r.enabled)
        .find_map(|r| r.hosted_client_registration_id)
        .ok_or(AuthorityError::Forbidden)?;
    registration(tx, scope, config.revision, id, p.return_url).await
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustomPin {
    pub revision: i64,
    pub endpoint_sha256: String,
}

pub(crate) struct IssuingPin {
    pub route: Option<i64>,
    pub client: Option<Uuid>,
    pub custom: Option<CustomPin>,
}

pub(crate) async fn issuing_pin(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<IssuingPin, RepositoryError> {
    let config = read_locked(tx, scope).await?;
    let p = match config.channel {
        Some(Settings::Profiles(profiles)) => profiles,
        Some(Settings::Custom(channel)) => {
            return Ok(IssuingPin {
                route: None,
                client: None,
                custom: Some(CustomPin {
                    revision: config.revision,
                    endpoint_sha256: aegaeon_crypto::hash::sha256_hex(channel.endpoint.as_bytes()),
                }),
            })
        }
        None => {
            return Ok(IssuingPin {
                route: None,
                client: None,
                custom: None,
            })
        }
    };
    let route = p
        .default_revision
        .and_then(|r| p.find(r))
        .filter(|r| r.enabled)
        .ok_or(AuthorityError::Forbidden)?;
    if let Some(id) = route.hosted_client_registration_id {
        registration(tx, scope, config.revision, id, p.return_url.clone()).await?;
    }
    Ok(IssuingPin {
        route: Some(route.revision),
        client: route.hosted_client_registration_id,
        custom: None,
    })
}

pub(crate) struct Resolved {
    pub revision: i64,
    pub channel: Option<Channel>,
}

/// An absent pin denotes the historical custom profile. It can never select
/// the hosted default, including when changing profiles or restoring a backup.
pub(crate) async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    revision: Option<i64>,
    client: Option<Uuid>,
) -> Result<Resolved, RepositoryError> {
    let config = read_locked(tx, scope).await?;
    let p = match config.channel {
        Some(Settings::Profiles(profiles)) => profiles,
        legacy => {
            require(revision.is_none())?;
            let channel = match legacy {
                Some(Settings::Custom(channel)) => Some(channel),
                _ => None,
            };
            return Ok(Resolved {
                revision: config.revision,
                channel,
            });
        }
    };
    let route = revision
        .or(p.legacy_revision)
        .and_then(|r| p.find(r))
        .filter(|r| r.enabled)
        .ok_or(AuthorityError::Forbidden)?;
    require(route.hosted_client_registration_id == client)?;
    if let Some(id) = client {
        registration(tx, scope, config.revision, id, p.return_url.clone()).await?;
    }
    Ok(Resolved {
        revision: route.transport_revision.unwrap_or(route.revision),
        channel: Some(route.channel.clone()),
    })
}
