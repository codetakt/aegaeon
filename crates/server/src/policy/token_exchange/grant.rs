use super::*;

// Version 1 did not retain the client's scope ceiling at authorization time.
// Never infer that missing authority from a later client registration.
const GRANT_VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ExchangeAuthorizationError {
    #[error("{0}")]
    InvalidTarget(&'static str),
    #[error("{0}")]
    InvalidScope(&'static str),
}

/// Server-side authority captured with the original authorization code.
/// Absence in a historical record must never be filled from current policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeGrant {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) organization: Option<crate::organizations::consent::RootAuthority>,
    version: u32,
    root: Option<ExchangeRoot>,
    issuer: String,
    client: String,
    user: String,
    policy_digest: String,
    pub(super) capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capability {
    target: String,
    scope: String,
    source_scopes: Vec<String>,
}

impl ExchangeGrant {
    pub(crate) fn has_client_scope_ceiling(&self) -> bool {
        self.version == GRANT_VERSION && self.organization_binding_valid()
    }

    /// Apply effective access scopes, while retaining the original snapshot on the refresh token.
    #[must_use]
    pub fn attenuate(&self, scopes: &[String]) -> Self {
        let mut grant = self.clone();
        grant.capabilities.retain(|cap| {
            !cap.source_scopes.is_empty()
                && cap.source_scopes.iter().all(|scope| scopes.contains(scope))
        });
        grant
    }
}

impl TokenExchangePolicy {
    #[must_use]
    pub fn capture(
        &self,
        issuer: &str,
        client: &str,
        user: &str,
        source: &str,
        scopes: &[String],
        client_scope_ceiling: &[String],
    ) -> Option<ExchangeGrant> {
        if self.validate().is_err() || issuer.is_empty() || client.is_empty() || user.is_empty() {
            return None;
        }
        let capabilities: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.client_id == client && rule.source_audience == source)
            .flat_map(|rule| {
                rule.scopes.iter().map(|mapping| Capability {
                    target: rule.target_audience.clone(),
                    scope: mapping.target_scope.clone(),
                    source_scopes: mapping.source_scopes.clone(),
                })
            })
            .filter(|cap| {
                client_scope_ceiling.contains(&cap.scope)
                    && cap.source_scopes.iter().all(|scope| scopes.contains(scope))
            })
            .collect();
        if capabilities.is_empty() {
            return None;
        }
        Some(ExchangeGrant {
            organization: None,
            version: GRANT_VERSION,
            root: None,
            issuer: issuer.into(),
            client: client.into(),
            user: user.into(),
            policy_digest: self.digest()?,
            capabilities,
        })
    }

    /// Validate the trusted subject's context, current route, original/current ceiling and scope semantics.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit authenticated subject and target context"
    )]
    pub fn authorize(
        &self,
        grant: &ExchangeGrant,
        issuer: &str,
        client: &str,
        user: &str,
        source: &str,
        source_scopes: &[String],
        target: &str,
        requested: Option<&[String]>,
    ) -> Result<(Vec<String>, ExchangeGrant), ExchangeAuthorizationError> {
        if grant.version != GRANT_VERSION
            || grant.issuer != issuer
            || grant.client != client
            || grant.user != user
            || self.digest().as_deref() != Some(grant.policy_digest.as_str())
        {
            return Err(ExchangeAuthorizationError::InvalidTarget(
                "exchange authorization context has changed",
            ));
        }
        let rule = self
            .rules
            .iter()
            .find(|rule| {
                rule.client_id == client
                    && rule.source_audience == source
                    && rule.target_audience == target
            })
            .ok_or(ExchangeAuthorizationError::InvalidTarget(
                "exchange route is not authorized",
            ))?;
        let scopes = requested.unwrap_or(&rule.default_scopes);
        if scopes.is_empty()
            || scopes.len() > 128
            || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len()
        {
            return Err(ExchangeAuthorizationError::InvalidScope(
                "explicit target scope or configured defaults are required",
            ));
        }
        for scope in scopes {
            if !grant
                .capabilities
                .iter()
                .any(|cap| cap.target == target && cap.scope == *scope)
                || !rule.scopes.iter().any(|mapping| {
                    mapping.target_scope == *scope
                        && !mapping.source_scopes.is_empty()
                        && mapping
                            .source_scopes
                            .iter()
                            .all(|needed| source_scopes.contains(needed))
                })
            {
                return Err(ExchangeAuthorizationError::InvalidScope(
                    "requested target scope exceeds subject authority",
                ));
            }
        }
        let mut output = grant.clone();
        output
            .capabilities
            .retain(|cap| cap.target == target && scopes.contains(&cap.scope));
        Ok((scopes.to_vec(), output))
    }
}

impl ExchangeGrant {
    pub(crate) fn is_restriction_of(&self, parent: &Self) -> bool {
        self.version == GRANT_VERSION
            && self.organization == parent.organization
            && self.organization_binding_valid()
            && self.version == parent.version
            && self.root == parent.root
            && self.issuer == parent.issuer
            && self.client == parent.client
            && self.user == parent.user
            && self.policy_digest == parent.policy_digest
            && self
                .capabilities
                .iter()
                .all(|cap| parent.capabilities.contains(cap))
    }

    pub(crate) fn covers_output(
        &self,
        client: &str,
        user: &str,
        target: &str,
        scopes: &[String],
    ) -> bool {
        self.version == GRANT_VERSION
            && self.client == client
            && self.user == user
            && !scopes.is_empty()
            && scopes.iter().all(|scope| {
                self.capabilities
                    .iter()
                    .any(|cap| cap.target == target && cap.scope == *scope)
            })
            && self
                .capabilities
                .iter()
                .all(|cap| cap.target == target && scopes.contains(&cap.scope))
    }
}

/// Independent, bounded revocation identity. It is never included in a JWT or client response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRoot {
    pub(crate) id: String,
    pub(crate) expires_at: std::time::SystemTime,
}

impl ExchangeGrant {
    pub(crate) fn with_lineage_deadline(mut self, expires_at: std::time::SystemTime) -> Self {
        self.root = Some(ExchangeRoot {
            id: format!("exchange-root:{}", uuid::Uuid::new_v4()),
            expires_at,
        });
        self
    }
    pub(crate) fn root(&self) -> Option<&ExchangeRoot> {
        self.root.as_ref()
    }
}

impl ExchangeGrant {
    pub(crate) fn bind_organization_approval(
        &mut self,
        consent: &crate::organizations::consent::Consent,
        details: &serde_json::Value,
    ) -> Result<(), crate::organizations::AuthorityError> {
        use crate::organizations::AuthorityError;
        let request = crate::organizations::consent::GrantRequest::parse(details)?;
        let root = self.root.as_mut().ok_or(AuthorityError::Forbidden)?;
        let expires = root
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(AuthorityError::Invalid)?;
        if self.organization.is_some()
            || consent.request != request
            || (
                consent.issuer.as_str(),
                consent.client_id.as_str(),
                consent.subject.as_str(),
            ) != (
                self.issuer.as_str(),
                self.client.as_str(),
                self.user.as_str(),
            )
            || !self
                .capabilities
                .iter()
                .any(|c| c.target == consent.request.locations[0])
        {
            return Err(AuthorityError::Forbidden);
        }
        let authority = consent.bind(&root.id, expires)?;
        root.expires_at = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(
                u64::try_from(authority.ceiling.expires_at).map_err(|_| AuthorityError::Invalid)?,
            ))
            .ok_or(AuthorityError::Invalid)?;
        self.organization = Some(authority);
        Ok(())
    }

    fn organization_binding_valid(&self) -> bool {
        let Some(organization) = &self.organization else {
            return true;
        };
        let Some(root) = &self.root else {
            return false;
        };
        let Some(expires) = root
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
        else {
            return false;
        };
        organization.consent.issuer == self.issuer
            && organization.consent.client_id == self.client
            && organization.consent.subject == self.user
            && organization
                .consent
                .bind(&root.id, expires)
                .is_ok_and(|value| value == *organization)
    }

    pub(crate) fn original_details_match(&self, details: Option<&serde_json::Value>) -> bool {
        match (&self.organization, details) {
            (None, None) => true,
            (Some(organization), Some(details)) => {
                self.organization_binding_valid()
                    && crate::organizations::consent::GrantRequest::parse(details)
                        .is_ok_and(|request| request == organization.consent.request)
            }
            _ => false,
        }
    }
}
