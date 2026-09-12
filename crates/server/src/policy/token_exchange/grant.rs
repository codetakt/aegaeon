use super::*;

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
            .filter(|cap| cap.source_scopes.iter().all(|scope| scopes.contains(scope)))
            .collect();
        if capabilities.is_empty() {
            return None;
        }
        Some(ExchangeGrant {
            version: 1,
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
        if grant.version != 1
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
        self.version == 1
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
        self.client == client
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
