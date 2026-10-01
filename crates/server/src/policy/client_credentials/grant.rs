//! Persisted client-credentials authority and the consumed issuance permit.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredentialsRegistration {
    pub(crate) client_id: String,
    pub(crate) registration_id: Uuid,
}

/// Server-owned snapshot; deserialization does not grant issuance authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredentialsGrant {
    pub(crate) version: u32,
    pub(crate) issuer: String,
    pub(crate) environment_id: Uuid,
    pub(crate) configuration_version_id: Uuid,
    pub(crate) configuration_document_fingerprint: String,
    pub(crate) runtime_client_fingerprint: String,
    pub(crate) caller: ClientCredentialsRegistration,
    pub(crate) audience: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) context_digest: String,
    pub(crate) introspection_clients: Vec<ClientCredentialsRegistration>,
}

/// A single issuance authorization. Only the authenticated server path constructs it.
/// It is deliberately neither Clone nor Deserialize and is consumed by every issuer API.
#[derive(Debug)]
pub struct AuthorizedClientCredentials {
    grant: ClientCredentialsGrant,
}

impl AuthorizedClientCredentials {
    pub(crate) fn new(grant: ClientCredentialsGrant) -> Result<Self, &'static str> {
        grant.validate()?;
        Ok(Self { grant })
    }

    pub(crate) fn caller_registration_id(&self) -> Uuid {
        self.grant.caller.registration_id
    }

    pub(crate) fn into_grant(self) -> ClientCredentialsGrant {
        self.grant
    }
}

impl ClientCredentialsGrant {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.issuer.is_empty()
            || self.environment_id.is_nil()
            || self.configuration_version_id.is_nil()
            || self.caller.client_id.is_empty()
            || self.caller.registration_id.is_nil()
            || self.audience.is_empty()
            || [
                &self.context_digest,
                &self.configuration_document_fingerprint,
                &self.runtime_client_fingerprint,
            ]
            .iter()
            .any(|digest| digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
            || self.scopes.is_empty()
            || self.scopes.len() > 128
            || self.scopes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.scopes.iter().any(|scope| {
                matches!(scope.as_str(), "openid" | "offline_access")
                    || !crate::oauth_scope::parse_scope_string(scope)
                        .is_ok_and(|scopes| scopes.len() == 1 && scopes[0] == *scope)
            })
            || self.introspection_clients.len() > 128
            || self
                .introspection_clients
                .windows(2)
                .any(|pair| pair[0].client_id >= pair[1].client_id)
            || self
                .introspection_clients
                .iter()
                .any(|identity| identity.client_id.is_empty() || identity.registration_id.is_nil())
        {
            return Err("invalid client-credentials authorization snapshot");
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<String, &'static str> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| "client-credentials snapshot serialization failed")?;
        Ok(aegaeon_crypto::hash::sha256_hex(&bytes))
    }

    pub(crate) fn covers(
        &self,
        client: &str,
        subject: &str,
        audience: &str,
        scopes: &[String],
    ) -> bool {
        let mut scopes = scopes.to_vec();
        scopes.sort();
        self.validate().is_ok()
            && self.caller.client_id == client
            && subject == client
            && self.audience == audience
            && self.scopes == scopes
    }

    pub(crate) fn attenuate(&self, scopes: &[String]) -> Result<Self, &'static str> {
        let mut restricted = self.clone();
        restricted.scopes = scopes.to_vec();
        restricted.scopes.sort();
        if !restricted.is_restriction_of(self) {
            return Err("client-credentials exchange exceeds source authority");
        }
        Ok(restricted)
    }

    pub(crate) fn is_restriction_of(&self, parent: &Self) -> bool {
        if self.validate().is_err()
            || parent.validate().is_err()
            || !self
                .scopes
                .iter()
                .all(|scope| parent.scopes.contains(scope))
        {
            return false;
        }
        let mut original = self.clone();
        original.scopes.clone_from(&parent.scopes);
        original == *parent
    }

    #[cfg(test)]
    pub(crate) fn fixture(issuer: &str, client: &str, audience: &str, scopes: &[String]) -> Self {
        let mut scopes = scopes.to_vec();
        scopes.sort();
        Self {
            version: 1,
            issuer: issuer.to_string(),
            environment_id: Uuid::from_u128(1),
            configuration_version_id: Uuid::from_u128(2),
            configuration_document_fingerprint: "0".repeat(64),
            runtime_client_fingerprint: "0".repeat(64),
            caller: ClientCredentialsRegistration {
                client_id: client.to_string(),
                registration_id: Uuid::from_u128(3),
            },
            audience: audience.to_string(),
            scopes,
            context_digest: "0".repeat(64),
            introspection_clients: Vec::new(),
        }
    }
}
