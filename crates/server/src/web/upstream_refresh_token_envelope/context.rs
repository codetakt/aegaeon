use super::UpstreamRefreshTokenEnvelopeError as Error;
use crate::oidc::{Audience, IdToken};
use serde::{Deserialize, Serialize};

/// Original validated claims, retained privately with their refresh grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::web) struct UpstreamRefreshAuthenticationContext {
    issuer: String,
    subject: String,
    audiences: Vec<String>,
    client_id: String,
    auth_time: Option<i64>,
    nonce: Option<String>,
}

fn audience_members(audience: &Audience) -> Vec<String> {
    let mut members = match audience {
        Audience::Single(value) => vec![value.clone()],
        Audience::Multiple(values) => values.clone(),
    };
    members.sort();
    members.dedup();
    members
}

impl UpstreamRefreshAuthenticationContext {
    /// Called only after the callback's signature and claims validation.
    pub(in crate::web) fn from_validated_id_token(
        token: &IdToken,
        client_id: &str,
        issuer: &str,
        subject_hash: &str,
    ) -> Result<Self, Error> {
        let context = Self {
            issuer: token.claims.iss.clone(),
            subject: token.claims.sub.clone(),
            audiences: audience_members(&token.claims.aud),
            client_id: client_id.to_string(),
            auth_time: token.claims.auth_time,
            nonce: token.claims.nonce.clone(),
        };
        context.validate_binding(issuer, subject_hash)?;
        Ok(context)
    }

    pub(in crate::web) fn matches_client(&self, client_id: &str) -> bool {
        self.client_id == client_id
    }

    pub(super) fn validate_binding(&self, issuer: &str, subject_hash: &str) -> Result<(), Error> {
        if self.issuer != issuer
            || crate::web::validate_upstream_issuer(&self.issuer).is_none()
            || self.subject.is_empty()
            || self.client_id.is_empty()
            || self.audiences.is_empty()
            || self.audiences.iter().any(String::is_empty)
            || !self.audiences.contains(&self.client_id)
            || self.audiences.windows(2).any(|pair| pair[0] >= pair[1])
            || self.auth_time.is_some_and(|value| value < 0)
            || self.nonce.as_ref().is_some_and(String::is_empty)
            || crate::upstream::upstream_subject_link_hash(&self.issuer, &self.subject)
                != subject_hash
        {
            return Err(Error::ContextInvalid);
        }
        Ok(())
    }

    pub(in crate::web) fn validate_refreshed_id_token(&self, token: &IdToken) -> Result<(), Error> {
        if token.claims.iss != self.issuer
            || token.claims.sub != self.subject
            || audience_members(&token.claims.aud) != self.audiences
            || token
                .claims
                .auth_time
                .is_some_and(|value| Some(value) != self.auth_time)
            || token
                .claims
                .nonce
                .as_ref()
                .is_some_and(|value| Some(value) != self.nonce.as_ref())
        {
            return Err(Error::ContextInvalid);
        }
        Ok(())
    }
}
