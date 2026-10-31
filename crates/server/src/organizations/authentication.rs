//! Private facts from an already validated OIDC callback, never request authority.
use super::{model::require, AuthorityError};
use crate::upstream::UpstreamConnectionContext;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalAuthentication {
    pub version: u8,
    pub context: UpstreamConnectionContext,
    pub issuer: String,
    pub upstream_client_id: String,
    pub upstream_subject_hash: String,
    pub user_id: Uuid,
    pub subject: String,
    pub identity_revision: i64,
    pub account_link_id: Uuid,
    pub account_link_revision: i64,
    pub account_link_provenance: String,
    pub auth_time: i64,
    pub observed_at: i64,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
}

impl OriginalAuthentication {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        require(
            self.version == 1
                && self.auth_time > 0
                && self.observed_at >= self.auth_time
                && (1..i64::MAX).contains(&self.identity_revision)
                && (1..i64::MAX).contains(&self.account_link_revision),
        )?;
        for id in [
            self.context.team_id,
            self.context.tenant_id,
            self.context.environment_id,
            self.context.connection_id,
            self.context.configuration_version_id,
            self.user_id,
            self.account_link_id,
        ] {
            require(!id.is_nil())?;
        }
        for text in [&self.issuer, &self.upstream_client_id, &self.subject] {
            require(bounded_text(text, 2048))?;
        }
        require(
            self.upstream_subject_hash.len() == 43
                && URL_SAFE_NO_PAD
                    .decode(&self.upstream_subject_hash)
                    .is_ok_and(|v| v.len() == 32)
                && matches!(
                    self.account_link_provenance.as_str(),
                    "legacy_unreviewed" | "jit_v2" | "administrator_confirmed"
                ),
        )?;
        require(self.acr.as_ref().is_none_or(|v| bounded_text(v, 256)))?;
        if let Some(amr) = &self.amr {
            require(
                !amr.is_empty()
                    && amr.len() <= 16
                    && amr.iter().all(|v| bounded_text(v, 128))
                    && amr.iter().collect::<BTreeSet<_>>().len() == amr.len(),
            )?;
        }
        Ok(())
    }

    pub fn matches_session(&self, subject: &str, auth_time: i64, created_at: i64) -> bool {
        self.validate().is_ok()
            && self.subject == subject
            && self.auth_time == auth_time
            && self.observed_at <= created_at
    }

    pub fn matches_identity(
        &self,
        environment_id: Uuid,
        user_id: Uuid,
        identity_revision: i64,
    ) -> bool {
        self.context.environment_id == environment_id
            && self.user_id == user_id
            && self.identity_revision == identity_revision
    }
}

fn bounded_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

#[cfg(test)]
impl OriginalAuthentication {
    pub(crate) fn fixture(
        environment: Uuid,
        user: Uuid,
        subject: &str,
        time: i64,
        observed: i64,
    ) -> Self {
        Self {
            version: 1,
            context: UpstreamConnectionContext::new(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                environment,
                Uuid::new_v4(),
            ),
            issuer: "https://upstream.example".into(),
            upstream_client_id: "upstream-client".into(),
            upstream_subject_hash: crate::upstream::upstream_subject_link_hash(
                "https://upstream.example",
                "upstream-subject",
            ),
            user_id: user,
            subject: subject.into(),
            identity_revision: 1,
            account_link_id: Uuid::new_v4(),
            account_link_revision: 1,
            account_link_provenance: "jit_v2".into(),
            auth_time: time,
            observed_at: observed,
            acr: Some("urn:example:assurance:two-factors".into()),
            amr: Some(vec!["pwd".into(), "otp".into()]),
        }
    }
}
