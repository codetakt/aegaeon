use super::*;
use crate::authcode::types::{BearerTokenMeta, SenderBinding};

impl SelectedAuthority {
    /// Reconstruct the binding from verified token fields and the server's scope.
    /// Store/root liveness and request DPoP are separate caller preconditions.
    pub(crate) fn token_binding(
        &self,
        meta: &BearerTokenMeta,
        environment_id: uuid::Uuid,
        issuer: &str,
        now: i64,
    ) -> Result<Binding, AuthorityError> {
        let grant = meta
            .exchange_grant
            .as_ref()
            .ok_or(AuthorityError::Forbidden)?;
        let original = grant
            .organization
            .as_ref()
            .ok_or(AuthorityError::Forbidden)?;
        require(
            grant.has_client_scope_ceiling()
                && grant.covers_output(
                    &meta.client_id,
                    &meta.user_id,
                    &meta.audience,
                    &meta.granted_scopes,
                )
                && original.consent.scope.environment_id == environment_id
                && meta.auth_time_epoch_secs == Some(original.consent.auth_time)
                && meta.authorization_details.as_ref()
                    == Some(&self.decision.authorization_details())
                && meta.audience == self.decision.audience,
        )?;
        let Some(SenderBinding::DPoP { jkt }) = &meta.sender_binding else {
            return Err(AuthorityError::Forbidden);
        };
        let binding = Binding {
            scope: original.consent.scope,
            issuer: issuer.into(),
            client_id: meta.client_id.clone(),
            client_registration_id: original.consent.client_registration_id,
            subject: meta.user_id.clone(),
            user_id: original.consent.user_id,
            root_id: grant.root().ok_or(AuthorityError::Forbidden)?.id.clone(),
            dpop_jkt: jkt.clone(),
        };
        self.validate_binding(original, &binding, now)?;
        let epoch = |value: std::time::SystemTime| {
            crate::util::unix_epoch_secs(value)
                .ok()
                .and_then(|v| i64::try_from(v).ok())
        };
        require(
            epoch(meta.issued_at) == Some(self.issued_at)
                && epoch(meta.expires_at) == Some(self.decision.expires_at),
        )?;
        Ok(binding)
    }
}
