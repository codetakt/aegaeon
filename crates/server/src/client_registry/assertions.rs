mod jwt_bearer;
mod private_key_jwt;
mod request_object;

fn request_object_used_as_assertion(
    header: &jsonwebtoken::Header,
    claims: &aegaeon_jose::jwt::JwtClaims,
) -> bool {
    // RFC 8725 section 3.12: audiences can overlap. Every admitted Request
    // Object has response_type, including legacy objects without explicit typ.
    header.typ.as_deref().is_some_and(|typ| {
        typ.eq_ignore_ascii_case("oauth-authz-req+jwt")
            || typ.eq_ignore_ascii_case("application/oauth-authz-req+jwt")
    }) || claims
        .custom
        .as_object()
        .is_none_or(|custom| custom.contains_key("response_type"))
}

/// A verified assertion whose single-use decision is still pending.
/// Fields are private to the verification modules; HTTP cannot forge an acceptance.
pub(crate) struct PreparedClientAssertion {
    store: std::sync::Arc<dyn crate::middleware::ReplayStore>,
    namespace: &'static str,
    client_id: String,
    jti: String,
    ttl_secs: i64,
    claims: aegaeon_jose::jwt::JwtClaims,
    leeway: u64,
    subject: String,
}

impl PreparedClientAssertion {
    fn is_fresh(&self) -> Result<bool, super::ClientAssertionValidationError> {
        let now =
            super::unix_epoch_now_i64("assertion replay completion clock").ok_or_else(|| {
                super::client_assertion_clock_error("assertion replay completion clock")
            })?;
        let ctx = aegaeon_jose::jwt::ValidationContext::builder()
            .now(now)
            .leeway(std::time::Duration::from_secs(self.leeway))
            .build();
        Ok(self.claims.validate(&ctx).is_ok())
    }

    fn finish(self) -> super::ClientAssertionValidationResult {
        crate::organizations::lifecycle::proofs::ensure_allowed(
            crate::organizations::lifecycle::proofs::Kind::Assertion,
        )
        .map_err(|_| super::ClientAssertionValidationError::RecoveryDeferred)?;
        if !self.is_fresh()? {
            return Ok(None);
        }
        let result = super::record_jwt_replay(
            &self.store,
            self.namespace,
            &self.client_id,
            &self.jti,
            self.ttl_secs,
        );
        self.result(&result)
    }

    pub(crate) async fn finish_async(self) -> super::ClientAssertionValidationResult {
        crate::organizations::lifecycle::proofs::ensure_allowed(
            crate::organizations::lifecycle::proofs::Kind::Assertion,
        )
        .map_err(|_| super::ClientAssertionValidationError::RecoveryDeferred)?;
        if !self.is_fresh()? {
            return Ok(None);
        }
        let material = crate::middleware::replay_key_material(&[
            self.client_id.as_bytes(),
            self.jti.as_bytes(),
        ]);
        let ttl = u64::try_from(self.ttl_secs)
            .map_err(|_| super::ClientAssertionValidationError::InvalidAssertion)?;
        let result = self
            .store
            .clone()
            .check_and_store_async(crate::middleware::replay_store::OwnedReplayEntry::new(
                self.namespace.into(),
                material,
                std::time::Duration::from_secs(ttl),
            ))
            .await;
        self.result(&result)
    }

    fn result(
        self,
        result: &Result<(), crate::middleware::ReplayStoreError>,
    ) -> super::ClientAssertionValidationResult {
        match result {
            Ok(()) if self.is_fresh()? => Ok(Some(self.subject)),
            Ok(()) | Err(crate::middleware::ReplayStoreError::Replay) => Ok(None),
            Err(_) => Err(super::ClientAssertionValidationError::Internal(
                "assertion replay database unavailable".into(),
            )),
        }
    }
}

impl super::ClientRegistry {
    async fn native_remote_keys(
        &self,
        reg: &super::RegisteredClient,
    ) -> Result<
        Option<std::sync::Arc<super::jwks_native::Body>>,
        super::ClientAssertionValidationError,
    > {
        if reg.jwks_pem.is_some() || reg.inline_jwks.is_some() {
            return Ok(None);
        }
        let Some(native) = self.jwks_state.native() else {
            return Ok(None);
        };
        let Some(uri) = &reg.jwks_uri else {
            return Ok(None);
        };
        native
            .fetch(uri)
            .await
            .map_err(super::ClientAssertionValidationError::Internal)?
            .map(Some)
            .ok_or(super::ClientAssertionValidationError::InvalidAssertion)
    }
}
