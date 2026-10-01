use super::{
    hash::verify_optional_hash, is_https_url, unix_time_now_i64, Audience, Error, IdToken,
    IdTokenValidationContext, Result,
};

impl IdToken {
    /// Validate ID token claims
    ///
    /// # Errors
    ///
    /// Returns an error when issuer, audience, nonce, timing, or optional hash
    /// checks do not satisfy the OIDC validation rules.
    pub fn validate(&self, client_id: &str, issuer: &str, nonce: Option<&str>) -> Result<()> {
        let ctx = IdTokenValidationContext::new(client_id, issuer);
        let ctx = IdTokenValidationContext {
            expected_nonce: nonce,
            ..ctx
        };
        self.validate_with_context(&ctx)
    }

    /// # Errors
    ///
    /// Returns an error when issuer, audience, nonce, timing, or optional hash
    /// checks do not satisfy the OIDC validation rules.
    pub fn validate_with_context(&self, ctx: &IdTokenValidationContext<'_>) -> Result<()> {
        let now = ctx
            .current_time
            .or_else(unix_time_now_i64)
            .ok_or_else(|| Error::ServerError("System time error".into()))?;
        if ctx.clock_skew < 0 {
            return Err(Error::InvalidRequest(
                "clock_skew must be non-negative".into(),
            ));
        }
        let now_with_skew = now.checked_add(ctx.clock_skew).ok_or_else(|| {
            Error::InvalidRequest("ID token clock skew is outside representable time".into())
        })?;

        if self.claims.iss != ctx.issuer {
            return Err(Error::InvalidRequest("Invalid issuer".into()));
        }

        if !is_https_url(&self.claims.iss) {
            return Err(Error::InvalidRequest("Issuer must be https".into()));
        }

        self.validate_audience_and_authorized_party(ctx.client_id)?;

        if self.claims.exp <= self.claims.iat {
            return Err(Error::InvalidRequest(
                "ID token exp must be after iat".into(),
            ));
        }

        if let Some(nbf) = self.claims.nbf {
            if self.claims.exp <= nbf {
                return Err(Error::InvalidRequest(
                    "ID token exp must be after nbf".into(),
                ));
            }
        }

        if now >= self.claims.exp {
            return Err(Error::InvalidRequest("ID token expired".into()));
        }

        if let Some(nbf) = self.claims.nbf {
            if now < nbf {
                return Err(Error::InvalidRequest("ID token not yet valid".into()));
            }
        }

        if self.claims.iat > now_with_skew {
            return Err(Error::InvalidRequest("ID token issued in future".into()));
        }

        if let Some(expected_nonce) = ctx.expected_nonce {
            match &self.claims.nonce {
                Some(token_nonce) if token_nonce == expected_nonce => {}
                _ => return Err(Error::InvalidRequest("Invalid or missing nonce".into())),
            }
        }

        if let Some(max_age) = ctx.max_age {
            if max_age < 0 {
                return Err(Error::InvalidRequest("max_age must be non-negative".into()));
            }
            let auth_time = self
                .claims
                .auth_time
                .ok_or_else(|| Error::InvalidRequest("auth_time missing".into()))?;
            if auth_time > now_with_skew {
                return Err(Error::InvalidRequest(
                    "Authentication time is in the future".into(),
                ));
            }
            let authentication_age = if auth_time > now {
                0
            } else {
                now.checked_sub(auth_time).ok_or_else(|| {
                    Error::InvalidRequest(
                        "Authentication time is outside representable time".into(),
                    )
                })?
            };
            if authentication_age > max_age {
                return Err(Error::InvalidRequest("Authentication too old".into()));
            }
        }

        verify_optional_hash(
            ctx.access_token_for_hash,
            self.claims.at_hash.as_deref(),
            &self.signing_alg,
            "at_hash",
        )?;
        verify_optional_hash(
            ctx.code_for_hash,
            self.claims.c_hash.as_deref(),
            &self.signing_alg,
            "c_hash",
        )?;

        Ok(())
    }

    fn validate_audience_and_authorized_party(&self, client_id: &str) -> Result<()> {
        // OIDC Core errata set 2, section 3.1.3.7: reject additional audiences
        // not trusted by this RP. The current context grants trust only to its
        // own client ID; azp does not grant trust in another audience.
        let audience_is_trusted = match &self.claims.aud {
            Audience::Single(value) => value == client_id,
            Audience::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| value == client_id)
            }
        };
        if !audience_is_trusted {
            return Err(Error::InvalidRequest("Invalid audience".into()));
        }

        // Aegaeon's supplied-azp comparison policy is independent of audience
        // representation. Core does not universally require azp to be present.
        if self
            .claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp != client_id)
        {
            return Err(Error::InvalidRequest("Invalid azp".into()));
        }

        Ok(())
    }
}
