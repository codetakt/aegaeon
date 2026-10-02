use super::*;
use crate::authcode::token::jwt_access::{
    verify_jwt, JwtAccessTokenAudience, JwtAccessTokenHeader, JwtAccessTokenPayload,
    JwtAccessTokenVerificationError, JwtTokenParts,
};
use crate::authcode::token::ACCESS_TOKEN_TYP;

impl TokenValidator {
    pub(super) fn verify_access_jwt(
        &self,
        token: &str,
        require_jwt: bool,
    ) -> Result<Option<JwtTokenParts>, BearerTokenValidationError> {
        if !require_jwt && !token.contains('.') {
            return Ok(None);
        }
        let verified = verify_jwt(token, self.access_verifier.as_ref())
            .map_err(|error| match error {
                JwtAccessTokenVerificationError::KeyManager(error) => BearerTokenValidationError::internal(format!("Token verification error: {error}")),
                JwtAccessTokenVerificationError::BackendPolicy(surface) => BearerTokenValidationError::internal(format!("access token parser backend misconfigured: unsupported raw JSON backend for {surface}")),
            })?
            .ok_or_else(|| BearerTokenValidationError::invalid("Invalid token signature"))?;
        Self::enforce_access_token_typ(&verified.header)
            .map_err(BearerTokenValidationError::invalid)?;
        let now = (self.now)().map_err(BearerTokenValidationError::internal)?;
        self.enforce_access_token_claims(&verified.payload, self.issuer.as_deref(), now)
            .map_err(BearerTokenValidationError::invalid)?;
        Ok(Some(verified))
    }

    /// Check signed-token content for an already observed stored token.
    /// The caller must separately establish requester visibility and current store/grant authority.
    /// This does not enforce resource sender proofs or expand recipient entitlement.
    ///
    /// # Errors
    ///
    /// Invalid signed content is distinguished from operational verification failures.
    pub fn validate_stored_access_token_jwt(
        &self,
        access: &AccessToken,
        meta: Option<&BearerTokenMeta>,
    ) -> Result<(), BearerTokenValidationError> {
        if let (Some(verified), Some(meta)) = (self.verify_access_jwt(&access.token, false)?, meta)
        {
            if !Self::aud_matches(&verified.payload, &meta.audience) {
                return Err(BearerTokenValidationError::invalid(
                    "invalid_token_audience",
                ));
            }
        }
        Ok(())
    }

    fn enforce_access_token_typ(header: &JwtAccessTokenHeader) -> Result<(), String> {
        let typ = header.typ.as_deref();
        match typ {
            Some(ACCESS_TOKEN_TYP | "application/at+jwt") => Ok(()),
            _ => Err("invalid_token_typ".to_string()),
        }
    }

    fn enforce_access_token_claims(
        &self,
        payload: &JwtAccessTokenPayload,
        issuer: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let iss = payload.iss.as_deref();
        if iss.is_none() {
            return Err("invalid_token_issuer".to_string());
        }
        if let Some(expected) = issuer {
            if iss != Some(expected) {
                return Err("invalid_token_issuer".to_string());
            }
        }
        if payload.sub.is_none() {
            return Err("invalid_token_subject".to_string());
        }
        if !payload.aud_present {
            return Err("invalid_token_audience".to_string());
        }
        if payload.aud.is_none() {
            return Err("invalid_token_audience".to_string());
        }
        if payload.exp.is_none() {
            return Err("invalid_token_exp".to_string());
        }
        if payload.iat.is_none() {
            return Err("invalid_token_iat".to_string());
        }
        self.enforce_access_token_times(payload, now)?;
        if payload.jti.is_none() {
            return Err("invalid_token_id".to_string());
        }
        Ok(())
    }

    fn enforce_access_token_times(
        &self,
        payload: &JwtAccessTokenPayload,
        now: u64,
    ) -> Result<(), String> {
        let exp = payload.exp.ok_or_else(|| "invalid_token_exp".to_string())?;
        let iat = payload.iat.ok_or_else(|| "invalid_token_iat".to_string())?;
        if exp <= iat {
            return Err("invalid_token_exp".to_string());
        }

        let leeway = self.jwt_leeway_secs;
        let exp_with_leeway = exp
            .checked_add(leeway)
            .ok_or_else(|| "invalid_token_exp".to_string())?;
        if exp_with_leeway < now {
            return Err("invalid_token_exp".to_string());
        }
        let now_with_leeway = now
            .checked_add(leeway)
            .ok_or_else(|| "invalid_token_iat".to_string())?;
        if iat > now_with_leeway {
            return Err("invalid_token_iat".to_string());
        }
        Ok(())
    }

    pub(super) fn aud_matches(payload: &JwtAccessTokenPayload, expected: &str) -> bool {
        match payload.aud.as_ref() {
            Some(JwtAccessTokenAudience::Single(aud)) => aud == expected,
            Some(JwtAccessTokenAudience::Multiple(list)) => {
                list.iter().any(|value| value == expected)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::{InMemoryPublicJwtKeyManager, KeyManager};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn stored_jwt_claim_clock_failure_is_operational() -> Result<(), Box<dyn std::error::Error>> {
        let manager = Arc::new(InMemoryPublicJwtKeyManager::new()?);
        let now = crate::util::now_unix_epoch_secs()?;
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"typ":"at+jwt","kid":manager.key_id(),"alg":"EdDSA"}))?), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","sub":"subject","aud":"resource","iat":now,"exp":now+300,"jti":"id"}))?));
        let token = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(manager.sign(input.as_bytes())?)
        );
        let mut validator = TokenValidator::new(TokenStore::new_process_local_for_tests(), manager);
        assert!(validator.verify_access_jwt(&token, false)?.is_some());
        validator.now = || Err("server_clock_unavailable".into());
        assert!(validator
            .verify_access_jwt(&token, false)
            .err()
            .is_some_and(|error| error.is_internal()));
        assert!(validator.verify_access_jwt("opaque", false)?.is_none());
        Ok(())
    }
}
