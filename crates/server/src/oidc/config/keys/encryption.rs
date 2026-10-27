use super::rsa::rsa_request_object_encryption_public_jwk_from_pkcs8_der;
use super::{kid_is_valid, OidcConfigError};
use crate::jwk_types::Jwk;
use std::sync::Arc;

#[derive(Clone)]
pub struct OidcRequestObjectEncryptionKey {
    kid: String,
    pkcs8_der: Arc<Vec<u8>>,
    public_jwk: Jwk,
    retiring: Arc<Vec<(Self, i64)>>,
}

impl std::fmt::Debug for OidcRequestObjectEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcRequestObjectEncryptionKey")
            .field("kid", &self.kid)
            .field("public_jwk", &self.public_jwk)
            .finish_non_exhaustive()
    }
}

impl OidcRequestObjectEncryptionKey {
    /// # Errors
    ///
    /// Returns an error when the `kid` is invalid, DER content is not a
    /// supported RSA PKCS#8 private key, or the public JWK cannot be derived.
    pub(crate) fn from_rsa_pkcs8_der(
        kid: String,
        private_der: &[u8],
    ) -> Result<Self, OidcConfigError> {
        if !kid_is_valid(&kid) {
            return Err(OidcConfigError::InvalidRequestObjectEncryptionKid);
        }

        let public_jwk =
            rsa_request_object_encryption_public_jwk_from_pkcs8_der(&kid, private_der)?;

        Ok(Self {
            kid,
            pkcs8_der: Arc::new(private_der.to_vec()),
            public_jwk,
            retiring: Arc::new(Vec::new()),
        })
    }

    pub(in crate::oidc::config) fn with_retiring(mut self, retiring: Vec<(Self, i64)>) -> Self {
        self.retiring = Arc::new(retiring);
        self
    }

    pub(crate) fn select_pkcs8(
        &self,
        kid: Option<&str>,
    ) -> Result<&[u8], aegaeon_jose::jwe::JweError> {
        let now = crate::util::now_unix_epoch_secs_i64()
            .map_err(|_| aegaeon_jose::jwe::JweError::KeySelection)?;
        self.select_pkcs8_at(kid, now)
    }

    pub(crate) fn select_pkcs8_at(
        &self,
        kid: Option<&str>,
        now: i64,
    ) -> Result<&[u8], aegaeon_jose::jwe::JweError> {
        let kid = kid
            .filter(|kid| !kid.is_empty())
            .ok_or(aegaeon_jose::jwe::JweError::KeySelection)?;
        let mut matching = std::iter::once(self)
            .chain(
                self.retiring
                    .iter()
                    .filter(|(_, deadline)| *deadline > now)
                    .map(|(key, _)| key),
            )
            .filter(|key| key.kid == kid);
        let selected = matching
            .next()
            .ok_or(aegaeon_jose::jwe::JweError::KeySelection)?;
        if matching.next().is_some() {
            return Err(aegaeon_jose::jwe::JweError::KeySelection);
        }
        Ok(selected.pkcs8_der())
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        self.pkcs8_der.as_ref()
    }

    #[must_use]
    pub(crate) fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }
}
