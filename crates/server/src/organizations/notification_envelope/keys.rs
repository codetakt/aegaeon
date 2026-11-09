use super::{valid_id, Error, MessageContext, Scope};
use aegaeon_crypto::{hash::sha256_digest, jwe};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Immutable local configuration snapshot; not a credential or a live clock.
#[derive(Clone)]
pub struct KeyVersion {
    pub id: String,
    pub deployment_id: Uuid,
    pub scope: Scope,
    pub not_before: i64,
    pub seal_until: i64,
    pub open_until: i64,
}

impl KeyVersion {
    fn validate(&self) -> Result<(), Error> {
        self.scope.validate()?;
        if !valid_id(&self.id)
            || self.deployment_id.is_nil()
            || self.not_before < 0
            || self.not_before >= self.seal_until
            || self.seal_until > self.open_until
        {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    pub(super) fn admit(
        &self,
        context: &MessageContext,
        now: i64,
        seal: bool,
    ) -> Result<(), Error> {
        if now < self.not_before
            || now >= self.open_until
            || (seal && now >= self.seal_until)
            || context.expires_at > self.open_until
            || context.deployment_id != self.deployment_id
            || !self.scope.admits(&context.scope)
        {
            return Err(Error::KeyUnavailable);
        }
        Ok(())
    }
}

/// Producer configuration contains only a validated public key, never PKCS#8.
pub struct PublicDeliveryKey {
    pub(super) version: KeyVersion,
    pub(super) spki: Vec<u8>,
    pub(super) fingerprint: [u8; 32],
}

impl PublicDeliveryKey {
    /// Fingerprint must be pinned by the caller's trusted delivery configuration.
    pub fn new(
        version: KeyVersion,
        spki: &[u8],
        expected_fingerprint: [u8; 32],
    ) -> Result<Self, Error> {
        version.validate()?;
        if spki.is_empty() || spki.len() > 2048 {
            return Err(Error::InvalidKey);
        }
        let canonical = jwe::rsa_encryption_public_spki(spki).map_err(|_| Error::InvalidKey)?;
        let fingerprint = sha256_digest(&canonical);
        if canonical != spki || fingerprint != expected_fingerprint {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            version,
            spki: canonical,
            fingerprint,
        })
    }
}

/// Worker-owned private bytes. No Debug, Clone, Serialize or key-export API.
pub struct PrivateDeliveryKey {
    pub(super) version: KeyVersion,
    pub(super) pkcs8: Zeroizing<Vec<u8>>,
    pub(super) fingerprint: [u8; 32],
}

impl PrivateDeliveryKey {
    /// Derive the public fingerprint from the private key, then match its pin.
    /// The transferred private allocation is erased on constructor failure/drop.
    pub fn new(
        version: KeyVersion,
        pkcs8: Zeroizing<Vec<u8>>,
        expected_fingerprint: [u8; 32],
    ) -> Result<Self, Error> {
        version.validate()?;
        if pkcs8.is_empty() || pkcs8.len() > 8192 {
            return Err(Error::InvalidKey);
        }
        let public =
            jwe::rsa_encryption_public_spki_from_pkcs8(&pkcs8).map_err(|_| Error::InvalidKey)?;
        let fingerprint = sha256_digest(&public);
        if fingerprint != expected_fingerprint {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            version,
            pkcs8,
            fingerprint,
        })
    }
}

/// At most sixteen exact versions. This does not load or refresh configuration.
pub struct PrivateKeyRing(Vec<PrivateDeliveryKey>);

impl PrivateKeyRing {
    pub fn new(keys: Vec<PrivateDeliveryKey>) -> Result<Self, Error> {
        if keys.len() > 16
            || keys
                .iter()
                .enumerate()
                .any(|(i, k)| keys[..i].iter().any(|old| old.version.id == k.version.id))
        {
            return Err(Error::InvalidKey);
        }
        Ok(Self(keys))
    }

    pub(super) fn select(
        &self,
        version: &str,
        context: &MessageContext,
        now: i64,
    ) -> Result<&PrivateDeliveryKey, Error> {
        if !valid_id(version) {
            return Err(Error::KeyUnavailable);
        }
        let key = self
            .0
            .iter()
            .find(|k| k.version.id == version)
            .ok_or(Error::KeyUnavailable)?;
        key.version.admit(context, now, false)?;
        Ok(key)
    }
}
