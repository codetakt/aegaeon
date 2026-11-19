//! Public producer key configuration. Worker private keys are never accepted here.
use super::*;
use crate::organizations::notification_envelope::{
    KeyVersion, PublicDeliveryKey, Scope as KeyScope,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationNotificationEncryption))]
pub struct Encryption {
    pub version: String,
    #[cfg_attr(feature="openapi",schema(value_type=String,format="uuid"))]
    pub deployment_id: Uuid,
    pub public_spki: String,
    pub spki_sha256: String,
    pub not_before: i64,
    pub seal_until: i64,
    pub open_until: i64,
}

impl Encryption {
    /// Reconstruct only an explicitly pinned public key for the current domain.
    ///
    /// # Errors
    /// Refuses noncanonical input, private-key encodings, bad pins or validity.
    pub fn public_key(&self, scope: Scope) -> Result<PublicDeliveryKey, AuthorityError> {
        scope.validate()?;
        require(self.public_spki.len() <= 2732 && self.spki_sha256.len() == 43)?;
        let spki = URL_SAFE_NO_PAD
            .decode(&self.public_spki)
            .map_err(|_| AuthorityError::Invalid)?;
        let digest = URL_SAFE_NO_PAD
            .decode(&self.spki_sha256)
            .map_err(|_| AuthorityError::Invalid)?;
        require(
            URL_SAFE_NO_PAD.encode(&spki) == self.public_spki
                && URL_SAFE_NO_PAD.encode(&digest) == self.spki_sha256,
        )?;
        let pin: [u8; 32] = digest.try_into().map_err(|_| AuthorityError::Invalid)?;
        PublicDeliveryKey::new(
            KeyVersion {
                id: self.version.clone(),
                deployment_id: self.deployment_id,
                scope: KeyScope::Domain {
                    environment_id: scope.environment_id,
                    domain_id: scope.domain_id,
                },
                not_before: self.not_before,
                seal_until: self.seal_until,
                open_until: self.open_until,
            },
            &spki,
            pin,
        )
        .map_err(|_| AuthorityError::Invalid)
    }
}
