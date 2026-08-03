use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{KeyManager, KeyManagerError};
use crate::jwk_types::Jwk;
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyUsage,
};
use std::time::{SystemTime, UNIX_EPOCH};

struct ManagedJwtSigningKey {
    kid: String,
    alg: &'static str,
    public_jwk: serde_json::Value,
    material: ManagedJwtSigningMaterial,
}

enum ManagedJwtSigningMaterial {
    EdDsa(aegaeon_crypto::signing::Ed25519SigningKey),
}

struct ManagedJwtVerificationKey {
    kid: String,
    alg: &'static str,
    retiring_expires_at_epoch_secs: Option<i64>,
    public_jwk: serde_json::Value,
    material: ManagedJwtVerificationMaterial,
}

enum ManagedJwtVerificationMaterial {
    EdDsa(Vec<u8>),
}

/// JWT key manager backed by management-database runtime keys.
///
/// Signing uses the active key for a single runtime-key usage. Verification accepts
/// both the active key and retiring keys for that usage, selected by JOSE `kid`.
pub struct ManagedJwtKeyManager {
    active: ManagedJwtSigningKey,
    verification_keys: Vec<ManagedJwtVerificationKey>,
}

impl ManagedJwtKeyManager {
    /// Build a JWT key manager for the given runtime-key usage.
    ///
    /// # Errors
    ///
    /// Returns an error when no active key exists, the provider is unsupported,
    /// managed key material cannot be decrypted, or the key material does not
    /// match the declared algorithm.
    pub fn try_from_runtime_keys(
        runtime_keys: &RuntimeKeySet,
        usage: RuntimeKeyUsage,
    ) -> Result<Self, KeyManagerError> {
        let active_key = runtime_keys
            .active_key(usage)
            .ok_or(KeyManagerError::KeyNotFound)?;
        let active = managed_jwt_signing_key(active_key)?;
        let mut verification_keys = std::iter::once(active_key)
            .chain(runtime_keys.retiring_keys(usage))
            .map(managed_jwt_verification_key)
            .collect::<Result<Vec<_>, _>>()?;
        verification_keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        verification_keys.dedup_by(|left, right| left.kid == right.kid && left.alg == right.alg);

        Ok(Self {
            active,
            verification_keys,
        })
    }
}

impl KeyManager for ManagedJwtKeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        match &self.active.material {
            ManagedJwtSigningMaterial::EdDsa(signer) => signer
                .sign(msg)
                .map_err(|_| KeyManagerError::OperationFailed),
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        self.verify_jwt_signature(&self.active.kid, self.active.alg, msg, sig)
    }

    fn verify_jwt_signature(
        &self,
        kid: &str,
        alg: &str,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<bool, KeyManagerError> {
        let now_epoch_secs = current_unix_epoch_secs();
        self.verification_keys
            .iter()
            .find(|key| key.kid == kid && key.alg == alg && key.is_active_at(now_epoch_secs))
            .map_or(Ok(false), |key| key.verify(msg, sig))
    }

    fn key_id(&self) -> String {
        self.active.kid.clone()
    }

    fn jwt_signing_alg(&self) -> &'static str {
        self.active.alg
    }

    fn jwt_signing_public_jwk(&self) -> Option<serde_json::Value> {
        Some(self.active.public_jwk.clone())
    }

    fn jwt_signing_public_jwks(&self) -> Vec<serde_json::Value> {
        let now_epoch_secs = current_unix_epoch_secs();
        self.verification_keys
            .iter()
            .filter(|key| key.is_active_at(now_epoch_secs))
            .map(|key| key.public_jwk.clone())
            .collect()
    }

    fn rotate(&self) -> Result<(), KeyManagerError> {
        Err(KeyManagerError::OperationFailed)
    }

    fn revoke(&self) -> Result<(), KeyManagerError> {
        Err(KeyManagerError::OperationFailed)
    }
}

impl ManagedJwtVerificationKey {
    fn is_active_at(&self, now_epoch_secs: i64) -> bool {
        self.retiring_expires_at_epoch_secs
            .is_none_or(|expires_at| expires_at > now_epoch_secs)
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        match &self.material {
            ManagedJwtVerificationMaterial::EdDsa(public_key) => {
                Ok(aegaeon_crypto::signature::verify_ed25519(public_key, msg, sig).is_ok())
            }
        }
    }
}

fn managed_jwt_signing_key(key: &RuntimeKey) -> Result<ManagedJwtSigningKey, KeyManagerError> {
    if key.provider != RuntimeKeyProvider::DatabaseEncrypted {
        return Err(KeyManagerError::OperationFailed);
    }
    let pkcs8 = decrypt_runtime_key_pkcs8_der(key)?;
    let material = match key.algorithm {
        RuntimeKeyAlgorithm::EdDsa => {
            let signer = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&pkcs8)
                .map_err(|_| KeyManagerError::OperationFailed)?;
            ensure_runtime_key_public_jwk_matches(
                key,
                &eddsa_public_jwk_from_signer(key, &signer)?,
            )?;
            ManagedJwtSigningMaterial::EdDsa(signer)
        }
        RuntimeKeyAlgorithm::Rs256 | RuntimeKeyAlgorithm::RsaOaepA256Gcm => {
            return Err(KeyManagerError::OperationFailed);
        }
    };
    Ok(ManagedJwtSigningKey {
        kid: key.kid.clone(),
        alg: jwt_alg_for_runtime_key(key.algorithm)?,
        public_jwk: serde_json::to_value(&key.public_jwk)
            .map_err(|_| KeyManagerError::OperationFailed)?,
        material,
    })
}

fn managed_jwt_verification_key(
    key: &RuntimeKey,
) -> Result<ManagedJwtVerificationKey, KeyManagerError> {
    let material = match key.algorithm {
        RuntimeKeyAlgorithm::EdDsa => {
            ManagedJwtVerificationMaterial::EdDsa(eddsa_public_key_from_jwk(key)?)
        }
        RuntimeKeyAlgorithm::Rs256 | RuntimeKeyAlgorithm::RsaOaepA256Gcm => {
            return Err(KeyManagerError::OperationFailed);
        }
    };
    Ok(ManagedJwtVerificationKey {
        kid: key.kid.clone(),
        alg: jwt_alg_for_runtime_key(key.algorithm)?,
        retiring_expires_at_epoch_secs: key.retiring_expires_at_epoch_secs,
        public_jwk: serde_json::to_value(&key.public_jwk)
            .map_err(|_| KeyManagerError::OperationFailed)?,
        material,
    })
}

fn jwt_alg_for_runtime_key(
    algorithm: RuntimeKeyAlgorithm,
) -> Result<&'static str, KeyManagerError> {
    match algorithm {
        RuntimeKeyAlgorithm::EdDsa => Ok("EdDSA"),
        RuntimeKeyAlgorithm::Rs256 | RuntimeKeyAlgorithm::RsaOaepA256Gcm => {
            Err(KeyManagerError::OperationFailed)
        }
    }
}

fn current_unix_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn decrypt_runtime_key_pkcs8_der(key: &RuntimeKey) -> Result<Vec<u8>, KeyManagerError> {
    let kek = crate::key_encryption::load_key_encryption_key()
        .map_err(|_| KeyManagerError::OperationFailed)?;
    let plaintext = crate::key_encryption::decrypt_key_handle(
        &key.key_handle,
        &kek,
        key.key_handle_encryption_context(),
    )
    .map_err(|_| KeyManagerError::OperationFailed)?;
    URL_SAFE_NO_PAD
        .decode(plaintext.trim())
        .map_err(|_| KeyManagerError::OperationFailed)
}

fn ensure_runtime_key_public_jwk_matches(
    key: &RuntimeKey,
    derived: &Jwk,
) -> Result<(), KeyManagerError> {
    if key.public_jwk.kty == derived.kty
        && key.public_jwk.use_ == derived.use_
        && key.public_jwk.kid == derived.kid
        && key.public_jwk.alg == derived.alg
        && key.public_jwk.n == derived.n
        && key.public_jwk.e == derived.e
        && key.public_jwk.x == derived.x
        && key.public_jwk.y == derived.y
        && key.public_jwk.crv == derived.crv
    {
        Ok(())
    } else {
        Err(KeyManagerError::OperationFailed)
    }
}

fn eddsa_public_jwk_from_signer(
    key: &RuntimeKey,
    signer: &aegaeon_crypto::signing::Ed25519SigningKey,
) -> Result<Jwk, KeyManagerError> {
    let public_key = signer
        .public_key_bytes()
        .map_err(|_| KeyManagerError::OperationFailed)?;
    if public_key.len() != 32 {
        return Err(KeyManagerError::OperationFailed);
    }
    Ok(Jwk {
        kty: "OKP".to_string(),
        use_: Some("sig".to_string()),
        kid: key.kid.clone(),
        alg: Some("EdDSA".to_string()),
        n: None,
        e: None,
        x: Some(URL_SAFE_NO_PAD.encode(public_key)),
        y: None,
        crv: Some("Ed25519".to_string()),
    })
}

fn eddsa_public_key_from_jwk(key: &RuntimeKey) -> Result<Vec<u8>, KeyManagerError> {
    let x = key
        .public_jwk
        .x
        .as_deref()
        .ok_or(KeyManagerError::OperationFailed)?;
    let public_key = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| KeyManagerError::OperationFailed)?;
    if public_key.len() == 32 {
        Ok(public_key)
    } else {
        Err(KeyManagerError::OperationFailed)
    }
}
