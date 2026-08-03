use super::{log_key_manager_invariant, KeyManager, KeyManagerError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::sync::RwLock;

/// ECDSA P-256 key data for federation signing.
struct FederationKeyData {
    /// PKCS#8 DER-encoded private key (used to reconstruct `EcdsaKeyPair` for signing).
    pkcs8: Vec<u8>,
    /// Raw X coordinate of the public key (32 bytes).
    public_x: Vec<u8>,
    /// Raw Y coordinate of the public key (32 bytes).
    public_y: Vec<u8>,
}

struct InMemoryJwtKey {
    key_id: String,
    key_bytes: Option<Vec<u8>>,
}

struct InMemoryPublicJwtKey {
    key_id: String,
    pkcs8: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

fn new_in_memory_jwt_key() -> InMemoryJwtKey {
    InMemoryJwtKey {
        key_id: format!("in-memory-{}", aegaeon_crypto::rand::random_base64url(16)),
        key_bytes: Some(aegaeon_crypto::rand::random_bytes(32)),
    }
}

fn new_in_memory_public_jwt_key() -> Result<InMemoryPublicJwtKey, KeyManagerError> {
    let key_data = aegaeon_crypto::signing::Ed25519SigningKey::generate()
        .map_err(|_| KeyManagerError::OperationFailed)?;
    Ok(InMemoryPublicJwtKey {
        key_id: format!(
            "in-memory-ed25519-{}",
            aegaeon_crypto::rand::random_base64url(16)
        ),
        pkcs8: Some(key_data.pkcs8),
        public_key: key_data.public_key,
    })
}

/// Generate a new ECDSA P-256 keypair for federation signing.
fn generate_federation_key() -> Result<FederationKeyData, KeyManagerError> {
    let key_data = aegaeon_crypto::signing::EcdsaP256SigningKey::generate()
        .map_err(|_| KeyManagerError::OperationFailed)?;

    Ok(FederationKeyData {
        pkcs8: key_data.pkcs8,
        public_x: key_data.public_x,
        public_y: key_data.public_y,
    })
}

/// In-memory key manager used for tests.
pub struct InMemoryKeyManager {
    key: RwLock<InMemoryJwtKey>,
    /// ECDSA P-256 keypair for federation entity signing (ES256).
    federation_key: RwLock<Option<FederationKeyData>>,
}

impl InMemoryKeyManager {
    /// Try to create a new in-memory manager with a random HMAC key and an ECDSA P-256 keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if the local random source cannot generate federation key material.
    pub fn try_new() -> Result<Self, KeyManagerError> {
        Ok(Self {
            key: RwLock::new(new_in_memory_jwt_key()),
            federation_key: RwLock::new(Some(generate_federation_key()?)),
        })
    }

    /// Create a new in-memory manager with a random HMAC key and an ECDSA P-256 keypair.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|err| {
            log_key_manager_invariant(err, "in-memory federation key generation failed");
            Self {
                key: RwLock::new(new_in_memory_jwt_key()),
                federation_key: RwLock::new(None),
            }
        })
    }
}

impl Default for InMemoryKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager for InMemoryKeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let key = self
            .key
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let key_bytes = key.key_bytes.as_ref().ok_or(KeyManagerError::KeyRevoked)?;
        let hmac_key = aegaeon_crypto::mac::HmacSha256Key::new(key_bytes);
        Ok(hmac_key.sign(msg))
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        let key = self
            .key
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let key_bytes = key.key_bytes.as_ref().ok_or(KeyManagerError::KeyRevoked)?;
        let hmac_key = aegaeon_crypto::mac::HmacSha256Key::new(key_bytes);
        Ok(hmac_key.verify(msg, sig))
    }

    fn key_id(&self) -> String {
        match self.key.read() {
            Ok(key) => key.key_id.clone(),
            Err(err) => {
                log_key_manager_invariant(err, "in-memory key manager key lock poisoned");
                "unavailable".to_string()
            }
        }
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "HS256"
    }

    fn rotate(&self) -> Result<(), KeyManagerError> {
        let mut key = self
            .key
            .write()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        *key = new_in_memory_jwt_key();
        Ok(())
    }

    fn revoke(&self) -> Result<(), KeyManagerError> {
        let mut key = self
            .key
            .write()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        key.key_bytes = None;
        Ok(())
    }

    fn sign_federation(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let guard = self
            .federation_key
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let fed_key = guard.as_ref().ok_or(KeyManagerError::KeyNotFound)?;

        let signer = aegaeon_crypto::signing::EcdsaP256SigningKey::from_pkcs8(&fed_key.pkcs8)
            .map_err(|_| KeyManagerError::OperationFailed)?;
        signer
            .sign(msg)
            .map_err(|_| KeyManagerError::OperationFailed)
    }

    fn federation_public_jwk(&self) -> Option<serde_json::Value> {
        let kid = match self.key.read() {
            Ok(key) => key.key_id.clone(),
            Err(err) => {
                log_key_manager_invariant(err, "in-memory key manager key lock poisoned");
                return None;
            }
        };
        let guard = match self.federation_key.read() {
            Ok(guard) => guard,
            Err(err) => {
                log_key_manager_invariant(err, "in-memory federation key lock poisoned");
                return None;
            }
        };
        let fed_key = guard.as_ref()?;
        Some(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&fed_key.public_x),
            "y": URL_SAFE_NO_PAD.encode(&fed_key.public_y),
            "kid": format!("fed-{}", kid),
            "use": "sig",
            "alg": "ES256",
        }))
    }

    fn federation_alg(&self) -> &'static str {
        "ES256"
    }
}

/// In-memory asymmetric JWT key manager for opt-in public JWT surfaces.
///
/// JWT signing uses Ed25519/`EdDSA`, which has public verification material
/// suitable for JWKS publication. Federation signing remains ES256 so existing
/// OpenID Federation behaviour is unchanged.
pub struct InMemoryPublicJwtKeyManager {
    key: RwLock<InMemoryPublicJwtKey>,
    federation_key: RwLock<Option<FederationKeyData>>,
}

impl InMemoryPublicJwtKeyManager {
    /// Create a new in-memory manager with an Ed25519 JWT key and an ES256
    /// federation key.
    ///
    /// # Errors
    ///
    /// Returns an error if the local random source cannot generate key material.
    pub fn new() -> Result<Self, KeyManagerError> {
        let key = new_in_memory_public_jwt_key()?;
        let federation_key = generate_federation_key()?;
        Ok(Self {
            key: RwLock::new(key),
            federation_key: RwLock::new(Some(federation_key)),
        })
    }
}

impl KeyManager for InMemoryPublicJwtKeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let key = self
            .key
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let pkcs8 = key.pkcs8.as_ref().ok_or(KeyManagerError::KeyRevoked)?;
        let signer = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(pkcs8)
            .map_err(|_| KeyManagerError::OperationFailed)?;
        signer
            .sign(msg)
            .map_err(|_| KeyManagerError::OperationFailed)
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        let expected = self.sign(msg)?;
        Ok(crate::util::constant_time_eq(&expected, sig))
    }

    fn key_id(&self) -> String {
        match self.key.read() {
            Ok(key) => key.key_id.clone(),
            Err(err) => {
                log_key_manager_invariant(
                    err,
                    "in-memory public JWT key manager key lock poisoned",
                );
                "unavailable".to_string()
            }
        }
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "EdDSA"
    }

    fn jwt_signing_public_jwk(&self) -> Option<serde_json::Value> {
        let key = match self.key.read() {
            Ok(key) => key,
            Err(err) => {
                log_key_manager_invariant(
                    err,
                    "in-memory public JWT key manager key lock poisoned",
                );
                return None;
            }
        };
        key.pkcs8.as_ref()?;
        Some(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(&key.public_key),
            "kid": key.key_id.clone(),
            "use": "sig",
            "alg": "EdDSA",
        }))
    }

    fn rotate(&self) -> Result<(), KeyManagerError> {
        let mut key = self
            .key
            .write()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        *key = new_in_memory_public_jwt_key()?;
        Ok(())
    }

    fn revoke(&self) -> Result<(), KeyManagerError> {
        let mut key = self
            .key
            .write()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        key.pkcs8 = None;
        Ok(())
    }

    fn sign_federation(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let guard = self
            .federation_key
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let fed_key = guard.as_ref().ok_or(KeyManagerError::KeyNotFound)?;

        let signer = aegaeon_crypto::signing::EcdsaP256SigningKey::from_pkcs8(&fed_key.pkcs8)
            .map_err(|_| KeyManagerError::OperationFailed)?;
        signer
            .sign(msg)
            .map_err(|_| KeyManagerError::OperationFailed)
    }

    fn federation_public_jwk(&self) -> Option<serde_json::Value> {
        let kid = match self.key.read() {
            Ok(key) => key.key_id.clone(),
            Err(err) => {
                log_key_manager_invariant(
                    err,
                    "in-memory public JWT key manager key lock poisoned",
                );
                return None;
            }
        };
        let guard = match self.federation_key.read() {
            Ok(guard) => guard,
            Err(err) => {
                log_key_manager_invariant(err, "in-memory public JWT federation key lock poisoned");
                return None;
            }
        };
        let fed_key = guard.as_ref()?;
        Some(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&fed_key.public_x),
            "y": URL_SAFE_NO_PAD.encode(&fed_key.public_y),
            "kid": format!("fed-{}", kid),
            "use": "sig",
            "alg": "ES256",
        }))
    }

    fn federation_alg(&self) -> &'static str {
        "ES256"
    }
}
