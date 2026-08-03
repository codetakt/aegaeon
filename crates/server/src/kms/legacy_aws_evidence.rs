//! Test-only legacy AWS KMS-backed key manager for KMS/HSM parity evidence.
//!
//! This manager implements the generic `KeyManager` trait with PS256-oriented AWS KMS signing.
//! It is compiled only for tests with the `kms-aws` feature. Production OIDC RS256 signing uses
//! the crate-private OIDC AWS KMS signer through management-DB runtime keys.

use super::{log_key_manager_invariant, KeyManager, KeyManagerError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::{
    primitives::Blob,
    types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec},
    Client,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use simple_asn1::ASN1Block;
use std::{env, fs, path::Path, sync::RwLock};

/// Configuration for the AWS KMS key manager.
#[derive(Deserialize)]
struct AwsKmsSettings {
    region: String,
    key_id: String,
}

impl AwsKmsSettings {
    /// Load settings from environment variables or a JSON config file.
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let region = env::var("AWS_REGION").ok();
        let key_id = env::var("AWS_KMS_KEY_ID").ok();

        if let (Some(region), Some(key_id)) = (region, key_id) {
            return Ok(Self { region, key_id });
        }

        let path = env::var("KMS_CONFIG_FILE").unwrap_or_else(|_| "kms_config.json".to_string());
        let contents = fs::read_to_string(Path::new(&path))?;
        let cfg: Self =
            crate::util::deserialize_json_without_duplicate_object_keys(contents.as_bytes())?;
        Ok(cfg)
    }
}

/// Legacy generic key manager backed by AWS KMS using the Sign and Verify APIs.
///
/// This type is retained only for KMS/HSM classification evidence tests. Use
/// management-database runtime keys for production OIDC ID Token signing.
pub struct LegacyAwsKmsKeyManager {
    client: Client,
    key_id: RwLock<String>,
    jwt_public_jwk: RwLock<Option<serde_json::Value>>,
    runtime: tokio::runtime::Runtime,
}

impl LegacyAwsKmsKeyManager {
    /// Construct a new AWS KMS key manager using configuration from the
    /// environment or a config file.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration loading, Tokio runtime construction,
    /// or AWS SDK initialization fails.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let settings = AwsKmsSettings::load()?;

        let runtime = tokio::runtime::Runtime::new()?;

        let region_provider = RegionProviderChain::first_try(Region::new(settings.region.clone()));
        let config = runtime.block_on(
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load(),
        );
        let client = Client::new(&config);

        Ok(Self {
            client,
            key_id: RwLock::new(settings.key_id),
            jwt_public_jwk: RwLock::new(None),
            runtime,
        })
    }

    fn fetch_jwt_signing_public_jwk(&self) -> Result<serde_json::Value, KeyManagerError> {
        let key_id = self
            .key_id
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .clone();
        let output = self
            .runtime
            .block_on(self.client.get_public_key().key_id(key_id.clone()).send())
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let key_spec = output.key_spec();
        if !matches!(
            key_spec,
            Some(KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096)
        ) {
            return Err(KeyManagerError::OperationFailed);
        }
        if !output
            .signing_algorithms()
            .contains(&SigningAlgorithmSpec::RsassaPssSha256)
        {
            return Err(KeyManagerError::OperationFailed);
        }
        let public_key_der = output
            .public_key()
            .map(std::convert::AsRef::as_ref)
            .ok_or(KeyManagerError::OperationFailed)?;
        let (modulus, exponent) = rsa_public_components_from_spki_public_der(public_key_der)
            .ok_or(KeyManagerError::OperationFailed)?;

        Ok(serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "kid": key_id,
            "alg": "PS256",
            "n": URL_SAFE_NO_PAD.encode(modulus),
            "e": URL_SAFE_NO_PAD.encode(exponent),
        }))
    }
}

impl KeyManager for LegacyAwsKmsKeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let key_id = self
            .key_id
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .clone();
        let fut = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(msg.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
            .send();

        match self.runtime.block_on(fut) {
            Ok(output) => output
                .signature()
                .map(|b| b.clone().into_inner())
                .ok_or(KeyManagerError::KeyNotFound),
            Err(_) => Err(KeyManagerError::OperationFailed),
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError> {
        let key_id = self
            .key_id
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .clone();
        let fut = self
            .client
            .verify()
            .key_id(key_id)
            .message(Blob::new(msg.to_vec()))
            .signature(Blob::new(sig.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
            .send();

        match self.runtime.block_on(fut) {
            Ok(output) => Ok(output.signature_valid()),
            Err(_) => Err(KeyManagerError::OperationFailed),
        }
    }

    fn key_id(&self) -> String {
        match self.key_id.read() {
            Ok(key_id) => key_id.clone(),
            Err(err) => {
                log_key_manager_invariant(err, "AWS KMS key manager key id lock poisoned");
                "unavailable".to_string()
            }
        }
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "PS256"
    }

    fn jwt_signing_public_jwk(&self) -> Option<serde_json::Value> {
        {
            let guard = match self.jwt_public_jwk.read() {
                Ok(guard) => guard,
                Err(err) => {
                    log_key_manager_invariant(err, "AWS KMS public JWK cache lock poisoned");
                    return None;
                }
            };
            if let Some(jwk) = guard.as_ref() {
                return Some(jwk.clone());
            }
        }

        let jwk = self.fetch_jwt_signing_public_jwk().ok()?;
        let mut guard = match self.jwt_public_jwk.write() {
            Ok(guard) => guard,
            Err(err) => {
                log_key_manager_invariant(err, "AWS KMS public JWK cache lock poisoned");
                return None;
            }
        };
        *guard = Some(jwk.clone());
        Some(jwk)
    }

    fn rotate(&self) -> Result<(), KeyManagerError> {
        let fut = self
            .client
            .create_key()
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(KeySpec::Rsa2048)
            .send();
        match self.runtime.block_on(fut) {
            Ok(resp) => {
                let new_id = resp
                    .key_metadata
                    .map(|m| m.key_id)
                    .ok_or(KeyManagerError::OperationFailed)?;
                let mut key_id = self
                    .key_id
                    .write()
                    .map_err(|_| KeyManagerError::OperationFailed)?;
                *key_id = new_id;
                self.jwt_public_jwk
                    .write()
                    .map_err(|_| KeyManagerError::OperationFailed)?
                    .take();
                Ok(())
            }
            Err(_) => Err(KeyManagerError::OperationFailed),
        }
    }

    fn revoke(&self) -> Result<(), KeyManagerError> {
        let key_id = self
            .key_id
            .read()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .clone();
        let fut = self.client.disable_key().key_id(key_id.clone()).send();
        if self.runtime.block_on(fut).is_err() {
            return Err(KeyManagerError::OperationFailed);
        }
        self.jwt_public_jwk
            .write()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .take();
        let fut = self
            .client
            .schedule_key_deletion()
            .key_id(key_id)
            .pending_window_in_days(7)
            .send();
        self.runtime
            .block_on(fut)
            .map(|_| ())
            .map_err(|_| KeyManagerError::OperationFailed)
    }
}

fn rsa_public_components_from_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let modulus = match &seq[0] {
        ASN1Block::Integer(_, n) => n.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    let exponent = match &seq[1] {
        ASN1Block::Integer(_, e) => e.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    Some((modulus, exponent))
}

fn rsa_public_components_from_spki_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let ASN1Block::BitString(_, _bit_len, public_key) = &seq[1] else {
        return None;
    };
    rsa_public_components_from_public_der(public_key).or_else(|| {
        public_key
            .strip_prefix(&[0x00])
            .and_then(rsa_public_components_from_public_der)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn new(key: &'static str, value: Option<&str>) -> Self {
            let previous = env::var(key).ok();
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_deref() {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn load_config_file_rejects_duplicate_object_keys() -> Result<(), String> {
        let _env = ENV_LOCK
            .lock()
            .map_err(|err| format!("kms env lock poisoned: {err}"))?;
        let path = env::temp_dir().join(format!(
            "aegaeon-kms-duplicate-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_nanos()
        ));
        fs::write(
            &path,
            br#"{"region":"ap-northeast-1","region":"us-east-1","key_id":"test-key"}"#,
        )
        .map_err(|err| format!("write duplicate-key KMS config: {err}"))?;

        let _region = EnvVarGuard::new("AWS_REGION", None);
        let _key_id = EnvVarGuard::new("AWS_KMS_KEY_ID", None);
        let _config = EnvVarGuard::new("KMS_CONFIG_FILE", path.to_str());

        let result = AwsKmsSettings::load();

        let _ = fs::remove_file(path);
        let err = result
            .err()
            .ok_or_else(|| "duplicate KMS config keys must fail closed".to_string())?;
        assert!(
            err.to_string().contains("duplicate JSON object key"),
            "unexpected error: {err}"
        );
        Ok(())
    }
}
