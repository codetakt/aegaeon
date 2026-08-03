// SD-JWT (Selective Disclosure JWT) implementation
// Based on SD-JWT specification (IETF draft / RFC 9901 track)
//
// SD-JWT enables selective disclosure of JWT claims through a hash commitment
// scheme: the issuer replaces plaintext claims with SHA-256 digests of
// base64url-encoded disclosure arrays [salt, claim_name, claim_value].
// The holder can then reveal individual claims by presenting the corresponding
// disclosures alongside the JWT.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The hash algorithm identifier placed in the `_sd_alg` claim.
const SD_ALG: &str = "sha-256";

/// Minimum salt length in bytes (128 bits of entropy per spec recommendation).
const MIN_SALT_BYTES: usize = 16;

/// Maximum number of disclosures we accept when parsing (`DoS` guard).
const MAX_DISCLOSURES: usize = 256;

/// Separator between the JWT and disclosures in the SD-JWT compound format.
const DISCLOSURE_SEPARATOR: char = '~';

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdJwtError {
    #[error("invalid SD-JWT format")]
    InvalidFormat,

    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(&'static str),

    #[error("duplicate disclosure digest")]
    DuplicateDigest,

    #[error("disclosure digest not found in _sd array")]
    DigestNotFound,

    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("too many disclosures (max {MAX_DISCLOSURES})")]
    TooManyDisclosures,

    #[error("salt too short (min {MIN_SALT_BYTES} bytes)")]
    SaltTooShort,

    #[error("JSON error: {0}")]
    Json(String),

    #[error("base64 decode error")]
    Base64Decode,

    #[error("key binding JWT error: {0}")]
    KeyBinding(&'static str),

    #[error("missing _sd_alg claim")]
    MissingSdAlg,
}

impl From<serde_json::Error> for SdJwtError {
    fn from(e: serde_json::Error) -> Self {
        SdJwtError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for SdJwtError {
    fn from(_: base64::DecodeError) -> Self {
        SdJwtError::Base64Decode
    }
}

// ---------------------------------------------------------------------------
// Disclosure
// ---------------------------------------------------------------------------

/// A single SD-JWT disclosure: `[salt, claim_name, claim_value]`.
///
/// The disclosure is serialized as a JSON array, then base64url-encoded.
/// Its digest is `base64url(SHA-256(base64url(json([salt, name, value]))))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// Random salt (base64url-encoded, at least 128 bits of entropy).
    pub salt: String,
    /// The claim name being disclosed.
    pub claim_name: String,
    /// The claim value (arbitrary JSON).
    pub claim_value: Value,
}

impl Disclosure {
    /// Create a new disclosure with an explicit salt.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if the salt is not valid base64url, the decoded
    /// salt is shorter than [`MIN_SALT_BYTES`], or the claim name is empty.
    pub fn new(salt: String, claim_name: String, claim_value: Value) -> Result<Self, SdJwtError> {
        // Validate salt has sufficient entropy
        let salt_bytes = URL_SAFE_NO_PAD
            .decode(&salt)
            .map_err(|_| SdJwtError::InvalidDisclosure("salt is not valid base64url"))?;
        if salt_bytes.len() < MIN_SALT_BYTES {
            return Err(SdJwtError::SaltTooShort);
        }
        if claim_name.is_empty() {
            return Err(SdJwtError::InvalidDisclosure(
                "claim_name must not be empty",
            ));
        }
        Ok(Self {
            salt,
            claim_name,
            claim_value,
        })
    }

    /// Create a new disclosure with a random 128-bit salt.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if random generation fails or the generated
    /// disclosure does not satisfy the same validation rules as [`Self::new`].
    pub fn with_random_salt(claim_name: String, claim_value: Value) -> Result<Self, SdJwtError> {
        let mut salt_bytes = [0u8; MIN_SALT_BYTES];
        aegaeon_crypto::rand::fill_random(&mut salt_bytes)
            .map_err(|_| SdJwtError::InvalidDisclosure("failed to generate random salt"))?;
        let salt = URL_SAFE_NO_PAD.encode(salt_bytes);
        Self::new(salt, claim_name, claim_value)
    }

    /// Serialize the disclosure to its base64url-encoded form.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError::Json`] if serializing the disclosure array fails.
    pub fn encode(&self) -> Result<String, SdJwtError> {
        let array = Value::Array(vec![
            Value::String(self.salt.clone()),
            Value::String(self.claim_name.clone()),
            self.claim_value.clone(),
        ]);
        let json_bytes = serde_json::to_vec(&array).map_err(SdJwtError::from)?;
        Ok(URL_SAFE_NO_PAD.encode(&json_bytes))
    }

    /// Compute the SHA-256 digest of this disclosure (base64url-encoded).
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if disclosure serialization fails or the encoded
    /// disclosure violates the ASCII precondition required by the verified hash
    /// model.
    pub fn digest(&self) -> Result<String, SdJwtError> {
        let encoded = self.encode()?;
        digest_of_encoded(&encoded).ok_or(SdJwtError::InvalidDisclosure(
            "disclosure contains non-ASCII bytes",
        ))
    }

    /// Parse a disclosure from its base64url-encoded form.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if the disclosure is not valid base64url, is not
    /// a 3-element JSON array, or fails salt / claim-name validation.
    pub fn decode(encoded: &str) -> Result<Self, SdJwtError> {
        let json_bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let array: Vec<Value> = serde_json::from_slice(&json_bytes)
            .map_err(|_| SdJwtError::InvalidDisclosure("disclosure is not a JSON array"))?;
        if array.len() != 3 {
            return Err(SdJwtError::InvalidDisclosure(
                "disclosure array must have exactly 3 elements",
            ));
        }
        let salt = array[0]
            .as_str()
            .ok_or(SdJwtError::InvalidDisclosure("salt must be a string"))?
            .to_string();
        let claim_name = array[1]
            .as_str()
            .ok_or(SdJwtError::InvalidDisclosure("claim_name must be a string"))?
            .to_string();
        let claim_value = array[2].clone();

        // Validate salt length
        let salt_bytes = URL_SAFE_NO_PAD
            .decode(&salt)
            .map_err(|_| SdJwtError::InvalidDisclosure("salt is not valid base64url"))?;
        if salt_bytes.len() < MIN_SALT_BYTES {
            return Err(SdJwtError::SaltTooShort);
        }
        if claim_name.is_empty() {
            return Err(SdJwtError::InvalidDisclosure(
                "claim_name must not be empty",
            ));
        }

        Ok(Self {
            salt,
            claim_name,
            claim_value,
        })
    }
}

/// Compute `base64url(SHA-256(ascii_bytes))` of an already-encoded disclosure string.
///
/// `encoded` is the output of `URL_SAFE_NO_PAD.encode()`, which produces only
/// `[A-Za-z0-9\-_]` characters — guaranteed ASCII. This satisfies the F* model's
/// `bytes_of_string` ASCII precondition without an explicit runtime check.
/// Returns `None` if `encoded` contains non-ASCII bytes (violates F* model precondition).
/// In practice, `encoded` is always base64url output (`[A-Za-z0-9\-_]`), so this
/// guard never triggers — but it enforces the precondition in release builds.
fn digest_of_encoded(encoded: &str) -> Option<String> {
    if !encoded.is_ascii() {
        return None;
    }
    let hash = aegaeon_crypto::hash::sha256_digest(encoded.as_bytes());
    Some(URL_SAFE_NO_PAD.encode(hash))
}

// ---------------------------------------------------------------------------
// SD-JWT Issuer
// ---------------------------------------------------------------------------

/// Issuer-side SD-JWT builder.
///
/// Takes a set of claims and a set of claim names to selectively disclose,
/// and produces the issuer JWT payload (with `_sd` digests) plus the
/// corresponding disclosures.
pub struct SdJwtIssuer;

/// The result of issuing an SD-JWT: the modified payload and disclosures.
#[derive(Debug, Clone)]
pub struct IssuanceResult {
    /// The JWT payload with `_sd` digests replacing selectively-disclosed claims.
    pub payload: Value,
    /// The disclosures corresponding to each selectively-disclosed claim.
    pub disclosures: Vec<Disclosure>,
}

impl SdJwtIssuer {
    /// Build an SD-JWT payload from plaintext claims.
    ///
    /// Claims whose names appear in `sd_claims` are replaced with digests
    /// in the `_sd` array. Claims not in `sd_claims` remain in plaintext.
    ///
    /// # Arguments
    ///
    /// * `claims` - The full set of JWT claims as a JSON object
    /// * `sd_claims` - Names of claims to make selectively disclosable
    ///
    /// # Returns
    ///
    /// An `IssuanceResult` containing the modified payload and disclosures.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if `claims` is not a JSON object or if creating a
    /// disclosure for any selectively-disclosed claim fails.
    pub fn issue(claims: &Value, sd_claims: &[&str]) -> Result<IssuanceResult, SdJwtError> {
        let obj = claims
            .as_object()
            .ok_or(SdJwtError::Json("claims must be a JSON object".into()))?;

        let mut payload = Map::new();
        let mut disclosures = Vec::new();
        let mut sd_digests: Vec<String> = Vec::new();

        for (key, value) in obj {
            if sd_claims.contains(&key.as_str()) {
                let disclosure = Disclosure::with_random_salt(key.clone(), value.clone())?;
                sd_digests.push(disclosure.digest()?);
                disclosures.push(disclosure);
            } else {
                payload.insert(key.clone(), value.clone());
            }
        }

        if !sd_digests.is_empty() {
            // Sort digests for deterministic output (not required by spec,
            // but aids testing and reproducibility).
            sd_digests.sort();
            payload.insert(
                "_sd".to_string(),
                Value::Array(sd_digests.into_iter().map(Value::String).collect()),
            );
            payload.insert("_sd_alg".to_string(), Value::String(SD_ALG.to_string()));
        }

        Ok(IssuanceResult {
            payload: Value::Object(payload),
            disclosures,
        })
    }
}

// ---------------------------------------------------------------------------
// SD-JWT Format (compound serialization)
// ---------------------------------------------------------------------------

/// The compound SD-JWT format: `<issuer-jwt>~<disclosure1>~<disclosure2>~...~[<kb-jwt>]`
#[derive(Debug, Clone)]
pub struct SdJwt {
    /// The issuer-signed JWT in compact JWS form.
    pub jwt: String,
    /// Base64url-encoded disclosures.
    pub disclosures: Vec<String>,
    /// Optional Key Binding JWT.
    pub key_binding_jwt: Option<String>,
}

impl SdJwt {
    /// Serialize to the compound SD-JWT format.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut result = self.jwt.clone();
        for d in &self.disclosures {
            result.push(DISCLOSURE_SEPARATOR);
            result.push_str(d);
        }
        result.push(DISCLOSURE_SEPARATOR);
        if let Some(ref kb) = self.key_binding_jwt {
            result.push_str(kb);
        }
        result
    }

    /// Parse a compound SD-JWT string.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if the compound serialization is malformed, the
    /// issuer JWT is missing, or the optional key-binding JWT is not a compact
    /// JWS.
    pub fn parse(input: &str) -> Result<Self, SdJwtError> {
        if input.is_empty() {
            return Err(SdJwtError::InvalidFormat);
        }

        // The format is: <jwt>~<d1>~<d2>~...~[<kb-jwt>]
        // Split on '~'. The first element is the JWT.
        // The last element is either empty (no KB-JWT) or the KB-JWT.
        // Everything in between is a disclosure.
        let parts: Vec<&str> = input.split(DISCLOSURE_SEPARATOR).collect();
        if parts.len() < 2 {
            return Err(SdJwtError::InvalidFormat);
        }

        let jwt = parts[0].to_string();
        if jwt.is_empty() || jwt.split('.').count() != 3 {
            return Err(SdJwtError::InvalidFormat);
        }

        let Some(last) = parts.last().copied() else {
            return Err(SdJwtError::InvalidFormat);
        };
        let key_binding_jwt = if last.is_empty() {
            None
        } else {
            // Validate it looks like a JWT (3 dot-separated segments)
            if last.split('.').count() != 3 {
                return Err(SdJwtError::KeyBinding("malformed key binding JWT"));
            }
            Some(last.to_string())
        };

        // Disclosures are parts[1..len-1]
        let disclosure_parts = &parts[1..parts.len() - 1];
        if disclosure_parts.len() > MAX_DISCLOSURES {
            return Err(SdJwtError::TooManyDisclosures);
        }

        let disclosures: Vec<String> = disclosure_parts
            .iter()
            .filter(|d| !d.is_empty())
            .map(ToString::to_string)
            .collect();

        Ok(SdJwt {
            jwt,
            disclosures,
            key_binding_jwt,
        })
    }
}

// ---------------------------------------------------------------------------
// SD-JWT Verifier
// ---------------------------------------------------------------------------

/// Verifier-side SD-JWT processing.
///
/// Given an SD-JWT payload (already signature-verified) and a set of
/// disclosures, the verifier reconstructs the disclosed claims.
pub struct SdJwtVerifier;

/// The result of verifying an SD-JWT: the reconstructed claims.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The reconstructed claims (plaintext claims + disclosed claims).
    pub claims: Value,
    /// Digests that were present in `_sd` but had no matching disclosure
    /// (i.e., claims the holder chose not to reveal).
    pub undisclosed_digests: Vec<String>,
}

impl SdJwtVerifier {
    /// Verify disclosures against the SD-JWT payload and reconstruct claims.
    ///
    /// # Arguments
    ///
    /// * `payload` - The JWT payload (must contain `_sd` and `_sd_alg`)
    /// * `encoded_disclosures` - The base64url-encoded disclosure strings
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with the reconstructed claims.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if the payload shape is invalid, `_sd`/`_sd_alg`
    /// are malformed, disclosure decoding fails, or a disclosure digest does
    /// not match the advertised commitments.
    pub fn verify(
        payload: &Value,
        encoded_disclosures: &[String],
    ) -> Result<VerificationResult, SdJwtError> {
        let obj = payload
            .as_object()
            .ok_or(SdJwtError::Json("payload must be a JSON object".into()))?;

        // If there is no _sd array, just return the payload as-is.
        let Some(sd_array) = obj.get("_sd") else {
            return Ok(VerificationResult {
                claims: payload.clone(),
                undisclosed_digests: Vec::new(),
            });
        };

        // Validate _sd_alg
        let sd_alg = obj
            .get("_sd_alg")
            .and_then(|v| v.as_str())
            .ok_or(SdJwtError::MissingSdAlg)?;
        if sd_alg != SD_ALG {
            return Err(SdJwtError::UnsupportedAlgorithm(sd_alg.to_string()));
        }

        // Extract the set of expected digests from _sd
        let expected_digests: Vec<&str> = sd_array
            .as_array()
            .ok_or(SdJwtError::Json("_sd must be an array".into()))?
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or(SdJwtError::Json("_sd entries must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if encoded_disclosures.len() > MAX_DISCLOSURES {
            return Err(SdJwtError::TooManyDisclosures);
        }

        // Parse and verify each disclosure
        let mut reconstructed = Map::new();
        let mut matched_digests = std::collections::HashSet::new();

        // First, copy all non-SD claims
        for (key, value) in obj {
            if key != "_sd" && key != "_sd_alg" {
                reconstructed.insert(key.clone(), value.clone());
            }
        }

        // Then, process disclosures
        for encoded in encoded_disclosures {
            let disclosure = Disclosure::decode(encoded)?;
            let digest = digest_of_encoded(encoded).ok_or(SdJwtError::InvalidDisclosure(
                "disclosure contains non-ASCII bytes",
            ))?;

            if !expected_digests.contains(&digest.as_str()) {
                return Err(SdJwtError::DigestNotFound);
            }

            if !matched_digests.insert(digest) {
                return Err(SdJwtError::DuplicateDigest);
            }

            reconstructed.insert(disclosure.claim_name, disclosure.claim_value);
        }

        // Collect unmatched digests
        let undisclosed_digests: Vec<String> = expected_digests
            .iter()
            .filter(|d| !matched_digests.contains(**d))
            .map(ToString::to_string)
            .collect();

        Ok(VerificationResult {
            claims: Value::Object(reconstructed),
            undisclosed_digests,
        })
    }
}

// ---------------------------------------------------------------------------
// SD-JWT Holder
// ---------------------------------------------------------------------------

/// Holder-side SD-JWT processing.
///
/// The holder selects which disclosures to present to a verifier.
pub struct SdJwtHolder;

impl SdJwtHolder {
    /// Select a subset of disclosures to present.
    ///
    /// Given all disclosures from the issuer, returns only those whose
    /// claim names are in `claims_to_disclose`.
    #[must_use]
    pub fn select_disclosures(
        all_disclosures: &[Disclosure],
        claims_to_disclose: &[&str],
    ) -> Vec<Disclosure> {
        all_disclosures
            .iter()
            .filter(|d| claims_to_disclose.contains(&d.claim_name.as_str()))
            .cloned()
            .collect()
    }

    /// Build a presentation SD-JWT from the issuer JWT and selected disclosures.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if any disclosure cannot be serialized.
    pub fn present(jwt: &str, selected_disclosures: &[Disclosure]) -> Result<SdJwt, SdJwtError> {
        let disclosures = selected_disclosures
            .iter()
            .map(Disclosure::encode)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SdJwt {
            jwt: jwt.to_string(),
            disclosures,
            key_binding_jwt: None,
        })
    }

    /// Build a presentation SD-JWT with a Key Binding JWT.
    ///
    /// # Errors
    ///
    /// Returns [`SdJwtError`] if any disclosure cannot be serialized.
    pub fn present_with_kb(
        jwt: &str,
        selected_disclosures: &[Disclosure],
        key_binding_jwt: String,
    ) -> Result<SdJwt, SdJwtError> {
        let disclosures = selected_disclosures
            .iter()
            .map(Disclosure::encode)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SdJwt {
            jwt: jwt.to_string(),
            disclosures,
            key_binding_jwt: Some(key_binding_jwt),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error;
    use std::io::Error as IoError;

    type TestResult = Result<(), Box<dyn Error>>;

    fn make_salt() -> Result<String, getrandom::Error> {
        let mut bytes = [0u8; MIN_SALT_BYTES];
        getrandom::getrandom(&mut bytes)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn require_object(value: &Value) -> Result<&Map<String, Value>, Box<dyn Error>> {
        value
            .as_object()
            .ok_or_else(|| IoError::other("expected JSON object").into())
    }

    fn require_array<'a>(
        value: Option<&'a Value>,
        label: &'static str,
    ) -> Result<&'a Vec<Value>, Box<dyn Error>> {
        value
            .and_then(Value::as_array)
            .ok_or_else(|| IoError::other(format!("expected `{label}` to be a JSON array")).into())
    }

    fn encode_disclosures(disclosures: &[Disclosure]) -> Result<Vec<String>, SdJwtError> {
        disclosures.iter().map(Disclosure::encode).collect()
    }

    // --- Disclosure tests ---

    #[test]
    fn disclosure_roundtrip() -> TestResult {
        let salt = make_salt()?;
        let d = Disclosure::new(salt.clone(), "given_name".to_string(), json!("John"))?;

        let encoded = d.encode()?;
        let decoded = Disclosure::decode(&encoded)?;

        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.claim_name, "given_name");
        assert_eq!(decoded.claim_value, json!("John"));
        Ok(())
    }

    #[test]
    fn disclosure_digest_is_deterministic() -> TestResult {
        let salt = make_salt()?;
        let d = Disclosure::new(salt, "sub".to_string(), json!("user_42"))?;

        let digest1 = d.digest()?;
        let digest2 = d.digest()?;
        assert_eq!(digest1, digest2);
        Ok(())
    }

    #[test]
    fn disclosure_rejects_short_salt() {
        let short_salt = URL_SAFE_NO_PAD.encode([0u8; 8]); // 64 bits, below minimum
        assert_eq!(
            Disclosure::new(short_salt, "sub".to_string(), json!("x")).err(),
            Some(SdJwtError::SaltTooShort)
        );
    }

    #[test]
    fn disclosure_rejects_empty_claim_name() -> TestResult {
        let salt = make_salt()?;
        assert_eq!(
            Disclosure::new(salt, String::new(), json!("x")).err(),
            Some(SdJwtError::InvalidDisclosure(
                "claim_name must not be empty"
            ))
        );
        Ok(())
    }

    #[test]
    fn disclosure_decode_rejects_wrong_length() -> TestResult {
        let bad = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!(["salt", "name"]))?);
        assert_eq!(
            Disclosure::decode(&bad).err(),
            Some(SdJwtError::InvalidDisclosure(
                "disclosure array must have exactly 3 elements"
            ))
        );
        Ok(())
    }

    #[test]
    fn disclosure_decode_rejects_non_string_salt() -> TestResult {
        let bad = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!([42, "name", "value"]))?);
        assert_eq!(
            Disclosure::decode(&bad).err(),
            Some(SdJwtError::InvalidDisclosure("salt must be a string"))
        );
        Ok(())
    }

    #[test]
    fn disclosure_with_complex_value() -> TestResult {
        let salt = make_salt()?;
        let complex = json!({"street": "123 Main St", "city": "Anytown"});
        let d = Disclosure::new(salt, "address".to_string(), complex.clone())?;
        let encoded = d.encode()?;
        let decoded = Disclosure::decode(&encoded)?;
        assert_eq!(decoded.claim_value, complex);
        Ok(())
    }

    // --- Issuer tests ---

    #[test]
    fn issuer_produces_sd_payload() -> TestResult {
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user_42",
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com"
        });

        let result = SdJwtIssuer::issue(&claims, &["given_name", "family_name", "email"])?;

        let payload = require_object(&result.payload)?;

        // Non-SD claims remain in plaintext
        assert_eq!(
            payload.get("iss"),
            Some(&Value::String("https://issuer.example.com".to_string()))
        );
        assert_eq!(
            payload.get("sub"),
            Some(&Value::String("user_42".to_string()))
        );

        // SD claims are replaced with digests
        assert!(payload.get("given_name").is_none());
        assert!(payload.get("family_name").is_none());
        assert!(payload.get("email").is_none());

        // _sd array contains exactly 3 digests
        let sd = require_array(payload.get("_sd"), "_sd")?;
        assert_eq!(sd.len(), 3);

        // _sd_alg is set
        assert_eq!(
            payload.get("_sd_alg"),
            Some(&Value::String(SD_ALG.to_string()))
        );

        // 3 disclosures produced
        assert_eq!(result.disclosures.len(), 3);
        Ok(())
    }

    #[test]
    fn issuer_no_sd_claims_passes_through() -> TestResult {
        let claims = json!({"iss": "https://example.com", "sub": "alice"});
        let result = SdJwtIssuer::issue(&claims, &[])?;

        let payload = require_object(&result.payload)?;
        assert!(payload.get("_sd").is_none());
        assert!(payload.get("_sd_alg").is_none());
        assert_eq!(result.disclosures.len(), 0);
        Ok(())
    }

    // --- Verifier tests ---

    #[test]
    fn verifier_reconstructs_all_claims() -> TestResult {
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user_42",
            "given_name": "John",
            "family_name": "Doe"
        });

        let result = SdJwtIssuer::issue(&claims, &["given_name", "family_name"])?;

        // Present all disclosures
        let encoded = encode_disclosures(&result.disclosures)?;
        let verified = SdJwtVerifier::verify(&result.payload, &encoded)?;

        let obj = require_object(&verified.claims)?;
        assert_eq!(
            obj.get("iss"),
            Some(&Value::String("https://issuer.example.com".to_string()))
        );
        assert_eq!(obj.get("sub"), Some(&Value::String("user_42".to_string())));
        assert_eq!(
            obj.get("given_name"),
            Some(&Value::String("John".to_string()))
        );
        assert_eq!(
            obj.get("family_name"),
            Some(&Value::String("Doe".to_string()))
        );
        assert!(verified.undisclosed_digests.is_empty());
        Ok(())
    }

    #[test]
    fn verifier_partial_disclosure() -> TestResult {
        let claims = json!({
            "iss": "https://issuer.example.com",
            "given_name": "John",
            "family_name": "Doe"
        });

        let result = SdJwtIssuer::issue(&claims, &["given_name", "family_name"])?;

        // Only disclose given_name
        let selected = SdJwtHolder::select_disclosures(&result.disclosures, &["given_name"]);
        let encoded = encode_disclosures(&selected)?;
        let verified = SdJwtVerifier::verify(&result.payload, &encoded)?;

        let obj = require_object(&verified.claims)?;
        assert_eq!(
            obj.get("iss"),
            Some(&Value::String("https://issuer.example.com".to_string()))
        );
        assert_eq!(
            obj.get("given_name"),
            Some(&Value::String("John".to_string()))
        );
        assert!(obj.get("family_name").is_none());
        assert_eq!(verified.undisclosed_digests.len(), 1);
        Ok(())
    }

    #[test]
    fn verifier_rejects_unknown_disclosure() -> TestResult {
        let claims = json!({"iss": "https://example.com", "sub": "alice"});
        let result = SdJwtIssuer::issue(&claims, &["sub"])?;

        // Forge a disclosure for a non-existent claim
        let forged = Disclosure::with_random_salt("evil".to_string(), json!("hacked"))?;
        let encoded = vec![forged.encode()?];

        assert_eq!(
            SdJwtVerifier::verify(&result.payload, &encoded).err(),
            Some(SdJwtError::DigestNotFound)
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_duplicate_disclosure() -> TestResult {
        let claims = json!({"iss": "https://example.com", "sub": "alice"});
        let result = SdJwtIssuer::issue(&claims, &["sub"])?;

        let encoded = result.disclosures[0].encode()?;
        assert_eq!(
            SdJwtVerifier::verify(&result.payload, &[encoded.clone(), encoded]).err(),
            Some(SdJwtError::DuplicateDigest)
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_wrong_sd_alg() {
        let payload = json!({
            "iss": "https://example.com",
            "_sd": ["abc"],
            "_sd_alg": "sha-512"
        });
        assert_eq!(
            SdJwtVerifier::verify(&payload, &[]).err(),
            Some(SdJwtError::UnsupportedAlgorithm("sha-512".to_string()))
        );
    }

    #[test]
    fn verifier_rejects_missing_sd_alg() {
        let payload = json!({
            "iss": "https://example.com",
            "_sd": ["abc"]
        });
        assert_eq!(
            SdJwtVerifier::verify(&payload, &[]).err(),
            Some(SdJwtError::MissingSdAlg)
        );
    }

    // --- SD-JWT Format (compound serialization) tests ---

    #[test]
    fn sd_jwt_format_roundtrip_no_kb() -> Result<(), SdJwtError> {
        let original = SdJwt {
            jwt: "eyJ0.eyJp.sig".to_string(),
            disclosures: vec!["disc1".to_string(), "disc2".to_string()],
            key_binding_jwt: None,
        };

        let serialized = original.serialize();
        assert_eq!(serialized, "eyJ0.eyJp.sig~disc1~disc2~");

        let parsed = SdJwt::parse(&serialized)?;
        assert_eq!(parsed.jwt, "eyJ0.eyJp.sig");
        assert_eq!(parsed.disclosures, vec!["disc1", "disc2"]);
        assert!(parsed.key_binding_jwt.is_none());
        Ok(())
    }

    #[test]
    fn sd_jwt_format_roundtrip_with_kb() -> Result<(), SdJwtError> {
        let original = SdJwt {
            jwt: "eyJ0.eyJp.sig".to_string(),
            disclosures: vec!["disc1".to_string()],
            key_binding_jwt: Some("eyKB.eyJp.kbs".to_string()),
        };

        let serialized = original.serialize();
        assert_eq!(serialized, "eyJ0.eyJp.sig~disc1~eyKB.eyJp.kbs");

        let parsed = SdJwt::parse(&serialized)?;
        assert_eq!(parsed.jwt, "eyJ0.eyJp.sig");
        assert_eq!(parsed.disclosures, vec!["disc1"]);
        assert_eq!(parsed.key_binding_jwt.as_deref(), Some("eyKB.eyJp.kbs"));
        Ok(())
    }

    #[test]
    fn sd_jwt_format_no_disclosures() -> Result<(), SdJwtError> {
        let serialized = "eyJ0.eyJp.sig~";
        let parsed = SdJwt::parse(serialized)?;
        assert_eq!(parsed.jwt, "eyJ0.eyJp.sig");
        assert!(parsed.disclosures.is_empty());
        assert!(parsed.key_binding_jwt.is_none());
        Ok(())
    }

    #[test]
    fn sd_jwt_format_rejects_empty_input() {
        assert_eq!(SdJwt::parse("").err(), Some(SdJwtError::InvalidFormat));
    }

    #[test]
    fn sd_jwt_format_rejects_no_separator() {
        assert_eq!(
            SdJwt::parse("just-a-jwt").err(),
            Some(SdJwtError::InvalidFormat)
        );
    }

    #[test]
    fn sd_jwt_format_rejects_invalid_jwt() {
        assert_eq!(
            SdJwt::parse("not-a-jwt~disc~").err(),
            Some(SdJwtError::InvalidFormat)
        );
    }

    // --- Holder tests ---

    #[test]
    fn holder_selects_subset() -> Result<(), SdJwtError> {
        let d1 = Disclosure::with_random_salt("name".to_string(), json!("Alice"))?;
        let d2 = Disclosure::with_random_salt("email".to_string(), json!("a@b.c"))?;
        let d3 = Disclosure::with_random_salt("age".to_string(), json!(30))?;

        let selected = SdJwtHolder::select_disclosures(&[d1, d2, d3], &["name", "age"]);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].claim_name, "name");
        assert_eq!(selected[1].claim_name, "age");
        Ok(())
    }

    // --- End-to-end test ---

    #[test]
    fn end_to_end_issue_hold_verify() -> TestResult {
        // 1. Issuer creates SD-JWT
        let claims = json!({
            "iss": "https://issuer.example.com",
            "iat": 1_683_000_000,
            "exp": 1_883_000_000,
            "sub": "user_42",
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com",
            "phone": "+1-555-0100"
        });

        let issuance =
            SdJwtIssuer::issue(&claims, &["given_name", "family_name", "email", "phone"])?;

        // Simulate: issuer signs the payload as a JWT (mock compact JWS)
        let jwt_payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&issuance.payload)?);
        let mock_jwt = format!("eyJhbGciOiJFUzI1NiJ9.{jwt_payload_b64}.mock_signature");

        // 2. Holder selects disclosures (only name and email)
        let selected =
            SdJwtHolder::select_disclosures(&issuance.disclosures, &["given_name", "email"]);

        let sd_jwt = SdJwtHolder::present(&mock_jwt, &selected)?;
        let serialized = sd_jwt.serialize();

        // 3. Verifier parses and verifies
        let parsed = SdJwt::parse(&serialized)?;
        assert_eq!(parsed.jwt, mock_jwt);
        assert_eq!(parsed.disclosures.len(), 2);

        // Extract payload from JWT (in production, after signature verification)
        let jwt_parts: Vec<&str> = parsed.jwt.split('.').collect();
        let payload_segment = jwt_parts
            .get(1)
            .ok_or_else(|| IoError::other("missing JWT payload segment"))?;
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment)?;
        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        let result = SdJwtVerifier::verify(&payload, &parsed.disclosures)?;

        let obj = require_object(&result.claims)?;

        // Disclosed claims present
        assert_eq!(
            obj.get("given_name"),
            Some(&Value::String("John".to_string()))
        );
        assert_eq!(
            obj.get("email"),
            Some(&Value::String("john@example.com".to_string()))
        );

        // Non-SD claims present
        assert_eq!(
            obj.get("iss"),
            Some(&Value::String("https://issuer.example.com".to_string()))
        );
        assert_eq!(obj.get("sub"), Some(&Value::String("user_42".to_string())));

        // Undisclosed claims absent
        assert!(obj.get("family_name").is_none());
        assert!(obj.get("phone").is_none());

        // 2 undisclosed digests remain
        assert_eq!(result.undisclosed_digests.len(), 2);
        Ok(())
    }

    // --- Digest correctness test (known vector) ---

    #[test]
    fn digest_known_vector() {
        // Verify that our digest computation matches the expected behavior:
        // digest = base64url(SHA-256(encoded_disclosure))
        let disclosure_json = r#"["salt123456789012345678","sub","user"]"#;
        let encoded = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());
        let expected_hash = aegaeon_crypto::hash::sha256_digest(encoded.as_bytes());
        let expected_digest = URL_SAFE_NO_PAD.encode(expected_hash);

        assert_eq!(
            digest_of_encoded(&encoded).as_deref(),
            Some(expected_digest.as_str())
        );
    }
}
