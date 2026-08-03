// JWS (JSON Web Signature) implementation
// RFC 7515 compliant

use crate::algorithms::{Algorithm, AlgorithmError, CryptoProfile, RsaPssSigner, RsaPssVerifier};
use crate::policy::{JoseContext, KID_MAX_LEN};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("Algorithm error: {0}")]
    Algorithm(#[from] AlgorithmError),

    #[error("Invalid JWS format")]
    InvalidFormat,

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JSON Low* error: {0}")]
    JsonLowStar(#[from] crate::json_lowstar::JsonError),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Unsupported JWS algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Algorithm declared in header does not match verification key")]
    AlgorithmMismatch,

    #[error("Invalid key material: {0}")]
    InvalidKey(&'static str),

    #[error("JWS protected header exceeds configured length limit")]
    HeaderTooLong,

    #[error("invalid kid header parameter")]
    InvalidKid,

    #[error("unsupported critical header parameter `{0}`")]
    UnsupportedCriticalHeader(String),

    #[error("unsupported protected header parameter `{0}`")]
    UnsupportedHeader(String),

    #[error("algorithm `{0}` not allowed by crypto profile")]
    AlgorithmNotAllowed(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub struct Jws {
    pub header: JwsHeader,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Supported JWS algorithms for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlgorithm {
    Hs256,
    Rs256,
    Es256,
    Ps256,
    EdDSA,
}

impl TryFrom<&str> for JwsAlgorithm {
    type Error = JwsError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "HS256" => Ok(JwsAlgorithm::Hs256),
            "RS256" => Ok(JwsAlgorithm::Rs256),
            "ES256" => Ok(JwsAlgorithm::Es256),
            "PS256" => Ok(JwsAlgorithm::Ps256),
            "EdDSA" => Ok(JwsAlgorithm::EdDSA),
            "none" | "NONE" => Err(JwsError::UnsupportedAlgorithm("alg=none".into())),
            other => Err(JwsError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl JwsHeader {
    fn algorithm(&self) -> Result<JwsAlgorithm, JwsError> {
        JwsAlgorithm::try_from(self.alg.as_str())
    }

    fn validate(&self) -> Result<(), JwsError> {
        if let Some(kid) = &self.kid {
            if kid.is_empty() || kid.len() > KID_MAX_LEN || !kid.is_ascii() {
                return Err(JwsError::InvalidKid);
            }
        }
        Ok(())
    }
}

/// Verification key material matching supported algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKey<'a> {
    /// HMAC-SHA256 shared secret.
    HmacSha256(&'a [u8]),
    /// RSA PKCS#1 v1.5 public key components (modulus `n`, exponent `e`).
    RsaPkcs1Sha256 {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
    /// ECDSA P-256 public key in SEC1 uncompressed form (65 bytes: 0x04 || X || Y).
    EcdsaP256Sha256(&'a [u8]),
    /// RSA-PSS public key components (modulus `n`, exponent `e`).
    RsaPssSha256 {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
    /// Ed25519 raw public key (32 bytes).
    Ed25519(&'a [u8]),
}

impl VerificationKey<'_> {
    fn expected_alg(&self) -> JwsAlgorithm {
        match self {
            VerificationKey::HmacSha256(_) => JwsAlgorithm::Hs256,
            VerificationKey::RsaPkcs1Sha256 { .. } => JwsAlgorithm::Rs256,
            VerificationKey::EcdsaP256Sha256(_) => JwsAlgorithm::Es256,
            VerificationKey::RsaPssSha256 { .. } => JwsAlgorithm::Ps256,
            VerificationKey::Ed25519(_) => JwsAlgorithm::EdDSA,
        }
    }
}

const RSA_OID_NULL: [u8; 15] = [
    0x30, 0x0d, // sequence length 13
    0x06, 0x09, // OID header + length
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
    0x05, 0x00, // NULL
];

/// Verify a compact JWS using the supplied verification key and context.
///
/// This function is profile-blind — it does not check the algorithm against a
/// `CryptoProfile`. Use [`verify_compact_with_profile`] when profile enforcement
/// is required (e.g., `DPoP`, `PKJWT`). Profile-blind verification is appropriate
/// for federation paths that inherently use non-verified algorithms (ES256).
///
/// **Profile-blind**: Does not check algorithms against `CryptoProfile`.
/// This is intentional for paths where non-verified algorithms are required:
/// - Federation (ES256 required by OIDC Federation spec)
/// - Any cross-boundary verification where algorithm choice is external
///
/// For profile-enforced verification, use [`verify_compact_with_profile`].
///
/// # Arguments
///
/// * `jws` - The compact JWS string
/// * `key` - The verification key
/// * `context` - The JOSE context for per-request policy (e.g., header length limits)
///
/// # Returns
///
/// The verified payload bytes on success
///
/// # Errors
///
/// Returns [`JwsError`] if the compact serialization is malformed, header
/// parsing fails, the header algorithm does not match the supplied key, or the
/// signature verification step fails.
pub fn verify_compact_with_context(
    jws: &str,
    key: VerificationKey<'_>,
    context: &JoseContext,
) -> Result<Vec<u8>, JwsError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JwsError::InvalidFormat);
    }

    if parts[0].len() > context.header_max_length() {
        return Err(JwsError::HeaderTooLong);
    }

    let header_json = URL_SAFE_NO_PAD.decode(parts[0])?;
    let header = parse_header_bytes(&header_json)?;
    let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

    let alg = header.algorithm()?;
    if alg != key.expected_alg() {
        return Err(JwsError::AlgorithmMismatch);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    match key {
        VerificationKey::HmacSha256(secret) => {
            verify_hmac_sha256(secret, signing_input.as_bytes(), &signature)?;
        }
        VerificationKey::RsaPkcs1Sha256 { modulus, exponent } => {
            verify_rsa_pkcs1_sha256(modulus, exponent, signing_input.as_bytes(), &signature)?;
        }
        VerificationKey::EcdsaP256Sha256(sec1) => {
            verify_ecdsa_p256_sha256(sec1, signing_input.as_bytes(), &signature)?;
        }
        VerificationKey::RsaPssSha256 { modulus, exponent } => {
            verify_rsa_pss_sha256(modulus, exponent, signing_input.as_bytes(), &signature)?;
        }
        VerificationKey::Ed25519(pk) => {
            verify_ed25519_sig(pk, signing_input.as_bytes(), &signature)?;
        }
    }

    Ok(payload)
}

/// Verify a compact JWS with crypto profile enforcement.
///
/// When `profile` is `CryptoProfile::Verified`, only algorithms in the
/// verified allowlist (HS256/384/512, PS256, `EdDSA`) are accepted. Non-verified
/// algorithms are rejected with `AlgorithmNotAllowed` before any
/// cryptographic operation is attempted.
///
/// Use this for profile-aware verification paths (e.g., `DPoP`, `private_key_jwt`).
/// Federation paths intentionally use [`verify_compact_with_context`] (profile-bypass)
/// because cross-boundary algorithms like ES256 are required by spec.
///
/// ## `CryptoProfile` Enforcement Map
///
/// | Verification Path | Profile Enforced? | Rationale |
/// |---|---|---|
/// | `private_key_jwt` | Yes | `crypto_profile` parameter in `validate_private_key_jwt` |
/// | `DPoP` | N/A (`EdDSA`-only) | `ffi::verify_dpop` hardcodes `EdDSA`; inherently verified |
/// | Federation | No (bypass) | ES256 required by OIDC Federation spec |
/// | JWT AT signing | N/A | Server-side operation, key choice is configuration |
///
/// # Errors
///
/// Returns [`JwsError`] if the header cannot be decoded, the algorithm is not
/// allowed by `profile`, or the underlying verification with context fails.
pub fn verify_compact_with_profile(
    jws: &str,
    key: VerificationKey<'_>,
    context: &JoseContext,
    profile: CryptoProfile,
) -> Result<Vec<u8>, JwsError> {
    // Enforce header length limit before any parsing (matches verify_compact_with_context order)
    let header_b64 = jws.split('.').next().ok_or(JwsError::InvalidFormat)?;
    if header_b64.len() > context.header_max_length() {
        return Err(JwsError::HeaderTooLong);
    }
    // Check algorithm against profile before doing any crypto work
    let alg = Algorithm::from_string(&peek_alg_from_b64(header_b64)?)?;
    if !profile.allows(&alg) {
        return Err(JwsError::AlgorithmNotAllowed(alg.as_str().to_string()));
    }
    verify_compact_with_context(jws, key, context)
}

/// Verify a compact JWS using the supplied verification key.
///
/// This function uses the default context (4096 byte header limit).
/// For per-request configuration, use [`verify_compact_with_context`].
///
/// # Deprecated
///
/// Consider using `verify_compact_with_context` for explicit per-request policies.
///
/// # Errors
///
/// Returns [`JwsError`] under the same conditions as
/// [`verify_compact_with_context`].
#[allow(deprecated)]
pub fn verify_compact(jws: &str, key: VerificationKey<'_>) -> Result<Vec<u8>, JwsError> {
    verify_compact_with_context(jws, key, &JoseContext::default())
}

/// Extract the `alg` value from a base64url-encoded JWS header.
fn peek_alg_from_b64(header_b64: &str) -> Result<String, JwsError> {
    let header_json = URL_SAFE_NO_PAD.decode(header_b64)?;
    let pairs = parse_header_pairs(&header_json)?;
    for (key, value) in pairs {
        if key == "alg" {
            return Ok(value);
        }
    }
    Err(JwsError::InvalidFormat)
}

fn header_from_pairs<I>(pairs: I) -> Result<JwsHeader, JwsError>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut alg: Option<String> = None;
    let mut typ: Option<String> = None;
    let mut kid: Option<String> = None;

    for (key, value) in pairs {
        match key.as_str() {
            "alg" => alg = Some(value),
            "typ" => typ = Some(value),
            "kid" => kid = Some(value),
            "crit" => return Err(JwsError::UnsupportedCriticalHeader(value)),
            // Allow-listed but ignored in this minimal JWS verifier.
            "cty" => {}
            // Fail closed on unsupported header parameters to prevent cross-JWT confusion
            // and SSRF risks from untrusted header hints (RFC 8725 \u00a73.10 / \u00a73.12).
            "zip" => return Err(JwsError::UnsupportedHeader(key)),
            other => return Err(JwsError::UnsupportedHeader(other.to_string())),
        }
    }

    let alg = alg.ok_or(JwsError::InvalidFormat)?;
    let header = JwsHeader { alg, typ, kid };
    header.validate()?;
    Ok(header)
}

fn parse_header_pairs(bytes: &[u8]) -> Result<Vec<(String, String)>, JwsError> {
    crate::json::parse_json_header(bytes).map_err(JwsError::from)
}

#[cfg(test)]
fn resolve_header_pairs(
    parsed: Result<Vec<(String, String)>, crate::json_lowstar::JsonError>,
    bytes: &[u8],
) -> Result<Vec<(String, String)>, JwsError> {
    crate::json::resolve_json_header_pairs(parsed, bytes).map_err(JwsError::from)
}

fn parse_header_bytes(bytes: &[u8]) -> Result<JwsHeader, JwsError> {
    let pairs = parse_header_pairs(bytes)?;
    header_from_pairs(pairs)
}

/// Verify HMAC-SHA256 signature using the verified `EverCrypt` FFI path.
///
/// In production builds this routes to `EverCrypt_HMAC_compute` (formally
/// verified via HACL*) with constant-time tag comparison.  In test and Kani
/// builds the FFI crate transparently falls back to the Rust `hmac` + `sha2`
/// crates, preserving the same API surface.
fn verify_hmac_sha256(
    secret: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwsError> {
    if ::ffi::verify_hmac(::ffi::JwsAlg::HS256, secret, signing_input, signature) {
        Ok(())
    } else {
        Err(JwsError::VerificationFailed)
    }
}

fn verify_rsa_pkcs1_sha256(
    modulus: &[u8],
    exponent: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwsError> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(JwsError::InvalidKey("RSA public key missing"));
    }
    let modulus = trim_leading_zero(modulus);
    let exponent = trim_leading_zero(exponent);
    if is_zero_bytes(modulus) || is_zero_bytes(exponent) {
        return Err(JwsError::InvalidKey("RSA modulus/exponent invalid"));
    }
    if signature.len() != modulus.len() {
        return Err(JwsError::InvalidKey("RSA signature length mismatch"));
    }
    let spki = encode_rsa_spki(modulus, exponent)?;
    aegaeon_crypto::signature::verify_rsa_pkcs1_sha256(&spki, signing_input, signature)
        .map_err(|_| JwsError::VerificationFailed)
}

fn verify_rsa_pss_sha256(
    modulus: &[u8],
    exponent: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwsError> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(JwsError::InvalidKey("RSA-PSS public key missing"));
    }
    let modulus = trim_leading_zero(modulus);
    let exponent = trim_leading_zero(exponent);
    if is_zero_bytes(modulus) || is_zero_bytes(exponent) {
        return Err(JwsError::InvalidKey("RSA-PSS modulus/exponent invalid"));
    }
    if signature.len() != modulus.len() {
        return Err(JwsError::InvalidKey("RSA-PSS signature length mismatch"));
    }
    if ::ffi::verify_rsa(
        ::ffi::JwsAlg::PS256,
        modulus,
        exponent,
        signing_input,
        signature,
    ) {
        Ok(())
    } else {
        Err(JwsError::VerificationFailed)
    }
}

#[doc(hidden)]
pub fn __verify_rsa_pss_sha256_for_tests(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), JwsError> {
    verify_rsa_pss_sha256(modulus, exponent, message, signature)
}

fn verify_ecdsa_p256_sha256(
    sec1: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwsError> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(JwsError::InvalidKey("expected uncompressed SEC1 P-256 key"));
    }
    aegaeon_crypto::signature::verify_ecdsa_p256_sha256(sec1, signing_input, signature)
        .map_err(|_| JwsError::VerificationFailed)
}

/// Verify Ed25519 signature using the verified FFI path (ed25519-dalek / HACL*).
fn verify_ed25519_sig(pk: &[u8], signing_input: &[u8], signature: &[u8]) -> Result<(), JwsError> {
    if pk.len() != 32 {
        return Err(JwsError::InvalidKey("Ed25519 public key must be 32 bytes"));
    }
    if ::ffi::verify_ed25519(::ffi::JwsAlg::EdDSA, pk, signing_input, signature) {
        Ok(())
    } else {
        Err(JwsError::VerificationFailed)
    }
}

fn trim_leading_zero(bytes: &[u8]) -> &[u8] {
    let mut idx = 0;
    while idx + 1 < bytes.len() && bytes[idx] == 0 {
        idx += 1;
    }
    &bytes[idx..]
}

fn is_zero_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn encode_length(len: usize) -> Result<Vec<u8>, JwsError> {
    if len < 0x80 {
        Ok(vec![u8::try_from(len).map_err(|_| {
            JwsError::InvalidKey("DER length overflow")
        })?])
    } else {
        let mut bytes = Vec::new();
        let mut value = len;
        while value > 0 {
            bytes.push(
                u8::try_from(value & 0xFF)
                    .map_err(|_| JwsError::InvalidKey("DER length overflow"))?,
            );
            value >>= 8;
        }
        bytes.reverse();
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(
            0x80 | u8::try_from(bytes.len())
                .map_err(|_| JwsError::InvalidKey("DER length overflow"))?,
        );
        out.extend(bytes);
        Ok(out)
    }
}

fn encode_integer(bytes: &[u8]) -> Result<Vec<u8>, JwsError> {
    let mut value = bytes;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    let mut body = value.to_vec();
    if !body.is_empty() && body[0] & 0x80 != 0 {
        let mut prefixed = Vec::with_capacity(body.len() + 1);
        prefixed.push(0u8);
        prefixed.extend(body);
        body = prefixed;
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x02);
    out.extend(encode_length(body.len())?);
    out.extend(body);
    Ok(out)
}

#[cfg_attr(test, allow(dead_code))]
fn encode_rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, JwsError> {
    if exponent.len() > 8 {
        return Err(JwsError::InvalidKey("RSA exponent too large"));
    }
    let modulus_int = encode_integer(modulus)?;
    let exponent_int = encode_integer(exponent)?;

    let mut public_key_seq = Vec::with_capacity(modulus_int.len() + exponent_int.len() + 4);
    public_key_seq.push(0x30);
    public_key_seq.extend(encode_length(modulus_int.len() + exponent_int.len())?);
    public_key_seq.extend(modulus_int);
    public_key_seq.extend(exponent_int);

    let mut bit_string = Vec::with_capacity(public_key_seq.len() + 3);
    bit_string.push(0x03);
    bit_string.extend(encode_length(public_key_seq.len() + 1)?);
    bit_string.push(0x00); // no unused bits
    bit_string.extend(public_key_seq);

    let mut spki = Vec::with_capacity(RSA_OID_NULL.len() + bit_string.len() + 4);
    spki.push(0x30);
    spki.extend(encode_length(RSA_OID_NULL.len() + bit_string.len())?);
    spki.extend_from_slice(&RSA_OID_NULL);
    spki.extend(bit_string);
    Ok(spki)
}

#[cfg_attr(not(test), allow(dead_code))]
#[doc(hidden)]
pub fn __encode_rsa_spki_for_tests(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, JwsError> {
    encode_rsa_spki(modulus, exponent)
}

impl Jws {
    /// Create a new JWS with RSA-PSS signature
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] if the header is invalid or signing fails.
    pub fn sign_with_rsa_pss(
        payload: &[u8],
        signer: &RsaPssSigner,
        algorithm: Algorithm,
        kid: Option<String>,
    ) -> Result<String, JwsError> {
        // Create header
        let header = JwsHeader {
            alg: algorithm.as_str().to_string(),
            typ: Some("JWT".to_string()),
            kid,
        };
        header.validate()?;

        // Encode header
        let header_json = serde_json::to_vec(&header)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);

        // Encode payload
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        // Create signing input
        let signing_input = format!("{header_b64}.{payload_b64}");

        // Sign
        let signature = signer.sign(signing_input.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        // Create compact serialization
        Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
    }

    /// Verify a JWS with RSA-PSS signature
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] if the compact form is invalid, the header does not
    /// advertise `PS256`, or signature verification fails.
    pub fn verify_rsa_pss(
        jws: &str,
        verifier: &RsaPssVerifier,
        public_key_der: &[u8],
    ) -> Result<Vec<u8>, JwsError> {
        // Parse compact serialization
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(JwsError::InvalidFormat);
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // Decode header and validate algorithm
        let header_json = URL_SAFE_NO_PAD.decode(header_b64)?;
        let header = parse_header_bytes(&header_json)?;
        if header.algorithm()? != JwsAlgorithm::Ps256 {
            return Err(JwsError::AlgorithmMismatch);
        }

        // Decode signature
        let signature = URL_SAFE_NO_PAD.decode(signature_b64)?;

        // Create signing input and verify
        let signing_input = format!("{header_b64}.{payload_b64}");
        verifier
            .verify_with_public_key(signing_input.as_bytes(), &signature, public_key_der)
            .map_err(|_| JwsError::VerificationFailed)?;

        // Return payload
        Ok(URL_SAFE_NO_PAD.decode(payload_b64)?)
    }

    /// Parse a JWS from compact serialization
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] if the compact serialization is malformed or any
    /// segment fails to decode / validate.
    pub fn from_compact(jws: &str) -> Result<Self, JwsError> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(JwsError::InvalidFormat);
        }

        let header_json = URL_SAFE_NO_PAD.decode(parts[0])?;
        let header = parse_header_bytes(&header_json)?;
        let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// Convert to compact serialization
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] if serializing the header fails.
    pub fn to_compact(&self) -> Result<String, JwsError> {
        let header_json = serde_json::to_vec(&self.header)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&self.payload);
        let signature_b64 = URL_SAFE_NO_PAD.encode(&self.signature);

        Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::Deserialize;
    use std::error::Error;
    use std::io::Error as IoError;
    use std::sync::MutexGuard;

    #[derive(Debug, Deserialize)]
    struct TestVectors {
        test_cases: Vec<TestCase>,
    }

    #[derive(Debug, Deserialize)]
    struct TestCase {
        title: String,
        #[serde(default)]
        signing_input: Option<String>,
        #[serde(default)]
        output: Option<TestOutput>,
        input: TestInput,
    }

    #[derive(Debug, Deserialize)]
    struct TestInput {
        key: serde_json::Value,
    }

    #[derive(Debug, Deserialize)]
    struct TestOutput {
        #[serde(default)]
        jws: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct WycheproofRsaSignatureVectors {
        #[serde(rename = "testGroups")]
        test_groups: Vec<WycheproofRsaTestGroup>,
    }

    #[derive(Debug, Deserialize)]
    struct WycheproofRsaTestGroup {
        #[serde(rename = "publicKey")]
        public_key: WycheproofRsaPublicKey,
        tests: Vec<WycheproofRsaTest>,
    }

    #[derive(Debug, Deserialize)]
    struct WycheproofRsaPublicKey {
        modulus: String,
        #[serde(rename = "publicExponent")]
        public_exponent: String,
    }

    #[derive(Debug, Deserialize)]
    struct WycheproofRsaTest {
        #[serde(rename = "tcId")]
        tc_id: u32,
        msg: String,
        sig: String,
        result: String,
    }

    const RFC7520_VECTORS: &str = include_str!("../../../tests/vectors/rfc7520-subset.json");
    const WYCHEPROOF_RSA_SIGNATURE_2048_SHA256: &str =
        include_str!("../../../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json");

    type TestResult = Result<(), Box<dyn Error>>;

    fn lock_raw_json_env_guard() -> Result<MutexGuard<'static, ()>, IoError> {
        crate::raw_json::RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))
    }

    fn decode_b64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(input)
    }

    fn decode_hex(input: &str) -> Result<Vec<u8>, IoError> {
        if !input.len().is_multiple_of(2) {
            return Err(IoError::other("hex input must have an even length"));
        }
        (0..input.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&input[index..index + 2], 16)
                    .map_err(|error| IoError::other(format!("invalid hex byte: {error}")))
            })
            .collect()
    }

    fn load_test_case(title: &str) -> Result<TestCase, Box<dyn Error>> {
        let vectors: TestVectors = serde_json::from_str(RFC7520_VECTORS)?;
        vectors
            .test_cases
            .into_iter()
            .find(|tc| tc.title == title)
            .ok_or_else(|| IoError::other("test case present").into())
    }

    #[test]
    fn kid_validation_rejects_empty() {
        let header = JwsHeader {
            alg: "HS256".into(),
            typ: None,
            kid: Some(String::new()),
        };
        assert!(matches!(header.validate(), Err(JwsError::InvalidKid)));
    }

    // Note: TLV-specific tests removed - covered by integration tests in tests/tlv_parity.rs

    #[test]
    fn kid_validation_rejects_too_long_or_non_ascii() {
        let long_kid = "a".repeat(KID_MAX_LEN + 1);
        let header = JwsHeader {
            alg: "HS256".into(),
            typ: None,
            kid: Some(long_kid),
        };
        assert!(matches!(header.validate(), Err(JwsError::InvalidKid)));

        let non_ascii = "kid-✓".to_string();
        let header = JwsHeader {
            alg: "HS256".into(),
            typ: None,
            kid: Some(non_ascii),
        };
        assert!(matches!(header.validate(), Err(JwsError::InvalidKid)));
    }

    #[test]
    fn verify_compact_rejects_crit_header() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let header = serde_json::json!({
            "alg": "HS256",
            "crit": ["exp"]
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
        let signature_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{header_b64}.{payload_b64}.{signature_b64}");

        let err = verify_compact(&token, VerificationKey::HmacSha256(b"secret"))
            .err()
            .ok_or_else(|| IoError::other("crit header must be rejected"))?;
        // Accept either:
        // - UnsupportedCriticalHeader (if Low* parser supports arrays in future)
        // - JsonLowStar error (current behavior: Low* parser rejects arrays)
        // Both outcomes ensure crit headers are rejected, meeting security requirements
        assert!(
            matches!(err, JwsError::UnsupportedCriticalHeader(_))
                || matches!(err, JwsError::JsonLowStar(_)),
            "Expected UnsupportedCriticalHeader or JsonLowStar error, got: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn verify_compact_rejects_missing_alg() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let header = serde_json::json!({
            "typ": "JWT"
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
        let signature_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{header_b64}.{payload_b64}.{signature_b64}");

        let err = verify_compact(&token, VerificationKey::HmacSha256(b"secret"))
            .expect_err("missing alg must be rejected");
        assert!(matches!(err, JwsError::InvalidFormat));
        Ok(())
    }

    #[test]
    fn verify_compact_rejects_unsupported_alg() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let header = serde_json::json!({
            "alg": "none"
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
        let signature_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{header_b64}.{payload_b64}.{signature_b64}");

        let err = verify_compact(&token, VerificationKey::HmacSha256(b"secret"))
            .err()
            .ok_or_else(|| IoError::other("unsupported alg must be rejected"))?;
        // Accept either:
        // - UnsupportedAlgorithm (when Low* parser is available)
        // - JsonLowStar error (when Low* parser is unavailable in test builds)
        assert!(
            matches!(err, JwsError::UnsupportedAlgorithm(_))
                || matches!(err, JwsError::JsonLowStar(_)),
            "Expected UnsupportedAlgorithm or JsonLowStar error, got: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn verify_compact_rejects_jku_x5u_headers() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        for (key, value) in [
            ("jku", "https://example.com/jwks"),
            ("x5u", "https://example.com/certs"),
        ] {
            let header = serde_json::json!({
                "alg": "HS256",
                key: value,
            });
            let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
            let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
            let signature_b64 = URL_SAFE_NO_PAD.encode(b"sig");
            let token = format!("{header_b64}.{payload_b64}.{signature_b64}");

            let err = verify_compact(&token, VerificationKey::HmacSha256(b"secret"))
                .err()
                .ok_or_else(|| IoError::other("unsupported header must be rejected"))?;
            assert!(
                matches!(err, JwsError::UnsupportedHeader(ref k) if k == key)
                    || matches!(err, JwsError::JsonLowStar(_)),
                "Expected UnsupportedHeader({key}) or JsonLowStar error, got: {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parser_unavailability_fails_closed() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"HS256","kid":"unavailable"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("parser unavailability must fail closed"))?;

        assert!(matches!(
            err,
            JwsError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn parser_unavailability_does_not_fallback_to_duplicate_key_scan() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"HS256","alg":"RS256"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("parser unavailability must fail closed"))?;

        assert!(matches!(
            err,
            JwsError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", not(feature = "verified-claim")))]
    #[test]
    fn ffi_tlv_feature_parses_valid_header_pairs() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let pairs = parse_header_pairs(br#"{"alg":"HS256","kid":"compat"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "compat".to_string())
            ]
        );
        Ok(())
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn verified_claim_profile_rejects_parser_unavailable() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"HS256"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("strict profile must fail closed"))?;

        assert!(matches!(
            err,
            JwsError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", feature = "verified-claim"))]
    #[test]
    fn ffi_tlv_feature_parses_valid_header_pairs_in_verified_profile() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let pairs = parse_header_pairs(br#"{"alg":"HS256","kid":"strict"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "strict".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn compat_fallback_does_not_consume_internal_parser_errors() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::Internal(
                "unsupported raw JSON backend `future` for surface `jose-header` via AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER".to_string(),
            )),
            br#"{"alg":"HS256","kid":"compat"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("internal parser errors must fail closed"))?;

        assert!(matches!(
            err,
            JwsError::JsonLowStar(crate::json_lowstar::JsonError::Internal(ref msg))
                if msg.contains("unsupported raw JSON backend `future`")
        ));
        Ok(())
    }

    #[test]
    fn verify_rsa_pkcs1_accepts_leading_zeros() -> TestResult {
        let test_case = load_test_case("JWS RS256 Signature")?;
        let signing_input = test_case
            .signing_input
            .as_ref()
            .ok_or_else(|| IoError::other("signing input present"))?;
        let token = test_case
            .output
            .as_ref()
            .and_then(|out| out.jws.as_ref())
            .ok_or_else(|| IoError::other("jws present"))?;

        let modulus = test_case
            .input
            .key
            .get("n")
            .and_then(serde_json::Value::as_str)
            .map(decode_b64url)
            .transpose()?
            .ok_or_else(|| IoError::other("modulus present"))?;
        let exponent = test_case
            .input
            .key
            .get("e")
            .and_then(serde_json::Value::as_str)
            .map(decode_b64url)
            .transpose()?
            .ok_or_else(|| IoError::other("exponent present"))?;
        let signature = token
            .split('.')
            .nth(2)
            .map(decode_b64url)
            .transpose()?
            .ok_or_else(|| IoError::other("signature segment"))?;

        let mut modulus_with_zero = Vec::with_capacity(modulus.len() + 1);
        modulus_with_zero.push(0);
        modulus_with_zero.extend_from_slice(&modulus);
        let mut exponent_with_zero = Vec::with_capacity(exponent.len() + 1);
        exponent_with_zero.push(0);
        exponent_with_zero.extend_from_slice(&exponent);

        verify_rsa_pkcs1_sha256(
            &modulus_with_zero,
            &exponent_with_zero,
            signing_input.as_bytes(),
            &signature,
        )?;
        Ok(())
    }

    #[test]
    fn verify_rsa_pkcs1_rejects_signature_length_mismatch() -> TestResult {
        let modulus = vec![0xAA; 256];
        let exponent = vec![0x01, 0x00, 0x01]; // 65537
        let signature = vec![0x55; modulus.len() + 1]; // longer than modulus

        let err = verify_rsa_pkcs1_sha256(&modulus, &exponent, b"header.payload", &signature)
            .err()
            .ok_or_else(|| IoError::other("signature longer than modulus must be rejected"))?;
        assert!(matches!(err, JwsError::InvalidKey(msg) if msg == "RSA signature length mismatch"));
        Ok(())
    }

    #[test]
    fn verify_rsa_pkcs1_rejects_zero_exponent() -> TestResult {
        let modulus = vec![0x01; 128];
        let exponent = vec![0x00];
        let signature = vec![0x00; modulus.len()];

        let err = verify_rsa_pkcs1_sha256(&modulus, &exponent, b"", &signature)
            .err()
            .ok_or_else(|| IoError::other("zero exponent must be rejected"))?;
        assert!(matches!(err, JwsError::InvalidKey(msg) if msg == "RSA modulus/exponent invalid"));
        Ok(())
    }

    #[test]
    fn verify_rsa_pkcs1_rejects_wycheproof_invalid_vectors() -> TestResult {
        let vectors: WycheproofRsaSignatureVectors =
            serde_json::from_str(WYCHEPROOF_RSA_SIGNATURE_2048_SHA256)?;
        let mut invalid_count = 0usize;
        for group in vectors.test_groups {
            let modulus = decode_hex(&group.public_key.modulus)?;
            let exponent = decode_hex(&group.public_key.public_exponent)?;
            for test in group.tests {
                if test.result != "invalid" {
                    continue;
                }
                invalid_count += 1;
                let message = decode_hex(&test.msg)?;
                let signature = decode_hex(&test.sig)?;
                let err = verify_rsa_pkcs1_sha256(&modulus, &exponent, &message, &signature)
                    .err()
                    .ok_or_else(|| {
                        IoError::other(format!(
                            "Wycheproof invalid tcId {} must be rejected",
                            test.tc_id
                        ))
                    })?;
                assert!(
                    matches!(err, JwsError::VerificationFailed | JwsError::InvalidKey(_)),
                    "Wycheproof invalid tcId {} failed with unexpected error: {err:?}",
                    test.tc_id
                );
            }
        }

        assert_eq!(
            invalid_count, 249,
            "unexpected Wycheproof invalid-vector count"
        );
        Ok(())
    }

    #[test]
    fn verify_compact_with_profile_rejects_non_verified_alg() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        use crate::algorithms::CryptoProfile;
        use crate::policy::JoseContext;

        // Build an RS256-signed JWS token
        let header = serde_json::json!({"alg": "RS256"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"test-payload");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"fake-sig");
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        // Verified profile should reject RS256 before any crypto
        let err = verify_compact_with_profile(
            &token,
            VerificationKey::HmacSha256(b"unused"),
            &JoseContext::default(),
            CryptoProfile::Verified,
        )
        .err()
        .ok_or_else(|| IoError::other("Verified profile must reject RS256"))?;
        assert!(
            matches!(err, JwsError::AlgorithmNotAllowed(ref alg) if alg == "RS256"),
            "Expected AlgorithmNotAllowed(RS256), got: {err:?}",
        );
        Ok(())
    }

    #[test]
    fn verify_compact_with_profile_allows_hs256_in_verified() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        use crate::algorithms::CryptoProfile;
        use crate::policy::JoseContext;

        // Build an HS256-signed JWS token
        let header = serde_json::json!({"alg": "HS256"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"test-payload");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"fake-sig");
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        // Verified profile should allow HS256 — will fail at signature
        // verification (wrong key), NOT at algorithm check
        let err = verify_compact_with_profile(
            &token,
            VerificationKey::HmacSha256(b"wrong-key"),
            &JoseContext::default(),
            CryptoProfile::Verified,
        )
        .err()
        .ok_or_else(|| IoError::other("signature verification should fail"))?;
        // Should be a signature/verification error, NOT AlgorithmNotAllowed
        assert!(
            !matches!(err, JwsError::AlgorithmNotAllowed(_)),
            "HS256 should be allowed in Verified profile, got: {err:?}",
        );
        Ok(())
    }

    #[test]
    fn verify_compact_with_profile_allows_ps256_in_verified() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        use crate::algorithms::CryptoProfile;
        use crate::policy::JoseContext;

        let header = serde_json::json!({"alg": "PS256"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"test-payload");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 256]);
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let modulus = [0x80u8; 256];
        let exponent = [0x01, 0x00, 0x01];

        let result = verify_compact_with_profile(
            &token,
            VerificationKey::RsaPssSha256 {
                modulus: &modulus,
                exponent: &exponent,
            },
            &JoseContext::default(),
            CryptoProfile::Verified,
        );
        assert!(
            !matches!(result, Err(JwsError::AlgorithmNotAllowed(_))),
            "PS256 should pass the Verified profile allowlist"
        );
        Ok(())
    }

    /// Sign a compact JWS with Ed25519 (for test use).
    fn sign_ed25519_compact(
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<String, Box<dyn Error>> {
        use ed25519_dalek::Signer;
        let header = serde_json::json!({"alg": "EdDSA"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }

    #[test]
    fn verify_ed25519_roundtrip() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key();
        let token = sign_ed25519_compact(b"hello-ed25519", &sk)?;
        let payload = verify_compact(&token, VerificationKey::Ed25519(pk.as_bytes()))?;
        assert_eq!(payload, b"hello-ed25519");
        Ok(())
    }

    #[test]
    fn verify_ed25519_rejects_wrong_key() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let alternate_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let alternate_public_key = alternate_signing_key.verifying_key();
        let token = sign_ed25519_compact(b"payload", &sk)?;
        let err = verify_compact(
            &token,
            VerificationKey::Ed25519(alternate_public_key.as_bytes()),
        )
        .err()
        .ok_or_else(|| IoError::other("wrong key must fail"))?;
        assert!(matches!(err, JwsError::VerificationFailed));
        Ok(())
    }

    #[test]
    fn verify_ed25519_rejects_truncated_key() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let err = verify_compact(
            "eyJhbGciOiJFZERTQSJ9.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            VerificationKey::Ed25519(&[0u8; 16]),
        )
        .err()
        .ok_or_else(|| IoError::other("truncated key must fail"))?;
        assert!(matches!(err, JwsError::InvalidKey(_)));
        Ok(())
    }

    #[test]
    fn verify_ed25519_with_verified_profile() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        use crate::algorithms::CryptoProfile;
        use crate::policy::JoseContext;

        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key();
        let token = sign_ed25519_compact(b"verified-ed25519", &sk)?;
        let payload = verify_compact_with_profile(
            &token,
            VerificationKey::Ed25519(pk.as_bytes()),
            &JoseContext::default(),
            CryptoProfile::Verified,
        )?;
        assert_eq!(payload, b"verified-ed25519");
        Ok(())
    }

    #[test]
    fn verify_ed25519_alg_mismatch() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        // HS256 key + EdDSA header = AlgorithmMismatch
        let header = serde_json::json!({"alg": "EdDSA"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let err = verify_compact(&token, VerificationKey::HmacSha256(b"secret"))
            .err()
            .ok_or_else(|| IoError::other("mismatched alg/key must fail"))?;
        assert!(matches!(err, JwsError::AlgorithmMismatch));
        Ok(())
    }
}
