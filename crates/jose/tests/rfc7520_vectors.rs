use aegaeon_jose::jwe::{decrypt_rsa_oaep_a256gcm_pkcs8, JweError};
use aegaeon_jose::jws::{verify_compact, JwsError, VerificationKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{digest::KeyInit, Hmac, Mac};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use simple_asn1::{to_der, ASN1Block, BigInt, BigUint};
use std::error::Error;
use std::io;

/// Helper macro to skip test when Low* FFI is unavailable
macro_rules! skip_if_lowstar_unavailable {
    () => {
        if ffi::is_lowstar_unavailable() {
            eprintln!("Skipping: Low* FFI unavailable in this build");
            return Ok(());
        }
    };
}

#[derive(Debug, Deserialize, Serialize)]
struct TestVectors {
    title: String,
    description: String,
    test_cases: Vec<TestCase>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TestCase {
    title: String,
    description: String,
    input: TestInput,
    #[serde(default)]
    signing_input: Option<String>,
    #[serde(default)]
    output: Option<TestOutput>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TestInput {
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    protected: Option<String>,
    key: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct TestOutput {
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    jws: Option<String>,
    #[serde(default)]
    protected: Option<String>,
    #[serde(default)]
    encrypted_key: Option<String>,
    #[serde(default)]
    iv: Option<String>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

struct JweParts<'a> {
    protected: &'a str,
    encrypted_key: &'a str,
    iv: &'a str,
    ciphertext: &'a str,
    tag: &'a str,
}

type AnyResult<T> = Result<T, Box<dyn Error>>;
type TestResult = AnyResult<()>;

const RFC7520_VECTORS: &str = include_str!("../../../tests/vectors/rfc7520-subset.json");

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn load_vectors() -> Result<TestVectors, serde_json::Error> {
    serde_json::from_str(RFC7520_VECTORS)
}

fn find_case<'a>(vectors: &'a TestVectors, title: &str) -> AnyResult<&'a TestCase> {
    vectors
        .test_cases
        .iter()
        .find(|test_case| test_case.title == title)
        .ok_or_else(|| test_error(format!("test case `{title}` not found")))
}

fn option_ref<'a, T>(value: Option<&'a T>, name: &str) -> AnyResult<&'a T> {
    value.ok_or_else(|| test_error(format!("{name} missing")))
}

fn option_str<'a>(value: Option<&'a str>, name: &str) -> AnyResult<&'a str> {
    value.ok_or_else(|| test_error(format!("{name} missing")))
}

fn decode_b64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

fn key_field_str<'a>(jwk: &'a Value, field: &'static str) -> AnyResult<&'a str> {
    jwk.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("field `{field}` missing")))
}

fn compact_jws_parts(token: &str) -> AnyResult<(&str, &str, &str)> {
    let mut segments = token.split('.');
    let header = segments
        .next()
        .ok_or_else(|| test_error("header segment missing"))?;
    let payload = segments
        .next()
        .ok_or_else(|| test_error("payload segment missing"))?;
    let signature = segments
        .next()
        .ok_or_else(|| test_error("signature segment missing"))?;

    if segments.next().is_some() {
        return Err(test_error("compact serialization must have 3 parts"));
    }

    Ok((header, payload, signature))
}

fn jws_output(test_case: &TestCase) -> AnyResult<&str> {
    option_str(
        option_ref(test_case.output.as_ref(), "output")?
            .jws
            .as_deref(),
        "jws",
    )
}

fn signing_input(test_case: &TestCase) -> AnyResult<&str> {
    option_str(test_case.signing_input.as_deref(), "signing input")
}

fn payload_bytes(test_case: &TestCase) -> AnyResult<Vec<u8>> {
    Ok(decode_b64url(option_str(
        test_case.input.payload.as_deref(),
        "payload",
    )?)?)
}

fn plaintext_bytes(test_case: &TestCase) -> AnyResult<&[u8]> {
    Ok(option_str(test_case.input.plaintext.as_deref(), "plaintext")?.as_bytes())
}

fn ec_p256_public_sec1_from_jwk(jwk: &Value) -> AnyResult<Vec<u8>> {
    let x_coord = decode_b64url(key_field_str(jwk, "x")?)?;
    let y_coord = decode_b64url(key_field_str(jwk, "y")?)?;
    let mut sec1 = Vec::with_capacity(1 + x_coord.len() + y_coord.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x_coord);
    sec1.extend_from_slice(&y_coord);
    Ok(sec1)
}

fn ec_p256_signing_key_from_jwk(jwk: &Value) -> AnyResult<SigningKey> {
    let private_scalar = decode_b64url(key_field_str(jwk, "d")?)?;
    Ok(SigningKey::from_slice(&private_scalar)?)
}

fn asn1_integer_from_biguint(value: &BigUint) -> ASN1Block {
    ASN1Block::Integer(0, BigInt::from(value.clone()))
}

fn biguint_from_jwk(jwk: &Value, field: &'static str) -> AnyResult<BigUint> {
    Ok(BigUint::from_bytes_be(&decode_b64url(key_field_str(
        jwk, field,
    )?)?))
}

fn rsa_public_key_from_jwk(jwk: &Value) -> AnyResult<(Vec<u8>, Vec<u8>)> {
    Ok((
        decode_b64url(key_field_str(jwk, "n")?)?,
        decode_b64url(key_field_str(jwk, "e")?)?,
    ))
}

fn rsa_private_key_pkcs8_from_jwk(jwk: &Value) -> AnyResult<Vec<u8>> {
    let modulus = biguint_from_jwk(jwk, "n")?;
    let exponent = biguint_from_jwk(jwk, "e")?;
    let private_exponent = biguint_from_jwk(jwk, "d")?;
    let prime_p = biguint_from_jwk(jwk, "p")?;
    let prime_q = biguint_from_jwk(jwk, "q")?;
    let private_exponent_mod_p = biguint_from_jwk(jwk, "dp")?;
    let private_exponent_mod_q = biguint_from_jwk(jwk, "dq")?;
    let coefficient_qi = biguint_from_jwk(jwk, "qi")?;

    let rsa_private = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from(0)),
            asn1_integer_from_biguint(&modulus),
            asn1_integer_from_biguint(&exponent),
            asn1_integer_from_biguint(&private_exponent),
            asn1_integer_from_biguint(&prime_p),
            asn1_integer_from_biguint(&prime_q),
            asn1_integer_from_biguint(&private_exponent_mod_p),
            asn1_integer_from_biguint(&private_exponent_mod_q),
            asn1_integer_from_biguint(&coefficient_qi),
        ],
    );
    let rsa_der = to_der(&rsa_private)?;

    let algorithm = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1)),
            ASN1Block::Null(0),
        ],
    );
    let pkcs8 = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from(0)),
            algorithm,
            ASN1Block::OctetString(0, rsa_der),
        ],
    );

    Ok(to_der(&pkcs8)?)
}

fn sign_hs256_compact(header_json: &[u8], payload: &[u8], secret: &[u8]) -> AnyResult<String> {
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

fn jwe_parts(test_case: &TestCase) -> AnyResult<JweParts<'_>> {
    let output = option_ref(test_case.output.as_ref(), "output")?;
    Ok(JweParts {
        protected: option_str(output.protected.as_deref(), "protected")?,
        encrypted_key: option_str(output.encrypted_key.as_deref(), "encrypted_key")?,
        iv: option_str(output.iv.as_deref(), "iv")?,
        ciphertext: option_str(output.ciphertext.as_deref(), "ciphertext")?,
        tag: option_str(output.tag.as_deref(), "tag")?,
    })
}

fn compact_jwe(parts: &JweParts<'_>) -> String {
    compact_jwe_with(parts, parts.protected, parts.tag)
}

fn compact_jwe_with(parts: &JweParts<'_>, protected: &str, tag: &str) -> String {
    format!(
        "{protected}.{}.{}.{}.{}",
        parts.encrypted_key, parts.iv, parts.ciphertext, tag
    )
}

fn tampered_signature_token(token: &str) -> AnyResult<String> {
    let (header, payload, signature_segment) = compact_jws_parts(token)?;
    let mut signature = decode_b64url(signature_segment)?;
    let first = signature
        .first_mut()
        .ok_or_else(|| test_error("signature unexpectedly empty"))?;
    *first ^= 0x01;

    let tampered_signature = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{header}.{payload}.{tampered_signature}"))
}

#[test]
fn test_rs256_vector_verification() -> TestResult {
    skip_if_lowstar_unavailable!();
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWS RS256 Signature")?;

    let expected_payload = payload_bytes(test_case)?;
    let claims: Value = serde_json::from_slice(&expected_payload)?;
    let token = jws_output(test_case)?;

    let (mut modulus, exponent) = rsa_public_key_from_jwk(&test_case.input.key)?;
    if modulus.first() == Some(&0) {
        modulus.remove(0);
    }
    assert_eq!(
        modulus.len(),
        256,
        "expected 2048-bit modulus after trimming leading zero"
    );

    let payload = verify_compact(
        token,
        VerificationKey::RsaPkcs1Sha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
    )?;
    let verified_claims: Value = serde_json::from_slice(&payload)?;
    assert_eq!(verified_claims, claims);
    Ok(())
}

#[test]
fn test_rs256_vector_rejects_modified_signature() -> TestResult {
    skip_if_lowstar_unavailable!();
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWS RS256 Signature")?;
    let token = jws_output(test_case)?;
    let tampered_token = tampered_signature_token(token)?;

    let (modulus, exponent) = rsa_public_key_from_jwk(&test_case.input.key)?;
    let result = verify_compact(
        &tampered_token,
        VerificationKey::RsaPkcs1Sha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
    );
    assert!(
        matches!(result, Err(JwsError::VerificationFailed)),
        "tampered signature must be rejected"
    );
    Ok(())
}

#[test]
fn test_ps256_vector_verification() -> TestResult {
    skip_if_lowstar_unavailable!();
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWS PS256 Signature")?;

    let expected_payload = payload_bytes(test_case)?;
    let claims: Value = serde_json::from_slice(&expected_payload)?;
    let token = jws_output(test_case)?;
    let (modulus, exponent) = rsa_public_key_from_jwk(&test_case.input.key)?;

    let payload = verify_compact(
        token,
        VerificationKey::RsaPssSha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
    )?;
    let verified_claims: Value = serde_json::from_slice(&payload)?;
    assert_eq!(verified_claims, claims);
    Ok(())
}

#[test]
fn test_ps256_vector_rejects_modified_signature() -> TestResult {
    skip_if_lowstar_unavailable!();
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWS PS256 Signature")?;
    let token = jws_output(test_case)?;
    let tampered_token = tampered_signature_token(token)?;

    let (modulus, exponent) = rsa_public_key_from_jwk(&test_case.input.key)?;
    let result = verify_compact(
        &tampered_token,
        VerificationKey::RsaPssSha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
    );
    assert!(
        matches!(result, Err(JwsError::VerificationFailed)),
        "tampered signature must be rejected"
    );
    Ok(())
}

#[test]
fn test_hs256_roundtrip() -> TestResult {
    skip_if_lowstar_unavailable!();
    let payload = br#"{"sub":"hs256"}"#;
    let secret = b"top-secret-key";
    let header_json = serde_json::to_vec(&json!({ "alg": "HS256" }))?;
    let jws = sign_hs256_compact(&header_json, payload, secret)?;

    let verified_payload = verify_compact(&jws, VerificationKey::HmacSha256(secret))?;
    assert_eq!(verified_payload, payload);
    Ok(())
}

#[test]
fn test_es256_roundtrip_from_jwk() -> TestResult {
    skip_if_lowstar_unavailable!();
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWS ES256 Signature")?;
    let signing_input = signing_input(test_case)?;
    let signing_key = ec_p256_signing_key_from_jwk(&test_case.input.key)?;
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let jws = format!("{signing_input}.{signature_b64}");

    let public_sec1 = ec_p256_public_sec1_from_jwk(&test_case.input.key)?;
    let verified = verify_compact(&jws, VerificationKey::EcdsaP256Sha256(&public_sec1))?;
    let expected_payload = payload_bytes(test_case)?;
    assert_eq!(verified, expected_payload);
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_vector() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let plaintext = decrypt_rsa_oaep_a256gcm_pkcs8(&compact_jwe(&parts), &pkcs8)?;
    assert_eq!(plaintext, plaintext_bytes(test_case)?);
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_modified_tag() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let mut tampered_tag_chars: Vec<char> = parts.tag.chars().collect();
    let first_char = tampered_tag_chars
        .first_mut()
        .ok_or_else(|| test_error("tag unexpectedly empty"))?;
    *first_char = if *first_char == 'A' { 'B' } else { 'A' };
    let tampered_tag: String = tampered_tag_chars.into_iter().collect();

    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;
    let err = decrypt_rsa_oaep_a256gcm_pkcs8(
        &compact_jwe_with(&parts, parts.protected, &tampered_tag),
        &pkcs8,
    )
    .err()
    .ok_or_else(|| test_error("tampered tag must fail"))?;
    assert!(matches!(err, JweError::ContentDecryption));
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_missing_enc() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "alg": "RSA-OAEP"
    }))?);
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let err =
        decrypt_rsa_oaep_a256gcm_pkcs8(&compact_jwe_with(&parts, &header_b64, parts.tag), &pkcs8)
            .err()
            .ok_or_else(|| test_error("missing enc must fail"))?;
    assert!(matches!(err, JweError::MissingEnc));
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_unsupported_enc() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "alg": "RSA-OAEP",
        "enc": "A128GCM"
    }))?);
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let err =
        decrypt_rsa_oaep_a256gcm_pkcs8(&compact_jwe_with(&parts, &header_b64, parts.tag), &pkcs8)
            .err()
            .ok_or_else(|| test_error("unsupported enc must fail"))?;
    assert!(matches!(err, JweError::UnsupportedEnc(enc) if enc == "A128GCM"));
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_unsupported_alg() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "alg": "RSA1_5",
        "enc": "A256GCM"
    }))?);
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let err =
        decrypt_rsa_oaep_a256gcm_pkcs8(&compact_jwe_with(&parts, &header_b64, parts.tag), &pkcs8)
            .err()
            .ok_or_else(|| test_error("unsupported alg must fail"))?;
    assert!(matches!(err, JweError::UnsupportedAlg(alg) if alg == "RSA1_5"));
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_invalid_tag_length() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let mut tag_bytes = decode_b64url(parts.tag)?;
    if tag_bytes.pop().is_none() {
        return Err(test_error("tag has at least one byte"));
    }
    let short_tag = URL_SAFE_NO_PAD.encode(tag_bytes);
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let err = decrypt_rsa_oaep_a256gcm_pkcs8(
        &compact_jwe_with(&parts, parts.protected, &short_tag),
        &pkcs8,
    )
    .err()
    .ok_or_else(|| test_error("short tag must fail"))?;
    assert!(matches!(err, JweError::InvalidSerialization));
    Ok(())
}

#[test]
fn test_jwe_rsa_oaep_a256gcm_rejects_modified_header_aad() -> TestResult {
    let vectors = load_vectors()?;
    let test_case = find_case(&vectors, "JWE RSA-OAEP and AES GCM")?;
    let parts = jwe_parts(test_case)?;
    let mut header_value: Value = serde_json::from_slice(&decode_b64url(parts.protected)?)?;
    let header_object = header_value
        .as_object_mut()
        .ok_or_else(|| test_error("header object missing"))?;
    header_object.insert("kid".to_string(), Value::String("extra".into()));
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_value)?);
    let pkcs8 = rsa_private_key_pkcs8_from_jwk(&test_case.input.key)?;

    let err =
        decrypt_rsa_oaep_a256gcm_pkcs8(&compact_jwe_with(&parts, &header_b64, parts.tag), &pkcs8)
            .err()
            .ok_or_else(|| test_error("modified header should break AAD verification"))?;
    assert!(matches!(err, JweError::ContentDecryption));
    Ok(())
}
