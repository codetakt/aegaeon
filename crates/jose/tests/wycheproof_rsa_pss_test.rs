use aegaeon_jose::jws::__verify_rsa_pss_sha256_for_tests;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use simple_asn1::ASN1Block;
use std::error::Error;
use std::io;

#[derive(Debug, Deserialize)]
struct WycheproofRsaPssVectors {
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofRsaPssGroup>,
}

#[derive(Debug, Deserialize)]
struct WycheproofRsaPssGroup {
    sha: String,
    #[serde(rename = "mgfSha")]
    mgf_sha: String,
    #[serde(rename = "sLen")]
    salt_len: u32,
    #[serde(rename = "publicKey")]
    public_key: WycheproofRsaPublicKey,
    tests: Vec<WycheproofRsaPssTest>,
}

#[derive(Debug, Deserialize)]
struct WycheproofRsaPublicKey {
    modulus: String,
    #[serde(rename = "publicExponent")]
    public_exponent: String,
}

#[derive(Debug, Deserialize)]
struct WycheproofRsaPssTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    sig: String,
    result: String,
}

type TestResult = Result<(), Box<dyn Error>>;

const WYCHEPROOF_RSA_PSS_2048_SHA256_MGF1_32: &str =
    include_str!("../../../tests/vectors/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json");
const RSA_PRIVATE_KEY: &str = include_str!("../../server/tests/fixtures/rsa2048-private.pk8.pem");

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !input.len().is_multiple_of(2) {
        return Err(test_error("hex input must have an even length"));
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&input[index..index + 2], 16)
                .map_err(|error| test_error(format!("invalid hex byte: {error}")))
        })
        .collect()
}

fn decode_pem_body(pem: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let body = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    Ok(STANDARD.decode(body)?)
}

fn rsa_components_from_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, rsa) = blocks.first()? else {
        return None;
    };
    let (Some(ASN1Block::Integer(_, modulus)), Some(ASN1Block::Integer(_, exponent))) =
        (rsa.first(), rsa.get(1))
    else {
        return None;
    };
    Some((
        modulus.to_biguint()?.to_bytes_be(),
        exponent.to_biguint()?.to_bytes_be(),
    ))
}

fn rsa_components_from_public_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    if let Some(components) = rsa_components_from_der(der) {
        return Ok(components);
    }
    let blocks = simple_asn1::from_der(der)?;
    let Some(ASN1Block::Sequence(_, spki)) = blocks.first() else {
        return Err(test_error("public key must be a DER sequence"));
    };
    let Some(ASN1Block::BitString(_, _, public_key)) = spki.get(1) else {
        return Err(test_error("SPKI must contain an RSA public key bit string"));
    };
    rsa_components_from_der(public_key)
        .ok_or_else(|| test_error("RSA public key components are missing"))
}

#[test]
fn wycheproof_rsa_pss_sha256_vectors_follow_expected_results() -> TestResult {
    let vectors: WycheproofRsaPssVectors =
        serde_json::from_str(WYCHEPROOF_RSA_PSS_2048_SHA256_MGF1_32)?;
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut acceptable_count = 0usize;

    for group in vectors.test_groups {
        if group.sha != "SHA-256" || group.mgf_sha != "SHA-256" || group.salt_len != 32 {
            continue;
        }
        let modulus = decode_hex(&group.public_key.modulus)?;
        let exponent = decode_hex(&group.public_key.public_exponent)?;
        for test in group.tests {
            let message = decode_hex(&test.msg)?;
            let signature = decode_hex(&test.sig)?;
            let result =
                __verify_rsa_pss_sha256_for_tests(&modulus, &exponent, &message, &signature);
            match test.result.as_str() {
                "valid" => {
                    valid_count += 1;
                    assert!(
                        result.is_ok(),
                        "Wycheproof valid tcId {} must verify: {result:?}",
                        test.tc_id
                    );
                }
                "invalid" => {
                    invalid_count += 1;
                    assert!(
                        result.is_err(),
                        "Wycheproof invalid tcId {} must be rejected",
                        test.tc_id
                    );
                }
                "acceptable" => acceptable_count += 1,
                other => {
                    return Err(test_error(format!(
                        "Wycheproof tcId {} has unexpected result `{other}`",
                        test.tc_id
                    )));
                }
            }
        }
    }

    assert_eq!(valid_count, 63, "unexpected Wycheproof valid-vector count");
    assert_eq!(
        invalid_count, 45,
        "unexpected Wycheproof invalid-vector count"
    );
    assert_eq!(acceptable_count, 0, "unexpected acceptable-vector count");
    Ok(())
}

#[test]
fn aws_lc_ps256_signature_verifies_through_hacl() -> TestResult {
    let private_key = decode_pem_body(RSA_PRIVATE_KEY)?;
    let signer = aegaeon_crypto::signing::RsaPssSigner::from_pkcs8(&private_key)?;
    let message = b"aws-lc signer to Hacl_RSAPSS verifier";
    let signature = signer.sign_pss256(message)?;
    let (modulus, exponent) = rsa_components_from_public_der(&signer.public_key_der())?;

    __verify_rsa_pss_sha256_for_tests(&modulus, &exponent, message, &signature)?;
    Ok(())
}
