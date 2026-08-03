use aegaeon_jose::jws::__encode_rsa_spki_for_tests;
use serde::Deserialize;
use std::error::Error;
use std::io;

#[derive(Debug, Deserialize)]
struct WycheproofRsaSignatureVectors {
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofRsaTestGroup>,
}

#[derive(Debug, Deserialize)]
struct WycheproofRsaTestGroup {
    sha: String,
    #[serde(rename = "publicKey")]
    public_key: Option<WycheproofRsaPublicKey>,
    #[serde(rename = "publicKeyDer")]
    public_key_der: Option<String>,
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

type TestResult = Result<(), Box<dyn Error>>;

const WYCHEPROOF_RSA_SIGNATURE_2048_SHA256: &str =
    include_str!("../../../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json");

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

fn spki_for_group(group: &WycheproofRsaTestGroup) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(public_key) = &group.public_key {
        let modulus = decode_hex(&public_key.modulus)?;
        let exponent = decode_hex(&public_key.public_exponent)?;
        return Ok(__encode_rsa_spki_for_tests(&modulus, &exponent)?);
    }
    if let Some(spki) = &group.public_key_der {
        return decode_hex(spki);
    }
    Err(test_error(
        "Wycheproof group missing publicKey or publicKeyDer",
    ))
}

#[test]
fn wycheproof_rsa_pkcs1_sha256_vectors_follow_expected_results() -> TestResult {
    let vectors: WycheproofRsaSignatureVectors =
        serde_json::from_str(WYCHEPROOF_RSA_SIGNATURE_2048_SHA256)?;
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut acceptable_count = 0usize;

    for group in vectors.test_groups {
        if group.sha != "SHA-256" {
            continue;
        }
        let spki = spki_for_group(&group)?;
        for test in group.tests {
            let message = decode_hex(&test.msg)?;
            let signature = decode_hex(&test.sig)?;
            let result =
                aegaeon_crypto::signature::verify_rsa_pkcs1_sha256(&spki, &message, &signature);
            match test.result.as_str() {
                "valid" => {
                    valid_count += 1;
                    assert!(
                        result.is_ok(),
                        "Wycheproof valid tcId {} must verify",
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
                "acceptable" => {
                    acceptable_count += 1;
                }
                other => {
                    return Err(test_error(format!(
                        "Wycheproof tcId {} has unexpected result `{other}`",
                        test.tc_id
                    )));
                }
            }
        }
    }

    assert_eq!(valid_count, 9, "unexpected Wycheproof valid-vector count");
    assert_eq!(
        invalid_count, 249,
        "unexpected Wycheproof invalid-vector count"
    );
    assert_eq!(
        acceptable_count, 1,
        "unexpected Wycheproof acceptable-vector count"
    );
    Ok(())
}
