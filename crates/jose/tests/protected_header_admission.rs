use aegaeon_jose::{
    decrypt_rsa_oaep_a256gcm_pkcs8_with_context, verify_compact_with_context,
    verify_request_object, verify_request_object_ps256_promoted,
    verify_request_object_rs256_promoted, Algorithm, JoseContext, Jws, JwsError, RsaPssSigner,
    VerificationKey,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use simple_asn1::{to_der, ASN1Block, BigInt, BigUint};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
const SECRET: &[u8] = b"protected-header-admission-test-secret";
const PAYLOAD: &[u8] = b"original payload\0with arbitrary bytes\xff";

fn input(header: &str, payload: &[u8]) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

fn hs_token(header: &str, payload: &[u8]) -> String {
    let input = input(header, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).expect("HMAC key");
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

type RsaFixture = (Value, Vec<u8>, Vec<u8>);

fn rsa_fixture() -> Result<RsaFixture, Box<dyn Error>> {
    let fixtures: Value =
        serde_json::from_str(include_str!("../../../tests/vectors/rfc7520-subset.json"))?;
    let case = fixtures["test_cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["title"] == "JWE RSA-OAEP and AES GCM")
        .expect("RSA private fixture")
        .clone();
    let key = &case["input"]["key"];
    let mut integers = vec![ASN1Block::Integer(0, BigInt::from(0))];
    for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        integers.push(ASN1Block::Integer(
            0,
            BigInt::from(BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD.decode(key[field].as_str().expect("key component"))?,
            )),
        ));
    }
    let pkcs1 = to_der(&ASN1Block::Sequence(0, integers))?;
    let pkcs8 = to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from(0)),
            ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1)),
                    ASN1Block::Null(0),
                ],
            ),
            ASN1Block::OctetString(0, pkcs1.clone()),
        ],
    ))?;
    Ok((case, pkcs1, pkcs8))
}

#[test]
fn protected_header_unknown_values_and_names_verify_original_bytes() -> TestResult {
    for extension in [
        r#""extension":"text""#.to_string(),
        r#""extension":null"#.into(),
        r#""extension":7.25"#.into(),
        r#""extension":true"#.into(),
        r#""extension":{"nested":[false,null,2]}"#.into(),
        r#""extension":["value",{}]"#.into(),
        r#""\u0065xtension":"escaped""#.into(),
        "\"拡張\":\"value\"".into(),
        format!("\"extension\":\"{}\"", "x".repeat(300)),
    ] {
        let header = format!("{{\"kid\":\"k\", {extension}, \"cty\":\"JWT\", \"alg\":\"HS256\"}}");
        let token = hs_token(&header, PAYLOAD);
        let decoded = verify_compact_with_context(
            &token,
            VerificationKey::HmacSha256(SECRET),
            &JoseContext::default(),
        )?;
        assert_eq!(decoded, PAYLOAD);
        assert_eq!(Jws::from_compact(&token)?.to_compact()?, token);
    }
    Ok(())
}

#[test]
fn protected_header_all_unsupported_processing_and_wrong_types_refuse() {
    let mut headers = Vec::new();
    for field in ["crit", "b64", "zip"] {
        for value in [
            "null",
            "true",
            "false",
            "0",
            "\"b64\"",
            "[]",
            "[\"b64\"]",
            "{}",
        ] {
            headers.push(format!("{{\"alg\":\"HS256\",\"{field}\":{value}}}"));
        }
    }
    for value in ["true", "false", "null", "\"false\""] {
        headers.push(format!(
            "{{\"alg\":\"HS256\",\"b64\":{value},\"crit\":[\"b64\"]}}"
        ));
    }
    for field in ["alg", "typ", "kid", "cty"] {
        for value in ["null", "true", "42", "[]", "{}"] {
            headers.push(if field == "alg" {
                format!("{{\"alg\":{value}}}")
            } else {
                format!("{{\"alg\":\"HS256\",\"{field}\":{value}}}")
            });
        }
    }
    headers.extend([
        r#"{"alg":"HS256","\u0061lg":"HS256"}"#.into(),
        r#"{"alg":"HS256","extension":0,"\u0065xtension":1}"#.into(),
        r#"{"alg":"HS256","extension":[1,]}"#.into(),
        r#"{"alg":"HS256","extension":{"x":1,}}"#.into(),
        r#"{"alg":"HS256","extension":0,}"#.into(),
        r#"{"alg":"HS256",}"#.into(),
        r#"{"alg":"HS256"} {}"#.into(),
        r#"{"alg":"none"}"#.into(),
        r#"{"alg":"ES256"}"#.into(),
    ]);
    for header in headers {
        let token = hs_token(&header, PAYLOAD);
        assert!(
            verify_compact_with_context(
                &token,
                VerificationKey::HmacSha256(SECRET),
                &JoseContext::default()
            )
            .is_err(),
            "accepted {header}"
        );
    }
}

#[test]
fn protected_header_roundtrip_refuses_mutations_and_does_not_verify() -> TestResult {
    let token = hs_token(
        r#"{ "typ":"JWT", "extension":"\u2603", "\u0061lg":"HS256", "cty":"JWT", "kid":"k" }"#,
        PAYLOAD,
    );
    let mut parsed = Jws::from_compact(&token)?;
    let original = parsed.header.clone();
    for field in ["alg", "typ", "kid"] {
        match field {
            "alg" => parsed.header.alg = "ES256".into(),
            "typ" => parsed.header.typ = Some("different".into()),
            _ => parsed.header.kid = None,
        }
        assert!(matches!(
            parsed.to_compact(),
            Err(JwsError::ParsedFieldsChanged)
        ));
        parsed.header = original.clone();
        assert_eq!(parsed.to_compact()?, token);
    }
    parsed.payload.push(0);
    assert!(matches!(
        parsed.to_compact(),
        Err(JwsError::ParsedFieldsChanged)
    ));
    parsed.payload.pop();
    parsed.signature[0] ^= 1;
    assert!(matches!(
        parsed.to_compact(),
        Err(JwsError::ParsedFieldsChanged)
    ));
    parsed.signature[0] ^= 1;
    assert_eq!(parsed.to_compact()?, token);
    let bad = format!(
        "{}.{}",
        token.rsplit_once('.').expect("signature").0,
        URL_SAFE_NO_PAD.encode([0; 32])
    );
    assert_eq!(Jws::from_compact(&bad)?.to_compact()?, bad);
    assert!(matches!(
        verify_compact_with_context(
            &bad,
            VerificationKey::HmacSha256(SECRET),
            &JoseContext::default()
        ),
        Err(JwsError::VerificationFailed)
    ));
    assert!(matches!(
        Jws::from_compact_with_context(&token, &JoseContext::new(1)),
        Err(JwsError::HeaderTooLong)
    ));
    Ok(())
}

#[test]
fn protected_header_key_families_and_unused_hints_do_not_fetch() -> TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("http://{}/keys", listener.local_addr()?);
    let (case, pkcs1, pkcs8) = rsa_fixture()?;
    let n = URL_SAFE_NO_PAD.decode(case["input"]["key"]["n"].as_str().expect("n"))?;
    let e = URL_SAFE_NO_PAD.decode(case["input"]["key"]["e"].as_str().expect("e"))?;
    let ed = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let ec = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into())?;
    let ec_public = ec.verifying_key().to_encoded_point(false);
    let ed_public = ed.verifying_key().to_bytes();
    for alg in ["HS256", "RS256", "PS256", "ES256", "EdDSA"] {
        let header = json!({"alg":alg,"jku":url,"x5u":url,"x5c":["unused"],"jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode([9;32])},"拡張":{"nested":[null,false,1]},"long":"x".repeat(300)}).to_string();
        let signed = input(&header, PAYLOAD);
        let (signature, key) = match alg {
            "HS256" => {
                let token = hs_token(&header, PAYLOAD);
                (
                    token.rsplit_once('.').expect("signature").1.to_string(),
                    VerificationKey::HmacSha256(SECRET),
                )
            }
            "RS256" => (
                jsonwebtoken::crypto::sign(
                    signed.as_bytes(),
                    &jsonwebtoken::EncodingKey::from_rsa_der(&pkcs1),
                    jsonwebtoken::Algorithm::RS256,
                )?,
                VerificationKey::RsaPkcs1Sha256 {
                    modulus: &n,
                    exponent: &e,
                },
            ),
            "PS256" => (
                URL_SAFE_NO_PAD.encode(
                    RsaPssSigner::from_der(&pkcs8, Algorithm::PS256)?.sign(signed.as_bytes())?,
                ),
                VerificationKey::RsaPssSha256 {
                    modulus: &n,
                    exponent: &e,
                },
            ),
            "ES256" => {
                let signature: p256::ecdsa::Signature = ec.sign(signed.as_bytes());
                (
                    URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    VerificationKey::EcdsaP256Sha256(ec_public.as_bytes()),
                )
            }
            _ => (
                URL_SAFE_NO_PAD.encode(ed.sign(signed.as_bytes()).to_bytes()),
                VerificationKey::Ed25519(&ed_public),
            ),
        };
        let token = format!("{signed}.{signature}");
        assert_eq!(
            verify_compact_with_context(&token, key, &JoseContext::default())?,
            PAYLOAD
        );
        assert_eq!(Jws::from_compact(&token)?.to_compact()?, token);
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
    let signer = RsaPssSigner::from_der(&pkcs8, Algorithm::PS256)?;
    let token = Jws::sign_with_rsa_pss(PAYLOAD, &signer, Algorithm::PS256, Some("key".into()))?;
    assert_eq!(Jws::from_compact(&token)?.to_compact()?, token);
    assert_eq!(
        verify_compact_with_context(
            &token,
            VerificationKey::RsaPssSha256 {
                modulus: &n,
                exponent: &e
            },
            &JoseContext::default()
        )?,
        PAYLOAD
    );
    Ok(())
}

#[test]
fn protected_header_request_objects_public_and_promoted_paths() -> TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let hint = format!("http://{}/keys", listener.local_addr()?);
    let (case, pkcs1, _) = rsa_fixture()?;
    let key = &case["input"]["key"];
    let n = URL_SAFE_NO_PAD.decode(key["n"].as_str().expect("n"))?;
    let e = URL_SAFE_NO_PAD.decode(key["e"].as_str().expect("e"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let payload =
        json!({"iss":"client","aud":"https://issuer.example","client_id":"client","exp":now+300})
            .to_string();
    let aud = vec!["https://issuer.example".into()];
    let decode = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().expect("n"),
        key["e"].as_str().expect("e"),
    )?;
    for alg in [
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::PS256,
    ] {
        for (extra, accepted) in [
            (r#""extension":{"a":[null,true]},"\u2603":"ignored""#, true),
            (r#""crit":null"#, false),
            (r#""b64":true"#, false),
            (r#""kid":null"#, false),
            (r#""extension":0,"\u0065xtension":1"#, false),
        ] {
            let hints = json!({"jku":hint,"x5u":hint,"x5c":["unused"],"jwk":{"kty":"RSA","n":key["n"],"e":key["e"]}}).to_string();
            let header = format!(
                "{{\"alg\":\"{alg:?}\",{extra},{}}}",
                &hints[1..hints.len() - 1]
            );
            let signed = input(&header, payload.as_bytes());
            let signature = jsonwebtoken::crypto::sign(
                signed.as_bytes(),
                &jsonwebtoken::EncodingKey::from_rsa_der(&pkcs1),
                alg,
            )?;
            let token = format!("{signed}.{signature}");
            assert_eq!(
                verify_request_object(&token, &decode, &aud, 0).is_ok(),
                accepted,
                "{header}"
            );
            let result = if alg == jsonwebtoken::Algorithm::RS256 {
                verify_request_object_rs256_promoted(&token, &n, &e, &aud, 0)
            } else {
                verify_request_object_ps256_promoted(&token, &n, &e, &aud, 0)
            };
            assert_eq!(result.is_ok(), accepted, "{header}: {result:?}");
        }
    }
    assert_eq!(
        listener
            .accept()
            .expect_err("unused hints must not fetch")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn protected_header_jwe_authenticated_decryption_keeps_original_aad() -> TestResult {
    let (case, _, pkcs8) = rsa_fixture()?;
    let encrypted = URL_SAFE_NO_PAD.decode(
        case["output"]["encrypted_key"]
            .as_str()
            .expect("encrypted key"),
    )?;
    let cek = aegaeon_crypto::jwe::rsa_oaep_unwrap(&pkcs8, &encrypted)?;
    for (extra, accepted) in [
        (r#""extension":{"nested":[false,null]},"\u2603":7"#, true),
        (r#""extension":[1,]"#, false),
        (r#""extension":{"x":1,}"#, false),
        (r#""enc":null"#, false),
        (r#""b64":true"#, false),
        (r#""crit":[]"#, false),
        (r#""zip":"DEF""#, false),
    ] {
        let header = if extra.starts_with("\"enc\"") {
            format!("{{\"alg\":\"RSA-OAEP\",{extra}}}")
        } else {
            format!("{{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",{extra}}}")
        };
        let protected = URL_SAFE_NO_PAD.encode(header);
        let mut iv = [0; 12];
        getrandom::getrandom(&mut iv).map_err(|error| std::io::Error::other(error.to_string()))?;
        let sealed =
            aegaeon_crypto::jwe::encrypt_a256gcm(&cek, &iv, PAYLOAD, protected.as_bytes())?;
        let (cipher, tag) = sealed.split_at(sealed.len() - 16);
        let token = format!(
            "{protected}.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&encrypted),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(cipher),
            URL_SAFE_NO_PAD.encode(tag)
        );
        let result =
            decrypt_rsa_oaep_a256gcm_pkcs8_with_context(&token, &pkcs8, JoseContext::default());
        if accepted {
            assert_eq!(result?, PAYLOAD);
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}
