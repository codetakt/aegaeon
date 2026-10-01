use aegaeon_jose::{
    decrypt_nested_jwt_rsa_oaep_a256gcm_pkcs8_with_context as nested,
    decrypt_rsa_oaep_a256gcm_pkcs8, decrypt_rsa_oaep_a256gcm_pkcs8_with_context as generic,
    verify_compact_with_context, JoseContext, VerificationKey,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use simple_asn1::{to_der, ASN1Block, BigInt, BigUint};
use std::error::Error;
type TestResult = Result<(), Box<dyn Error>>;
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

struct EnvelopeFixture {
    key: Vec<u8>,
    encrypted_key: Vec<u8>,
    cek: Vec<u8>,
}
impl EnvelopeFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let (case, _, key) = rsa_fixture()?;
        let encrypted_key = URL_SAFE_NO_PAD.decode(
            case["output"]["encrypted_key"]
                .as_str()
                .ok_or("encrypted key")?,
        )?;
        let cek = aegaeon_crypto::jwe::rsa_oaep_unwrap(&key, &encrypted_key)?;
        Ok(Self {
            key,
            encrypted_key,
            cek,
        })
    }
    fn seal(&self, header: &str, plaintext: &[u8]) -> Result<String, Box<dyn Error>> {
        let protected = URL_SAFE_NO_PAD.encode(header);
        let mut iv = [0; 12];
        getrandom::getrandom(&mut iv).map_err(|e| std::io::Error::other(e.to_string()))?;
        let sealed =
            aegaeon_crypto::jwe::encrypt_a256gcm(&self.cek, &iv, plaintext, protected.as_bytes())?;
        let (cipher, tag) = sealed.split_at(sealed.len() - 16);
        Ok(format!(
            "{protected}.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&self.encrypted_key),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(cipher),
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }
}

#[test]
fn required_jwe_algorithms_use_the_actual_authenticated_header() -> TestResult {
    let fixture = EnvelopeFixture::new()?;
    for header in [
        r#"{"enc":"A256GCM"}"#,
        r#"{"alg":null,"enc":"A256GCM"}"#,
        r#"{"alg":7,"enc":"A256GCM"}"#,
        r#"{"alg":"","enc":"A256GCM"}"#,
        r#"{"alg":"rsa-oaep","enc":"A256GCM"}"#,
        r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#,
        r#"{"alg":"RSA1_5","enc":"A256GCM"}"#,
        r#"{"alg":"RSA-OAEP","alg":"RSA-OAEP","enc":"A256GCM"}"#,
        r#"{"alg":"RSA-OAEP"}"#,
        r#"{"alg":"RSA-OAEP","enc":null}"#,
        r#"{"alg":"RSA-OAEP","enc":[]}"#,
        r#"{"alg":"RSA-OAEP","enc":""}"#,
        r#"{"alg":"RSA-OAEP","enc":"a256gcm"}"#,
        r#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#,
        r#"{"alg":"RSA-OAEP","enc":"A256GCM","enc":"A256GCM"}"#,
    ] {
        let token = fixture.seal(header, b"arbitrary bytes\0\xff")?;
        assert!(
            generic(&token, &fixture.key, JoseContext::default()).is_err(),
            "{header}"
        );
        assert!(decrypt_rsa_oaep_a256gcm_pkcs8(&token, &fixture.key).is_err());
    }
    Ok(())
}

#[test]
fn nested_jwt_content_type_and_generic_bytes_have_distinct_contracts() -> TestResult {
    let fixture = EnvelopeFixture::new()?;
    for extra in ["", r#", "cty":"text/plain""#, r#", "cty":"""#] {
        let token = fixture.seal(
            &format!(r#"{{"alg":"RSA-OAEP","enc":"A256GCM"{extra}}}"#),
            b"arbitrary bytes\0\xff",
        )?;
        assert_eq!(
            generic(&token, &fixture.key, JoseContext::default())?,
            b"arbitrary bytes\0\xff"
        );
        assert_eq!(
            decrypt_rsa_oaep_a256gcm_pkcs8(&token, &fixture.key)?,
            b"arbitrary bytes\0\xff"
        );
        assert!(nested(&token, &fixture.key, JoseContext::default()).is_err());
    }
    for cty in [
        r#"null"#,
        "7",
        "[]",
        r#""application/jwt; charset=utf-8""#,
        r#"" JWT""#,
        r#""JWT ""#,
        r#""application/*""#,
        r#""application/example+jwt""#,
    ] {
        let header = format!(r#"{{"alg":"RSA-OAEP","enc":"A256GCM","cty":{cty}}}"#);
        assert!(nested(
            &fixture.seal(&header, b"a.b.c")?,
            &fixture.key,
            JoseContext::default()
        )
        .is_err());
    }
    let secret = b"nested-jwt-test-signing-key";
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(br#"{"sub":"nested-jwt-library-control"}"#)
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(input.as_bytes());
    let inner = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    for cty in [
        "JWT",
        "jwt",
        "jWt",
        "application/jwt",
        "APPLICATION/JWT",
        "Application/JwT",
    ] {
        let header = format!(
            r#"{{ "extension":{{"ignored":[null,true]}},"alg":"RSA-OAEP","enc":"A256GCM","cty":"{cty}" }}"#
        );
        let token = fixture.seal(&header, inner.as_bytes())?;
        let plaintext = nested(&token, &fixture.key, JoseContext::default())?;
        assert_eq!(plaintext, inner.as_bytes());
        verify_compact_with_context(
            std::str::from_utf8(&plaintext)?,
            VerificationKey::HmacSha256(secret),
            &JoseContext::default(),
        )?;
        assert!(nested(&token, b"wrong key", JoseContext::default()).is_err());
        for part in [0, 3, 4] {
            let mut segments: Vec<String> = token.split('.').map(str::to_owned).collect();
            if part == 0 {
                segments[0] = URL_SAFE_NO_PAD.encode(header.replace("ignored", "changed"));
            } else {
                let mut bytes = URL_SAFE_NO_PAD.decode(&segments[part])?;
                bytes[0] ^= 1;
                segments[part] = URL_SAFE_NO_PAD.encode(bytes);
            }
            assert!(nested(&segments.join("."), &fixture.key, JoseContext::default()).is_err());
        }
    }
    Ok(())
}
