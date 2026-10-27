//! Real signing material shared by JWK usage consumer tests.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

pub(crate) const KID: &str = "usage-key";
const RSA: &str = include_str!("../../tests/fixtures/rsa2048-private.pk8.pem");
const EC: &str = include_str!("../../tests/fixtures/p256-private.pk8.pem");

#[cfg(test)]
pub(crate) fn material(algorithm: Algorithm) -> (Value, EncodingKey) {
    match algorithm {
        Algorithm::RS256 | Algorithm::PS256 => {
            let key = crate::oidc::OidcSigningKey::from_rsa_pem(KID.into(), RSA)
                .expect("RSA signing fixture");
            let mut value =
                serde_json::to_value(key.jwks()).expect("public JWKS")["keys"][0].clone();
            value.as_object_mut().expect("JWK object").remove("use");
            value["alg"] = json!(format!("{algorithm:?}"));
            (
                value,
                EncodingKey::from_rsa_pem(RSA.as_bytes()).expect("RSA encoding key"),
            )
        }
        Algorithm::ES256 => {
            let der = pem::parse(EC).expect("EC PEM");
            let pair = aegaeon_crypto::signing::EcdsaP256SigningKey::from_pkcs8(der.contents())
                .expect("EC signing fixture");
            let point = pair.public_key_sec1().expect("EC public point");
            (
                json!({"kty":"EC","kid":KID,"alg":"ES256","crv":"P-256",
                "x":URL_SAFE_NO_PAD.encode(&point[1..33]),
                "y":URL_SAFE_NO_PAD.encode(&point[33..65])}),
                EncodingKey::from_ec_pem(EC.as_bytes()).expect("EC encoding key"),
            )
        }
        Algorithm::ES384 => {
            use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_ASN1_SIGNING};
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                .expect("P-384 fixture generation");
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, der.as_ref())
                .expect("P-384 fixture key");
            let point = pair.public_key().as_ref();
            (
                json!({"kty":"EC","kid":KID,"alg":"ES384","crv":"P-384",
                    "x":URL_SAFE_NO_PAD.encode(&point[1..49]),
                    "y":URL_SAFE_NO_PAD.encode(&point[49..97])}),
                EncodingKey::from_ec_der(der.as_ref()),
            )
        }
        _ => panic!("unsupported fixture algorithm"),
    }
}

pub(crate) fn sign(algorithm: Algorithm, key: &EncodingKey, claims: &Value) -> String {
    let mut header = Header::new(algorithm);
    header.kid = Some(KID.into());
    jsonwebtoken::encode(&header, claims, key).expect("signed usage fixture")
}

// All cases here remain structurally representable. Malformed metadata has
// separate parser controls; a second eligible key lets consumers admit the set
// while still requiring the token's exact kid to be denied.
pub(crate) fn cases() -> Vec<(Value, bool)> {
    vec![
        (json!({}), true),
        (json!({"use":"sig"}), true),
        (json!({"key_ops":["verify"]}), true),
        (json!({"use":"sig","key_ops":["sign","verify"]}), true),
        (json!({"use":"enc"}), false),
        (json!({"use":"SIG"}), false),
        (json!({"use":" sig "}), false),
        (json!({"use":"extension"}), false),
        (json!({"use":""}), false),
        (json!({"key_ops":[]}), false),
        (json!({"key_ops":["sign"]}), false),
        (json!({"key_ops":["VERIFY"]}), false),
        (json!({"key_ops":[" verify "]}), false),
        (json!({"key_ops":["verify","encrypt"]}), false),
        (json!({"key_ops":["verify","extension"]}), false),
    ]
}

pub(crate) fn keyset(key: &Value, metadata: &Value) -> Value {
    let mut target = key.clone();
    target
        .as_object_mut()
        .expect("target object")
        .extend(metadata.as_object().expect("metadata object").clone());
    let mut other = key.clone();
    other["kid"] = json!("other-key");
    json!({"keys":[target,other]})
}

/// Unusable siblings must not poison a valid public verification candidate.
#[cfg(test)]
pub(crate) fn unusable_siblings(key: &Value) -> Vec<Value> {
    let mut cases = vec![
        json!(null),
        json!(7),
        json!([]),
        json!({}),
        json!({"kty":"OKP","kid":"ignored","crv":"Ed25519","x":"AA"}),
        json!({"kty":"oct","kid":"ignored","k":"not-retained"}),
    ];
    let fields = [
        ("kty", json!(null)),
        ("kty", json!(1)),
        ("kid", json!(null)),
        ("kid", json!(1)),
        ("alg", json!(null)),
        ("alg", json!(1)),
        ("alg", json!("unknown")),
        ("use", json!(null)),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["verify", "verify"])),
        ("key_ops", json!(null)),
        ("key_ops", json!(["verify", 1])),
    ];
    for (field, value) in fields {
        let mut bad = key.clone();
        bad["kid"] = json!("ignored");
        bad[field] = value;
        cases.push(bad);
    }
    let names: &[&str] = if key["kty"] == "RSA" {
        &["n", "e"]
    } else {
        &["x", "y", "crv"]
    };
    for field in names {
        for value in [
            json!(null),
            json!(1),
            json!(""),
            json!("AA=="),
            json!("!"),
            json!("AA"),
        ] {
            let mut bad = key.clone();
            bad["kid"] = json!("ignored");
            bad[*field] = value;
            cases.push(bad);
        }
        let mut bad = key.clone();
        bad["kid"] = json!("ignored");
        bad.as_object_mut().unwrap().remove(*field);
        cases.push(bad);
    }
    cases
}

/// Deterministic public-shape fixture for cache identity tests only, not signatures.
#[cfg(test)]
pub(crate) fn public_shape_modulus(marker: &str) -> String {
    let mut bytes = vec![0xff; 256];
    for (slot, byte) in bytes[1..255].iter_mut().zip(marker.as_bytes()) {
        *slot = *byte;
    }
    URL_SAFE_NO_PAD.encode(bytes)
}
