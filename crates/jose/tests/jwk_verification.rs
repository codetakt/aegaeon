use aegaeon_jose::jwk::{Jwk, JwkError, JwkSet};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

fn key() -> Value {
    let generated = aegaeon_crypto::signing::EcdsaP256SigningKey::generate().unwrap();
    json!({"kty":"EC","kid":"good","crv":"P-256","alg":"ES256",
        "x":URL_SAFE_NO_PAD.encode(generated.public_x),"y":URL_SAFE_NO_PAD.encode(generated.public_y)})
}

#[test]
fn verification_set_ignores_unusable_members_in_either_order_and_drops_extras() {
    let mut good = key();
    good["extension"] = json!({"opaque":"not retained"});
    let mut bads = vec![
        Value::Null,
        json!(7),
        json!({}),
        json!({"kty":"OKP","kid":"bad"}),
        json!({"kty":"oct","kid":"bad"}),
    ];
    for (name, value) in [
        ("kid", Value::Null),
        ("alg", Value::Null),
        ("alg", json!("es256")),
        ("alg", json!("RS256")),
        ("crv", json!("p-256")),
        ("x", json!("AA")),
        ("y", json!(true)),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["verify", "verify"])),
    ] {
        let mut bad = good.clone();
        bad["kid"] = json!("bad");
        bad[name] = value;
        bads.push(bad);
    }
    for bad in bads {
        for keys in [
            vec![good.clone(), bad.clone()],
            vec![bad.clone(), good.clone()],
        ] {
            let set = JwkSet::from_verification_value(json!({"keys":keys})).unwrap();
            assert_eq!(set.keys().len(), 1);
            assert!(set.keys()[0].extra.is_empty());
            assert_eq!(
                set.select_verification_key(None).unwrap().unwrap().kid(),
                Some("good")
            );
        }
    }
}

#[test]
fn verification_set_keeps_original_kid_identity_and_missing_kid_obligations() {
    let good = key();
    let set =
        JwkSet::from_verification_value(json!({"keys":[good,{"kty":"OKP","kid":"good"},null]}))
            .unwrap();
    assert!(matches!(
        set.ensure_unique_kid(),
        Err(JwkError::DuplicateKid(_))
    ));
    assert_eq!(set.ensure_all_have_kid(), Err(JwkError::KidRequired));
    assert!(set.observed_kid("good"));
    assert!(set.select_verification_key(Some("good")).is_err());
    let observed = JwkSet::from_verification_value(json!({"keys":[{"kid":"ignored"}]})).unwrap();
    let empty = JwkSet::from_verification_value(json!({"keys":[]})).unwrap();
    assert_ne!(observed, empty);
    assert!(observed.clone().observed_kid("ignored"));
    assert!(observed.select_verification_key(None).unwrap().is_none());
}

#[test]
fn verification_set_preserves_strict_api_and_checks_typed_mutations() {
    let mut good = key();
    good["alg"] = Value::Null;
    assert!(Jwk::from_value(good.clone()).is_ok());
    assert!(JwkSet::from_verification_value(json!({"keys":[good]}))
        .unwrap()
        .keys()
        .is_empty());
    assert!(JwkSet::from_value(json!({"keys":[key(),{"kty":"OKP"}]})).is_err());
    for envelope in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"keys":null}),
        json!({"keys":{}}),
    ] {
        assert!(JwkSet::from_verification_value(envelope).is_err());
    }
    let mut typed = Jwk::from_value(key()).unwrap();
    assert!(typed.is_verification_candidate());
    typed.key_type = "RSA".into();
    assert!(!typed.is_verification_candidate());
}

#[test]
fn verification_set_rejects_noncanonical_and_compensating_coordinate_lengths() {
    let good = key();
    let x = URL_SAFE_NO_PAD.decode(good["x"].as_str().unwrap()).unwrap();
    let y = URL_SAFE_NO_PAD.decode(good["y"].as_str().unwrap()).unwrap();
    let mut shifted = good.clone();
    shifted["x"] = json!(URL_SAFE_NO_PAD.encode(&x[..31]));
    shifted["y"] = json!(URL_SAFE_NO_PAD.encode([&x[31..], &y].concat()));
    let mut zero = good.clone();
    zero["x"] = json!(URL_SAFE_NO_PAD.encode([0; 32]));
    zero["y"] = zero["x"].clone();
    let mut variants = vec![shifted, zero];
    for encoded in [
        format!("{}=", good["x"].as_str().unwrap()),
        String::new(),
        " ".into(),
        "YR".into(),
        "+w".into(),
    ] {
        let mut bad = good.clone();
        bad["x"] = json!(encoded);
        variants.push(bad);
    }
    for bad in variants {
        assert!(JwkSet::from_verification_value(json!({"keys":[bad]}))
            .unwrap()
            .keys()
            .is_empty());
    }
}

#[test]
fn verification_selection_counts_candidates_before_algorithm_narrowing() {
    let mut first = key();
    first.as_object_mut().unwrap().remove("alg");
    let mut second = key();
    second["kid"] = json!("second");
    let set = JwkSet::from_verification_value(json!({"keys":[first,second]})).unwrap();
    assert!(set.select_verification_key(None).unwrap().is_none());
    assert!(set
        .select_verification_key(Some("second"))
        .unwrap()
        .is_some());
    assert!(set
        .select_verification_key(Some("missing"))
        .unwrap()
        .is_none());
}
