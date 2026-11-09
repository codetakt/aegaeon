use super::*;
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{
        KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
        OAEP_SHA256_MGF1SHA256,
    },
};

const NOW: i64 = 10;
const PAYLOAD: &[u8] = b"stable logical message, fixed delivery proof";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn context() -> MessageContext {
    MessageContext {
        message_id: id(1),
        deployment_id: id(2),
        runtime_generation: id(3),
        scope: Scope::Organization {
            environment_id: id(4),
            domain_id: id(5),
            organization_id: id(6),
        },
        organization_generation: Revision::Value(1),
        purpose: "invitation".into(),
        template: "first_admin".into(),
        template_version: 1,
        expires_at: 180,
        authority_revision: Revision::Value(0),
        contact_revision: Revision::NotApplicable,
        configuration_revision: Revision::Value(1),
        authority_binding: [7; 32],
        destination_binding: [8; 32],
        payload_digest: sha256_digest(PAYLOAD),
    }
}

fn version(name: &str) -> KeyVersion {
    KeyVersion {
        id: name.into(),
        deployment_id: id(2),
        scope: Scope::Environment {
            environment_id: id(4),
        },
        not_before: 5,
        seal_until: 100,
        open_until: 200,
    }
}

fn material() -> (Zeroizing<Vec<u8>>, Vec<u8>, [u8; 32]) {
    let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let public = key.public_key().as_der().unwrap().as_ref().to_vec();
    (
        Zeroizing::new(key.as_der().unwrap().as_ref().to_vec()),
        public.clone(),
        sha256_digest(&public),
    )
}

fn pair(
    meta: KeyVersion,
    private: &[u8],
    public: &[u8],
    pin: [u8; 32],
) -> (PublicDeliveryKey, PrivateKeyRing) {
    (
        PublicDeliveryKey::new(meta.clone(), public, pin).unwrap(),
        PrivateKeyRing::new(vec![PrivateDeliveryKey::new(
            meta,
            Zeroizing::new(private.to_vec()),
            pin,
        )
        .unwrap()])
        .unwrap(),
    )
}

#[test]
fn roundtrip_binds_explicit_installation_environment_domain_and_organization_scopes() {
    let (private, public, pin) = material();
    let scopes = [
        Scope::Installation,
        Scope::Environment {
            environment_id: id(4),
        },
        Scope::Domain {
            environment_id: id(4),
            domain_id: id(5),
        },
        context().scope,
    ];
    for scope in scopes {
        let mut context = context();
        context.organization_generation = if matches!(scope, Scope::Organization { .. }) {
            Revision::Value(1)
        } else {
            Revision::NotApplicable
        };
        context.scope = scope.clone();
        let mut meta = version("key_1");
        meta.scope = scope;
        let (producer, worker) = pair(meta, &private, &public, pin);
        let jwe = producer.seal(&context, PAYLOAD, NOW).unwrap();
        let opened: Zeroizing<Vec<u8>> = worker.open("key_1", &context, &jwe, NOW).unwrap();
        assert_eq!(opened.as_slice(), PAYLOAD);
        assert_eq!(jwe.split('.').count(), 5);
        assert!(jwe.len() <= MAX_ENVELOPE_BYTES);
    }
}

#[test]
fn standard_jwe_segments_interoperate_with_direct_provider_operations() {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let (private, public, pin) = material();
    let context = context();
    let (producer, worker) = pair(version("key_1"), &private, &public, pin);
    let wire = producer.seal(&context, PAYLOAD, NOW).unwrap();
    let s: Vec<_> = wire.split('.').collect();
    let h: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s[0]).unwrap()).unwrap();
    assert_eq!(h["alg"], "RSA-OAEP-256");
    assert_eq!(h["enc"], "A256GCM");
    assert_eq!(h["kid"], "key_1");
    assert_eq!(h["typ"], TYPE);
    assert_eq!(h["crit"], serde_json::json!([PROFILE]));
    assert_eq!(
        h[PROFILE]["context"],
        serde_json::to_value(&context).unwrap()
    );
    let pk = PrivateDecryptingKey::from_pkcs8(&private).unwrap();
    let public_oaep = OaepPublicEncryptingKey::new(pk.public_key()).unwrap();
    let private_oaep = OaepPrivateDecryptingKey::new(pk).unwrap();
    let mut cek_buf = Zeroizing::new(vec![0; private_oaep.min_output_size()]);
    let wrapped = URL_SAFE_NO_PAD.decode(s[1]).unwrap();
    let cek = private_oaep
        .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut cek_buf, None)
        .unwrap();
    assert_eq!(cek.len(), 32);
    let aes = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, cek).unwrap());
    let iv: [u8; 12] = URL_SAFE_NO_PAD.decode(s[2]).unwrap().try_into().unwrap();
    let mut body = Zeroizing::new(URL_SAFE_NO_PAD.decode(s[3]).unwrap());
    body.extend_from_slice(&URL_SAFE_NO_PAD.decode(s[4]).unwrap());
    assert_eq!(
        aes.open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(s[0].as_bytes()),
            &mut body
        )
        .unwrap(),
        PAYLOAD
    );

    // Independently seal with the standard provider, using the admitted profile
    // header bytes and a fresh CEK/IV, without calling the application seal.
    let fresh = Zeroizing::new(random_bytes(32));
    let mut iv = [0; 12];
    fill_random(&mut iv).unwrap();
    let mut wrapped = vec![0; public_oaep.ciphertext_size()];
    let wrapped = public_oaep
        .encrypt(&OAEP_SHA256_MGF1SHA256, fresh.as_ref(), &mut wrapped, None)
        .unwrap();
    let aes = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, fresh.as_ref()).unwrap());
    let mut body = Zeroizing::new(PAYLOAD.to_vec());
    aes.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(iv),
        Aad::from(s[0].as_bytes()),
        &mut *body,
    )
    .unwrap();
    let cut = body.len() - 16;
    let independent = format!(
        "{}.{}.{}.{}.{}",
        s[0],
        URL_SAFE_NO_PAD.encode(wrapped),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&body[..cut]),
        URL_SAFE_NO_PAD.encode(&body[cut..])
    );
    assert_eq!(
        worker
            .open("key_1", &context, &independent, NOW)
            .unwrap()
            .as_slice(),
        PAYLOAD
    );
}

#[test]
fn every_expected_message_binding_is_authenticated_including_absent_vs_zero_revision() {
    let (private, public, pin) = material();
    let original = context();
    let (producer, worker) = pair(version("key_1"), &private, &public, pin);
    let wire = producer.seal(&original, PAYLOAD, NOW).unwrap();
    for field in 0..18 {
        let mut other = original.clone();
        match field {
            0 => other.message_id = id(99),
            1 => other.deployment_id = id(99),
            2 => other.runtime_generation = id(99),
            3 => {
                other.scope = Scope::Organization {
                    environment_id: id(99),
                    domain_id: id(5),
                    organization_id: id(6),
                }
            }
            4 => {
                other.scope = Scope::Organization {
                    environment_id: id(4),
                    domain_id: id(99),
                    organization_id: id(6),
                }
            }
            5 => {
                other.scope = Scope::Organization {
                    environment_id: id(4),
                    domain_id: id(5),
                    organization_id: id(99),
                }
            }
            6 => other.organization_generation = Revision::Value(2),
            7 => other.purpose = "recovery".into(),
            8 => other.template = "another_template".into(),
            9 => other.template_version = 2,
            10 => other.expires_at += 1,
            11 => other.authority_revision = Revision::NotApplicable,
            12 => other.contact_revision = Revision::Value(0),
            13 => other.configuration_revision = Revision::Value(2),
            14 => other.authority_binding[0] ^= 1,
            15 => other.destination_binding[0] ^= 1,
            16 => other.payload_digest[0] ^= 1,
            _ => {
                other.scope = Scope::Environment {
                    environment_id: id(4),
                };
                other.organization_generation = Revision::NotApplicable;
            }
        }
        assert!(
            worker.open("key_1", &other, &wire, NOW).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn rejects_header_changes_and_malformed_or_corrupted_compact_components() {
    let (private, public, pin) = material();
    let context = context();
    let (producer, worker) = pair(version("key_1"), &private, &public, pin);
    let wire = producer.seal(&context, PAYLOAD, NOW).unwrap();
    let segments: Vec<_> = wire.split('.').map(str::to_owned).collect();
    let header = String::from_utf8(URL_SAFE_NO_PAD.decode(&segments[0]).unwrap()).unwrap();
    for header in [
        header.replace("RSA-OAEP-256", "RSA-OAEP"),
        header.replace("A256GCM", "A128GCM"),
        header.replace("key_1", "key_2"),
        header.replace(TYPE, "JWT"),
        header.replace("\"crit\"", "\"unknown\""),
        header.replacen('{', "{\"alg\":\"RSA-OAEP-256\",", 1),
        header.replacen('{', "{\"unknown\":true,", 1),
        format!(" {header}"),
        header.replace(
            &URL_SAFE_NO_PAD.encode(pin),
            &URL_SAFE_NO_PAD.encode([9; 32]),
        ),
    ] {
        let mut s = segments.clone();
        s[0] = URL_SAFE_NO_PAD.encode(header);
        assert_eq!(
            worker
                .open("key_1", &context, &s.join("."), NOW)
                .unwrap_err(),
            Error::OpenFailed
        );
    }
    for n in 1..5 {
        let mut s = segments.clone();
        let mut bytes = URL_SAFE_NO_PAD.decode(&s[n]).unwrap();
        bytes[0] ^= 1;
        s[n] = URL_SAFE_NO_PAD.encode(bytes);
        assert!(worker.open("key_1", &context, &s.join("."), NOW).is_err());
        let mut s = segments.clone();
        s[n].push('=');
        assert!(worker.open("key_1", &context, &s.join("."), NOW).is_err());
    }
    for malformed in [
        segments[..4].join("."),
        format!("{wire}.extra"),
        ".".repeat(MAX_ENVELOPE_BYTES + 1),
        String::new(),
    ] {
        assert!(worker.open("key_1", &context, &malformed, NOW).is_err());
    }
    for (segment, size) in [
        (0, MAX_HEADER_BYTES + 1),
        (1, 1025),
        (2, 13),
        (3, MAX_PAYLOAD_BYTES + 1),
        (4, 17),
    ] {
        let mut s = segments.clone();
        s[segment] = URL_SAFE_NO_PAD.encode(vec![0; size]);
        assert!(worker.open("key_1", &context, &s.join("."), NOW).is_err());
    }
}

#[test]
fn enforces_payload_context_key_and_unwrapped_cek_bounds() {
    let (private, public, pin) = material();
    let mut context = context();
    let (producer, worker) = pair(version("key_1"), &private, &public, pin);
    for size in [0, MAX_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES + 1] {
        let payload = Zeroizing::new(vec![0x5a; size]);
        context.payload_digest = sha256_digest(&payload);
        let sealed = producer.seal(&context, &payload, NOW);
        if size <= MAX_PAYLOAD_BYTES {
            assert_eq!(
                worker
                    .open("key_1", &context, &sealed.unwrap(), NOW)
                    .unwrap()
                    .as_slice(),
                payload.as_slice()
            );
        } else {
            assert_eq!(sealed.unwrap_err(), Error::InvalidInput);
        }
    }
    context.payload_digest = sha256_digest(PAYLOAD);
    assert_eq!(
        producer
            .seal(&context, b"different payload", NOW)
            .unwrap_err(),
        Error::InvalidInput
    );
    for invalid in [
        "".to_owned(),
        "a".repeat(65),
        "bad.name".into(),
        "récovery".into(),
    ] {
        let mut c = context.clone();
        c.purpose = invalid.clone();
        assert!(producer.seal(&c, PAYLOAD, NOW).is_err());
        c = context.clone();
        c.template = invalid.clone();
        assert!(producer.seal(&c, PAYLOAD, NOW).is_err());
        let mut meta = version("key_1");
        meta.id = invalid;
        assert!(PublicDeliveryKey::new(meta, &public, pin).is_err());
    }
    let mut c = context.clone();
    c.authority_revision = Revision::Value(-1);
    assert!(producer.seal(&c, PAYLOAD, NOW).is_err());
    c = context.clone();
    c.message_id = Uuid::nil();
    assert!(producer.seal(&c, PAYLOAD, NOW).is_err());
    c = context.clone();
    c.organization_generation = Revision::Value(0);
    assert!(producer.seal(&c, PAYLOAD, NOW).is_err());
    assert!(PublicDeliveryKey::new(version("key_1"), &vec![0; 2049], pin).is_err());
    assert!(PrivateDeliveryKey::new(version("key_1"), Zeroizing::new(vec![0; 8193]), pin).is_err());
    let wire = producer.seal(&context, PAYLOAD, NOW).unwrap();
    for size in [31, 33] {
        let mut s: Vec<_> = wire.split('.').map(str::to_owned).collect();
        s[1] = URL_SAFE_NO_PAD.encode(jwe::rsa_oaep_256_wrap(&public, &vec![0x5a; size]).unwrap());
        assert_eq!(
            worker
                .open("key_1", &context, &s.join("."), NOW)
                .unwrap_err(),
            Error::OpenFailed
        );
    }
}

#[test]
fn key_selection_scope_fingerprint_retirement_and_time_are_fail_closed() {
    let (private, public, pin) = material();
    let context = context();
    let (producer, worker) = pair(version("key_1"), &private, &public, pin);
    let wire = producer.seal(&context, PAYLOAD, NOW).unwrap();
    for time in [-1, 4, 100] {
        assert!(producer.seal(&context, PAYLOAD, time).is_err());
    }
    assert_eq!(
        worker
            .open("key_1", &context, &wire, 100)
            .unwrap()
            .as_slice(),
        PAYLOAD
    );
    assert!(worker.open("key_1", &context, &wire, 180).is_err());
    assert_eq!(
        worker.open("missing", &context, &wire, NOW).unwrap_err(),
        Error::KeyUnavailable
    );
    assert_eq!(
        PrivateKeyRing::new(vec![])
            .unwrap()
            .open("key_1", &context, &wire, NOW)
            .unwrap_err(),
        Error::KeyUnavailable
    );
    let mut pin_bad = pin;
    pin_bad[0] ^= 1;
    assert!(PublicDeliveryKey::new(version("key_1"), &public, pin_bad).is_err());
    assert!(
        PrivateDeliveryKey::new(version("key_1"), Zeroizing::new(private.to_vec()), pin_bad)
            .is_err()
    );
    let (other, _, _) = material();
    assert!(PrivateDeliveryKey::new(version("key_1"), other, pin).is_err());
    let mut retired = version("key_1");
    retired.seal_until = 6;
    retired.open_until = 7;
    let (_, retired) = pair(retired, &private, &public, pin);
    assert_eq!(
        retired.open("key_1", &context, &wire, NOW).unwrap_err(),
        Error::KeyUnavailable
    );
    let mut unrelated = version("key_1");
    unrelated.scope = Scope::Installation;
    let (unrelated, _) = pair(unrelated, &private, &public, pin);
    assert_eq!(
        unrelated.seal(&context, PAYLOAD, NOW).unwrap_err(),
        Error::KeyUnavailable
    );
    let mut meta = version("key_1");
    meta.deployment_id = id(99);
    assert_eq!(
        pair(meta, &private, &public, pin)
            .1
            .open("key_1", &context, &wire, NOW)
            .unwrap_err(),
        Error::KeyUnavailable
    );
}

#[test]
fn duplicate_and_excess_key_versions_are_rejected_without_fallback() {
    let (private, _, pin) = material();
    let keys = (0..2)
        .map(|_| {
            PrivateDeliveryKey::new(version("duplicate"), Zeroizing::new(private.to_vec()), pin)
                .unwrap()
        })
        .collect();
    assert!(PrivateKeyRing::new(keys).is_err());
    let keys = (0..17)
        .map(|i| {
            PrivateDeliveryKey::new(
                version(&format!("key_{i}")),
                Zeroizing::new(private.to_vec()),
                pin,
            )
            .unwrap()
        })
        .collect();
    assert!(PrivateKeyRing::new(keys).is_err());
}

#[test]
fn explicit_reseal_changes_key_version_but_preserves_logical_payload_and_proof() {
    let (private, public, pin) = material();
    let (old, old_ring) = pair(version("old"), &private, &public, pin);
    let (new_private, new_public, new_pin) = material();
    let (new, new_ring) = pair(version("new"), &new_private, &new_public, new_pin);
    let context = context();
    let before = old.seal(&context, PAYLOAD, NOW).unwrap();
    let recovered = old_ring.open("old", &context, &before, NOW).unwrap();
    let after = new.seal(&context, &recovered, NOW).unwrap();
    assert_ne!(before, after);
    assert_eq!(
        new_ring
            .open("new", &context, &after, NOW)
            .unwrap()
            .as_slice(),
        PAYLOAD
    );
    assert!(new_ring.open("new", &context, &before, NOW).is_err());
    assert!(old_ring.open("old", &context, &after, NOW).is_err());
}

#[test]
fn v1_protected_header_is_stable_and_opens_independently_sealed_fixture() {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    // Persisted v1 headers are exact bytes. Keep this independent of Serialize;
    // changing field order or representation requires a profile migration.
    const PIN: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
    const GOLDEN: &str = concat!(
        r#"{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"key_1","typ":"application/aegaeon-notification+jwe","crit":["https://github.com/codetakt/aegaeon/spec/notification-envelope/v1"],"https://github.com/codetakt/aegaeon/spec/notification-envelope/v1":{"context":{"message_id":"00000000-0000-0000-0000-000000000001","deployment_id":"00000000-0000-0000-0000-000000000002","runtime_generation":"00000000-0000-0000-0000-000000000003","scope":{"kind":"organization","environment_id":"00000000-0000-0000-0000-000000000004","domain_id":"00000000-0000-0000-0000-000000000005","organization_id":"00000000-0000-0000-0000-000000000006"},"organization_generation":{"kind":"value","value":1},"purpose":"invitation","template":"first_admin","template_version":1,"expires_at":180,"authority_revision":{"kind":"value","value":0},"contact_revision":{"kind":"not_applicable"},"configuration_revision":{"kind":"value","value":1},"authority_binding":["#,
        "7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7",
        r#"],"destination_binding":["#,
        "8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8",
        r#"],"payload_digest":[193,248,125,132,12,146,198,149,111,1,117,1,179,212,109,87,236,160,239,199,36,243,144,107,8,212,164,77,129,5,180,32]},"spki_sha256":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"}}"#,
    );
    let context = context();
    let generated = protected(&context, "key_1", &[9; 32]).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.decode(generated).unwrap(),
        GOLDEN.as_bytes()
    );

    // Only the ephemeral key's public fingerprint changes in the hand-written
    // fixture. Neither application seal nor protected-header serialization builds
    // these AAD bytes. The actual provider constructs all encrypted segments.
    let (private, public, pin) = material();
    let (_, worker) = pair(version("key_1"), &private, &public, pin);
    let header = URL_SAFE_NO_PAD.encode(GOLDEN.replace(PIN, &URL_SAFE_NO_PAD.encode(pin)));
    let rsa = OaepPublicEncryptingKey::new(
        aws_lc_rs::rsa::PublicEncryptingKey::from_der(&public).unwrap(),
    )
    .unwrap();
    let cek = Zeroizing::new(random_bytes(32));
    let mut iv = [0; 12];
    fill_random(&mut iv).unwrap();
    let mut wrapped = vec![0; rsa.ciphertext_size()];
    let wrapped = rsa
        .encrypt(&OAEP_SHA256_MGF1SHA256, cek.as_ref(), &mut wrapped, None)
        .unwrap();
    let aes = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, cek.as_ref()).unwrap());
    let mut body = Zeroizing::new(PAYLOAD.to_vec());
    aes.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(iv),
        Aad::from(header.as_bytes()),
        &mut *body,
    )
    .unwrap();
    let cut = body.len() - 16;
    let fixture = format!(
        "{}.{}.{}.{}.{}",
        header,
        URL_SAFE_NO_PAD.encode(wrapped),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&body[..cut]),
        URL_SAFE_NO_PAD.encode(&body[cut..]),
    );
    assert_eq!(
        worker
            .open("key_1", &context, &fixture, NOW)
            .unwrap()
            .as_slice(),
        PAYLOAD
    );
}
