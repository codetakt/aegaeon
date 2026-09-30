//! Observable key consumption and AES-256-GCM known-answer vectors.
//!
//! No test reads freed memory or claims to inspect provider-internal cleanup.
use aegaeon_crypto::jwe::{decrypt_a256gcm, encrypt_a256gcm, rsa_oaep_unwrap};
use aegaeon_crypto::CryptoError;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeySize, OaepPublicEncryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1};

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("public vector hex"))
        .collect()
}

#[test]
fn aes256_gcm_known_answer_vectors_and_empty_plaintext() {
    let vectors = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        ),
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            concat!(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
                "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
            ),
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            concat!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b"
            ),
        ),
    ];
    for (key, nonce, plaintext, aad, expected) in vectors {
        let key = hex(key);
        let nonce: [u8; 12] = hex(nonce).try_into().expect("96-bit vector IV");
        let plaintext = hex(plaintext);
        let aad = hex(aad);
        let expected = hex(expected);
        let encrypted = encrypt_a256gcm(&key, &nonce, &plaintext, &aad).expect("vector seal");
        assert_eq!(encrypted, expected);
        let split = expected.len() - 16;
        let mut cek = key.clone();
        let opened = decrypt_a256gcm(
            &mut cek,
            &nonce,
            &expected[..split],
            &expected[split..],
            &aad,
        )
        .expect("vector open");
        assert_eq!(opened, plaintext);
        assert!(cek.iter().all(|byte| *byte == 0));
        // The borrowed immutable input remains owned by the caller.
        assert_eq!(encrypted.len(), plaintext.len() + 16);
    }
}

#[test]
fn key_and_iv_validation_errors_consume_cek() {
    for key_length in [0, 1, 16, 24, 31, 33, 64] {
        let mut cek = vec![0xa5; key_length];
        let result = decrypt_a256gcm(&mut cek, &[0; 12], &[], &[0; 16], &[]);
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
        assert!(cek.iter().all(|byte| *byte == 0));
        assert!(matches!(
            encrypt_a256gcm(&vec![0xa5; key_length], &[0; 12], b"input", &[]),
            Err(CryptoError::InvalidKey(_))
        ));
    }
    for iv_length in [0, 1, 11, 13, 32] {
        let mut cek = [0xa5; 32];
        let result = decrypt_a256gcm(&mut cek, &vec![0; iv_length], &[], &[0; 16], &[]);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
        assert_eq!(cek, [0; 32]);
    }
}

#[test]
fn authentication_errors_consume_cek_for_every_authenticated_input() {
    let key = [0xa5; 32];
    let nonce = [0x12; 12];
    let aad = b"expected scope";
    let bytes = encrypt_a256gcm(&key, &nonce, b"owned plaintext", aad).expect("seal");
    let split = bytes.len() - 16;
    for modified in 0..5 {
        let mut cek = key;
        let mut test_nonce = nonce;
        let mut ciphertext = bytes[..split].to_vec();
        let mut tag = bytes[split..].to_vec();
        let mut test_aad = aad.to_vec();
        match modified {
            0 => cek[0] ^= 1,
            1 => test_nonce[0] ^= 1,
            2 => ciphertext[0] ^= 1,
            3 => tag[0] ^= 1,
            _ => test_aad[0] ^= 1,
        }
        let result = decrypt_a256gcm(&mut cek, &test_nonce, &ciphertext, &tag, &test_aad);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
        assert_eq!(cek, [0; 32]);
    }
}

#[test]
fn rsa_unwrap_preserves_plaintext_domain_and_rejects_invalid_inputs() {
    // Generate a fresh RSA key in memory for this test.
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("test RSA key");
    let public = OaepPublicEncryptingKey::new(private.public_key()).expect("OAEP public key");
    let pkcs8 = private.as_der().expect("test PKCS8");
    for plaintext in [vec![], vec![0xa5; 32], vec![0x17; 214]] {
        let mut output = vec![0; public.ciphertext_size()];
        let encrypted = public
            .encrypt(&OAEP_SHA1_MGF1SHA1, &plaintext, &mut output, None)
            .expect("test OAEP seal");
        assert_eq!(
            rsa_oaep_unwrap(pkcs8.as_ref(), encrypted).expect("unwrap"),
            plaintext
        );
        let truncated = &encrypted[..encrypted.len() - 1];
        assert!(matches!(
            rsa_oaep_unwrap(pkcs8.as_ref(), truncated),
            Err(CryptoError::DecryptionFailed(_))
        ));
        encrypted[0] ^= 1;
        assert!(matches!(
            rsa_oaep_unwrap(pkcs8.as_ref(), encrypted),
            Err(CryptoError::DecryptionFailed(_))
        ));
    }
    assert!(matches!(
        rsa_oaep_unwrap(b"invalid PKCS8", &[0; 256]),
        Err(CryptoError::InvalidKey(_))
    ));
}
