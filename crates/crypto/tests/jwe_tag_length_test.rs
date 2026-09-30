//! The detached AES-256-GCM tag must contain exactly 16 bytes.
use aegaeon_crypto::jwe::{decrypt_a256gcm, encrypt_a256gcm};
use aegaeon_crypto::CryptoError;

#[test]
fn moving_bytes_between_ciphertext_and_tag_is_rejected() {
    let key = [0x42; 32];
    let nonce = [0x17; 12];
    let aad = b"message context";
    let plaintext = b"detached authentication tag";
    let sealed = encrypt_a256gcm(&key, &nonce, plaintext, aad).expect("seal");
    // Every split preserves the concatenated authenticated bytes. Only the
    // split with a 16-byte detached tag is a valid API input.
    for split in 0..=sealed.len() {
        let mut cek = key;
        let result = decrypt_a256gcm(&mut cek, &nonce, &sealed[..split], &sealed[split..], aad);
        assert_eq!(cek, [0; 32]);
        if sealed.len() - split == 16 {
            assert_eq!(result.expect("valid detached tag"), plaintext);
        } else {
            assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
        }
    }
}

#[test]
fn empty_plaintext_still_requires_a_complete_tag() {
    let key = [0; 32];
    let nonce = [0; 12];
    // AES-256-GCM known-answer vector for an empty message and empty AAD.
    let tag = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];
    let mut cek = key;
    assert_eq!(
        decrypt_a256gcm(&mut cek, &nonce, &[], &tag, &[]).expect("empty message"),
        Vec::<u8>::new()
    );
    assert_eq!(cek, [0; 32]);
    for length in 0..16 {
        let mut cek = key;
        assert!(matches!(
            decrypt_a256gcm(&mut cek, &nonce, &[], &tag[..length], &[]),
            Err(CryptoError::DecryptionFailed(_))
        ));
        assert_eq!(cek, [0; 32]);
    }
    let mut extended_tag = tag.to_vec();
    extended_tag.push(0);
    let mut cek = key;
    assert!(matches!(
        decrypt_a256gcm(&mut cek, &nonce, &[], &extended_tag, &[]),
        Err(CryptoError::DecryptionFailed(_))
    ));
    assert_eq!(cek, [0; 32]);
}
