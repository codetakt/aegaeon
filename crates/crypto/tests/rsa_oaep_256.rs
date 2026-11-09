//! Provider-backed public sealing and private opening, without deployment claims.

use aegaeon_crypto::jwe::{
    decrypt_a256gcm, encrypt_a256gcm, rsa_oaep_256_unwrap, rsa_oaep_256_wrap, rsa_oaep_unwrap,
};
use aegaeon_crypto::CryptoError;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256,
};
use zeroize::Zeroizing;

fn keys() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("ephemeral test RSA key");
    let public = private.public_key().as_der().expect("public SPKI");
    let private = private.as_der().expect("private PKCS8");
    (
        Zeroizing::new(private.as_ref().to_vec()),
        public.as_ref().to_vec(),
    )
}

#[test]
fn public_only_wrap_private_open_and_oaep_size_boundary() {
    let (private, public) = keys();
    // RSA2048 OAEP-SHA256 permits k - 2*hLen - 2 = 190 bytes.
    for len in [0, 32, 190] {
        let plaintext = vec![0xa5; len];
        let ciphertext = rsa_oaep_256_wrap(&public, &plaintext).expect("public-only seal");
        assert_eq!(ciphertext.len(), 256);
        assert_eq!(
            rsa_oaep_256_unwrap(&private, &ciphertext).expect("private open"),
            plaintext
        );
        assert_eq!(plaintext, vec![0xa5; len]);
    }
    assert!(matches!(
        rsa_oaep_256_wrap(&public, &[0xa5; 191]),
        Err(CryptoError::EncryptionFailed(_))
    ));
}

#[test]
fn rejects_private_material_at_public_api_and_public_material_at_private_api() {
    let (private, public) = keys();
    for invalid_public in [&[][..], b"not DER", private.as_slice()] {
        assert!(matches!(
            rsa_oaep_256_wrap(invalid_public, &[0xa5; 32]),
            Err(CryptoError::InvalidKey(_))
        ));
    }
    for invalid_private in [&[][..], b"not DER", public.as_slice()] {
        assert!(matches!(
            rsa_oaep_256_unwrap(invalid_private, &[0; 256]),
            Err(CryptoError::InvalidKey(_))
        ));
    }
}

#[test]
fn rejects_wrong_private_key_and_invalid_ciphertext() {
    let (private, public) = keys();
    let (other_private, _) = keys();
    let ciphertext = rsa_oaep_256_wrap(&public, &[0xa5; 32]).expect("seal");
    assert!(matches!(
        rsa_oaep_256_unwrap(&other_private, &ciphertext),
        Err(CryptoError::DecryptionFailed(_))
    ));
    let mut corrupted = ciphertext.clone();
    corrupted[0] ^= 1;
    let mut extended = ciphertext.clone();
    extended.push(0);
    for invalid in [&[][..], &ciphertext[..255], &corrupted, &extended] {
        assert!(matches!(
            rsa_oaep_256_unwrap(&private, invalid),
            Err(CryptoError::DecryptionFailed(_))
        ));
    }
}

#[test]
fn fixed_profile_interoperates_with_provider_without_sha1_or_label_fallback() {
    let (private, public) = keys();
    let provider_private = PrivateDecryptingKey::from_pkcs8(&private).expect("private key");
    let provider_public =
        OaepPublicEncryptingKey::new(provider_private.public_key()).expect("provider public key");
    let provider_private =
        OaepPrivateDecryptingKey::new(provider_private).expect("provider private key");
    let plaintext = [0xa5; 32];
    let ciphertext = rsa_oaep_256_wrap(&public, &plaintext).expect("facade seal");
    let mut opened = Zeroizing::new(vec![0; provider_private.min_output_size()]);
    assert_eq!(
        provider_private
            .decrypt(&OAEP_SHA256_MGF1SHA256, &ciphertext, &mut opened, None)
            .expect("provider open"),
        plaintext
    );
    assert!(matches!(
        rsa_oaep_unwrap(&private, &ciphertext),
        Err(CryptoError::DecryptionFailed(_))
    ));
    for (algorithm, label, accepted) in [
        (&OAEP_SHA256_MGF1SHA256, None, true),
        (&OAEP_SHA1_MGF1SHA1, None, false),
        (
            &OAEP_SHA256_MGF1SHA256,
            Some(b"other domain".as_slice()),
            false,
        ),
    ] {
        let mut output = vec![0; provider_public.ciphertext_size()];
        let encrypted = provider_public
            .encrypt(algorithm, &plaintext, &mut output, label)
            .expect("provider seal");
        let result = rsa_oaep_256_unwrap(&private, encrypted);
        if accepted {
            assert_eq!(result.expect("facade open"), plaintext);
        } else {
            assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
        }
    }
}

#[test]
fn public_wrapped_cek_opens_authenticated_payload_and_rejects_changed_context() {
    let (private, public) = keys();
    let cek = Zeroizing::new(aegaeon_crypto::rand::random_bytes(32));
    let mut nonce = [0; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce).expect("fresh test nonce");
    // Illustrative context bytes only; application encoding/version policy is
    // not implemented or qualified by this primitive composition test.
    let aad = b"test-delivery:v1:message=1:purpose=invite:key=v1";
    let plaintext = b"one stable logical message with one proof";
    let ciphertext = encrypt_a256gcm(&cek, &nonce, plaintext, aad).expect("seal payload");
    let wrapped = rsa_oaep_256_wrap(&public, &cek).expect("public-only wrap CEK");
    let split = ciphertext.len() - 16;
    for context in [
        aad.as_slice(),
        b"test-delivery:v1:message=2:purpose=invite:key=v1",
    ] {
        let mut unwrapped = rsa_oaep_256_unwrap(&private, &wrapped).expect("private-only unwrap");
        assert_eq!(unwrapped.len(), 32);
        let result = decrypt_a256gcm(
            &mut unwrapped,
            &nonce,
            &ciphertext[..split],
            &ciphertext[split..],
            context,
        );
        assert!(unwrapped.iter().all(|byte| *byte == 0));
        if context == aad {
            assert_eq!(result.expect("matching context"), plaintext);
        } else {
            assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
        }
    }
}
