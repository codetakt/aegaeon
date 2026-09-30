//! Exercise the public wrapper against the selected native or compatibility
//! backend. Unlike lib unit tests, integration builds do not set cfg(test) in ffi.
use ffi::{encrypt_chacha20poly1305, verify_decrypt_jwe};

#[test]
fn rejects_short_ciphertext_or_tag_without_writes() {
    let key = [7; 32];
    let nonce = [3; 12];
    let plaintext = [0x42; 32];
    for plaintext_len in [0, 1, 15, 16, 17, 31, 32] {
        for ciphertext_len in [0, 1, 15, 16, 17, 31, 32] {
            for tag_len in 0..=17 {
                if ciphertext_len >= plaintext_len && tag_len >= 16 {
                    continue;
                }
                let mut ciphertext = [0xa5; 32];
                let mut tag = [0x5a; 17];
                assert!(!encrypt_chacha20poly1305(
                    &key,
                    &nonce,
                    b"bound-aad",
                    &plaintext[..plaintext_len],
                    &mut ciphertext[..ciphertext_len],
                    &mut tag[..tag_len],
                ));
                assert_eq!(ciphertext, [0xa5; 32]);
                assert_eq!(tag, [0x5a; 17]);
            }
        }
    }
}

#[test]
fn rejects_invalid_key_or_nonce_without_writes() {
    let key = [7; 33];
    let nonce = [3; 13];
    for key_len in [0, 31, 32, 33] {
        for nonce_len in [0, 11, 12, 13] {
            if key_len == 32 && nonce_len == 12 {
                continue;
            }
            let mut ciphertext = [0xa5; 3];
            let mut tag = [0x5a; 16];
            assert!(!encrypt_chacha20poly1305(
                &key[..key_len],
                &nonce[..nonce_len],
                &[],
                b"abc",
                &mut ciphertext,
                &mut tag,
            ));
            assert_eq!(ciphertext, [0xa5; 3]);
            assert_eq!(tag, [0x5a; 16]);
        }
    }
}

#[test]
fn encrypts_empty_and_nonempty_inputs_without_touching_output_tails() {
    let key = [7; 32];
    let nonce = [3; 12];
    let plaintext = [0x42; 65];
    for len in [0, 1, 15, 16, 17, 63, 64, 65] {
        for aad in [&[][..], &b"bound-aad"[..]] {
            let mut ciphertext = [0xa5; 66];
            let mut tag = [0x5a; 17];
            assert!(encrypt_chacha20poly1305(
                &key,
                &nonce,
                aad,
                &plaintext[..len],
                &mut ciphertext,
                &mut tag,
            ));
            assert_eq!(&ciphertext[len..], &[0xa5; 66][len..]);
            assert_eq!(tag[16], 0x5a);
            assert_eq!(
                verify_decrypt_jwe(&key, &nonce, aad, &ciphertext[..len], &tag[..16]),
                Some(plaintext[..len].to_vec())
            );
            tag[0] ^= 1;
            assert!(
                verify_decrypt_jwe(&key, &nonce, aad, &ciphertext[..len], &tag[..16]).is_none()
            );
        }
    }
}

#[test]
fn matches_rfc8439_aead_vector() {
    // RFC 8439 section 2.8.2; fixed data with no application credentials.
    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |c: u8| match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    _ => panic!("invalid test-vector digit"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }
    let key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = bytes("070000004041424344454647");
    let aad = bytes("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut ciphertext = vec![0; plaintext.len()];
    let mut tag = [0; 16];
    assert!(encrypt_chacha20poly1305(
        &key,
        &nonce,
        &aad,
        plaintext,
        &mut ciphertext,
        &mut tag
    ));
    assert_eq!(
        ciphertext,
        bytes(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3",
            "ff4def08e4b7a9de576d26586cec64b6116"
        ))
    );
    assert_eq!(tag.as_slice(), bytes("1ae10b594f09e26a7e902ecbd0600691"));
}
