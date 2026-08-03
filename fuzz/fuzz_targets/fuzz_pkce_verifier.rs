#![forbid(unsafe_code)]
#![no_main]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ffi::verify_pkce;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

const PKCE_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn project_to_valid_pkce_verifier(data: &[u8]) -> String {
    let len = if data.is_empty() {
        43
    } else {
        43 + (data.len() % 86)
    };

    let mut verifier = String::with_capacity(len);
    for index in 0..len {
        let byte = data.get(index % data.len().max(1)).copied().unwrap_or(0);
        verifier.push(PKCE_ALPHABET[(byte as usize) % PKCE_ALPHABET.len()] as char);
    }
    verifier
}

fuzz_target!(|data: &[u8]| {
    let verifier = String::from_utf8_lossy(data).into_owned();

    // Happy-path: a verifier projected into the RFC 7636 alphabet/length window must validate.
    let valid_verifier = project_to_valid_pkce_verifier(data);
    let expected_challenge = challenge_for(&valid_verifier);
    assert!(verify_pkce(&valid_verifier, &expected_challenge));

    // Cross-check with a reversed verifier string to exercise mismatch paths.
    if !data.is_empty() {
        let mut reversed = data.to_vec();
        reversed.reverse();
        let reversed_verifier = String::from_utf8_lossy(&reversed).into_owned();
        let reversed_challenge = challenge_for(&reversed_verifier);
        let _ = verify_pkce(&verifier, &reversed_challenge);
        let _ = verify_pkce(&reversed_verifier, &expected_challenge);
    }

    // Arbitrary challenges produced directly from fuzz bytes must not panic.
    let arbitrary_challenge = URL_SAFE_NO_PAD.encode(data);
    let _ = verify_pkce(&verifier, &arbitrary_challenge);

    // Truncate to PKCE nominal length window to stress near-boundary inputs.
    let truncated_verifier = verifier.chars().take(128).collect::<String>();
    let truncated_challenge = challenge_for(&truncated_verifier);
    let _ = verify_pkce(&truncated_verifier, &truncated_challenge);
});
