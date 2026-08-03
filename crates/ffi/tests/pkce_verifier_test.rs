use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ffi::verify_pkce;
use sha2::{Digest, Sha256};

#[test]
fn valid_pair_passes_verification() {
    let verifier = "correct horse battery staple";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert!(verify_pkce(verifier, &challenge));
}

#[test]
fn invalid_pair_fails_verification() {
    let verifier = "foo";
    // challenge derived from a different verifier
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(b"bar"));
    assert!(!verify_pkce(verifier, &challenge));
}
