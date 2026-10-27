use aegaeon_crypto::{
    signature::verify_rsa_pkcs1_sha256_components, signing::RsaPkcs1Sha256Signer,
};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
use aws_lc_rs::signature::KeyPair as _;

#[test]
fn imported_rsa_pkcs1_key_signs_exact_message_and_rejects_tampering() {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("RSA fixture");
    let der = private.as_der().expect("PKCS8 fixture");
    let signer = RsaPkcs1Sha256Signer::from_pkcs8(der.as_ref()).expect("import");
    let independent =
        aws_lc_rs::signature::RsaKeyPair::from_pkcs8(der.as_ref()).expect("reference");
    assert_eq!(signer.public_key_der(), independent.public_key().as_ref());
    let public = independent.public_key();
    let modulus = public.modulus();
    let exponent = public.exponent();
    let n = modulus.big_endian_without_leading_zero();
    let e = exponent.big_endian_without_leading_zero();
    for message in [b"".as_slice(), b"introspection.header.payload"] {
        let signature = signer.sign(message).expect("sign");
        assert_eq!(signature.len(), 256);
        verify_rsa_pkcs1_sha256_components(n, e, message, &signature).expect("components verify");
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            independent.public_key().as_ref(),
        )
        .verify(message, &signature)
        .expect("independent provider verification");
        assert!(verify_rsa_pkcs1_sha256_components(n, e, b"changed message", &signature).is_err());
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(verify_rsa_pkcs1_sha256_components(n, e, message, &changed).is_err());
        assert!(verify_rsa_pkcs1_sha256_components(n, e, message, &signature[..255]).is_err());
        assert!(verify_rsa_pkcs1_sha256_components(&[], e, message, &signature).is_err());
        assert!(verify_rsa_pkcs1_sha256_components(n, &[0], message, &signature).is_err());
    }
    assert!(RsaPkcs1Sha256Signer::from_pkcs8(b"malformed key").is_err());
    let ed25519 = aegaeon_crypto::signing::Ed25519SigningKey::generate().expect("Ed25519 fixture");
    assert!(RsaPkcs1Sha256Signer::from_pkcs8(&ed25519.pkcs8).is_err());
}
