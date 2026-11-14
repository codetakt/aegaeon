use aegaeon_crypto::jwe::{rsa_encryption_public_spki, rsa_encryption_public_spki_from_pkcs8};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeySize, PrivateDecryptingKey},
};
use zeroize::Zeroizing;

#[test]
fn derives_the_public_spki_from_actual_private_material() {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("ephemeral RSA key");
    let public = private.public_key().as_der().expect("public SPKI");
    let pkcs8 = private.as_der().expect("private PKCS8");
    let derived = rsa_encryption_public_spki_from_pkcs8(pkcs8.as_ref()).expect("derive");
    assert_eq!(derived, public.as_ref());
    assert_eq!(
        rsa_encryption_public_spki(&derived).expect("validate"),
        derived
    );
    let other = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("other ephemeral key");
    assert_ne!(
        derived,
        rsa_encryption_public_spki_from_pkcs8(other.as_der().unwrap().as_ref()).unwrap()
    );
}

#[test]
fn public_and_private_der_inputs_are_not_interchangeable() {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let public = private.public_key().as_der().unwrap();
    let private = Zeroizing::new(private.as_der().unwrap().as_ref().to_vec());
    for bad in [&[][..], b"not DER", private.as_slice()] {
        assert!(rsa_encryption_public_spki(bad).is_err());
    }
    for bad in [&[][..], b"not DER", public.as_ref()] {
        assert!(rsa_encryption_public_spki_from_pkcs8(bad).is_err());
    }
}
