// ── JWK Material Decoding ────────────────────────────────────────

#[test]
fn decode_jwk_material_ec_p256() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    assert_eq!(decoded.data.len(), 65); // 0x04 + 32 + 32
    assert_eq!(decoded.data[0], 0x04);
    assert!(decoded.extra.is_empty());
}

#[test]
fn decode_jwk_material_rsa() {
    let jwk_value = json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "kid": "rsa-test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    assert!(!decoded.data.is_empty()); // modulus
    assert!(!decoded.extra.is_empty()); // exponent
}

#[test]
fn decode_jwk_material_unsupported_curve() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-384",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let err = must_err(decode_jwk_material(&jwk));
    assert!(matches!(err, FederationError::UnsupportedAlgorithm(_)));
}

// ── VerificationKey from JWK ─────────────────────────────────────

#[test]
fn verification_key_for_alg_es256() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    let vk = must_ok(verification_key_for_alg(&jwk, &decoded, "ES256"));
    assert!(matches!(vk, VerificationKey::EcdsaP256Sha256(_)));
}

#[test]
fn verification_key_for_alg_mismatch() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    // RS256 requires RSA key, not EC
    let err = must_err(verification_key_for_alg(&jwk, &decoded, "RS256"));
    assert!(matches!(err, FederationError::NoSuitableKey));
}

#[test]
fn verification_key_for_alg_jwk_alg_conflict() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "alg": "ES256",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    // JWK says ES256 but JWS says PS256
    let err = must_err(verification_key_for_alg(&jwk, &decoded, "PS256"));
    assert!(matches!(err, FederationError::NoSuitableKey));
}

#[test]
fn verification_key_unsupported_alg() {
    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "test"
    });
    let jwk = must_ok(Jwk::from_value(jwk_value));
    let decoded = must_ok(decode_jwk_material(&jwk));
    let err = must_err(verification_key_for_alg(&jwk, &decoded, "EdDSA"));
    assert!(matches!(err, FederationError::UnsupportedAlgorithm(_)));
}
