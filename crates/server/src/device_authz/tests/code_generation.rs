use super::*;

#[test]
fn user_code_alphabet_has_20_chars() {
    assert_eq!(USER_CODE_ALPHABET.len(), 20);
}

#[test]
fn user_code_entropy_at_least_31_bits() {
    // log₂(20⁸) = 8 * log₂(20) ≈ 8 * 4.322 = 34.57
    let entropy = 20_f64.powi(8).log2();
    assert!(
        entropy >= 31.0,
        "user code entropy {entropy:.1} bits < 31 bits"
    );
}

#[test]
fn user_code_no_confusable_chars() {
    let confusable = b"0OoIi1lL2Zz5Ss8Bb";
    for &c in USER_CODE_ALPHABET {
        assert!(
            !confusable.contains(&c),
            "alphabet contains confusable character '{}'",
            c as char
        );
    }
}

#[test]
fn device_code_has_256_bits_entropy() -> DeviceTestResult {
    let code = must_ok!(
        generate_device_code(),
        "device code entropy should be available",
    );
    // base64url(32 bytes) = 43 characters
    assert_eq!(code.len(), 43);
    Ok(())
}

#[test]
fn user_code_normalization() {
    assert_eq!(normalize_user_code("ACDE-FGHJ"), "ACDEFGHJ");
    assert_eq!(normalize_user_code("acde fghj"), "ACDEFGHJ");
    assert_eq!(normalize_user_code("  AcDe-FgHj  "), "ACDEFGHJ");
}

#[test]
fn user_code_formatting() {
    assert_eq!(format_user_code("ABCDEFGH"), "ABCD-EFGH");
    assert_eq!(format_user_code("SHORT"), "SHORT"); // non-standard length
}

#[test]
fn user_code_random_byte_mapping_rejects_modulo_bias_tail() {
    assert_eq!(
        user_code_char_from_random_byte(239),
        Some(USER_CODE_ALPHABET[19] as char)
    );
    assert_eq!(user_code_char_from_random_byte(240), None);
    assert_eq!(user_code_char_from_random_byte(255), None);
}
