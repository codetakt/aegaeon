#![cfg(not(no_mbedtls))]

use ffi::jose_header::{check_jose_header_entry, JoseHeaderEntryError};

fn sample_entry() -> Vec<u8> {
    vec![3, b'a', b'l', b'g', 5, b'H', b'S', b'2', b'5', b'6']
}

#[test]
fn native_entry_validator_accepts_valid_framing() {
    assert_eq!(check_jose_header_entry(&sample_entry()), Ok(()));
}

#[test]
fn native_entry_validator_reports_truncated_entry() {
    let truncated = [3, b'a', b'l'];
    assert_eq!(
        check_jose_header_entry(&truncated),
        Err(JoseHeaderEntryError::Truncated)
    );
}

#[test]
fn native_entry_validator_only_checks_framing() {
    // The EverParse schema currently validates TLV framing only. Semantic
    // policy checks such as rejecting empty keys remain in the handwritten
    // parser layer.
    let empty_key_entry = [0, 1, b'a'];
    assert_eq!(check_jose_header_entry(&empty_key_entry), Ok(()));
}

#[test]
fn native_entry_validator_accepts_valid_entry_prefix_with_trailing_bytes() {
    // The generated validator admits a single jose_header_entry prefix. Whole-
    // stream consumption remains the responsibility of the higher-level TLV
    // parser, which iterates over entries and rejects leftover bytes.
    let valid_prefix_with_trailing_byte = [0, 0, 0];
    assert_eq!(
        check_jose_header_entry(&valid_prefix_with_trailing_byte),
        Ok(())
    );
}
