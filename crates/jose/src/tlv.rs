pub use aegaeon_jose_tlv::{parse_jose_header_tlv_with_validator, JoseHeaderParseError};

#[cfg(feature = "everparse_jose_header_entry")]
fn everparse_check_entry(entry: &[u8]) -> Result<(), JoseHeaderParseError> {
    resolve_everparse_entry_check(ffi::jose_header::check_jose_header_entry(entry))
}

#[cfg(feature = "everparse_jose_header_entry")]
fn resolve_everparse_entry_check(
    result: Result<(), ffi::jose_header::JoseHeaderEntryError>,
) -> Result<(), JoseHeaderParseError> {
    match result {
        Ok(()) => Ok(()),
        Err(ffi::jose_header::JoseHeaderEntryError::ParserUnavailable) => {
            Err(JoseHeaderParseError::EntryValidatorUnavailable)
        }
        Err(ffi::jose_header::JoseHeaderEntryError::Truncated) => {
            Err(JoseHeaderParseError::Truncated)
        }
        Err(
            ffi::jose_header::JoseHeaderEntryError::BufferTooLarge
            | ffi::jose_header::JoseHeaderEntryError::InvalidPayload,
        ) => Err(JoseHeaderParseError::EntryValidationFailed),
    }
}

/// Parse TLV-encoded JOSE header entries into key-value pairs.
///
/// # Errors
///
/// Returns [`JoseHeaderParseError`] when the TLV stream is malformed or the
/// optional `EverParse` entry validator rejects an entry.
pub fn parse_jose_header_tlv(raw: &[u8]) -> Result<Vec<(String, String)>, JoseHeaderParseError> {
    #[cfg(feature = "everparse_jose_header_entry")]
    {
        parse_jose_header_tlv_with_validator(raw, everparse_check_entry)
    }

    #[cfg(not(feature = "everparse_jose_header_entry"))]
    {
        aegaeon_jose_tlv::parse_jose_header_tlv(raw)
    }
}

#[cfg(feature = "ffi_jose_header_tlv")]
fn map_tlv_abi_error(err: ffi::tlv::JoseHeaderTlvAbiError) -> crate::json_lowstar::JsonError {
    match err {
        ffi::tlv::JoseHeaderTlvAbiError::Parse(JoseHeaderParseError::EntryValidatorUnavailable) => {
            crate::json_lowstar::JsonError::ParserUnavailable
        }
        ffi::tlv::JoseHeaderTlvAbiError::Parse(
            JoseHeaderParseError::NonAsciiKey | JoseHeaderParseError::NonUtf8Key,
        ) => crate::json_lowstar::JsonError::InvalidKeyEncoding(err.to_string()),
        ffi::tlv::JoseHeaderTlvAbiError::Parse(JoseHeaderParseError::NonUtf8Value) => {
            crate::json_lowstar::JsonError::InvalidValueUtf8(err.to_string())
        }
        ffi::tlv::JoseHeaderTlvAbiError::Parse(JoseHeaderParseError::TrailingBytes) => {
            crate::json_lowstar::JsonError::TrailingBytes(err.to_string())
        }
        ffi::tlv::JoseHeaderTlvAbiError::Parse(
            JoseHeaderParseError::Truncated | JoseHeaderParseError::EntryValidationFailed,
        )
        | ffi::tlv::JoseHeaderTlvAbiError::Internal
        | ffi::tlv::JoseHeaderTlvAbiError::NullEntries
        | ffi::tlv::JoseHeaderTlvAbiError::NullKey
        | ffi::tlv::JoseHeaderTlvAbiError::NullValue
        | ffi::tlv::JoseHeaderTlvAbiError::InvalidUtf8Key
        | ffi::tlv::JoseHeaderTlvAbiError::InvalidUtf8Value
        | ffi::tlv::JoseHeaderTlvAbiError::UnexpectedStatus(_) => {
            crate::json_lowstar::JsonError::Internal(err.to_string())
        }
    }
}

#[cfg(feature = "ffi_jose_header_tlv")]
fn push_tlv_component(
    out: &mut Vec<u8>,
    kind: &str,
    value: &str,
) -> Result<(), crate::json_lowstar::JsonError> {
    let len = u8::try_from(value.len()).map_err(|_| {
        crate::json_lowstar::JsonError::Internal(format!(
            "JOSE header TLV {kind} length exceeds u8::MAX"
        ))
    })?;
    out.push(len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(feature = "ffi_jose_header_tlv")]
fn encode_json_header_as_tlv(bytes: &[u8]) -> Result<Vec<u8>, crate::json_lowstar::JsonError> {
    let members = crate::json_lowstar::parse_json_header_string_members(bytes)?;
    let mut out = Vec::new();

    for member in members {
        let Some(value) = member.value else {
            continue;
        };

        push_tlv_component(&mut out, "key", &member.key)?;
        push_tlv_component(&mut out, "value", &value)?;
    }

    Ok(out)
}

/// Parse a JOSE header JSON object by normalizing it into TLV and routing the
/// resulting buffer through the exported FFI TLV parser.
///
/// # Errors
///
/// Returns [`crate::json_lowstar::JsonError`] when raw JSON normalization
/// fails, when normalized TLV encoding exceeds internal bounds, or when the FFI
/// TLV parser rejects the normalized representation.
#[cfg(feature = "ffi_jose_header_tlv")]
pub(crate) fn parse_json_header_pairs_via_tlv_ffi(
    bytes: &[u8],
) -> Result<Vec<(String, String)>, crate::json_lowstar::JsonError> {
    let tlv = encode_json_header_as_tlv(bytes)?;
    ffi::tlv::parse_jose_header_tlv_via_abi(&tlv).map_err(map_tlv_abi_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::tlv::{parse_jose_header_tlv_via_abi, JoseHeaderTlvAbiError};

    fn sample_entry() -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(3);
        raw.extend_from_slice(b"alg");
        raw.push(5);
        raw.extend_from_slice(b"HS256");
        raw
    }

    fn sample_header() -> Vec<u8> {
        let mut raw = sample_entry();
        raw.push(3);
        raw.extend_from_slice(b"kid");
        raw.push(4);
        raw.extend_from_slice(b"test");
        raw
    }

    #[cfg(all(
        feature = "everparse_jose_header_entry",
        not(feature = "verified-claim")
    ))]
    #[test]
    fn compat_profile_tolerates_unavailable_everparse_entry_validator() {
        let _entry = sample_entry();
        assert_eq!(
            resolve_everparse_entry_check(Err(
                ffi::jose_header::JoseHeaderEntryError::ParserUnavailable
            )),
            Ok(())
        );
    }

    #[cfg(all(
        feature = "everparse_jose_header_entry",
        not(feature = "verified-claim")
    ))]
    #[test]
    fn compat_profile_rejects_invalid_everparse_entry_payload() {
        let _entry = sample_entry();
        assert_eq!(
            resolve_everparse_entry_check(Err(
                ffi::jose_header::JoseHeaderEntryError::InvalidPayload
            )),
            Err(JoseHeaderParseError::EntryValidationFailed)
        );
    }

    #[cfg(all(feature = "everparse_jose_header_entry", feature = "verified-claim"))]
    #[test]
    fn verified_claim_profile_rejects_unavailable_everparse_entry_validator() {
        let _entry = sample_entry();
        assert_eq!(
            resolve_everparse_entry_check(Err(
                ffi::jose_header::JoseHeaderEntryError::ParserUnavailable
            )),
            Err(JoseHeaderParseError::EntryValidatorUnavailable)
        );
    }

    #[cfg(all(feature = "everparse_jose_header_entry", feature = "verified-claim"))]
    #[test]
    fn verified_claim_profile_rejects_invalid_everparse_entry_payload() {
        let _entry = sample_entry();
        assert_eq!(
            resolve_everparse_entry_check(Err(
                ffi::jose_header::JoseHeaderEntryError::InvalidPayload
            )),
            Err(JoseHeaderParseError::EntryValidationFailed)
        );
    }

    #[cfg(feature = "everparse_jose_header_entry")]
    #[test]
    fn entry_truncation_maps_to_tlv_truncated() {
        assert_eq!(
            resolve_everparse_entry_check(Err(ffi::jose_header::JoseHeaderEntryError::Truncated)),
            Err(JoseHeaderParseError::Truncated)
        );
    }

    #[test]
    fn abi_wrapper_matches_rust_tlv_parser_for_valid_header() {
        let raw = sample_header();

        assert_eq!(
            parse_jose_header_tlv_via_abi(&raw),
            parse_jose_header_tlv(&raw).map_err(JoseHeaderTlvAbiError::Parse)
        );
    }

    #[test]
    fn abi_wrapper_matches_rust_tlv_parser_for_truncated_input() {
        let raw = [3, b'a', b'l'];

        assert_eq!(
            parse_jose_header_tlv_via_abi(&raw),
            parse_jose_header_tlv(&raw).map_err(JoseHeaderTlvAbiError::Parse)
        );
    }

    #[test]
    fn abi_wrapper_matches_rust_tlv_parser_for_trailing_bytes() {
        let mut raw = sample_header();
        raw.push(0xff);

        assert_eq!(
            parse_jose_header_tlv_via_abi(&raw),
            parse_jose_header_tlv(&raw).map_err(JoseHeaderTlvAbiError::Parse)
        );
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", not(feature = "verified-claim")))]
    #[test]
    fn json_header_pairs_via_ffi_tlv_parse_valid_header() {
        assert_eq!(
            parse_json_header_pairs_via_tlv_ffi(br#"{"alg":"HS256","kid":"test"}"#),
            Ok(vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "test".to_string()),
            ])
        );
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", not(feature = "verified-claim")))]
    #[test]
    fn json_header_pairs_via_ffi_tlv_omits_null_values() {
        assert_eq!(
            parse_json_header_pairs_via_tlv_ffi(br#"{"alg":"HS256","kid":null,"typ":"JWT"}"#),
            Ok(vec![
                ("alg".to_string(), "HS256".to_string()),
                ("typ".to_string(), "JWT".to_string()),
            ])
        );
    }

    #[cfg(feature = "ffi_jose_header_tlv")]
    #[test]
    fn json_header_pairs_via_ffi_tlv_rejects_non_ascii_keys() {
        assert_eq!(
            parse_json_header_pairs_via_tlv_ffi(br#"{"\u00e5lg":"HS256"}"#),
            Err(crate::json_lowstar::JsonError::InvalidKeyEncoding(
                JoseHeaderParseError::NonAsciiKey.to_string()
            ))
        );
    }

    #[cfg(feature = "ffi_jose_header_tlv")]
    #[test]
    fn json_header_paths_reject_non_ascii_keys_consistently() {
        let expected = Err(crate::json_lowstar::JsonError::InvalidKeyEncoding(
            JoseHeaderParseError::NonAsciiKey.to_string(),
        ));
        let json = br#"{"\u00e5lg":"HS256"}"#;

        assert_eq!(
            crate::json_lowstar::parse_json_header_lowstar(json),
            expected.clone()
        );
        assert_eq!(parse_json_header_pairs_via_tlv_ffi(json), expected);
    }

    #[cfg(feature = "ffi_jose_header_tlv")]
    #[test]
    fn json_header_paths_reject_trailing_bytes_consistently() {
        let expected = Err(crate::json_lowstar::JsonError::TrailingBytes(
            "trailing bytes after JOSE header JSON object".to_string(),
        ));
        let json = br#"{"alg":"HS256"}x"#;

        assert_eq!(
            crate::json_lowstar::parse_json_header_lowstar(json),
            expected.clone()
        );
        assert_eq!(parse_json_header_pairs_via_tlv_ffi(json), expected);
    }

    #[cfg(feature = "ffi_jose_header_tlv")]
    #[test]
    fn tlv_trailing_bytes_map_to_json_trailing_bytes() {
        assert_eq!(
            map_tlv_abi_error(ffi::tlv::JoseHeaderTlvAbiError::Parse(
                JoseHeaderParseError::TrailingBytes
            )),
            crate::json_lowstar::JsonError::TrailingBytes(
                JoseHeaderParseError::TrailingBytes.to_string()
            )
        );
    }

    #[cfg(feature = "ffi_jose_header_tlv")]
    #[test]
    fn tlv_abi_parser_unavailable_maps_to_json_parser_unavailable() {
        assert_eq!(
            map_tlv_abi_error(ffi::tlv::JoseHeaderTlvAbiError::Parse(
                JoseHeaderParseError::EntryValidatorUnavailable
            )),
            crate::json_lowstar::JsonError::ParserUnavailable
        );
    }
}
