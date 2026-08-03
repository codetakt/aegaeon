//! JOSE header normalization entry points.

use crate::json_lowstar::JsonError;

/// Parse and normalize a JOSE protected header JSON object.
///
/// This is the public entry point for header normalization. It selects the
/// active verified parsing surface (`json_lowstar` or the optional TLV/FFI
/// bridge). Parser unavailability fails closed in normal builds.
///
/// # Errors
///
/// Returns [`JsonError`] when the normalized header is invalid, violates JOSE
/// policy, or the selected verified path fails closed.
pub fn parse_json_header(bytes: &[u8]) -> Result<Vec<(String, String)>, JsonError> {
    #[cfg(feature = "ffi_jose_header_tlv")]
    {
        return resolve_json_header_pairs(
            crate::tlv::parse_json_header_pairs_via_tlv_ffi(bytes),
            bytes,
        );
    }

    #[cfg(not(feature = "ffi_jose_header_tlv"))]
    resolve_json_header_pairs(crate::json_lowstar::parse_json_header_lowstar(bytes), bytes)
}

pub(crate) fn resolve_json_header_pairs(
    parsed: Result<Vec<(String, String)>, JsonError>,
    _bytes: &[u8],
) -> Result<Vec<(String, String)>, JsonError> {
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::Error as IoError;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn parse_json_header_normalizes_valid_header() -> TestResult {
        let pairs = parse_json_header(br#"{"alg":"HS256","kid":"key-1"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "key-1".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn parse_json_header_rejects_trailing_bytes() {
        assert_eq!(
            parse_json_header(br#"{"alg":"HS256"}x"#),
            Err(JsonError::TrailingBytes(
                "trailing bytes after JOSE header JSON object".to_string()
            ))
        );
    }

    #[test]
    fn parser_unavailability_fails_closed() -> TestResult {
        let err = resolve_json_header_pairs(
            Err(JsonError::ParserUnavailable),
            br#"{"alg":"HS256","kid":"unavailable"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("parser unavailability must fail closed"))?;

        assert_eq!(err, JsonError::ParserUnavailable);
        Ok(())
    }

    #[test]
    fn internal_errors_fail_closed() -> TestResult {
        let err = resolve_json_header_pairs(
            Err(JsonError::Internal(
                "unsupported raw JSON backend `future` for surface `jose-header` via AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER".to_string(),
            )),
            br#"{"alg":"HS256"}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("internal parser errors must fail closed"))?;

        assert!(matches!(
            err,
            JsonError::Internal(ref msg) if msg.contains("unsupported raw JSON backend `future`")
        ));
        Ok(())
    }
}
