#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum JoseHeaderParseError {
    Truncated,
    NonAsciiKey,
    NonUtf8Key,
    NonUtf8Value,
    TrailingBytes,
    EntryValidatorUnavailable,
    EntryValidationFailed,
}

impl fmt::Display for JoseHeaderParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoseHeaderParseError::Truncated => write!(f, "truncated JOSE header entry"),
            JoseHeaderParseError::NonAsciiKey => write!(f, "header key must be ASCII"),
            JoseHeaderParseError::NonUtf8Key => write!(f, "header key is not valid UTF-8"),
            JoseHeaderParseError::NonUtf8Value => write!(f, "header value is not valid UTF-8"),
            JoseHeaderParseError::TrailingBytes => {
                write!(f, "unused bytes remain after parsing header entries")
            }
            JoseHeaderParseError::EntryValidatorUnavailable => {
                write!(f, "JOSE header entry validator unavailable in this build")
            }
            JoseHeaderParseError::EntryValidationFailed => {
                write!(f, "JOSE header entry validator rejected an entry")
            }
        }
    }
}

impl std::error::Error for JoseHeaderParseError {}

/// Parse TLV-encoded JOSE header entries into UTF-8 string pairs.
///
/// # Errors
///
/// Returns [`JoseHeaderParseError`] when the input contains truncated entries,
/// non-ASCII keys, or invalid UTF-8.
pub fn parse_jose_header_tlv(raw: &[u8]) -> Result<Vec<(String, String)>, JoseHeaderParseError> {
    parse_jose_header_tlv_with_validator(raw, |_| Ok(()))
}

/// Parse TLV-encoded JOSE header entries and run a validator on each encoded entry.
///
/// # Errors
///
/// Returns [`JoseHeaderParseError`] when the input contains truncated entries,
/// non-ASCII keys, invalid UTF-8, or when `validator` rejects an entry.
pub fn parse_jose_header_tlv_with_validator<F>(
    raw: &[u8],
    mut validator: F,
) -> Result<Vec<(String, String)>, JoseHeaderParseError>
where
    F: FnMut(&[u8]) -> Result<(), JoseHeaderParseError>,
{
    let mut pairs = Vec::new();
    let mut offset = 0usize;

    while offset < raw.len() {
        let entry_start = offset;
        if raw.len() - offset < 1 {
            return Err(JoseHeaderParseError::Truncated);
        }

        let key_len = raw[offset] as usize;
        offset += 1;

        if raw.len() - offset < key_len + 1 {
            return Err(JoseHeaderParseError::Truncated);
        }
        let key_bytes = &raw[offset..offset + key_len];
        offset += key_len;

        let value_len = raw[offset] as usize;
        offset += 1;

        if raw.len() - offset < value_len {
            return Err(JoseHeaderParseError::Truncated);
        }
        let value_bytes = &raw[offset..offset + value_len];
        offset += value_len;

        validator(&raw[entry_start..offset])?;

        let key = std::str::from_utf8(key_bytes).map_err(|_| JoseHeaderParseError::NonUtf8Key)?;
        if !key.is_ascii() {
            return Err(JoseHeaderParseError::NonAsciiKey);
        }

        let value =
            std::str::from_utf8(value_bytes).map_err(|_| JoseHeaderParseError::NonUtf8Value)?;
        pairs.push((key.to_owned(), value.to_owned()));
    }

    if offset != raw.len() {
        return Err(JoseHeaderParseError::TrailingBytes);
    }

    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_jose_header_tlv, parse_jose_header_tlv_with_validator, JoseHeaderParseError,
    };

    #[test]
    fn parses_valid_jose_header_tlv() {
        assert_eq!(
            parse_jose_header_tlv(&[
                3, b'a', b'l', b'g', 5, b'R', b'S', b'2', b'5', b'6', 3, b'k', b'i', b'd', 7, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e',
            ]),
            Ok(vec![
                ("alg".to_string(), "RS256".to_string()),
                ("kid".to_string(), "example".to_string())
            ])
        );
    }

    #[test]
    fn rejects_truncated_entry() {
        let raw = vec![3u8, b'a', b'l'];
        assert_eq!(
            parse_jose_header_tlv(&raw),
            Err(JoseHeaderParseError::Truncated)
        );
    }

    #[test]
    fn rejects_non_ascii_key() {
        let raw = vec![4u8, 0xC3, 0xA5, 0xC3, 0xA4, 1, b'1'];
        assert_eq!(
            parse_jose_header_tlv(&raw),
            Err(JoseHeaderParseError::NonAsciiKey)
        );
    }

    #[test]
    fn propagates_entry_validator_failure() {
        let raw = vec![3u8, b'a', b'l', b'g', 5, b'R', b'S', b'2', b'5', b'6'];
        assert_eq!(
            parse_jose_header_tlv_with_validator(&raw, |_| {
                Err(JoseHeaderParseError::EntryValidationFailed)
            }),
            Err(JoseHeaderParseError::EntryValidationFailed)
        );
    }

    #[test]
    fn propagates_entry_validator_unavailable() {
        let raw = vec![3u8, b'a', b'l', b'g', 5, b'R', b'S', b'2', b'5', b'6'];
        assert_eq!(
            parse_jose_header_tlv_with_validator(&raw, |_| {
                Err(JoseHeaderParseError::EntryValidatorUnavailable)
            }),
            Err(JoseHeaderParseError::EntryValidatorUnavailable)
        );
    }
}
