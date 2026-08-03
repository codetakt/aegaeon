use aegaeon_jose_tlv::{parse_jose_header_tlv_with_validator, JoseHeaderParseError};
use std::ffi::{c_char, CStr, CString};

const TLV_PARSE_OK: i32 = 0;
const TLV_PARSE_ERROR_TRUNCATED: i32 = 1;
const TLV_PARSE_ERROR_NON_ASCII_KEY: i32 = 2;
const TLV_PARSE_ERROR_NON_UTF8_KEY: i32 = 3;
const TLV_PARSE_ERROR_NON_UTF8_VALUE: i32 = 4;
const TLV_PARSE_ERROR_TRAILING_BYTES: i32 = 5;
const TLV_PARSE_ERROR_ENTRY_VALIDATOR_UNAVAILABLE: i32 = 6;
const TLV_PARSE_ERROR_ENTRY_VALIDATION_FAILED: i32 = 7;
const TLV_PARSE_ERROR_INTERNAL: i32 = 100;
const TLV_PARSE_ERROR_NULL_PTR: i32 = 101;

/// Errors returned by the safe Rust wrapper around the JOSE TLV C ABI.
#[derive(Debug, PartialEq, Eq)]
pub enum JoseHeaderTlvAbiError {
    /// The parser rejected the TLV payload with a structured parse error.
    Parse(JoseHeaderParseError),
    /// The C ABI reported an internal failure while marshaling the result.
    Internal,
    /// The parser reported success but returned a null entries pointer.
    NullEntries,
    /// The parser reported success but an entry key pointer was null.
    NullKey,
    /// The parser reported success but an entry value pointer was null.
    NullValue,
    /// The parser returned a key that was not valid UTF-8.
    InvalidUtf8Key,
    /// The parser returned a value that was not valid UTF-8.
    InvalidUtf8Value,
    /// The C ABI returned an unexpected status code.
    UnexpectedStatus(i32),
}

impl std::fmt::Display for JoseHeaderTlvAbiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::Internal => write!(f, "JOSE TLV ABI reported an internal failure"),
            Self::NullEntries => write!(f, "JOSE TLV ABI returned a null entries pointer"),
            Self::NullKey => write!(f, "JOSE TLV ABI returned a null key pointer"),
            Self::NullValue => write!(f, "JOSE TLV ABI returned a null value pointer"),
            Self::InvalidUtf8Key => {
                write!(f, "JOSE TLV ABI returned a key that is not valid UTF-8")
            }
            Self::InvalidUtf8Value => {
                write!(f, "JOSE TLV ABI returned a value that is not valid UTF-8")
            }
            Self::UnexpectedStatus(code) => {
                write!(f, "JOSE TLV ABI returned unexpected status code {code}")
            }
        }
    }
}

impl std::error::Error for JoseHeaderTlvAbiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            Self::Internal
            | Self::NullEntries
            | Self::NullKey
            | Self::NullValue
            | Self::InvalidUtf8Key
            | Self::InvalidUtf8Value
            | Self::UnexpectedStatus(_) => None,
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct aegaeon_tlv_header_entry {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct aegaeon_tlv_header_result {
    pub entries: *mut aegaeon_tlv_header_entry,
    pub len: usize,
    pub error_code: i32,
    pub strings: *mut *mut c_char,
    pub strings_len: usize,
}

fn map_error(err: &JoseHeaderParseError) -> i32 {
    match err {
        JoseHeaderParseError::Truncated => TLV_PARSE_ERROR_TRUNCATED,
        JoseHeaderParseError::NonAsciiKey => TLV_PARSE_ERROR_NON_ASCII_KEY,
        JoseHeaderParseError::NonUtf8Key => TLV_PARSE_ERROR_NON_UTF8_KEY,
        JoseHeaderParseError::NonUtf8Value => TLV_PARSE_ERROR_NON_UTF8_VALUE,
        JoseHeaderParseError::TrailingBytes => TLV_PARSE_ERROR_TRAILING_BYTES,
        JoseHeaderParseError::EntryValidatorUnavailable => {
            TLV_PARSE_ERROR_ENTRY_VALIDATOR_UNAVAILABLE
        }
        JoseHeaderParseError::EntryValidationFailed => TLV_PARSE_ERROR_ENTRY_VALIDATION_FAILED,
    }
}

fn decode_error_code(code: i32) -> Option<JoseHeaderParseError> {
    match code {
        TLV_PARSE_ERROR_TRUNCATED => Some(JoseHeaderParseError::Truncated),
        TLV_PARSE_ERROR_NON_ASCII_KEY => Some(JoseHeaderParseError::NonAsciiKey),
        TLV_PARSE_ERROR_NON_UTF8_KEY => Some(JoseHeaderParseError::NonUtf8Key),
        TLV_PARSE_ERROR_NON_UTF8_VALUE => Some(JoseHeaderParseError::NonUtf8Value),
        TLV_PARSE_ERROR_TRAILING_BYTES => Some(JoseHeaderParseError::TrailingBytes),
        TLV_PARSE_ERROR_ENTRY_VALIDATOR_UNAVAILABLE => {
            Some(JoseHeaderParseError::EntryValidatorUnavailable)
        }
        TLV_PARSE_ERROR_ENTRY_VALIDATION_FAILED => {
            Some(JoseHeaderParseError::EntryValidationFailed)
        }
        _ => None,
    }
}

fn verified_claims_require_lowstar() -> bool {
    cfg!(feature = "verified-claim")
}

fn resolve_everparse_entry_check(
    result: Result<(), crate::jose_header::JoseHeaderEntryError>,
) -> Result<(), JoseHeaderParseError> {
    match result {
        Ok(()) => Ok(()),
        Err(crate::jose_header::JoseHeaderEntryError::ParserUnavailable)
            if !verified_claims_require_lowstar() =>
        {
            Ok(())
        }
        Err(crate::jose_header::JoseHeaderEntryError::ParserUnavailable) => {
            Err(JoseHeaderParseError::EntryValidatorUnavailable)
        }
        Err(crate::jose_header::JoseHeaderEntryError::Truncated) => {
            Err(JoseHeaderParseError::Truncated)
        }
        Err(
            crate::jose_header::JoseHeaderEntryError::BufferTooLarge
            | crate::jose_header::JoseHeaderEntryError::InvalidPayload,
        ) => Err(JoseHeaderParseError::EntryValidationFailed),
    }
}

fn everparse_check_entry(entry: &[u8]) -> Result<(), JoseHeaderParseError> {
    resolve_everparse_entry_check(crate::jose_header::check_jose_header_entry(entry))
}

fn clear_result(out: &mut aegaeon_tlv_header_result) {
    out.entries = std::ptr::null_mut();
    out.len = 0;
    out.error_code = TLV_PARSE_OK;
    out.strings = std::ptr::null_mut();
    out.strings_len = 0;
}

fn free_strings(strings: &mut Vec<*mut c_char>) {
    for ptr in strings.drain(..) {
        if !ptr.is_null() {
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }
    }
}

struct OwnedTlvHeaderResult {
    raw: aegaeon_tlv_header_result,
}

impl OwnedTlvHeaderResult {
    fn as_mut_ptr(&mut self) -> *mut aegaeon_tlv_header_result {
        std::ptr::addr_of_mut!(self.raw)
    }

    fn len(&self) -> usize {
        self.raw.len
    }

    fn entries(&self) -> Result<&[aegaeon_tlv_header_entry], JoseHeaderTlvAbiError> {
        if self.raw.len == 0 {
            return Ok(&[]);
        }
        if self.raw.entries.is_null() {
            return Err(JoseHeaderTlvAbiError::NullEntries);
        }
        // SAFETY: `aegaeon_parse_jose_header_tlv` populated `entries` with a boxed
        // slice allocation when `len > 0`.
        Ok(unsafe { std::slice::from_raw_parts(self.raw.entries, self.raw.len) })
    }
}

impl Default for OwnedTlvHeaderResult {
    fn default() -> Self {
        Self {
            raw: aegaeon_tlv_header_result {
                entries: std::ptr::null_mut(),
                len: 0,
                error_code: TLV_PARSE_OK,
                strings: std::ptr::null_mut(),
                strings_len: 0,
            },
        }
    }
}

impl Drop for OwnedTlvHeaderResult {
    fn drop(&mut self) {
        aegaeon_free_tlv_header_result(self.as_mut_ptr());
    }
}

/// Parse JOSE header TLV bytes through the exported C ABI and convert them back
/// into owned Rust strings.
///
/// # Errors
///
/// Returns [`JoseHeaderTlvAbiError`] when the ABI rejects the payload, reports
/// an internal failure, or returns an invalid/malformed result buffer.
pub fn parse_jose_header_tlv_via_abi(
    bytes: &[u8],
) -> Result<Vec<(String, String)>, JoseHeaderTlvAbiError> {
    let mut out = OwnedTlvHeaderResult::default();
    let status = aegaeon_parse_jose_header_tlv(bytes.as_ptr(), bytes.len(), out.as_mut_ptr());

    match status {
        TLV_PARSE_OK => {}
        TLV_PARSE_ERROR_INTERNAL => return Err(JoseHeaderTlvAbiError::Internal),
        code => {
            return Err(decode_error_code(code).map_or(
                JoseHeaderTlvAbiError::UnexpectedStatus(code),
                JoseHeaderTlvAbiError::Parse,
            ));
        }
    }

    let entries = out.entries()?;
    let mut pairs = Vec::with_capacity(out.len());

    for entry in entries {
        if entry.key.is_null() {
            return Err(JoseHeaderTlvAbiError::NullKey);
        }
        if entry.value.is_null() {
            return Err(JoseHeaderTlvAbiError::NullValue);
        }

        // SAFETY: successful ABI results populate `key` and `value` with
        // NUL-terminated strings allocated by `CString::into_raw`.
        let key = unsafe { CStr::from_ptr(entry.key) }
            .to_str()
            .map_err(|_| JoseHeaderTlvAbiError::InvalidUtf8Key)?
            .to_owned();
        // SAFETY: successful ABI results populate `key` and `value` with
        // NUL-terminated strings allocated by `CString::into_raw`.
        let value = unsafe { CStr::from_ptr(entry.value) }
            .to_str()
            .map_err(|_| JoseHeaderTlvAbiError::InvalidUtf8Value)?
            .to_owned();
        pairs.push((key, value));
    }

    Ok(pairs)
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_parse_jose_header_tlv(
    bytes: *const u8,
    len: usize,
    out: *mut aegaeon_tlv_header_result,
) -> i32 {
    if bytes.is_null() || out.is_null() {
        return TLV_PARSE_ERROR_NULL_PTR;
    }

    // SAFETY: caller guarantees out is valid.
    let out = unsafe { &mut *out };
    clear_result(out);

    // SAFETY: caller guarantees bytes is valid for len bytes.
    let raw = unsafe { std::slice::from_raw_parts(bytes, len) };
    let parsed = match parse_jose_header_tlv_with_validator(raw, everparse_check_entry) {
        Ok(pairs) => pairs,
        Err(err) => {
            let code = map_error(&err);
            out.error_code = code;
            return code;
        }
    };

    let mut strings = Vec::with_capacity(parsed.len().saturating_mul(2));
    let mut entries = Vec::with_capacity(parsed.len());

    for (key, value) in parsed {
        let Ok(key_c) = CString::new(key) else {
            free_strings(&mut strings);
            out.error_code = TLV_PARSE_ERROR_INTERNAL;
            return TLV_PARSE_ERROR_INTERNAL;
        };
        let Ok(value_c) = CString::new(value) else {
            free_strings(&mut strings);
            out.error_code = TLV_PARSE_ERROR_INTERNAL;
            return TLV_PARSE_ERROR_INTERNAL;
        };

        let key_ptr = key_c.into_raw();
        let value_ptr = value_c.into_raw();
        strings.push(key_ptr);
        strings.push(value_ptr);
        entries.push(aegaeon_tlv_header_entry {
            key: key_ptr,
            value: value_ptr,
        });
    }

    let entries_len = entries.len();
    let entries_ptr = Box::into_raw(entries.into_boxed_slice()).cast::<aegaeon_tlv_header_entry>();
    let strings_len = strings.len();
    let strings_ptr = Box::into_raw(strings.into_boxed_slice()).cast::<*mut c_char>();

    out.entries = entries_ptr;
    out.len = entries_len;
    out.error_code = TLV_PARSE_OK;
    out.strings = strings_ptr;
    out.strings_len = strings_len;

    TLV_PARSE_OK
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_free_tlv_header_result(res: *mut aegaeon_tlv_header_result) {
    if res.is_null() {
        return;
    }

    // SAFETY: caller guarantees res is valid.
    let res = unsafe { &mut *res };

    if !res.strings.is_null() && res.strings_len > 0 {
        // SAFETY: strings points to a boxed slice allocated in aegaeon_parse_jose_header_tlv.
        let strings_slice = unsafe { std::slice::from_raw_parts_mut(res.strings, res.strings_len) };
        for ptr in strings_slice.iter_mut() {
            if !ptr.is_null() {
                unsafe {
                    let _ = CString::from_raw(*ptr);
                }
            }
        }
        // SAFETY: strings_slice is a boxed slice allocated in aegaeon_parse_jose_header_tlv.
        unsafe {
            let _ = Box::from_raw(strings_slice);
        }
    }

    if !res.entries.is_null() && res.len > 0 {
        // SAFETY: entries points to a boxed slice allocated in aegaeon_parse_jose_header_tlv.
        unsafe {
            let entries_slice = std::slice::from_raw_parts_mut(res.entries, res.len);
            let _ = Box::from_raw(entries_slice);
        }
    }

    clear_result(res);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header_tlv() -> Vec<u8> {
        vec![
            3, b'a', b'l', b'g', 5, b'H', b'S', b'2', b'5', b'6', 3, b'k', b'i', b'd', 4, b't',
            b'e', b's', b't',
        ]
    }

    #[cfg(not(feature = "verified-claim"))]
    #[test]
    fn compat_profile_tolerates_unavailable_everparse_entry_validator() {
        assert_eq!(
            resolve_everparse_entry_check(Err(
                crate::jose_header::JoseHeaderEntryError::ParserUnavailable
            )),
            Ok(())
        );
    }

    #[cfg(not(feature = "verified-claim"))]
    #[test]
    fn compat_profile_rejects_invalid_everparse_entry_payload() {
        assert_eq!(
            resolve_everparse_entry_check(Err(
                crate::jose_header::JoseHeaderEntryError::InvalidPayload
            )),
            Err(JoseHeaderParseError::EntryValidationFailed)
        );
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn verified_claim_profile_rejects_unavailable_everparse_entry_validator() {
        assert_eq!(
            resolve_everparse_entry_check(Err(
                crate::jose_header::JoseHeaderEntryError::ParserUnavailable
            )),
            Err(JoseHeaderParseError::EntryValidatorUnavailable)
        );
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn verified_claim_profile_rejects_invalid_everparse_entry_payload() {
        assert_eq!(
            resolve_everparse_entry_check(Err(
                crate::jose_header::JoseHeaderEntryError::InvalidPayload
            )),
            Err(JoseHeaderParseError::EntryValidationFailed)
        );
    }

    #[test]
    fn entry_truncation_maps_to_tlv_truncated() {
        assert_eq!(
            resolve_everparse_entry_check(Err(crate::jose_header::JoseHeaderEntryError::Truncated)),
            Err(JoseHeaderParseError::Truncated)
        );
    }

    #[cfg(not(feature = "verified-claim"))]
    #[test]
    fn abi_wrapper_round_trips_valid_header_in_compat_profile() {
        assert_eq!(
            parse_jose_header_tlv_via_abi(&sample_header_tlv()),
            Ok(vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "test".to_string()),
            ])
        );
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn abi_wrapper_fails_closed_when_validator_unavailable_in_verified_profile() {
        assert_eq!(
            parse_jose_header_tlv_via_abi(&sample_header_tlv()),
            Err(JoseHeaderTlvAbiError::Parse(
                JoseHeaderParseError::EntryValidatorUnavailable
            ))
        );
    }

    #[test]
    fn abi_wrapper_maps_parse_errors() {
        assert_eq!(
            parse_jose_header_tlv_via_abi(&[3, b'a', b'l']),
            Err(JoseHeaderTlvAbiError::Parse(
                JoseHeaderParseError::Truncated
            ))
        );
    }
}
