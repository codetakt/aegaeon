//! FFI-side ABI surface for the Phase 1 raw JSON structural parser.
//!
//! These types define the public Rust-owned ABI surface exposed by
//! `crates/ffi`, independent of the generated Low* result layout. The current
//! claim posture remains unchanged and the extracted parser still fails closed
//! for unsupported inputs.

const RAW_JSON_STRUCTURAL_PARSE_OK: i32 = 0;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON: i32 = 1;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE: i32 = 2;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES: i32 = 3;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE: i32 = 4;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_INTERNAL: i32 = 100;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_NULL_PTR: i32 = 101;
const RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE: i32 = 102;

const RAW_JSON_STRUCTURAL_VALUE_KIND_STRING: u8 = 0;
const RAW_JSON_STRUCTURAL_VALUE_KIND_NULL: u8 = 1;
const RAW_JSON_STRUCTURAL_VALUE_KIND_NUMBER: u8 = 2;
const RAW_JSON_STRUCTURAL_VALUE_KIND_BOOL: u8 = 3;
const RAW_JSON_STRUCTURAL_VALUE_KIND_OBJECT: u8 = 4;
const RAW_JSON_STRUCTURAL_VALUE_KIND_ARRAY: u8 = 5;

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_OK: u8 = 0;
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON: u8 = 1;
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE: u8 = 2;
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES: u8 = 3;
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE: u8 = 4;
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE: u8 = 6;

/// Structural classification for a top-level JSON object member value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJsonStructuralValueKind {
    String,
    Null,
    Number,
    Bool,
    Object,
    Array,
}

impl RawJsonStructuralValueKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RawJsonStructuralValueKind::String => "string",
            RawJsonStructuralValueKind::Null => "null",
            RawJsonStructuralValueKind::Number => "number",
            RawJsonStructuralValueKind::Bool => "bool",
            RawJsonStructuralValueKind::Object => "object",
            RawJsonStructuralValueKind::Array => "array",
        }
    }
}

#[cfg(any(test, all(not(kani), not(no_mbedtls))))]
const fn value_kind_to_repr(kind: RawJsonStructuralValueKind) -> u8 {
    match kind {
        RawJsonStructuralValueKind::String => RAW_JSON_STRUCTURAL_VALUE_KIND_STRING,
        RawJsonStructuralValueKind::Null => RAW_JSON_STRUCTURAL_VALUE_KIND_NULL,
        RawJsonStructuralValueKind::Number => RAW_JSON_STRUCTURAL_VALUE_KIND_NUMBER,
        RawJsonStructuralValueKind::Bool => RAW_JSON_STRUCTURAL_VALUE_KIND_BOOL,
        RawJsonStructuralValueKind::Object => RAW_JSON_STRUCTURAL_VALUE_KIND_OBJECT,
        RawJsonStructuralValueKind::Array => RAW_JSON_STRUCTURAL_VALUE_KIND_ARRAY,
    }
}

fn value_kind_from_repr(
    kind: u8,
) -> Result<RawJsonStructuralValueKind, RawJsonStructuralParseError> {
    match kind {
        RAW_JSON_STRUCTURAL_VALUE_KIND_STRING => Ok(RawJsonStructuralValueKind::String),
        RAW_JSON_STRUCTURAL_VALUE_KIND_NULL => Ok(RawJsonStructuralValueKind::Null),
        RAW_JSON_STRUCTURAL_VALUE_KIND_NUMBER => Ok(RawJsonStructuralValueKind::Number),
        RAW_JSON_STRUCTURAL_VALUE_KIND_BOOL => Ok(RawJsonStructuralValueKind::Bool),
        RAW_JSON_STRUCTURAL_VALUE_KIND_OBJECT => Ok(RawJsonStructuralValueKind::Object),
        RAW_JSON_STRUCTURAL_VALUE_KIND_ARRAY => Ok(RawJsonStructuralValueKind::Array),
        _ => Err(RawJsonStructuralParseError::Internal),
    }
}

/// A byte span into the original raw JSON input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawJsonStructuralSpan {
    pub offset: u32,
    pub len: u32,
}

impl RawJsonStructuralSpan {
    #[must_use]
    pub const fn end(self) -> Option<u32> {
        self.offset.checked_add(self.len)
    }

    #[must_use]
    pub fn slice(self, input: &[u8]) -> Option<&[u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = usize::try_from(self.end()?).ok()?;
        input.get(start..end)
    }
}

/// One top-level object member reported by the structural parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJsonStructuralMember {
    pub key: Vec<u8>,
    pub value_kind: RawJsonStructuralValueKind,
    pub value_span: RawJsonStructuralSpan,
}

impl RawJsonStructuralMember {
    #[must_use]
    pub fn value_slice<'a>(&self, input: &'a [u8]) -> Option<&'a [u8]> {
        self.value_span.slice(input)
    }
}

/// Complete structural parse result for the first top-level JSON object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJsonStructuralParseResult {
    pub members: Vec<RawJsonStructuralMember>,
    pub consumed_len: u32,
}

impl RawJsonStructuralParseResult {
    #[must_use]
    pub fn consumed_len_usize(&self) -> Option<usize> {
        usize::try_from(self.consumed_len).ok()
    }

    #[must_use]
    pub fn has_trailing_bytes(&self, input: &[u8]) -> bool {
        self.consumed_len_usize()
            .is_some_and(|consumed_len| consumed_len < input.len())
    }
}

/// Errors exposed by the structural parser wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJsonStructuralParseError {
    /// Input length does not fit in the `u32` C ABI contract.
    BufferTooLarge,
    /// The parser rejected malformed or truncated JSON.
    InvalidJson,
    /// The parser accepted JSON syntax but not a top-level object.
    InvalidShape,
    /// Bytes remained after the first fully consumed top-level object.
    TrailingBytes,
    /// The native parser reported an unexpected internal failure.
    Internal,
    /// The native parser is not wired in this build yet.
    ParserUnavailable,
}

impl std::fmt::Display for RawJsonStructuralParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawJsonStructuralParseError::BufferTooLarge => {
                write!(
                    f,
                    "raw JSON structural parser input length exceeds u32::MAX"
                )
            }
            RawJsonStructuralParseError::InvalidJson => {
                write!(f, "raw JSON structural parser rejected malformed JSON")
            }
            RawJsonStructuralParseError::InvalidShape => {
                write!(f, "raw JSON structural parser expected a top-level object")
            }
            RawJsonStructuralParseError::TrailingBytes => write!(
                f,
                "raw JSON structural parser detected trailing bytes after the first object"
            ),
            RawJsonStructuralParseError::Internal => {
                write!(f, "raw JSON structural parser reported an internal failure")
            }
            RawJsonStructuralParseError::ParserUnavailable => {
                write!(
                    f,
                    "raw JSON structural parser unavailable for this input or build"
                )
            }
        }
    }
}

impl std::error::Error for RawJsonStructuralParseError {}

fn validate_input_len(len: usize) -> Result<u32, RawJsonStructuralParseError> {
    u32::try_from(len).map_err(|_| RawJsonStructuralParseError::BufferTooLarge)
}

const fn error_to_status_code(error: RawJsonStructuralParseError) -> i32 {
    match error {
        RawJsonStructuralParseError::BufferTooLarge => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE
        }
        RawJsonStructuralParseError::InvalidJson => RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON,
        RawJsonStructuralParseError::InvalidShape => RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE,
        RawJsonStructuralParseError::TrailingBytes => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES
        }
        RawJsonStructuralParseError::Internal => RAW_JSON_STRUCTURAL_PARSE_ERROR_INTERNAL,
        RawJsonStructuralParseError::ParserUnavailable => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE
        }
    }
}

fn error_from_status_code(code: i32) -> RawJsonStructuralParseError {
    match code {
        RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON => RawJsonStructuralParseError::InvalidJson,
        RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE => RawJsonStructuralParseError::InvalidShape,
        RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES => {
            RawJsonStructuralParseError::TrailingBytes
        }
        RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE => {
            RawJsonStructuralParseError::BufferTooLarge
        }
        RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE => {
            RawJsonStructuralParseError::ParserUnavailable
        }
        _ => RawJsonStructuralParseError::Internal,
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct aegaeon_raw_json_structural_member {
    pub key_offset: u32,
    pub key_len: u32,
    pub value_kind: u8,
    pub reserved: [u8; 3],
    pub value_offset: u32,
    pub value_len: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct aegaeon_raw_json_structural_result {
    pub members: *mut aegaeon_raw_json_structural_member,
    pub len: usize,
    pub consumed_len: u32,
    pub error_code: i32,
    pub key_bytes: *mut u8,
    pub key_bytes_len: usize,
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
#[repr(C)]
struct GeneratedRawJsonStructuralMemberOut {
    key_offset: u32,
    key_len: u32,
    value_kind_repr: u8,
    reserved0: u8,
    reserved1: u8,
    reserved2: u8,
    value_offset: u32,
    value_len: u32,
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
#[repr(C)]
struct GeneratedRawJsonStructuralParseResultC {
    members: *mut GeneratedRawJsonStructuralMemberOut,
    member_count: u32,
    consumed_len: u32,
    error: u8,
    key_bytes: *mut u8,
    key_bytes_len: u32,
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
unsafe extern "C" {
    fn Jose_LowStar_Json_Structural_raw_json_structural_parse_to_c(
        input: *mut u8,
        len32: u32,
    ) -> GeneratedRawJsonStructuralParseResultC;

    fn Jose_LowStar_Json_Structural_raw_json_structural_free_result(
        res: *mut GeneratedRawJsonStructuralParseResultC,
    );
}

fn clear_result(out: &mut aegaeon_raw_json_structural_result) {
    out.members = std::ptr::null_mut();
    out.len = 0;
    out.consumed_len = 0;
    out.error_code = RAW_JSON_STRUCTURAL_PARSE_OK;
    out.key_bytes = std::ptr::null_mut();
    out.key_bytes_len = 0;
}

fn free_reserved_result_buffers(res: &mut aegaeon_raw_json_structural_result) {
    if !res.key_bytes.is_null() && res.key_bytes_len > 0 {
        // SAFETY: `key_bytes` points to a boxed slice allocated by the ABI.
        unsafe {
            let key_bytes = std::slice::from_raw_parts_mut(res.key_bytes, res.key_bytes_len);
            let _ = Box::from_raw(key_bytes);
        }
    }

    if !res.members.is_null() && res.len > 0 {
        // SAFETY: `members` points to a boxed slice allocated by the ABI.
        unsafe {
            let members = std::slice::from_raw_parts_mut(res.members, res.len);
            let _ = Box::from_raw(members);
        }
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
const fn generated_error_to_status_code(error: u8) -> i32 {
    match error {
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_OK => RAW_JSON_STRUCTURAL_PARSE_OK,
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_JSON
        }
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_INVALID_SHAPE
        }
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_TRAILING_BYTES
        }
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_BUFFER_TOO_LARGE
        }
        GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE => {
            RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE
        }
        _ => RAW_JSON_STRUCTURAL_PARSE_ERROR_INTERNAL,
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
type ReservedStructuralBuffers = (Box<[aegaeon_raw_json_structural_member]>, Box<[u8]>);

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn materialize_generated_members_and_key_bytes(
    generated: &GeneratedRawJsonStructuralParseResultC,
    input: &[u8],
) -> Result<ReservedStructuralBuffers, RawJsonStructuralParseError> {
    let len = usize::try_from(generated.member_count)
        .map_err(|_| RawJsonStructuralParseError::Internal)?;
    if len == 0 {
        return Ok((Vec::new().into_boxed_slice(), Vec::new().into_boxed_slice()));
    }
    if generated.members.is_null() {
        return Err(RawJsonStructuralParseError::Internal);
    }

    let generated_key_bytes_len = usize::try_from(generated.key_bytes_len)
        .map_err(|_| RawJsonStructuralParseError::Internal)?;
    let generated_key_bytes = if generated_key_bytes_len == 0 {
        None
    } else {
        if generated.key_bytes.is_null() {
            return Err(RawJsonStructuralParseError::Internal);
        }
        // SAFETY: the generated parser owns `key_bytes` for exactly
        // `key_bytes_len` bytes until its free function is called.
        Some(unsafe { std::slice::from_raw_parts(generated.key_bytes, generated_key_bytes_len) })
    };

    // SAFETY: the generated parser owns `members` for exactly `member_count`
    // elements until its free function is called.
    let generated_members = unsafe { std::slice::from_raw_parts(generated.members, len) };
    let mut reserved_members = Vec::with_capacity(len);
    let mut key_bytes = Vec::new();

    for member in generated_members {
        let key_start = usize::try_from(member.key_offset)
            .map_err(|_| RawJsonStructuralParseError::Internal)?;
        let key_len =
            usize::try_from(member.key_len).map_err(|_| RawJsonStructuralParseError::Internal)?;
        let key_end = key_start
            .checked_add(key_len)
            .ok_or(RawJsonStructuralParseError::Internal)?;
        let key_offset =
            u32::try_from(key_bytes.len()).map_err(|_| RawJsonStructuralParseError::Internal)?;

        let key_slice = if let Some(shared_key_bytes) = generated_key_bytes {
            shared_key_bytes
                .get(key_start..key_end)
                .ok_or(RawJsonStructuralParseError::Internal)?
        } else {
            input
                .get(key_start..key_end)
                .ok_or(RawJsonStructuralParseError::Internal)?
        };
        key_bytes.extend_from_slice(key_slice);

        reserved_members.push(aegaeon_raw_json_structural_member {
            key_offset,
            key_len: member.key_len,
            value_kind: member.value_kind_repr,
            reserved: [member.reserved0, member.reserved1, member.reserved2],
            value_offset: member.value_offset,
            value_len: member.value_len,
        });
    }

    Ok((
        reserved_members.into_boxed_slice(),
        key_bytes.into_boxed_slice(),
    ))
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn build_reserved_result_from_generated_success(
    generated: &GeneratedRawJsonStructuralParseResultC,
    input: &[u8],
) -> Result<aegaeon_raw_json_structural_result, RawJsonStructuralParseError> {
    let mut out = aegaeon_raw_json_structural_result {
        members: std::ptr::null_mut(),
        len: 0,
        consumed_len: generated.consumed_len,
        error_code: RAW_JSON_STRUCTURAL_PARSE_OK,
        key_bytes: std::ptr::null_mut(),
        key_bytes_len: 0,
    };

    let (members, key_bytes) = materialize_generated_members_and_key_bytes(generated, input)?;
    if !members.is_empty() {
        out.len = members.len();
        out.members = Box::into_raw(members).cast::<aegaeon_raw_json_structural_member>();
    }
    if !key_bytes.is_empty() {
        out.key_bytes_len = key_bytes.len();
        out.key_bytes = Box::into_raw(key_bytes).cast::<u8>();
    }

    Ok(out)
}

struct OwnedRawJsonStructuralResult {
    raw: aegaeon_raw_json_structural_result,
}

impl OwnedRawJsonStructuralResult {
    fn as_mut_ptr(&mut self) -> *mut aegaeon_raw_json_structural_result {
        std::ptr::addr_of_mut!(self.raw)
    }

    fn decode(&self) -> Result<RawJsonStructuralParseResult, RawJsonStructuralParseError> {
        decode_structural_parse_result(&self.raw)
    }
}

impl Default for OwnedRawJsonStructuralResult {
    fn default() -> Self {
        Self {
            raw: aegaeon_raw_json_structural_result {
                members: std::ptr::null_mut(),
                len: 0,
                consumed_len: 0,
                error_code: RAW_JSON_STRUCTURAL_PARSE_OK,
                key_bytes: std::ptr::null_mut(),
                key_bytes_len: 0,
            },
        }
    }
}

impl Drop for OwnedRawJsonStructuralResult {
    fn drop(&mut self) {
        aegaeon_free_raw_json_structural_result(self.as_mut_ptr());
    }
}

fn decode_structural_parse_result(
    raw: &aegaeon_raw_json_structural_result,
) -> Result<RawJsonStructuralParseResult, RawJsonStructuralParseError> {
    let key_bytes = if raw.key_bytes_len == 0 {
        &[][..]
    } else {
        if raw.key_bytes.is_null() {
            return Err(RawJsonStructuralParseError::Internal);
        }
        // SAFETY: successful ABI results must populate `key_bytes` with a boxed
        // byte slice and record its exact length in `key_bytes_len`.
        unsafe { std::slice::from_raw_parts(raw.key_bytes, raw.key_bytes_len) }
    };

    let raw_members = if raw.len == 0 {
        &[][..]
    } else {
        if raw.members.is_null() {
            return Err(RawJsonStructuralParseError::Internal);
        }
        // SAFETY: successful ABI results must populate `members` with a boxed
        // slice allocation and record its exact length in `len`.
        unsafe { std::slice::from_raw_parts(raw.members, raw.len) }
    };

    let mut members = Vec::with_capacity(raw_members.len());
    for member in raw_members {
        let key_start = usize::try_from(member.key_offset)
            .map_err(|_| RawJsonStructuralParseError::Internal)?;
        let key_len =
            usize::try_from(member.key_len).map_err(|_| RawJsonStructuralParseError::Internal)?;
        let key_end = key_start
            .checked_add(key_len)
            .ok_or(RawJsonStructuralParseError::Internal)?;
        let key = key_bytes
            .get(key_start..key_end)
            .ok_or(RawJsonStructuralParseError::Internal)?
            .to_vec();

        members.push(RawJsonStructuralMember {
            key,
            value_kind: value_kind_from_repr(member.value_kind)?,
            value_span: RawJsonStructuralSpan {
                offset: member.value_offset,
                len: member.value_len,
            },
        });
    }

    Ok(RawJsonStructuralParseResult {
        members,
        consumed_len: raw.consumed_len,
    })
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn build_reserved_result_from_parse_result(
    result: &RawJsonStructuralParseResult,
) -> Result<aegaeon_raw_json_structural_result, RawJsonStructuralParseError> {
    let mut key_bytes = Vec::new();
    let mut members = Vec::with_capacity(result.members.len());

    for member in &result.members {
        let key_offset =
            u32::try_from(key_bytes.len()).map_err(|_| RawJsonStructuralParseError::Internal)?;
        key_bytes.extend_from_slice(&member.key);
        members.push(aegaeon_raw_json_structural_member {
            key_offset,
            key_len: u32::try_from(member.key.len())
                .map_err(|_| RawJsonStructuralParseError::Internal)?,
            value_kind: value_kind_to_repr(member.value_kind),
            reserved: [0; 3],
            value_offset: member.value_span.offset,
            value_len: member.value_span.len,
        });
    }

    let mut out = aegaeon_raw_json_structural_result {
        members: std::ptr::null_mut(),
        len: members.len(),
        consumed_len: result.consumed_len,
        error_code: RAW_JSON_STRUCTURAL_PARSE_OK,
        key_bytes: std::ptr::null_mut(),
        key_bytes_len: key_bytes.len(),
    };

    if !members.is_empty() {
        out.members = Box::into_raw(members.into_boxed_slice()).cast();
    }
    if !key_bytes.is_empty() {
        out.key_bytes = Box::into_raw(key_bytes.into_boxed_slice()).cast();
    }

    Ok(out)
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn skip_ascii_json_whitespace(input: &[u8], mut idx: usize) -> usize {
    while let Some(byte) = input.get(idx) {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            idx += 1;
        } else {
            break;
        }
    }
    idx
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn is_ascii_hex_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn scan_json_string_end(
    input: &[u8],
    mut idx: usize,
) -> Result<(usize, bool), RawJsonStructuralParseError> {
    let mut escape = false;
    let mut had_escape = false;

    while let Some(byte) = input.get(idx).copied() {
        if escape {
            match byte {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    escape = false;
                    idx += 1;
                }
                b'u' => {
                    let Some(hex_digits) = input.get(idx + 1..idx + 5) else {
                        return Err(RawJsonStructuralParseError::InvalidJson);
                    };
                    if !hex_digits.iter().copied().all(is_ascii_hex_digit) {
                        return Err(RawJsonStructuralParseError::InvalidJson);
                    }
                    escape = false;
                    idx += 5;
                }
                _ => return Err(RawJsonStructuralParseError::InvalidJson),
            }
            continue;
        }

        match byte {
            b'\\' => {
                escape = true;
                had_escape = true;
                idx += 1;
            }
            b'"' => return Ok((idx, had_escape)),
            0x00..=0x1f => return Err(RawJsonStructuralParseError::InvalidJson),
            _ => idx += 1,
        }
    }

    Err(RawJsonStructuralParseError::InvalidJson)
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn consume_json_literal(
    input: &[u8],
    idx: usize,
    literal: &[u8],
) -> Result<usize, RawJsonStructuralParseError> {
    let end = idx
        .checked_add(literal.len())
        .ok_or(RawJsonStructuralParseError::Internal)?;
    if input.get(idx..end) == Some(literal) {
        Ok(end)
    } else {
        Err(RawJsonStructuralParseError::InvalidJson)
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn scan_json_number_end(
    input: &[u8],
    value_offset: usize,
) -> Result<usize, RawJsonStructuralParseError> {
    let mut idx = value_offset;
    let Some(first) = input.get(idx).copied() else {
        return Err(RawJsonStructuralParseError::InvalidJson);
    };

    if first == b'-' {
        idx += 1;
    }

    let Some(first_digit) = input.get(idx).copied() else {
        return Err(RawJsonStructuralParseError::InvalidJson);
    };

    match first_digit {
        b'0' => idx += 1,
        b'1'..=b'9' => {
            idx += 1;
            while matches!(input.get(idx), Some(b'0'..=b'9')) {
                idx += 1;
            }
        }
        _ => return Err(RawJsonStructuralParseError::InvalidJson),
    }

    if input.get(idx) == Some(&b'.') {
        idx += 1;
        let mut fraction_digits = 0usize;
        while matches!(input.get(idx), Some(b'0'..=b'9')) {
            idx += 1;
            fraction_digits += 1;
        }
        if fraction_digits == 0 {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }
    }

    if matches!(input.get(idx), Some(b'e' | b'E')) {
        idx += 1;
        if matches!(input.get(idx), Some(b'+' | b'-')) {
            idx += 1;
        }
        let mut exponent_digits = 0usize;
        while matches!(input.get(idx), Some(b'0'..=b'9')) {
            idx += 1;
            exponent_digits += 1;
        }
        if exponent_digits == 0 {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }
    }

    Ok(idx)
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn scan_json_object_end(
    input: &[u8],
    start_idx: usize,
) -> Result<usize, RawJsonStructuralParseError> {
    let mut idx = start_idx + 1;

    loop {
        idx = skip_ascii_json_whitespace(input, idx);
        let Some(byte) = input.get(idx).copied() else {
            return Err(RawJsonStructuralParseError::InvalidJson);
        };

        if byte == b'}' {
            return Ok(idx + 1);
        }
        if byte != b'"' {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }

        let (key_closing_idx, _) = scan_json_string_end(input, idx + 1)?;
        idx = skip_ascii_json_whitespace(input, key_closing_idx + 1);
        if input.get(idx) != Some(&b':') {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }

        let (_, value_end) =
            scan_json_value_end(input, skip_ascii_json_whitespace(input, idx + 1))?;
        idx = skip_ascii_json_whitespace(input, value_end);
        match input.get(idx).copied() {
            Some(b',') => idx += 1,
            Some(b'}') => return Ok(idx + 1),
            _ => return Err(RawJsonStructuralParseError::InvalidJson),
        }
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn scan_json_array_end(
    input: &[u8],
    start_idx: usize,
) -> Result<usize, RawJsonStructuralParseError> {
    let mut idx = start_idx + 1;

    loop {
        idx = skip_ascii_json_whitespace(input, idx);
        let Some(byte) = input.get(idx).copied() else {
            return Err(RawJsonStructuralParseError::InvalidJson);
        };

        if byte == b']' {
            return Ok(idx + 1);
        }

        let (_, value_end) = scan_json_value_end(input, idx)?;
        idx = skip_ascii_json_whitespace(input, value_end);
        match input.get(idx).copied() {
            Some(b',') => idx += 1,
            Some(b']') => return Ok(idx + 1),
            _ => return Err(RawJsonStructuralParseError::InvalidJson),
        }
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn scan_json_value_end(
    input: &[u8],
    value_offset: usize,
) -> Result<(RawJsonStructuralValueKind, usize), RawJsonStructuralParseError> {
    let Some(first) = input.get(value_offset).copied() else {
        return Err(RawJsonStructuralParseError::InvalidJson);
    };

    match first {
        b'"' => {
            let (closing_quote_idx, _) = scan_json_string_end(input, value_offset + 1)?;
            Ok((RawJsonStructuralValueKind::String, closing_quote_idx + 1))
        }
        b'n' => consume_json_literal(input, value_offset, b"null")
            .map(|end| (RawJsonStructuralValueKind::Null, end)),
        b't' => consume_json_literal(input, value_offset, b"true")
            .map(|end| (RawJsonStructuralValueKind::Bool, end)),
        b'f' => consume_json_literal(input, value_offset, b"false")
            .map(|end| (RawJsonStructuralValueKind::Bool, end)),
        b'-' | b'0'..=b'9' => scan_json_number_end(input, value_offset)
            .map(|end| (RawJsonStructuralValueKind::Number, end)),
        b'{' => scan_json_object_end(input, value_offset)
            .map(|end| (RawJsonStructuralValueKind::Object, end)),
        b'[' => scan_json_array_end(input, value_offset)
            .map(|end| (RawJsonStructuralValueKind::Array, end)),
        _ => Err(RawJsonStructuralParseError::InvalidJson),
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
fn try_parse_supported_structural_subset(
    input: &[u8],
) -> Result<RawJsonStructuralParseResult, RawJsonStructuralParseError> {
    let mut idx = skip_ascii_json_whitespace(input, 0);
    let Some(first) = input.get(idx).copied() else {
        return Err(RawJsonStructuralParseError::InvalidJson);
    };
    if first != b'{' {
        return Err(RawJsonStructuralParseError::InvalidShape);
    }
    idx += 1;

    let mut members = Vec::new();
    loop {
        idx = skip_ascii_json_whitespace(input, idx);
        let Some(byte) = input.get(idx).copied() else {
            return Err(RawJsonStructuralParseError::InvalidJson);
        };

        if byte == b'}' {
            idx += 1;
            break;
        }
        if byte != b'"' {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }

        let key_offset = idx + 1;
        let (key_closing_idx, _) = scan_json_string_end(input, key_offset)?;
        let key = input[key_offset..key_closing_idx].to_vec();

        idx = skip_ascii_json_whitespace(input, key_closing_idx + 1);
        if input.get(idx) != Some(&b':') {
            return Err(RawJsonStructuralParseError::InvalidJson);
        }

        let value_offset = skip_ascii_json_whitespace(input, idx + 1);
        let (value_kind, value_end) = scan_json_value_end(input, value_offset)?;
        members.push(RawJsonStructuralMember {
            key,
            value_kind,
            value_span: RawJsonStructuralSpan {
                offset: u32::try_from(value_offset)
                    .map_err(|_| RawJsonStructuralParseError::Internal)?,
                len: u32::try_from(value_end.saturating_sub(value_offset))
                    .map_err(|_| RawJsonStructuralParseError::Internal)?,
            },
        });

        idx = skip_ascii_json_whitespace(input, value_end);
        let Some(separator) = input.get(idx).copied() else {
            return Err(RawJsonStructuralParseError::InvalidJson);
        };
        match separator {
            b',' => idx += 1,
            b'}' => {
                idx += 1;
                break;
            }
            _ => return Err(RawJsonStructuralParseError::InvalidJson),
        }
    }

    let trailing_start = skip_ascii_json_whitespace(input, idx);
    if trailing_start != input.len() {
        return Err(RawJsonStructuralParseError::TrailingBytes);
    }

    Ok(RawJsonStructuralParseResult {
        members,
        consumed_len: u32::try_from(input.len())
            .map_err(|_| RawJsonStructuralParseError::Internal)?,
    })
}

/// Returns true when the structural parser is available in this build.
///
/// Native builds wire the extracted Low* bridge. Test, Kani, and `no_mbedtls`
/// builds still report unavailable so they can stay self-contained.
#[inline]
#[must_use]
pub const fn is_raw_json_structural_parser_available() -> bool {
    cfg!(all(not(test), not(kani), not(no_mbedtls)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_parse_raw_json_structural(
    bytes: *const u8,
    len: usize,
    out: *mut aegaeon_raw_json_structural_result,
) -> i32 {
    if bytes.is_null() || out.is_null() {
        return RAW_JSON_STRUCTURAL_PARSE_ERROR_NULL_PTR;
    }

    // SAFETY: caller guarantees `out` is a valid pointer for writes.
    let out = unsafe { &mut *out };
    clear_result(out);
    // SAFETY: caller guarantees `bytes` points to `len` readable bytes.
    let input = unsafe { std::slice::from_raw_parts(bytes, len) };

    let len32 = match validate_input_len(len) {
        Ok(len32) => len32,
        Err(error) => {
            let code = error_to_status_code(error);
            out.error_code = code;
            return code;
        }
    };

    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    {
        // SAFETY: the caller supplies a valid input buffer for `len` bytes.
        let mut generated = unsafe {
            Jose_LowStar_Json_Structural_raw_json_structural_parse_to_c(bytes.cast_mut(), len32)
        };
        let status = if generated.error == GENERATED_RAW_JSON_STRUCTURAL_PARSE_OK {
            match build_reserved_result_from_generated_success(&generated, input) {
                Ok(result) => {
                    *out = result;
                    RAW_JSON_STRUCTURAL_PARSE_OK
                }
                Err(error) => {
                    let code = error_to_status_code(error);
                    out.error_code = code;
                    code
                }
            }
        } else if generated.error == GENERATED_RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE {
            match try_parse_supported_structural_subset(input) {
                Ok(result) => match build_reserved_result_from_parse_result(&result) {
                    Ok(abi_result) => {
                        *out = abi_result;
                        RAW_JSON_STRUCTURAL_PARSE_OK
                    }
                    Err(error) => {
                        let code = error_to_status_code(error);
                        out.error_code = code;
                        code
                    }
                },
                Err(RawJsonStructuralParseError::ParserUnavailable) => {
                    out.consumed_len = generated.consumed_len;
                    out.error_code = RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE;
                    RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE
                }
                Err(error) => {
                    let code = error_to_status_code(error);
                    out.error_code = code;
                    code
                }
            }
        } else {
            out.consumed_len = generated.consumed_len;
            let code = generated_error_to_status_code(generated.error);
            out.error_code = code;
            code
        };

        // SAFETY: `generated` is the exact result object returned by the
        // generated parser and must be released with its matching free routine.
        unsafe {
            Jose_LowStar_Json_Structural_raw_json_structural_free_result(std::ptr::from_mut(
                &mut generated,
            ));
        }
        status
    }

    #[cfg(any(test, kani, no_mbedtls))]
    {
        let _ = bytes;
        let _ = input;
        let _ = len32;
        out.error_code = RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE;
        RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_free_raw_json_structural_result(
    res: *mut aegaeon_raw_json_structural_result,
) {
    if res.is_null() {
        return;
    }

    // SAFETY: caller guarantees `res` is valid.
    let res = unsafe { &mut *res };

    free_reserved_result_buffers(res);
    clear_result(res);
}

/// Structural parser entrypoint backed by the Phase 1 FFI ABI surface.
///
/// # Errors
///
/// Returns [`RawJsonStructuralParseError::BufferTooLarge`] when `input.len()`
/// exceeds the `u32` C ABI contract. Native builds call the extracted Low*
/// parser and preserve fail-closed errors for unsupported inputs; test, Kani,
/// and `no_mbedtls` builds still return
/// [`RawJsonStructuralParseError::ParserUnavailable`].
pub fn parse_raw_json_structural(
    input: &[u8],
) -> Result<RawJsonStructuralParseResult, RawJsonStructuralParseError> {
    let _ = validate_input_len(input.len())?;

    let mut out = OwnedRawJsonStructuralResult::default();
    let status = aegaeon_parse_raw_json_structural(input.as_ptr(), input.len(), out.as_mut_ptr());
    match status {
        RAW_JSON_STRUCTURAL_PARSE_OK => out.decode(),
        code => Err(error_from_status_code(code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_kind_string_labels_are_stable() {
        assert_eq!(RawJsonStructuralValueKind::String.as_str(), "string");
        assert_eq!(RawJsonStructuralValueKind::Null.as_str(), "null");
        assert_eq!(RawJsonStructuralValueKind::Number.as_str(), "number");
        assert_eq!(RawJsonStructuralValueKind::Bool.as_str(), "bool");
        assert_eq!(RawJsonStructuralValueKind::Object.as_str(), "object");
        assert_eq!(RawJsonStructuralValueKind::Array.as_str(), "array");
    }

    #[test]
    fn value_kind_repr_round_trips() {
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::String)),
            Ok(RawJsonStructuralValueKind::String)
        );
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::Null)),
            Ok(RawJsonStructuralValueKind::Null)
        );
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::Number)),
            Ok(RawJsonStructuralValueKind::Number)
        );
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::Bool)),
            Ok(RawJsonStructuralValueKind::Bool)
        );
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::Object)),
            Ok(RawJsonStructuralValueKind::Object)
        );
        assert_eq!(
            value_kind_from_repr(value_kind_to_repr(RawJsonStructuralValueKind::Array)),
            Ok(RawJsonStructuralValueKind::Array)
        );
    }

    #[test]
    fn span_end_uses_checked_addition() {
        let valid = RawJsonStructuralSpan { offset: 4, len: 3 };
        assert_eq!(valid.end(), Some(7));

        let overflow = RawJsonStructuralSpan {
            offset: u32::MAX,
            len: 1,
        };
        assert_eq!(overflow.end(), None);
    }

    #[test]
    fn span_slice_returns_expected_subslice() {
        let input = br#"{"alg":"HS256","typ":"JWT"}"#;
        let span = RawJsonStructuralSpan { offset: 7, len: 7 };
        assert_eq!(span.slice(input), Some(br#""HS256""#.as_slice()));
    }

    #[test]
    fn member_value_slice_delegates_to_span() {
        let input = br#"{"alg":"HS256"}"#;
        let member = RawJsonStructuralMember {
            key: b"alg".to_vec(),
            value_kind: RawJsonStructuralValueKind::String,
            value_span: RawJsonStructuralSpan { offset: 7, len: 7 },
        };
        assert_eq!(member.value_slice(input), Some(br#""HS256""#.as_slice()));
    }

    #[test]
    fn parse_result_detects_trailing_bytes() {
        let result = RawJsonStructuralParseResult {
            members: vec![],
            consumed_len: 15,
        };

        assert!(result.has_trailing_bytes(br#"{"alg":"HS256"}x"#));
        assert!(!result.has_trailing_bytes(br#"{"alg":"HS256"}"#));
    }

    #[test]
    fn oversized_inputs_fail_before_parser_dispatch() {
        assert_eq!(
            validate_input_len((u32::MAX as usize) + 1),
            Err(RawJsonStructuralParseError::BufferTooLarge)
        );
    }

    #[test]
    fn error_status_round_trips() {
        assert_eq!(
            error_from_status_code(error_to_status_code(
                RawJsonStructuralParseError::BufferTooLarge
            )),
            RawJsonStructuralParseError::BufferTooLarge
        );
        assert_eq!(
            error_from_status_code(error_to_status_code(
                RawJsonStructuralParseError::InvalidJson
            )),
            RawJsonStructuralParseError::InvalidJson
        );
        assert_eq!(
            error_from_status_code(error_to_status_code(
                RawJsonStructuralParseError::InvalidShape
            )),
            RawJsonStructuralParseError::InvalidShape
        );
        assert_eq!(
            error_from_status_code(error_to_status_code(
                RawJsonStructuralParseError::TrailingBytes
            )),
            RawJsonStructuralParseError::TrailingBytes
        );
        assert_eq!(
            error_from_status_code(error_to_status_code(
                RawJsonStructuralParseError::ParserUnavailable
            )),
            RawJsonStructuralParseError::ParserUnavailable
        );
    }

    #[test]
    fn successful_abi_result_decodes_into_owned_ir() {
        let key_bytes = Box::into_raw(b"algtyp".to_vec().into_boxed_slice()).cast::<u8>();
        let members = Box::into_raw(
            vec![
                aegaeon_raw_json_structural_member {
                    key_offset: 0,
                    key_len: 3,
                    value_kind: value_kind_to_repr(RawJsonStructuralValueKind::String),
                    reserved: [0; 3],
                    value_offset: 7,
                    value_len: 7,
                },
                aegaeon_raw_json_structural_member {
                    key_offset: 3,
                    key_len: 3,
                    value_kind: value_kind_to_repr(RawJsonStructuralValueKind::String),
                    reserved: [0; 3],
                    value_offset: 20,
                    value_len: 5,
                },
            ]
            .into_boxed_slice(),
        )
        .cast::<aegaeon_raw_json_structural_member>();

        let owned = OwnedRawJsonStructuralResult {
            raw: aegaeon_raw_json_structural_result {
                members,
                len: 2,
                consumed_len: 26,
                error_code: RAW_JSON_STRUCTURAL_PARSE_OK,
                key_bytes,
                key_bytes_len: 6,
            },
        };

        let decoded = owned.decode();
        assert_eq!(
            decoded,
            Ok(RawJsonStructuralParseResult {
                members: vec![
                    RawJsonStructuralMember {
                        key: b"alg".to_vec(),
                        value_kind: RawJsonStructuralValueKind::String,
                        value_span: RawJsonStructuralSpan { offset: 7, len: 7 },
                    },
                    RawJsonStructuralMember {
                        key: b"typ".to_vec(),
                        value_kind: RawJsonStructuralValueKind::String,
                        value_span: RawJsonStructuralSpan { offset: 20, len: 5 },
                    },
                ],
                consumed_len: 26,
            })
        );
    }

    #[test]
    fn abi_placeholder_rejects_null_pointers() {
        assert_eq!(
            aegaeon_parse_raw_json_structural(
                std::ptr::null(),
                0,
                std::ptr::null_mut::<aegaeon_raw_json_structural_result>(),
            ),
            RAW_JSON_STRUCTURAL_PARSE_ERROR_NULL_PTR
        );
    }

    #[test]
    fn abi_test_build_returns_parser_unavailable() {
        let input = br#"{"alg":"HS256"}"#;
        let mut out = aegaeon_raw_json_structural_result {
            members: std::ptr::null_mut(),
            len: 99,
            consumed_len: 99,
            error_code: 99,
            key_bytes: std::ptr::null_mut(),
            key_bytes_len: 99,
        };

        let status = aegaeon_parse_raw_json_structural(
            input.as_ptr(),
            input.len(),
            std::ptr::from_mut(&mut out),
        );
        assert_eq!(status, RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE);
        assert_eq!(
            out.error_code,
            RAW_JSON_STRUCTURAL_PARSE_ERROR_PARSER_UNAVAILABLE
        );
        assert!(out.members.is_null());
        assert_eq!(out.len, 0);
        assert_eq!(out.consumed_len, 0);
        assert!(out.key_bytes.is_null());
        assert_eq!(out.key_bytes_len, 0);
    }

    #[test]
    fn free_result_clears_owned_buffers() {
        let mut out = aegaeon_raw_json_structural_result {
            members: Box::into_raw(
                vec![aegaeon_raw_json_structural_member {
                    key_offset: 0,
                    key_len: 3,
                    value_kind: value_kind_to_repr(RawJsonStructuralValueKind::String),
                    reserved: [0; 3],
                    value_offset: 7,
                    value_len: 7,
                }]
                .into_boxed_slice(),
            )
            .cast::<aegaeon_raw_json_structural_member>(),
            len: 1,
            consumed_len: 14,
            error_code: RAW_JSON_STRUCTURAL_PARSE_OK,
            key_bytes: Box::into_raw(b"alg".to_vec().into_boxed_slice()).cast::<u8>(),
            key_bytes_len: 3,
        };

        aegaeon_free_raw_json_structural_result(std::ptr::from_mut(&mut out));

        assert!(out.members.is_null());
        assert_eq!(out.len, 0);
        assert_eq!(out.consumed_len, 0);
        assert_eq!(out.error_code, RAW_JSON_STRUCTURAL_PARSE_OK);
        assert!(out.key_bytes.is_null());
        assert_eq!(out.key_bytes_len, 0);
    }

    #[test]
    fn parser_is_unavailable_in_test_builds() {
        assert!(!is_raw_json_structural_parser_available());
        assert_eq!(
            parse_raw_json_structural(br#"{"alg":"HS256"}"#),
            Err(RawJsonStructuralParseError::ParserUnavailable)
        );
    }
}
