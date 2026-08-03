//! Raw JSON structural parser contracts.
//!
//! These types are the Rust-side landing zone for the Phase 1 verified
//! structural parser work. They deliberately stop at structural information:
//! top-level member order, value kind, and raw byte spans.
//!
//! They are not yet claim-bearing by themselves. The current released raw JSON
//! claim boundary remains defined by `crate::raw_json`.

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
}
