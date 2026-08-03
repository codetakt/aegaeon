module Jose.HeaderParser.Assumptions

/// Trust boundary module — previously contained `read_u8_safe` (assume val).
///
/// The assume val has been eliminated by the Spec/Stack refactoring:
///   - Jose.HeaderParser.Spec uses `Seq.index` (pure Tot) instead of buffer reads
///   - Buffer-level access is confined to Jose.HeaderParser.TLV (Stack effect)
///
/// This module is retained as an empty placeholder for backward compatibility
/// (Jose.HeaderParser facade includes it).
