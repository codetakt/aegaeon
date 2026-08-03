module Jose.HeaderParser

/// Facade module that re-exports all definitions from the split sub-modules.
/// Module-level compatibility is preserved: `open Jose.HeaderParser` and
/// `module Parser = Jose.HeaderParser` continue to work.  However, the
/// function-level API has a breaking change — see below.
///
/// **Breaking API change (v0.9):** The buffer-based functions
/// (parse_jwe_buffer, parse_jws_buffer taking `LowStar.Buffer.buffer UInt8.t`)
/// have been removed.  The replacement is the seq-based API:
/// `parse_jwe_seq` / `parse_jws_seq` (taking `FStar.Seq.seq UInt8.t`).
/// `LowStar.Buffer.as_seq` is GTot so a correct Tot-effect buffer wrapper
/// cannot be provided without an assume val — which is the unsound
/// `read_u8_safe` that this refactoring eliminates.
///
/// Callers holding a buffer in Stack context should snapshot the heap
/// and project the ghost sequence for use in specifications (pseudocode):
///   `let h = FStar.HyperStack.ST.get () in`
///   `let s = LowStar.Buffer.as_seq h b in`
///   `... parse_jwe_seq s (LowStar.Buffer.length b) ...`
///
/// Internal structure:
///   Jose.HeaderParser.Assumptions — empty (read_u8_safe eliminated)
///   Jose.HeaderParser.Spec        — pure (Tot) TLV parser on seq UInt8.t
///   Jose.HeaderParser.TLV         — EverParse ref + backward-compat aliases
///                                    (re-exports Spec via `include`)
///   Jose.HeaderParser.Proofs      — standalone correctness lemmas

include Jose.HeaderParser.Assumptions
include Jose.HeaderParser.TLV       // TLV includes Spec; no separate Spec include needed
include Jose.HeaderParser.Proofs
