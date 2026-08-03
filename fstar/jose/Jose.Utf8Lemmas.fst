module Jose.Utf8Lemmas

/// Facade module that re-exports all definitions from the split sub-modules.
/// This preserves backwards compatibility with all existing consumers that
/// `open Jose.Utf8Lemmas`.
///
/// Internal structure:
///   Jose.Utf8          — base types, constants, helpers
///   Jose.Utf8.Validity — validation predicates + canonical bounds lemmas
///   Jose.Utf8.Encoding — encoding functions + length lemmas
///   Jose.Utf8.Lemmas   — decode functions + roundtrip + cross-cutting lemmas

include Jose.Utf8
include Jose.Utf8.Validity
include Jose.Utf8.Encoding
include Jose.Utf8.Lemmas
