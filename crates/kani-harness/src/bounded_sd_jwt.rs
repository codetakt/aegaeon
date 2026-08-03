//! Bounded SD-JWT types for Kani verification (Byte Array Version)
//!
//! Models the core SD-JWT (RFC 9901) data structures using fixed-size byte
//! arrays.  Avoids `String`, `serde_json`, `sha2`, `base64` to sidestep
//! Kani 0.66.0 ICE on heap-allocated types.
//!
//! **Design**: Mirrors `crates/jose/src/sd_jwt.rs` structure but replaces
//! `String`/`serde_json::Value` with `ByteString` for tractable BMC.
//!
//! **Encoding Model**: Real SD-JWT uses `base64url(json([salt, name, value]))`.
//! The bounded model uses length-prefixed binary:
//!   `[salt_len, salt..., name_len, name..., value_len, value...]`
//! This preserves injectivity (encode is invertible), so using the encoded
//! form as the digest is collision-free within the bounded input domain.
//!
//! **Verified Properties** (via harnesses in `lib.rs`):
//! 1. Disclosure roundtrip: encode → decode → identity
//! 2. Digest uniqueness: different disclosures → different digests
//! 3. Issuer payload: SD claims produce `_sd` digests
//! 4. Verifier reconstruction: all disclosures → all claims restored
//! 5. Holder selection: partial selection → partial disclosure
//! 6. Format parsing: serialize → parse → identity

use super::bounded_stores::ByteString;

/// Maximum number of selectively-disclosed claims in the bounded model.
pub const MAX_SD_CLAIMS: usize = 4;

/// Separator byte in the compound SD-JWT format (models `~`).
const FORMAT_SEP: u8 = b'~';

// ============================================================================
// Utility
// ============================================================================

/// Byte-by-byte comparison of two `ByteString`s (Kani-friendly, no slice eq).
pub fn bytestrings_equal(a: &ByteString, b: &ByteString) -> bool {
    if !a.valid || !b.valid {
        return false;
    }
    if a.len != b.len {
        return false;
    }
    let mut i = 0;
    while i < a.len {
        if a.data[i] != b.data[i] {
            return false;
        }
        i += 1;
    }
    true
}

// ============================================================================
// BoundedDisclosure
// ============================================================================

/// A single SD-JWT disclosure modeled as three byte strings.
///
/// Production equivalent: `Disclosure { salt, claim_name, claim_value }`
/// Encoding: length-prefixed binary (models base64url(json([salt, name, value])))
#[derive(Debug, Clone, Copy)]
pub struct BoundedDisclosure {
    pub salt: ByteString,
    pub claim_name: ByteString,
    pub claim_value: ByteString,
    pub valid: bool,
}

impl BoundedDisclosure {
    pub const fn empty() -> Self {
        Self {
            salt: ByteString::new(),
            claim_name: ByteString::new(),
            claim_value: ByteString::new(),
            valid: false,
        }
    }

    /// Create a disclosure from raw byte slices.
    pub fn new(salt: &[u8], name: &[u8], value: &[u8]) -> Self {
        let mut d = Self::empty();
        d.salt.store(salt);
        d.claim_name.store(name);
        d.claim_value.store(value);
        d.valid = true;
        d
    }

    /// Encode the disclosure to a length-prefixed byte sequence.
    ///
    /// Format: `[salt_len, salt..., name_len, name..., value_len, value...]`
    pub fn encode(&self) -> ByteString {
        let mut out = ByteString::new();
        if !self.valid {
            return out;
        }
        let mut pos: usize = 0;

        // Salt: length byte + data
        if pos < 64 {
            out.data[pos] = self.salt.len as u8;
            pos += 1;
        }
        let mut i = 0;
        while i < self.salt.len && pos < 64 {
            out.data[pos] = self.salt.data[i];
            pos += 1;
            i += 1;
        }

        // Name: length byte + data
        if pos < 64 {
            out.data[pos] = self.claim_name.len as u8;
            pos += 1;
        }
        i = 0;
        while i < self.claim_name.len && pos < 64 {
            out.data[pos] = self.claim_name.data[i];
            pos += 1;
            i += 1;
        }

        // Value: length byte + data
        if pos < 64 {
            out.data[pos] = self.claim_value.len as u8;
            pos += 1;
        }
        i = 0;
        while i < self.claim_value.len && pos < 64 {
            out.data[pos] = self.claim_value.data[i];
            pos += 1;
            i += 1;
        }

        out.len = pos;
        out.valid = true;
        out
    }

    /// Decode a disclosure from its length-prefixed form.
    ///
    /// Returns `None` if the encoding is malformed or truncated.
    pub fn decode(encoded: &ByteString) -> Option<Self> {
        if !encoded.valid || encoded.len == 0 {
            return None;
        }
        let data = &encoded.data;
        let total = encoded.len;
        let mut pos: usize = 0;

        // Salt
        if pos >= total {
            return None;
        }
        let salt_len = data[pos] as usize;
        pos += 1;
        if salt_len > 64 || pos + salt_len > total {
            return None;
        }
        let mut salt = ByteString::new();
        let mut i = 0;
        while i < salt_len {
            salt.data[i] = data[pos + i];
            i += 1;
        }
        salt.len = salt_len;
        salt.valid = true;
        pos += salt_len;

        // Name
        if pos >= total {
            return None;
        }
        let name_len = data[pos] as usize;
        pos += 1;
        if name_len > 64 || pos + name_len > total {
            return None;
        }
        let mut name = ByteString::new();
        i = 0;
        while i < name_len {
            name.data[i] = data[pos + i];
            i += 1;
        }
        name.len = name_len;
        name.valid = true;
        pos += name_len;

        // Value
        if pos >= total {
            return None;
        }
        let value_len = data[pos] as usize;
        pos += 1;
        if value_len > 64 || pos + value_len > total {
            return None;
        }
        let mut value = ByteString::new();
        i = 0;
        while i < value_len {
            value.data[i] = data[pos + i];
            i += 1;
        }
        value.len = value_len;
        value.valid = true;

        Some(Self {
            salt,
            claim_name: name,
            claim_value: value,
            valid: true,
        })
    }

    /// Compute the digest of this disclosure.
    ///
    /// Production: `base64url(SHA-256(encode(disclosure)))`.
    /// Bounded model: uses the encoded form directly as the digest.
    /// This is sound because the length-prefixed encoding is injective:
    /// different disclosures always produce different encoded forms.
    pub fn digest(&self) -> ByteString {
        self.encode()
    }
}

// ============================================================================
// BoundedSdArray — models the `_sd` claim in the JWT payload
// ============================================================================

/// Fixed-capacity array of disclosure digests.
///
/// Models the `_sd` JSON array in the issuer's JWT payload.
#[derive(Debug, Clone, Copy)]
pub struct BoundedSdArray {
    pub digests: [ByteString; MAX_SD_CLAIMS],
    pub len: usize,
}

impl BoundedSdArray {
    pub const fn new() -> Self {
        Self {
            digests: [ByteString::new(); MAX_SD_CLAIMS],
            len: 0,
        }
    }

    /// Add a digest to the array. Returns `false` if full.
    pub fn push(&mut self, digest: &ByteString) -> bool {
        if self.len >= MAX_SD_CLAIMS {
            return false;
        }
        self.digests[self.len] = *digest;
        self.len += 1;
        true
    }

    /// Check whether a digest is present in the array.
    pub fn contains(&self, digest: &ByteString) -> bool {
        let mut i = 0;
        while i < self.len {
            if bytestrings_equal(&self.digests[i], digest) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ============================================================================
// BoundedDisclosureSet — models issuer/holder disclosure sets
// ============================================================================

/// Fixed-capacity set of disclosures.
///
/// Models the `Vec<Disclosure>` in `IssuanceResult` and holder selection.
#[derive(Debug, Clone, Copy)]
pub struct BoundedDisclosureSet {
    pub items: [BoundedDisclosure; MAX_SD_CLAIMS],
    pub len: usize,
}

impl BoundedDisclosureSet {
    pub const fn new() -> Self {
        Self {
            items: [BoundedDisclosure::empty(); MAX_SD_CLAIMS],
            len: 0,
        }
    }

    /// Add a disclosure. Returns `false` if full.
    pub fn push(&mut self, d: &BoundedDisclosure) -> bool {
        if self.len >= MAX_SD_CLAIMS {
            return false;
        }
        self.items[self.len] = *d;
        self.len += 1;
        true
    }

    /// Select disclosures whose `claim_name` matches one of the given names.
    ///
    /// Models `SdJwtHolder::select_disclosures` from `sd_jwt.rs`.
    pub fn select(&self, names: &[&[u8]]) -> BoundedDisclosureSet {
        let mut result = BoundedDisclosureSet::new();
        let mut i = 0;
        while i < self.len {
            if self.items[i].valid {
                let mut j = 0;
                while j < names.len() {
                    if self.items[i].claim_name.equals(names[j]) {
                        result.push(&self.items[i]);
                        break;
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        result
    }
}

// ============================================================================
// BoundedSdJwtFormat — compound SD-JWT serialization
// ============================================================================

/// Bounded model of the SD-JWT compound format: `<jwt>~<disc1>~...~`
///
/// Models `SdJwt { jwt, disclosures, key_binding_jwt }` from `sd_jwt.rs`.
/// Key binding JWT is omitted (orthogonal to SD properties).
#[derive(Debug, Clone, Copy)]
pub struct BoundedSdJwtFormat {
    pub jwt: ByteString,
    pub disclosures: [ByteString; MAX_SD_CLAIMS],
    pub disc_len: usize,
}

impl BoundedSdJwtFormat {
    pub const fn new() -> Self {
        Self {
            jwt: ByteString::new(),
            disclosures: [ByteString::new(); MAX_SD_CLAIMS],
            disc_len: 0,
        }
    }

    /// Build from JWT bytes and encoded disclosures.
    pub fn build(jwt: &[u8], disc_count: usize, discs: &[ByteString; MAX_SD_CLAIMS]) -> Self {
        let mut f = Self::new();
        f.jwt.store(jwt);
        let count = if disc_count < MAX_SD_CLAIMS {
            disc_count
        } else {
            MAX_SD_CLAIMS
        };
        let mut i = 0;
        while i < count {
            f.disclosures[i] = discs[i];
            i += 1;
        }
        f.disc_len = count;
        f
    }

    /// Serialize to compound format: `jwt~disc1~disc2~...~`
    ///
    /// Models `SdJwt::serialize()` from `sd_jwt.rs`.
    pub fn serialize(&self) -> ByteString {
        let mut out = ByteString::new();
        let mut pos: usize = 0;

        // JWT bytes
        let mut i = 0;
        while i < self.jwt.len && pos < 64 {
            out.data[pos] = self.jwt.data[i];
            pos += 1;
            i += 1;
        }

        // Each disclosure preceded by separator
        let mut d = 0;
        while d < self.disc_len {
            if pos < 64 {
                out.data[pos] = FORMAT_SEP;
                pos += 1;
            }
            i = 0;
            while i < self.disclosures[d].len && pos < 64 {
                out.data[pos] = self.disclosures[d].data[i];
                pos += 1;
                i += 1;
            }
            d += 1;
        }

        // Trailing separator
        if pos < 64 {
            out.data[pos] = FORMAT_SEP;
            pos += 1;
        }

        out.len = pos;
        out.valid = true;
        out
    }

    /// Parse a compound SD-JWT byte string.
    ///
    /// Expects: `<jwt>~<disc1>~<disc2>~...~`
    /// Models `SdJwt::parse()` from `sd_jwt.rs`.
    pub fn parse(input: &ByteString) -> Option<Self> {
        if !input.valid || input.len == 0 {
            return None;
        }

        let data = &input.data;
        let total = input.len;
        let mut result = Self::new();

        // Find first '~' → JWT ends there
        let mut jwt_end: usize = 0;
        while jwt_end < total && data[jwt_end] != FORMAT_SEP {
            jwt_end += 1;
        }
        if jwt_end == 0 || jwt_end >= total {
            return None;
        }

        // Store JWT
        let mut i = 0;
        while i < jwt_end {
            result.jwt.data[i] = data[i];
            i += 1;
        }
        result.jwt.len = jwt_end;
        result.jwt.valid = true;

        // Parse disclosures between separators
        let mut pos = jwt_end + 1;
        let mut disc_idx: usize = 0;

        while pos < total && disc_idx < MAX_SD_CLAIMS {
            let seg_start = pos;
            while pos < total && data[pos] != FORMAT_SEP {
                pos += 1;
            }
            let seg_len = pos - seg_start;

            if seg_len > 0 {
                let mut disc = ByteString::new();
                i = 0;
                while i < seg_len && i < 64 {
                    disc.data[i] = data[seg_start + i];
                    i += 1;
                }
                disc.len = seg_len;
                disc.valid = true;
                result.disclosures[disc_idx] = disc;
                disc_idx += 1;
            }

            if pos < total {
                pos += 1; // skip separator
            }
        }

        result.disc_len = disc_idx;
        Some(result)
    }
}
