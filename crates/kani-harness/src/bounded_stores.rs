//! Bounded stores for Kani verification (Byte Array Version)
//!
//! This module provides HashMap-free bounded implementations of server stores
//! using fixed-size byte arrays instead of `String` to avoid Kani ICE.
//!
//! **Design Rationale**:
//! - Kani 0.66.0 cannot handle `std::string::String` (heap-allocated)
//! - Static slices (`&'static str`) work, but dynamic strings cause ICE
//! - Solution: Use `[u8; MAX_LEN]` with length tracking
//! - Byte-level comparison (no UTF-8 validation needed)
//!
//! **Security Properties**:
//! - Same invariants as production code (replay protection, single-use, etc.)
//! - Bounded state space for tractable Kani verification
//! - No constant-time comparison needed (JTI/state/nonce are public info)

use core::cmp::min;

/// Maximum length for stored byte strings (JTI, state, nonce, token IDs)
/// 64 bytes is sufficient for:
/// - DPoP JTI: 16-32 bytes typical
/// - OAuth state/nonce: 32-43 characters (base64url)
/// - Token IDs: 32-64 characters typical
const MAX_BYTE_LEN: usize = 64;

/// Maximum number of JTI entries to track
const MAX_JTI_ENTRIES: usize = 8;

/// Maximum number of token entries (access + refresh)
const MAX_TOKEN_ENTRIES: usize = 16;

/// Maximum number of authorization code entries
const MAX_AUTHCODE_ENTRIES: usize = 8;

// ============================================================================
// Utility Types and Functions
// ============================================================================

/// Fixed-length byte string with validity tracking
///
/// Represents a variable-length byte sequence stored in a fixed-size array.
/// The `valid` flag indicates whether this slot contains meaningful data.
#[derive(Debug, Clone, Copy)]
pub struct ByteString {
    /// Fixed-size byte buffer
    pub data: [u8; MAX_BYTE_LEN],
    /// Actual length of stored bytes (0..=MAX_BYTE_LEN)
    pub len: usize,
    /// Whether this slot contains valid data
    pub valid: bool,
}

impl ByteString {
    /// Create an empty (invalid) ByteString
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_BYTE_LEN],
            len: 0,
            valid: false,
        }
    }

    /// Create a ByteString from a byte slice
    #[cfg(feature = "kani-bytestring-utils")]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut bs = Self::new();
        bs.store(bytes);
        bs
    }

    /// Store bytes into this ByteString
    pub fn store(&mut self, bytes: &[u8]) {
        let copy_len = min(bytes.len(), MAX_BYTE_LEN);
        // Use manual loop instead of copy_from_slice to avoid potential Kani issues
        for i in 0..copy_len {
            self.data[i] = bytes[i];
        }
        self.len = copy_len;
        self.valid = true;
    }

    /// Get the stored bytes as a slice
    #[cfg(feature = "kani-bytestring-utils")]
    pub fn as_bytes(&self) -> &[u8] {
        if self.valid {
            &self.data[..self.len]
        } else {
            &[]
        }
    }

    /// Compare with another byte slice
    pub fn equals(&self, other: &[u8]) -> bool {
        if !self.valid {
            return false;
        }
        if self.len != other.len() {
            return false;
        }
        self.data[..self.len] == other[..]
    }

    /// Clear this ByteString (mark as invalid)
    pub fn clear(&mut self) {
        self.len = 0;
        self.valid = false;
    }
}

// ============================================================================
// BoundedJtiStore - DPoP JTI Replay Protection
// ============================================================================

/// Bounded JTI store for DPoP replay protection
///
/// Uses fixed-size arrays to track recent JTIs (JWT IDs) within a replay window.
/// Implements the same security invariants as production code but with bounded capacity.
///
/// **Verified Properties**:
/// - Replay rejection: Same JTI within replay window is rejected
/// - Expiration cleanup: JTIs older than replay window are removed
/// - Bounded capacity: Maximum of MAX_JTI_ENTRIES stored
#[derive(Debug, Clone)]
pub struct BoundedJtiStore {
    /// Stored JTI entries with timestamps
    /// Each entry: (jti_bytes, timestamp)
    entries: [(ByteString, i64); MAX_JTI_ENTRIES],
    /// Number of valid entries
    len: usize,
}

impl BoundedJtiStore {
    /// Create a new empty JTI store
    pub fn new() -> Self {
        Self {
            entries: [(ByteString::new(), 0); MAX_JTI_ENTRIES],
            len: 0,
        }
    }

    /// Check if JTI exists and store it if not (replay protection)
    ///
    /// Returns:
    /// - `true` if JTI was accepted (not a replay, stored successfully)
    /// - `false` if JTI was rejected (replay detected or store full)
    ///
    /// **Security Invariant**: Same JTI within replay window is always rejected
    pub fn check_and_store(&mut self, now: i64, replay_window: i64, jti: &[u8]) -> bool {
        // First, cleanup expired entries
        self.cleanup_expired(now, replay_window);

        // Check for replay
        for i in 0..self.len {
            if self.entries[i].0.equals(jti) {
                // Replay detected
                return false;
            }
        }

        // Store if not full
        if self.len < MAX_JTI_ENTRIES {
            self.entries[self.len].0.store(jti);
            self.entries[self.len].1 = now;
            self.len += 1;
            true
        } else {
            // Store full (conservative: reject to maintain security)
            false
        }
    }

    /// Remove JTI entries older than the replay window
    fn cleanup_expired(&mut self, now: i64, replay_window: i64) {
        let cutoff = now - replay_window;
        let mut write_idx = 0;

        for read_idx in 0..self.len {
            if self.entries[read_idx].1 >= cutoff {
                // Keep this entry (still within window)
                if write_idx != read_idx {
                    self.entries[write_idx] = self.entries[read_idx];
                }
                write_idx += 1;
            }
        }

        // Clear remaining slots
        for i in write_idx..self.len {
            self.entries[i].0.clear();
            self.entries[i].1 = 0;
        }

        self.len = write_idx;
    }

    /// Get current number of stored JTIs
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ============================================================================
// BoundedTokenStore - Access/Refresh Token Verification
// ============================================================================
//
// Expiration semantics match F* specification (AuthCode.Types.fst:86-87):
//   let is_expired (expires_at: nat) (current_time: nat) : Tot bool =
//     current_time >= expires_at
//
// i.e. `now == expires_at` ⟹ expired.  All comparisons use strict `<`.
//
// NOTE (V-3): `insert()` does not check for duplicate token IDs. The F* spec
// requires `not (issued s code)` as a precondition. Current harnesses use
// distinct literals; symbolic harnesses must add this as `kani::assume`.
//
// NOTE (V-4): Cascade revocation (F* Revocation.fst:100-122, production
// `refresh_children`) is not modeled. This store verifies per-token
// invariants only. Cascade semantics are a future extension point.

/// Kind of token stored in `BoundedTokenStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Access,
    Refresh,
}

/// A single token entry in the bounded store.
#[derive(Debug, Clone, Copy)]
struct TokenEntry {
    id: ByteString,
    kind: TokenKind,
    expires_at: i64,
    revoked: bool,
    /// For refresh tokens: marks the token as consumed after rotation.
    used: bool,
}

impl TokenEntry {
    const fn empty() -> Self {
        Self {
            id: ByteString::new(),
            kind: TokenKind::Access,
            expires_at: 0,
            revoked: false,
            used: false,
        }
    }
}

/// Bounded token store for Kani BMC verification of access and refresh tokens.
///
/// **Verified Properties**:
/// - Expiration enforcement: tokens at or past `expires_at` are rejected
/// - Revocation: revoked tokens are rejected even before expiration
/// - Refresh single-use: `rotate_refresh_token` succeeds exactly once
#[derive(Debug, Clone)]
pub struct BoundedTokenStore {
    entries: [TokenEntry; MAX_TOKEN_ENTRIES],
    len: usize,
}

impl BoundedTokenStore {
    /// Create a new empty token store.
    pub fn new() -> Self {
        Self {
            entries: [TokenEntry::empty(); MAX_TOKEN_ENTRIES],
            len: 0,
        }
    }

    /// Store an access token with its expiration time.
    ///
    /// Returns `true` if stored successfully, `false` if the store is full.
    pub fn store_access_token(&mut self, token: &[u8], expires_at: i64) -> bool {
        self.insert(token, TokenKind::Access, expires_at)
    }

    /// Store a refresh token with its expiration time.
    ///
    /// Returns `true` if stored successfully, `false` if the store is full.
    pub fn store_refresh_token(&mut self, token: &[u8], expires_at: i64) -> bool {
        self.insert(token, TokenKind::Refresh, expires_at)
    }

    /// Verify an access token: returns `true` iff the token exists, is not
    /// expired at `now`, and has not been revoked.
    ///
    /// Expiration: `now >= expires_at` ⟹ expired (matches F* `is_expired`).
    pub fn verify_access_token(&self, token: &[u8], now: i64) -> bool {
        for i in 0..self.len {
            let e = &self.entries[i];
            if e.id.equals(token) {
                return !e.revoked && now < e.expires_at;
            }
        }
        false
    }

    /// Revoke a token (access or refresh). No-op if not found.
    /// Idempotent (matches F* `lemma_revoke_token_idempotent`).
    pub fn revoke_token(&mut self, token: &[u8]) {
        for i in 0..self.len {
            if self.entries[i].id.equals(token) {
                self.entries[i].revoked = true;
                return;
            }
        }
    }

    /// Rotate a refresh token (single-use semantics).
    ///
    /// Returns `true` on the first call for a given token (consuming it).
    /// Returns `false` on subsequent calls, if expired, or if not found.
    ///
    /// Models F* `consume_code` / `lemma_consume_effect`: atomically moves
    /// the token from "issued" to "used" state.
    pub fn rotate_refresh_token(&mut self, token: &[u8], now: i64) -> bool {
        for i in 0..self.len {
            let e = &mut self.entries[i];
            if e.id.equals(token) && e.kind == TokenKind::Refresh {
                if e.used || e.revoked || now >= e.expires_at {
                    return false;
                }
                e.used = true;
                return true;
            }
        }
        false
    }

    // -- internal helpers --

    fn insert(&mut self, token: &[u8], kind: TokenKind, expires_at: i64) -> bool {
        if self.len >= MAX_TOKEN_ENTRIES {
            return false;
        }
        self.entries[self.len].id.store(token);
        self.entries[self.len].kind = kind;
        self.entries[self.len].expires_at = expires_at;
        self.entries[self.len].revoked = false;
        self.entries[self.len].used = false;
        self.len += 1;
        true
    }
}

// ============================================================================
// BoundedAuthCodeStore - Authorization Code Single-Use + State/Nonce Uniqueness
// ============================================================================
//
// NOTE (V-2): State/nonce uniqueness scope simplification.
//
// | Layer           | Scope                              | Strength |
// |-----------------|------------------------------------|----------|
// | F* Store.fst    | Seq.mem — full accumulated history | Strongest|
// | Production      | HashMap + TTL cleanup              | Medium   |
// | Kani (here)     | Live (unused) entries only         | Weakest  |
//
// After a code is consumed (`used=true`), its state/nonce is excluded from
// uniqueness checks. F* tracks them permanently. This is an intentional
// bounded-model simplification. For OAuth state (CSRF, RFC 6749 §10.12)
// this is low-risk; for OIDC nonce (ID token replay prevention) the
// production TTL-based tracking provides the necessary coverage.

/// A single authorization code entry.
#[derive(Debug, Clone, Copy)]
struct AuthCodeEntry {
    code: ByteString,
    expires_at: i64,
    state: ByteString,
    nonce: ByteString,
    used: bool,
}

impl AuthCodeEntry {
    const fn empty() -> Self {
        Self {
            code: ByteString::new(),
            expires_at: 0,
            state: ByteString::new(),
            nonce: ByteString::new(),
            used: false,
        }
    }
}

/// Bounded authorization code store for Kani BMC verification.
///
/// **Verified Properties**:
/// - Single-use: `use_code` succeeds exactly once per code
/// - Expiration: codes at or past `expires_at` are rejected
/// - State uniqueness: duplicate `state` values are rejected at store time
/// - Nonce uniqueness: duplicate `nonce` values are rejected at store time
#[derive(Debug, Clone)]
pub struct BoundedAuthCodeStore {
    entries: [AuthCodeEntry; MAX_AUTHCODE_ENTRIES],
    len: usize,
}

impl BoundedAuthCodeStore {
    /// Create a new empty auth code store.
    pub fn new() -> Self {
        Self {
            entries: [AuthCodeEntry::empty(); MAX_AUTHCODE_ENTRIES],
            len: 0,
        }
    }

    /// Store an authorization code.
    ///
    /// Returns `Ok(())` on success, `Err(())` if:
    /// - The store is full
    /// - A duplicate `state` is detected among existing (unused) entries
    /// - A duplicate `nonce` is detected among existing (unused) entries
    pub fn store_code(
        &mut self,
        code: &[u8],
        expires_at: i64,
        state: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<(), ()> {
        if self.len >= MAX_AUTHCODE_ENTRIES {
            return Err(());
        }

        // Enforce state uniqueness across live entries
        if let Some(s) = state {
            for i in 0..self.len {
                if !self.entries[i].used && self.entries[i].state.equals(s) {
                    return Err(());
                }
            }
        }

        // Enforce nonce uniqueness across live entries
        if let Some(n) = nonce {
            for i in 0..self.len {
                if !self.entries[i].used && self.entries[i].nonce.equals(n) {
                    return Err(());
                }
            }
        }

        let e = &mut self.entries[self.len];
        e.code.store(code);
        e.expires_at = expires_at;
        e.used = false;
        if let Some(s) = state {
            e.state.store(s);
        } else {
            e.state.clear();
        }
        if let Some(n) = nonce {
            e.nonce.store(n);
        } else {
            e.nonce.clear();
        }
        self.len += 1;
        Ok(())
    }

    /// Check whether a code exists and is not expired (non-consuming query).
    ///
    /// Expiration: `now >= expires_at` ⟹ expired (matches F* `is_expired`).
    pub fn get_code(&self, code: &[u8], now: i64) -> bool {
        for i in 0..self.len {
            let e = &self.entries[i];
            if e.code.equals(code) {
                return !e.used && now < e.expires_at;
            }
        }
        false
    }

    /// Consume an authorization code (single-use).
    ///
    /// Returns `true` on the first call for a valid, non-expired code.
    /// Returns `false` on subsequent calls, if expired, or if not found.
    ///
    /// Expiration: `now >= expires_at` ⟹ expired (matches F* `is_expired`).
    pub fn use_code(&mut self, code: &[u8], now: i64) -> bool {
        for i in 0..self.len {
            let e = &mut self.entries[i];
            if e.code.equals(code) {
                if e.used || now >= e.expires_at {
                    return false;
                }
                e.used = true;
                return true;
            }
        }
        false
    }
}
