//! Bounded upstream refresh store for Kani verification (Byte Array Version)
//!
//! Models the `aegaeon.account_links` table and upstream refresh token
//! lifecycle using fixed-size byte arrays.  Avoids `String`, `HashMap`,
//! and database types to sidestep Kani 0.66.0 ICE.
//!
//! **Production equivalent**: `crates/server/src/web/upstream_refresh.rs`,
//! `crates/server/src/web/upstream_refresh_links/query.rs`, and the callback
//! current-connection admission in
//! `crates/server/src/web/upstream_callback_connection.rs`, backed by the SQL schema:
//!
//! ```sql
//! CREATE TABLE aegaeon.account_links (
//!   id uuid PRIMARY KEY,
//!   upstream_issuer text NOT NULL,
//!   upstream_sub_hash text NOT NULL,
//!   end_user_id uuid NOT NULL,
//!   upstream_refresh_token_encrypted bytea,
//!   ...
//!   UNIQUE (environment_id, upstream_issuer, upstream_sub_hash)
//! );
//! ```
//!
//! **Verified Properties** (via harnesses in `lib.rs`):
//! 1. Rotation replaces: store(new) overwrites old, get returns new
//! 2. Requires valid link: get/store on non-existent link fails
//! 3. Single-use: after rotation, old token is unretrievable

use super::bounded_stores::ByteString;

/// Maximum number of account links in the bounded model.
const MAX_UPSTREAM_LINKS: usize = 4;

// ============================================================================
// UpstreamLinkEntry
// ============================================================================

/// A single account link entry.
///
/// Models one row of `aegaeon.account_links` with the columns relevant
/// to refresh token lifecycle.
#[derive(Debug, Clone, Copy)]
struct UpstreamLinkEntry {
    /// Upstream IdP issuer URL (models `upstream_issuer`).
    issuer: ByteString,
    /// Hash of upstream subject (models `upstream_sub_hash`).
    sub_hash: ByteString,
    /// Local user identifier (models `end_user_id`).
    user_id: ByteString,
    /// Connection/client binding for the stored refresh token.
    connection_id: ByteString,
    /// Stored refresh token (models `upstream_refresh_token_encrypted`).
    refresh_token: ByteString,
    /// Monotonic refresh-token generation.
    generation: u8,
    /// Whether a refresh token is present (models `IS NOT NULL` check).
    has_refresh: bool,
    /// Whether this link entry is active.
    active: bool,
}

impl UpstreamLinkEntry {
    const fn empty() -> Self {
        Self {
            issuer: ByteString::new(),
            sub_hash: ByteString::new(),
            user_id: ByteString::new(),
            connection_id: ByteString::new(),
            refresh_token: ByteString::new(),
            generation: 0,
            has_refresh: false,
            active: false,
        }
    }
}

// ============================================================================
// BoundedUpstreamRefreshStore
// ============================================================================

/// Bounded upstream refresh token store for Kani BMC verification.
///
/// Models the subset of `account_links` operations used by the upstream
/// refresh endpoint (`POST /oauth/upstream/refresh`).
///
/// **Verified Properties**:
/// - Rotation: `store_refresh_token` overwrites old token atomically
/// - Link requirement: operations fail for non-existent links
/// - Single-use: after rotation, old token value is gone from the store
/// - Uniqueness: duplicate (issuer, sub_hash) links are rejected
#[derive(Debug, Clone)]
pub struct BoundedUpstreamRefreshStore {
    entries: [UpstreamLinkEntry; MAX_UPSTREAM_LINKS],
    len: usize,
}

impl BoundedUpstreamRefreshStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            entries: [UpstreamLinkEntry::empty(); MAX_UPSTREAM_LINKS],
            len: 0,
        }
    }

    /// Create an account link (without refresh token).
    ///
    /// Models `INSERT INTO aegaeon.account_links ...`.
    /// Returns `false` if the store is full or a link with the same
    /// (issuer, sub_hash) already exists (UNIQUE constraint).
    pub fn create_link(
        &mut self,
        issuer: &[u8],
        sub_hash: &[u8],
        user_id: &[u8],
        connection_id: &[u8],
    ) -> bool {
        // Enforce uniqueness on (issuer, sub_hash)
        let mut i = 0;
        while i < self.len {
            if self.entries[i].active
                && self.entries[i].issuer.equals(issuer)
                && self.entries[i].sub_hash.equals(sub_hash)
            {
                return false;
            }
            i += 1;
        }

        if self.len >= MAX_UPSTREAM_LINKS {
            return false;
        }

        let e = &mut self.entries[self.len];
        e.issuer.store(issuer);
        e.sub_hash.store(sub_hash);
        e.user_id.store(user_id);
        e.connection_id.store(connection_id);
        e.generation = 0;
        e.has_refresh = false;
        e.active = true;
        self.len += 1;
        true
    }

    /// Store (or overwrite) a refresh token for an existing link.
    ///
    /// Models `UPDATE aegaeon.account_links SET upstream_refresh_token_encrypted = $1
    ///         WHERE upstream_issuer = $2 AND upstream_sub_hash = $3`.
    ///
    /// Returns `true` if the link exists and the token was stored.
    /// Returns `false` if no matching active link is found.
    pub fn store_refresh_token(
        &mut self,
        issuer: &[u8],
        sub_hash: &[u8],
        connection_id: &[u8],
        expected_generation: u8,
        token: &[u8],
    ) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].active
                && self.entries[i].issuer.equals(issuer)
                && self.entries[i].sub_hash.equals(sub_hash)
                && self.entries[i].connection_id.equals(connection_id)
                && self.entries[i].generation == expected_generation
            {
                self.entries[i].refresh_token.store(token);
                self.entries[i].generation = self.entries[i].generation.saturating_add(1);
                self.entries[i].has_refresh = true;
                return true;
            }
            i += 1;
        }
        false
    }

    /// Get the current refresh token for a link (by value, Copy).
    ///
    /// Models the SELECT query in the refresh endpoint that fetches
    /// `upstream_refresh_token_encrypted` for sending to the upstream IdP.
    ///
    /// Returns `None` if the link doesn't exist or has no refresh token.
    pub fn get_refresh_token(
        &self,
        issuer: &[u8],
        sub_hash: &[u8],
        connection_id: &[u8],
    ) -> Option<ByteString> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].active
                && self.entries[i].issuer.equals(issuer)
                && self.entries[i].sub_hash.equals(sub_hash)
                && self.entries[i].connection_id.equals(connection_id)
                && self.entries[i].has_refresh
            {
                return Some(self.entries[i].refresh_token);
            }
            i += 1;
        }
        None
    }

    pub fn get_generation(
        &self,
        issuer: &[u8],
        sub_hash: &[u8],
        connection_id: &[u8],
    ) -> Option<u8> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].active
                && self.entries[i].issuer.equals(issuer)
                && self.entries[i].sub_hash.equals(sub_hash)
                && self.entries[i].connection_id.equals(connection_id)
            {
                return Some(self.entries[i].generation);
            }
            i += 1;
        }
        None
    }

    /// Check whether a specific token value is stored in any link.
    ///
    /// Used in harnesses to verify that old tokens are no longer
    /// present after rotation (single-use property).
    pub fn has_token_value(&self, token: &[u8]) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].active
                && self.entries[i].has_refresh
                && self.entries[i].refresh_token.equals(token)
            {
                return true;
            }
            i += 1;
        }
        false
    }
}
