//! Bounded federation cache stores for Kani verification (Byte Array Version)
//!
//! Models the three federation repository tables using fixed-size arrays:
//!   - BoundedEntityCacheStore  → federation_entity_cache
//!   - BoundedChainCacheStore   → federation_trust_chains
//!   - BoundedPolicyProfileStore → oauth_profiles
//!
//! DB constraints verified:
//!   - federation_entity_cache_env_entity_unique
//!   - federation_entity_cache_expires_after_fetch
//!   - federation_trust_chains_env_leaf_anchor_unique
//!   - federation_trust_chains_expires_after_resolve
//!   - oauth_profiles_default_unique (at most one active default per env)
//!
//! **Verified Properties** (via harnesses in `lib.rs`):
//! 1. Expired entity cache entries return None on get
//! 2. Upsert maintains at most one entry per natural key
//! 3. Cleanup removes all expired entries, preserves valid ones
//! 4. Chain cache consistency: get returns upserted data
//! 5. Tenant isolation: cross-env operations don't interfere
//! 6. Policy resolution precedence: client > default > baseline
//! 7. No downgrade: OAuth 2.1 profiles cannot enable implicit/ROPC
//! 8. RP state/nonce binding for OIDC callback

use super::bounded_stores::ByteString;

/// Maximum number of entity cache entries.
const MAX_ENTITY_CACHE: usize = 4;

/// Maximum number of chain cache entries.
const MAX_CHAIN_CACHE: usize = 4;

/// Maximum number of policy profiles.
const MAX_PROFILES: usize = 4;

// ============================================================================
// Entity Cache
// ============================================================================

/// A single entity cache entry.
#[derive(Debug, Clone, Copy)]
pub struct EntityCacheEntry {
    pub env_id: u8,
    pub entity_id: ByteString,
    pub fetched_at: i64,
    pub expires_at: i64,
    pub occupied: bool,
}

impl EntityCacheEntry {
    pub const fn empty() -> Self {
        Self {
            env_id: 0,
            entity_id: ByteString::new(),
            fetched_at: 0,
            expires_at: 0,
            occupied: false,
        }
    }

    /// DB constraint: expires_at > fetched_at
    pub fn is_well_formed(&self) -> bool {
        !self.occupied || self.expires_at > self.fetched_at
    }

    /// Entry is valid (not expired) at time `now`.
    /// Expiration: now >= expires_at ⟹ expired (matches F* is_expired)
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.occupied && now < self.expires_at
    }
}

/// Bounded entity cache store.
#[derive(Debug, Clone)]
pub struct BoundedEntityCacheStore {
    entries: [EntityCacheEntry; MAX_ENTITY_CACHE],
    len: usize,
}

impl BoundedEntityCacheStore {
    pub fn new() -> Self {
        Self {
            entries: [EntityCacheEntry::empty(); MAX_ENTITY_CACHE],
            len: 0,
        }
    }

    /// Get a non-expired entry by (env_id, entity_id).
    pub fn get(&self, env_id: u8, entity_id: &[u8], now: i64) -> Option<usize> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].entity_id.equals(entity_id)
                && self.entries[i].is_valid_at(now)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Upsert: insert or replace by (env_id, entity_id).
    pub fn upsert(
        &mut self,
        env_id: u8,
        entity_id: &[u8],
        fetched_at: i64,
        expires_at: i64,
    ) -> bool {
        if expires_at <= fetched_at {
            return false;
        }
        // Check for existing entry with same key
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].entity_id.equals(entity_id)
            {
                // Replace existing
                self.entries[i].fetched_at = fetched_at;
                self.entries[i].expires_at = expires_at;
                return true;
            }
            i += 1;
        }

        // Insert new
        if self.len >= MAX_ENTITY_CACHE {
            return false;
        }
        let e = &mut self.entries[self.len];
        e.env_id = env_id;
        e.entity_id.store(entity_id);
        e.fetched_at = fetched_at;
        e.expires_at = expires_at;
        e.occupied = true;
        self.len += 1;
        true
    }

    /// DB constraint check over occupied entity-cache entries.
    pub fn all_entries_well_formed(&self) -> bool {
        let mut i = 0;
        while i < self.len {
            if !self.entries[i].is_well_formed() {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Count entries with a given (env_id, entity_id) key.
    pub fn count_key(&self, env_id: u8, entity_id: &[u8]) -> usize {
        let mut count = 0usize;
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].entity_id.equals(entity_id)
            {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Remove all expired entries.
    pub fn cleanup_expired(&mut self, now: i64) {
        let mut write = 0;
        for read in 0..self.len {
            if self.entries[read].is_valid_at(now) {
                if write != read {
                    self.entries[write] = self.entries[read];
                }
                write += 1;
            }
        }
        for i in write..self.len {
            self.entries[i] = EntityCacheEntry::empty();
        }
        self.len = write;
    }

    /// Check if any expired entry remains after cleanup.
    pub fn has_expired(&self, now: i64) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied && !self.entries[i].is_valid_at(now) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ============================================================================
// Chain Cache
// ============================================================================

/// A single chain cache entry.
#[derive(Debug, Clone, Copy)]
pub struct ChainCacheEntry {
    pub env_id: u8,
    pub leaf_entity_id: ByteString,
    pub anchor_entity_id: ByteString,
    pub resolved_at: i64,
    pub expires_at: i64,
    pub occupied: bool,
}

impl ChainCacheEntry {
    pub const fn empty() -> Self {
        Self {
            env_id: 0,
            leaf_entity_id: ByteString::new(),
            anchor_entity_id: ByteString::new(),
            resolved_at: 0,
            expires_at: 0,
            occupied: false,
        }
    }

    pub fn is_valid_at(&self, now: i64) -> bool {
        self.occupied && now < self.expires_at
    }
}

/// Bounded chain cache store.
#[derive(Debug, Clone)]
pub struct BoundedChainCacheStore {
    entries: [ChainCacheEntry; MAX_CHAIN_CACHE],
    len: usize,
}

impl BoundedChainCacheStore {
    pub fn new() -> Self {
        Self {
            entries: [ChainCacheEntry::empty(); MAX_CHAIN_CACHE],
            len: 0,
        }
    }

    /// Get a non-expired chain entry.
    pub fn get(
        &self,
        env_id: u8,
        leaf: &[u8],
        anchor: &[u8],
        now: i64,
    ) -> Option<usize> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].leaf_entity_id.equals(leaf)
                && self.entries[i].anchor_entity_id.equals(anchor)
                && self.entries[i].is_valid_at(now)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Upsert a chain cache entry.
    pub fn upsert(
        &mut self,
        env_id: u8,
        leaf: &[u8],
        anchor: &[u8],
        resolved_at: i64,
        expires_at: i64,
    ) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].leaf_entity_id.equals(leaf)
                && self.entries[i].anchor_entity_id.equals(anchor)
            {
                self.entries[i].resolved_at = resolved_at;
                self.entries[i].expires_at = expires_at;
                return true;
            }
            i += 1;
        }

        if self.len >= MAX_CHAIN_CACHE {
            return false;
        }
        let e = &mut self.entries[self.len];
        e.env_id = env_id;
        e.leaf_entity_id.store(leaf);
        e.anchor_entity_id.store(anchor);
        e.resolved_at = resolved_at;
        e.expires_at = expires_at;
        e.occupied = true;
        self.len += 1;
        true
    }
}

// ============================================================================
// RP Session State (OIDC RP authorize/callback binding)
// ============================================================================

/// OIDC RP session state for state/nonce binding verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpSessionState {
    Idle,
    PendingCallback,
    Authenticated,
    Failed,
    Expired,
}

/// Bounded RP session entry.
///
/// Fields match `UpstreamAuthRequest` in production code:
///   state_param, nonce_param, code_verifier, issuer,
///   token_endpoint, jwks_uri, issued_at, expires_at
#[derive(Debug, Clone, Copy)]
pub struct BoundedRpSession {
    pub state: RpSessionState,
    pub state_param: ByteString,
    pub nonce_param: ByteString,
    pub code_verifier: ByteString,
    pub has_code_verifier: bool,
    pub issuer: ByteString,
    pub token_endpoint: ByteString,
    pub jwks_uri: ByteString,
    pub issued_at: i64,
    pub expires_at: i64,
    pub occupied: bool,
}

impl BoundedRpSession {
    pub const fn empty() -> Self {
        Self {
            state: RpSessionState::Idle,
            state_param: ByteString::new(),
            nonce_param: ByteString::new(),
            code_verifier: ByteString::new(),
            has_code_verifier: false,
            issuer: ByteString::new(),
            token_endpoint: ByteString::new(),
            jwks_uri: ByteString::new(),
            issued_at: 0,
            expires_at: 0,
            occupied: false,
        }
    }

    /// Initiate authorization: store state, nonce, expected issuer, endpoints, TTL.
    /// Transitions Idle → PendingCallback.
    pub fn authorize(
        &mut self,
        state: &[u8],
        nonce: &[u8],
        issuer: &[u8],
    ) -> bool {
        if self.state != RpSessionState::Idle {
            return false;
        }
        self.state_param.store(state);
        self.nonce_param.store(nonce);
        self.issuer.store(issuer);
        self.state = RpSessionState::PendingCallback;
        self.occupied = true;
        true
    }

    /// Extended authorize with PKCE, endpoints, and TTL fields.
    pub fn authorize_full(
        &mut self,
        state: &[u8],
        nonce: &[u8],
        issuer: &[u8],
        code_verifier: Option<&[u8]>,
        token_endpoint: &[u8],
        jwks_uri: &[u8],
        issued_at: i64,
        expires_at: i64,
    ) -> bool {
        if self.state != RpSessionState::Idle {
            return false;
        }
        if expires_at <= issued_at {
            return false;
        }
        self.state_param.store(state);
        self.nonce_param.store(nonce);
        self.issuer.store(issuer);
        if let Some(cv) = code_verifier {
            self.code_verifier.store(cv);
            self.has_code_verifier = true;
        }
        self.token_endpoint.store(token_endpoint);
        self.jwks_uri.store(jwks_uri);
        self.issued_at = issued_at;
        self.expires_at = expires_at;
        self.state = RpSessionState::PendingCallback;
        self.occupied = true;
        true
    }

    /// Session is valid (not expired) at time `now`.
    /// Expiration: now >= expires_at ⟹ expired (matches F* is_expired)
    pub fn is_valid_at(&self, now: i64) -> bool {
        now < self.expires_at
    }

    /// Handle callback: verify state matches, consume the session.
    /// Transitions PendingCallback → Authenticated or Failed.
    pub fn callback(
        &mut self,
        callback_state: &[u8],
        id_token_nonce: &[u8],
        id_token_iss: &[u8],
    ) -> bool {
        if self.state != RpSessionState::PendingCallback {
            return false;
        }

        // SM1: state parameter must match
        if !self.state_param.equals(callback_state) {
            self.state = RpSessionState::Failed;
            return false;
        }

        // SM2: nonce must match
        if !self.nonce_param.equals(id_token_nonce) {
            self.state = RpSessionState::Failed;
            return false;
        }

        // SM3: issuer must match
        if !self.issuer.equals(id_token_iss) {
            self.state = RpSessionState::Failed;
            return false;
        }

        self.state = RpSessionState::Authenticated;
        true
    }

    /// Handle callback with TTL enforcement (SM6).
    /// Checks expiration before verifying bindings.
    pub fn callback_with_ttl(
        &mut self,
        callback_state: &[u8],
        id_token_nonce: &[u8],
        id_token_iss: &[u8],
        now: i64,
    ) -> bool {
        if self.state != RpSessionState::PendingCallback {
            return false;
        }

        // SM6: check expiration first
        if !self.is_valid_at(now) {
            self.state = RpSessionState::Expired;
            return false;
        }

        // SM1: state parameter must match
        if !self.state_param.equals(callback_state) {
            self.state = RpSessionState::Failed;
            return false;
        }

        // SM2: nonce must match
        if !self.nonce_param.equals(id_token_nonce) {
            self.state = RpSessionState::Failed;
            return false;
        }

        // SM3: issuer must match
        if !self.issuer.equals(id_token_iss) {
            self.state = RpSessionState::Failed;
            return false;
        }

        self.state = RpSessionState::Authenticated;
        true
    }
}

// ============================================================================
// Policy Profile Resolution
// ============================================================================

/// Bounded policy profile entry.
#[derive(Debug, Clone, Copy)]
pub struct BoundedProfileEntry {
    pub env_id: u8,
    pub profile_id: u8,
    pub is_default: bool,
    pub is_active: bool,
    pub require_pkce: bool,
    pub expires_at: i64, // 0 = no expiry
    pub occupied: bool,
}

impl BoundedProfileEntry {
    pub const fn empty() -> Self {
        Self {
            env_id: 0,
            profile_id: 0,
            is_default: false,
            is_active: false,
            require_pkce: true,
            expires_at: 0,
            occupied: false,
        }
    }

    /// Profile is valid at time `now`.
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.occupied
            && self.is_active
            && (self.expires_at == 0 || now < self.expires_at)
    }

    /// Modern flow well-formedness: profiles cannot relax PKCE.
    pub fn is_modern_flow_well_formed(&self) -> bool {
        self.require_pkce
    }
}

/// Resolved policy result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub profile_id: u8,
    pub require_pkce: bool,
}

impl ResolvedPolicy {
    /// Strict code-flow baseline.
    pub const BASELINE: Self = Self {
        profile_id: 0,
        require_pkce: true,
    };

    pub fn is_modern_flow_compliant(&self) -> bool {
        self.require_pkce
    }
}

/// Bounded profile store for Kani verification.
#[derive(Debug, Clone)]
pub struct BoundedProfileStore {
    entries: [BoundedProfileEntry; MAX_PROFILES],
    len: usize,
}

impl BoundedProfileStore {
    pub fn new() -> Self {
        Self {
            entries: [BoundedProfileEntry::empty(); MAX_PROFILES],
            len: 0,
        }
    }

    pub fn add_profile(&mut self, entry: BoundedProfileEntry) -> bool {
        if self.len >= MAX_PROFILES {
            return false;
        }
        self.entries[self.len] = entry;
        self.entries[self.len].occupied = true;
        self.len += 1;
        true
    }

    /// Find a profile by (env_id, profile_id).
    fn find_profile(&self, env_id: u8, profile_id: u8, now: i64) -> Option<usize> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].profile_id == profile_id
                && self.entries[i].is_valid_at(now)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Find the default profile for an environment.
    fn find_default(&self, env_id: u8, now: i64) -> Option<usize> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].is_default
                && self.entries[i].is_valid_at(now)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Resolve the effective policy.
    /// Precedence: client profile > default > baseline 2.1
    pub fn resolve(
        &self,
        env_id: u8,
        client_profile_id: Option<u8>,
        now: i64,
    ) -> ResolvedPolicy {
        if let Some(pid) = client_profile_id {
            if let Some(idx) = self.find_profile(env_id, pid, now) {
                let p = &self.entries[idx];
                return ResolvedPolicy {
                    profile_id: p.profile_id,
                    require_pkce: p.require_pkce,
                };
            }
        }

        if let Some(idx) = self.find_default(env_id, now) {
            let p = &self.entries[idx];
            return ResolvedPolicy {
                profile_id: p.profile_id,
                require_pkce: p.require_pkce,
            };
        }

        ResolvedPolicy::BASELINE
    }

    /// Count active defaults for an environment.
    pub fn count_active_defaults(&self, env_id: u8) -> usize {
        let mut count = 0usize;
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied
                && self.entries[i].env_id == env_id
                && self.entries[i].is_default
                && self.entries[i].is_active
            {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Check all profiles for modern flow well-formedness.
    pub fn all_modern_flow_well_formed(&self) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].occupied && !self.entries[i].is_modern_flow_well_formed() {
                return false;
            }
            i += 1;
        }
        true
    }
}
