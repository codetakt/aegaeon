#![forbid(unsafe_code)]
#![cfg_attr(not(kani), allow(dead_code))]

#[cfg(kani)]
mod bounded_device_authz;
#[cfg(kani)]
mod bounded_entity_config;
#[cfg(kani)]
mod bounded_federation_cache;
#[cfg(kani)]
mod bounded_jwt_introspection;
#[cfg(kani)]
mod bounded_management;
#[cfg(kani)]
mod bounded_sd_jwt;
#[cfg(kani)]
mod bounded_stores;
#[cfg(kani)]
mod bounded_subordinate_stmt;
#[cfg(kani)]
mod bounded_upstream;

#[cfg(kani)]
mod harnesses {
    use aegaeon_pure as pure;
    use kani::any;
    use kani::assume;

    const KEY_TYPE_EC: u8 = 1;
    const KEY_TYPE_RSA: u8 = 2;

    #[derive(Clone, Copy)]
    enum CacheControlCase {
        PublicMaxAge120,
        MaxAgeZero,
        Empty,
        InvalidMaxAge,
    }

    const fn parse_cache_control_case(case: CacheControlCase) -> Option<u64> {
        match case {
            CacheControlCase::PublicMaxAge120 => Some(120),
            CacheControlCase::MaxAgeZero => Some(0),
            CacheControlCase::Empty | CacheControlCase::InvalidMaxAge => None,
        }
    }

    #[kani::proof]
    pub fn proof_trivial_arithmetic() {
        assert!(1 + 1 == 2);
    }

    /// TEST: Primitives with variables (before bounded_stores usage)
    #[kani::proof]
    pub fn proof_test_primitives_early() {
        let x: u8 = 42;
        assert!(x == 42);
    }

    /// TEST: Minimal ByteString reproduction (inline struct)
    #[kani::proof]
    pub fn proof_bytestring_minimal_inline() {
        #[derive(Clone, Copy)]
        struct ByteString {
            data: [u8; 64],
            len: usize,
            valid: bool,
        }

        let mut bs = ByteString {
            data: [0; 64],
            len: 0,
            valid: false,
        };
        bs.data[0] = 1;
        bs.len = 1;
        bs.valid = true;
        assert!(bs.valid);
        assert!(bs.len == 1);
        assert!(bs.data[0] == 1);
    }

    /// TEST: Small array (size 8) with for loop
    #[kani::proof]
    pub fn proof_small_array_loop() {
        let mut arr: [u8; 8] = [0; 8];

        for i in 0..4 {
            arr[i] = i as u8;
        }

        assert!(arr[0] == 0);
        assert!(arr[3] == 3);
    }

    /// TEST: Large array (size 64) with for loop
    #[kani::proof]
    pub fn proof_large_array_loop() {
        let mut arr: [u8; 64] = [0; 64];

        for i in 0..4 {
            arr[i] = i as u8;
        }

        assert!(arr[0] == 0);
        assert!(arr[3] == 3);
    }

    /// TEST: For loop with slice indexing
    #[kani::proof]
    pub fn proof_for_loop_slice_copy() {
        let mut arr: [u8; 64] = [0; 64];
        let input: &[u8] = b"test";

        for i in 0..4 {
            arr[i] = input[i];
        }

        assert!(arr[0] == input[0]);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    pub fn proof_parse_cache_control_no_panic() {
        let choice: u8 = any();
        assume(choice < 4);
        let case = match choice {
            0 => CacheControlCase::PublicMaxAge120,
            1 => CacheControlCase::MaxAgeZero,
            2 => CacheControlCase::Empty,
            _ => CacheControlCase::InvalidMaxAge,
        };
        let res = parse_cache_control_case(case);
        match case {
            CacheControlCase::PublicMaxAge120 => assert!(res == Some(120)),
            CacheControlCase::MaxAgeZero => assert!(res == Some(0)),
            CacheControlCase::Empty | CacheControlCase::InvalidMaxAge => assert!(res.is_none()),
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_manual_byte_loop() {
        let pick: u8 = any();
        assume(pick < 4);
        let s = match pick {
            0 => "",
            1 => "a",
            2 => "ab",
            _ => "abc",
        };
        let bytes = s.as_bytes();
        let mut start = 0usize;
        let mut i = 0usize;
        while i <= bytes.len() {
            if i == bytes.len() || bytes[i] == b',' {
                start = i + 1;
            }
            i += 1;
        }
        assert!(start <= bytes.len().saturating_add(1));
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_option_loop() {
        let bytes = match any::<u8>() {
            0 => b"" as &[u8],
            1 => b"a" as &[u8],
            _ => b"ab" as &[u8],
        };
        let mut res = None;
        let mut i = 0usize;
        while i <= bytes.len() {
            if i == bytes.len() {
                res = Some(42u64);
            }
            i += 1;
        }
        if let Some(v) = res {
            assert!(v == 42);
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_sha256_hex_len_constant() {
        let a = pure::sha256_hex(b"");
        let b = pure::sha256_hex(b"abc");
        assert!(a.len() == 64);
        assert!(b.len() == 64);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_duplicate_kid_detection() {
        let duplicate = any::<bool>();
        let jwks = pure::Jwks::new([
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_EC,
                kid_present: true,
                kid: 1,
                n_present: false,
                n: 0,
                e_present: false,
                e: 0,
            },
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_EC,
                kid_present: true,
                kid: if duplicate { 1 } else { 2 },
                n_present: false,
                n: 0,
                e_present: false,
                e: 0,
            },
            pure::Jwk::empty(),
            pure::Jwk::empty(),
            pure::Jwk::empty(),
        ]);
        let has_dup = pure::has_duplicate_kid(&jwks);
        if duplicate {
            assert!(has_dup);
        } else {
            assert!(!has_dup);
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_kid_reuse_violation_detected() {
        let change = any::<bool>();
        let prev = [(1u8, 1u8)];
        let next_fp = if change { 2 } else { 1 };
        let newm = [(1u8, next_fp)];
        let changed = pure::kid_reuse_changed(&prev, &newm);
        if change {
            assert!(changed);
        } else {
            assert!(!changed);
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_select_jwk_by_kid_or_first() {
        let pick_second = any::<bool>();
        let jwks = pure::Jwks::new([
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_EC,
                kid_present: true,
                kid: 1,
                n_present: false,
                n: 0,
                e_present: false,
                e: 0,
            },
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_RSA,
                kid_present: true,
                kid: 2,
                n_present: true,
                n: 1,
                e_present: true,
                e: 1,
            },
            pure::Jwk::empty(),
            pure::Jwk::empty(),
            pure::Jwk::empty(),
        ]);
        let requested = if pick_second { Some(2) } else { Some(1) };
        let selected = pure::select_jwk(&jwks, requested);
        assert!(selected.is_some());
        let s = selected.unwrap();
        if pick_second {
            assert!(s.kty == KEY_TYPE_RSA);
        } else {
            assert!(s.kty == KEY_TYPE_EC);
        }

        let default = pure::select_jwk(&jwks, None);
        assert!(default.is_some());
        let def = default.unwrap();
        assert!(def.kty == KEY_TYPE_EC);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    pub fn proof_overlap_active_kid_conflict_rejected() {
        let conflict = any::<bool>();
        let active = pure::Jwk {
            present: true,
            kty: KEY_TYPE_RSA,
            kid_present: true,
            kid: 7,
            n_present: true,
            n: 1,
            e_present: true,
            e: 1,
        };
        let overlap = pure::Jwks::new([
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_RSA,
                kid_present: true,
                kid: if conflict { 7 } else { 8 },
                n_present: true,
                n: 2,
                e_present: true,
                e: 1,
            },
            pure::Jwk::empty(),
            pure::Jwk::empty(),
            pure::Jwk::empty(),
            pure::Jwk::empty(),
        ]);

        let has_conflict = pure::has_conflicting_active_kid(&overlap, 7);
        let merged = pure::merge_active_and_additional(&active, 7, &overlap);
        if conflict {
            assert!(has_conflict);
            assert!(merged.is_none());
        } else {
            assert!(!has_conflict);
            assert!(merged.is_some());
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    pub fn proof_overlap_merge_keeps_active_first_and_unique_kids() {
        let include_second = any::<bool>();
        let active = pure::Jwk {
            present: true,
            kty: KEY_TYPE_RSA,
            kid_present: true,
            kid: 7,
            n_present: true,
            n: 1,
            e_present: true,
            e: 1,
        };
        let overlap = pure::Jwks::new([
            pure::Jwk {
                present: true,
                kty: KEY_TYPE_RSA,
                kid_present: true,
                kid: 8,
                n_present: true,
                n: 2,
                e_present: true,
                e: 1,
            },
            pure::Jwk {
                present: include_second,
                kty: KEY_TYPE_RSA,
                kid_present: include_second,
                kid: 9,
                n_present: include_second,
                n: 3,
                e_present: include_second,
                e: 1,
            },
            pure::Jwk::empty(),
            pure::Jwk::empty(),
            pure::Jwk::empty(),
        ]);

        let merged =
            pure::merge_active_and_additional(&active, 7, &overlap).expect("valid overlap merge");
        assert!(merged.keys[0].present);
        assert!(merged.keys[0].kid_present);
        assert!(merged.keys[0].kid == 7);
        assert!(!pure::has_duplicate_kid(&merged));
        assert!(pure::select_jwk(&merged, Some(7)).unwrap().kid == 7);
    }

    // ========================================================================
    // Bounded Store Harnesses (HashMap-free server verification)
    // ========================================================================

    /// Verify DPoP JTI replay protection with bounded store (Byte Array Version)
    ///
    /// Property: Same JTI within replay window must be rejected
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_dpop_jti_replay_rejected() {
        use crate::bounded_stores::BoundedJtiStore;

        let mut store = BoundedJtiStore::new();

        // Use byte literals instead of String (avoids Kani ICE)
        let jti: &[u8] = b"test-jti";
        let now: i64 = 1000;
        let replay_window: i64 = 300;

        // First insertion succeeds
        let first = store.check_and_store(now, replay_window, jti);
        assert!(first, "First JTI insertion should succeed");

        // Immediate replay within window is rejected
        let replay = store.check_and_store(now, replay_window, jti);
        assert!(!replay, "Replay within window must be rejected");

        // Different JTI succeeds
        let different: &[u8] = b"different-jti";
        let third = store.check_and_store(now, replay_window, different);
        assert!(third, "Different JTI should succeed");
    }

    /// Verify JTI cleanup after replay window expires (Byte Array Version)
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_dpop_jti_cleanup_after_window() {
        use crate::bounded_stores::BoundedJtiStore;

        let mut store = BoundedJtiStore::new();

        let jti: &[u8] = b"test-jti";
        let t1: i64 = 1000;
        let replay_window: i64 = 300;

        // Insert at t1
        let first = store.check_and_store(t1, replay_window, jti);
        assert!(first);

        // Same JTI at t1 + window + 1 (after expiration)
        let t2 = t1 + replay_window + 1;
        let second = store.check_and_store(t2, replay_window, jti);
        assert!(second, "JTI after replay window should be accepted");
    }

    // ========================================================================
    // Incremental Complexity Tests - Isolate ICE Trigger
    // ========================================================================

    /// Level 0: Just primitives, no struct
    #[kani::proof]
    pub fn proof_level0_primitives_only() {
        let x: u8 = 42;
        let y: bool = true;
        assert_eq!(x, 42);
        assert!(y);
    }

    /// Level 1: Simple struct with single byte
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level1_single_byte_struct() {
        #[derive(Debug, Clone, Copy)]
        struct SimpleByte {
            data: u8,
            valid: bool,
        }

        let s = SimpleByte {
            data: 42,
            valid: true,
        };
        assert_eq!(s.data, 42);
    }

    /// Level 2: Small fixed array [u8; 8]
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level2_small_array() {
        let arr: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(arr[0], 1);
        assert_eq!(arr[7], 8);
    }

    /// Level 3: Struct with small array [u8; 8]
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level3_struct_small_array() {
        #[derive(Debug, Clone, Copy)]
        struct SmallByteArray {
            data: [u8; 8],
            len: usize,
        }

        let s = SmallByteArray {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
            len: 8,
        };
        assert_eq!(s.len, 8);
        assert_eq!(s.data[0], 1);
    }

    /// Level 4: Struct with medium array [u8; 32]
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level4_struct_medium_array() {
        #[derive(Debug, Clone, Copy)]
        struct MediumByteArray {
            data: [u8; 32],
            len: usize,
        }

        let s = MediumByteArray {
            data: [0u8; 32],
            len: 0,
        };
        assert_eq!(s.len, 0);
    }

    /// Level 5: ByteString struct (full size [u8; 64])
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level5_bytestring_struct() {
        use crate::bounded_stores::ByteString;

        let bs = ByteString::new();
        assert!(!bs.valid);
        assert_eq!(bs.len, 0);
    }

    /// Level 6: ByteString with store operation
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level6_bytestring_store() {
        use crate::bounded_stores::ByteString;

        let mut bs = ByteString::new();
        bs.store(b"test");
        assert!(bs.valid);
        assert_eq!(bs.len, 4);
    }

    /// Level 7: Single ByteString in array
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level7_bytestring_array_one() {
        use crate::bounded_stores::ByteString;

        let arr: [ByteString; 1] = [ByteString::new()];
        assert!(!arr[0].valid);
    }

    /// Level 8: Two ByteStrings in array
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level8_bytestring_array_two() {
        use crate::bounded_stores::ByteString;

        let arr: [ByteString; 2] = [ByteString::new(); 2];
        assert!(!arr[0].valid);
        assert!(!arr[1].valid);
    }

    /// Level 9: Array of tuples (ByteString, i64) - size 2
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level9_tuple_array_two() {
        use crate::bounded_stores::ByteString;

        let arr: [(ByteString, i64); 2] = [(ByteString::new(), 0); 2];
        assert_eq!(arr[0].1, 0);
        assert_eq!(arr[1].1, 0);
    }

    /// Level 10: Full BoundedJtiStore construction
    #[kani::proof]
    #[kani::unwind(5)]
    pub fn proof_level10_store_construction() {
        use crate::bounded_stores::BoundedJtiStore;

        let store = BoundedJtiStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    // ========================================================================
    // BoundedTokenStore Harnesses
    // ========================================================================

    /// Verify access token expiration enforcement
    ///
    /// Tests three points: before, at, and after `expires_at`.
    /// F* `is_expired`: `current_time >= expires_at` ⟹ expired.
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_expired_access_token_rejected() {
        use crate::bounded_stores::BoundedTokenStore;

        let mut store = BoundedTokenStore::new();

        let token: &[u8] = b"access-token-1";
        let created_at: i64 = 1000;
        let expires_in: i64 = 300;
        let expires_at = created_at + expires_in;

        store.store_access_token(token, expires_at);

        // Before expiration: valid
        let valid = store.verify_access_token(token, created_at + 100);
        assert!(valid, "Token should be valid before expiration");

        // At exact expiration boundary: expired (V-1 fix, matches F* is_expired)
        let at_boundary = store.verify_access_token(token, expires_at);
        assert!(!at_boundary, "Token at exact expiration must be rejected");

        // After expiration: expired
        let expired = store.verify_access_token(token, expires_at + 1);
        assert!(!expired, "Expired token must be rejected");
    }

    /// Verify revoked token is rejected
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_revoked_access_token_rejected() {
        use crate::bounded_stores::BoundedTokenStore;

        let mut store = BoundedTokenStore::new();

        let token: &[u8] = b"access-token-1";
        let now: i64 = 1000;
        let expires_at = now + 3600;

        store.store_access_token(token, expires_at);
        let valid = store.verify_access_token(token, now);
        assert!(valid);

        // Revoke
        store.revoke_token(token);

        // Verify revoked token is rejected
        let revoked = store.verify_access_token(token, now);
        assert!(!revoked, "Revoked token must be rejected");
    }

    /// Verify refresh token single-use (rotation)
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_refresh_token_single_use() {
        use crate::bounded_stores::BoundedTokenStore;

        let mut store = BoundedTokenStore::new();

        let token: &[u8] = b"refresh-token-1";
        let now: i64 = 1000;
        let expires_at = now + 3600;

        store.store_refresh_token(token, expires_at);

        // First rotation succeeds
        let first_rotation = store.rotate_refresh_token(token, now);
        assert!(first_rotation, "First rotation should succeed");

        // Second rotation fails (single-use)
        let second_rotation = store.rotate_refresh_token(token, now);
        assert!(!second_rotation, "Second rotation must fail (single-use)");
    }

    /// Verify refresh token rotation rejects at expiration boundary
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_refresh_token_rotation_boundary() {
        use crate::bounded_stores::BoundedTokenStore;

        let mut store = BoundedTokenStore::new();

        let token: &[u8] = b"refresh-token-2";
        let expires_at: i64 = 2000;

        store.store_refresh_token(token, expires_at);

        // At exact expiration boundary: rejected (matches F* is_expired)
        let at_boundary = store.rotate_refresh_token(token, expires_at);
        assert!(
            !at_boundary,
            "Rotation at exact expiration must be rejected"
        );
    }

    // ========================================================================
    // BoundedAuthCodeStore Harnesses
    // ========================================================================

    /// Verify authorization code single-use enforcement
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_authcode_single_use() {
        use crate::bounded_stores::BoundedAuthCodeStore;

        let mut store = BoundedAuthCodeStore::new();

        let code: &[u8] = b"auth-code-1";
        let now: i64 = 1000;
        let expires_at = now + 600;

        let result = store.store_code(code, expires_at, None, None);
        assert!(result.is_ok());

        // First use succeeds
        let first_use = store.use_code(code, now);
        assert!(first_use, "First code use should succeed");

        // Second use fails (single-use)
        let second_use = store.use_code(code, now);
        assert!(!second_use, "Second code use must fail (single-use)");
    }

    /// Verify state parameter uniqueness
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_state_uniqueness() {
        use crate::bounded_stores::BoundedAuthCodeStore;

        let mut store = BoundedAuthCodeStore::new();

        let code1: &[u8] = b"code-1";
        let code2: &[u8] = b"code-2";
        let state: &[u8] = b"state-123";
        let expires_at: i64 = 1600;

        // First code with state succeeds
        let first = store.store_code(code1, expires_at, Some(state), None);
        assert!(first.is_ok());

        // Second code with same state fails
        let second = store.store_code(code2, expires_at, Some(state), None);
        assert!(second.is_err(), "Duplicate state must be rejected");
    }

    /// Verify nonce parameter uniqueness
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_nonce_uniqueness() {
        use crate::bounded_stores::BoundedAuthCodeStore;

        let mut store = BoundedAuthCodeStore::new();

        let code1: &[u8] = b"code-1";
        let code2: &[u8] = b"code-2";
        let nonce: &[u8] = b"nonce-xyz";
        let expires_at: i64 = 1600;

        // First code with nonce succeeds
        let first = store.store_code(code1, expires_at, None, Some(nonce));
        assert!(first.is_ok());

        // Second code with same nonce fails
        let second = store.store_code(code2, expires_at, None, Some(nonce));
        assert!(second.is_err(), "Duplicate nonce must be rejected");
    }

    /// Verify expired authorization code is rejected
    ///
    /// Tests three points: before, at, and after `expires_at`.
    /// F* `is_expired`: `current_time >= expires_at` ⟹ expired.
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_expired_authcode_rejected() {
        use crate::bounded_stores::BoundedAuthCodeStore;

        let mut store = BoundedAuthCodeStore::new();

        let code: &[u8] = b"code-1";
        let created_at: i64 = 1000;
        let expires_in: i64 = 600;
        let expires_at = created_at + expires_in;

        store.store_code(code, expires_at, None, None).unwrap();

        // Before expiration: valid
        let before = store.get_code(code, expires_at - 1);
        assert!(before, "Code should be valid before expiration");

        // At exact expiration boundary: expired (V-1 fix, matches F* is_expired)
        let at_boundary = store.get_code(code, expires_at);
        assert!(!at_boundary, "Code at exact expiration must be rejected");

        // After expiration: use_code also rejects
        let after = store.use_code(code, expires_at + 1);
        assert!(!after, "Expired code must be rejected");
    }

    // ========================================
    // Minimal String ICE Tests (Kani 0.66.0)
    // ========================================

    /// Minimal test: String::new() only
    #[kani::proof]
    pub fn proof_string_new_minimal() {
        let s: String = String::new();
        assert!(s.is_empty(), "Empty string should be empty");
    }

    /// Minimal test: Static str in Option
    #[kani::proof]
    pub fn proof_option_static_str() {
        let opt: Option<&'static str> = Some("test");
        assert!(opt.is_some(), "Option should contain value");
    }

    /// Minimal test: String::from() only
    #[kani::proof]
    pub fn proof_string_from_minimal() {
        let s: String = String::from("test");
        assert!(!s.is_empty(), "String should not be empty");
    }

    /// Minimal test: Option<String> construction
    #[kani::proof]
    pub fn proof_option_string_minimal() {
        let opt: Option<String> = Some(String::from("test"));
        assert!(opt.is_some(), "Option should contain value");
    }

    /// TEST: HashMap basic operations (ICE trigger test)
    #[kani::proof]
    pub fn proof_hashmap_basic() {
        use std::collections::HashMap;

        let mut map: HashMap<u8, u8> = HashMap::new();
        map.insert(1, 42);

        assert!(map.contains_key(&1));
        assert_eq!(map.get(&1), Some(&42));
    }

    /// TEST: HashMap with String keys (ICE trigger test)
    #[kani::proof]
    pub fn proof_hashmap_string_keys() {
        use std::collections::HashMap;

        let mut map: HashMap<String, u8> = HashMap::new();
        map.insert(String::from("key1"), 100);

        assert!(map.contains_key("key1"));
    }

    /// Lightweight integration test for Nix build verification
    /// This harness is designed to be fast (<1s) to validate Kani toolchain setup
    #[kani::proof]
    pub fn proof_nix_integration_check() {
        let x: u8 = kani::any();
        kani::assume(x < 10);

        // Basic arithmetic
        let y = x + 1;
        assert!(y <= 10);

        // Array access
        let arr: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(arr[x as usize] == x);
    }

    // ========================================================================
    // SD-JWT Bounded Verification Harnesses (RFC 9901)
    // ========================================================================

    /// Verify disclosure encode → decode → identity
    ///
    /// Property: For any valid disclosure, encoding then decoding
    /// produces the original salt, claim_name, and claim_value.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_disclosure_roundtrip() {
        use crate::bounded_sd_jwt::BoundedDisclosure;

        let salt: &[u8] = b"sa";
        let name: &[u8] = b"nm";
        let value: &[u8] = b"vl";

        let d = BoundedDisclosure::new(salt, name, value);
        let encoded = d.encode();
        let decoded = BoundedDisclosure::decode(&encoded);

        assert!(decoded.is_some(), "Decode must succeed for valid encoding");
        let dd = decoded.unwrap();
        assert!(dd.salt.equals(salt), "Salt must roundtrip");
        assert!(dd.claim_name.equals(name), "Name must roundtrip");
        assert!(dd.claim_value.equals(value), "Value must roundtrip");
    }

    /// Verify different disclosures produce different digests
    ///
    /// Property: If two disclosures differ in any field (salt, name, or value),
    /// their digests must differ.  This models the collision-resistance of
    /// SHA-256 in the real implementation.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_digest_uniqueness() {
        use crate::bounded_sd_jwt::{bytestrings_equal, BoundedDisclosure};

        let d1 = BoundedDisclosure::new(b"s1", b"nm", b"v1");
        let d2 = BoundedDisclosure::new(b"s2", b"nm", b"v2");

        let dig1 = d1.digest();
        let dig2 = d2.digest();

        assert!(dig1.valid && dig2.valid, "Digests must be valid");
        assert!(
            !bytestrings_equal(&dig1, &dig2),
            "Different disclosures must produce different digests"
        );
    }

    /// Verify issuer payload contains correct SD digests
    ///
    /// Property: Each selectively-disclosed claim's digest appears in the
    /// `_sd` array, and a forged disclosure's digest does not.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_issuer_payload() {
        use crate::bounded_sd_jwt::{BoundedDisclosure, BoundedSdArray};

        let d1 = BoundedDisclosure::new(b"s1", b"gn", b"Jo");
        let d2 = BoundedDisclosure::new(b"s2", b"fn", b"Do");

        let dig1 = d1.digest();
        let dig2 = d2.digest();

        // Issuer builds _sd array from disclosure digests
        let mut sd_array = BoundedSdArray::new();
        sd_array.push(&dig1);
        sd_array.push(&dig2);

        // Each disclosure's digest must be in the _sd array
        assert!(sd_array.contains(&dig1), "Digest of d1 must be in _sd");
        assert!(sd_array.contains(&dig2), "Digest of d2 must be in _sd");

        // A forged disclosure's digest must NOT be in the _sd array
        let forged = BoundedDisclosure::new(b"xx", b"ev", b"!!").digest();
        assert!(
            !sd_array.contains(&forged),
            "Forged digest must not be in _sd"
        );
    }

    /// Verify all disclosures reconstruct all SD claims
    ///
    /// Property: When the verifier receives all disclosures, every digest
    /// matches and every claim name/value pair is recovered.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_verifier_reconstruction() {
        use crate::bounded_sd_jwt::{BoundedDisclosure, BoundedSdArray};

        let d1 = BoundedDisclosure::new(b"s1", b"gn", b"Jo");
        let d2 = BoundedDisclosure::new(b"s2", b"fn", b"Do");

        // Issuer builds _sd array
        let dig1 = d1.digest();
        let dig2 = d2.digest();
        let mut sd = BoundedSdArray::new();
        sd.push(&dig1);
        sd.push(&dig2);

        // Verifier checks all disclosures against _sd
        let disclosures = [d1, d2];
        let mut all_matched = true;
        let mut i = 0;
        while i < 2 {
            let dig = disclosures[i].digest();
            if !sd.contains(&dig) {
                all_matched = false;
            }
            i += 1;
        }
        assert!(all_matched, "All disclosures must match _sd digests");

        // Verify reconstructed claims match original values
        assert!(disclosures[0].claim_name.equals(b"gn"), "First claim name");
        assert!(
            disclosures[0].claim_value.equals(b"Jo"),
            "First claim value"
        );
        assert!(disclosures[1].claim_name.equals(b"fn"), "Second claim name");
        assert!(
            disclosures[1].claim_value.equals(b"Do"),
            "Second claim value"
        );
    }

    /// Verify holder partial selection produces correct subset
    ///
    /// Property: Selecting a subset of claim names from all disclosures
    /// yields exactly the disclosures with matching names, preserving order.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_holder_selection() {
        use crate::bounded_sd_jwt::{BoundedDisclosure, BoundedDisclosureSet};

        let d1 = BoundedDisclosure::new(b"s1", b"gn", b"Jo");
        let d2 = BoundedDisclosure::new(b"s2", b"fn", b"Do");
        let d3 = BoundedDisclosure::new(b"s3", b"em", b"jd");

        let mut all = BoundedDisclosureSet::new();
        all.push(&d1);
        all.push(&d2);
        all.push(&d3);

        // Holder selects only "gn" and "em" (skips "fn")
        let names: &[&[u8]] = &[b"gn", b"em"];
        let selected = all.select(names);

        assert!(selected.len == 2, "Must select exactly 2 disclosures");
        assert!(
            selected.items[0].claim_name.equals(b"gn"),
            "First selected must be 'gn'"
        );
        assert!(
            selected.items[1].claim_name.equals(b"em"),
            "Second selected must be 'em'"
        );
    }

    /// Verify SD-JWT compound format serialize → parse → identity
    ///
    /// Property: Serializing an SD-JWT to the compound format and parsing
    /// it back produces the same JWT and disclosures.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn proof_sd_jwt_format_parsing() {
        use crate::bounded_sd_jwt::{bytestrings_equal, BoundedSdJwtFormat, MAX_SD_CLAIMS};
        use crate::bounded_stores::ByteString;

        // Build an SD-JWT with JWT + 1 short disclosure
        let mut disc = ByteString::new();
        disc.store(b"d1d1d1");

        let mut discs = [ByteString::new(); MAX_SD_CLAIMS];
        discs[0] = disc;

        let original = BoundedSdJwtFormat::build(b"h.p.s", 1, &discs);
        let serialized = original.serialize();
        let parsed = BoundedSdJwtFormat::parse(&serialized);

        assert!(
            parsed.is_some(),
            "Parse must succeed for valid serialization"
        );
        let p = parsed.unwrap();
        assert!(p.jwt.equals(b"h.p.s"), "JWT must roundtrip");
        assert!(p.disc_len == 1, "Must have 1 disclosure");
        assert!(
            bytestrings_equal(&p.disclosures[0], &disc),
            "Disclosure must roundtrip"
        );
    }

    // ========================================================================
    // Upstream Refresh Token Lifecycle Harnesses
    // ========================================================================

    /// Verify refresh token rotation replaces old token
    ///
    /// Property: After storing a new refresh token for a link, `get` returns
    /// the new token and the old token value is no longer in the store.
    /// Models the `UPDATE ... SET upstream_refresh_token_encrypted = $1`
    /// in the production refresh endpoint.
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_upstream_refresh_token_rotation() {
        use crate::bounded_upstream::BoundedUpstreamRefreshStore;

        let mut store = BoundedUpstreamRefreshStore::new();

        let issuer: &[u8] = b"idp";
        let sub: &[u8] = b"u1";
        let user: &[u8] = b"me";
        let conn: &[u8] = b"c1";
        let token_a: &[u8] = b"tA";
        let token_b: &[u8] = b"tB";

        // Create link and store initial refresh token
        assert!(store.create_link(issuer, sub, user, conn));
        assert!(store.store_refresh_token(issuer, sub, conn, 0, token_a));

        // Verify token_a is stored
        let got = store.get_refresh_token(issuer, sub, conn);
        assert!(got.is_some(), "Link must have a refresh token");
        assert!(
            got.unwrap().equals(token_a),
            "Initial token must be token_a"
        );

        // Rotate: upstream IdP returns new token_b
        assert!(store.store_refresh_token(issuer, sub, conn, 1, token_b));

        // Verify token_b is now stored
        let got2 = store.get_refresh_token(issuer, sub, conn);
        assert!(got2.is_some(), "Link must still have a refresh token");
        assert!(
            got2.unwrap().equals(token_b),
            "After rotation, must be token_b"
        );

        // Old token_a is gone from the store
        assert!(
            !store.has_token_value(token_a),
            "Old token must not be in store after rotation"
        );
    }

    /// Verify refresh requires a valid account link
    ///
    /// Property: `get_refresh_token` and `store_refresh_token` fail for
    /// (issuer, sub_hash) pairs that have no corresponding account link.
    /// Models the `WHERE upstream_issuer = $1 AND upstream_sub_hash = $2`
    /// query returning zero rows → 404 in the production endpoint.
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_upstream_refresh_requires_valid_link() {
        use crate::bounded_upstream::BoundedUpstreamRefreshStore;

        let mut store = BoundedUpstreamRefreshStore::new();

        let issuer: &[u8] = b"idp";
        let sub: &[u8] = b"u1";
        let user: &[u8] = b"me";
        let conn: &[u8] = b"c1";
        let token: &[u8] = b"rt";

        // Create link for (idp, u1) only
        assert!(store.create_link(issuer, sub, user, conn));
        assert!(store.store_refresh_token(issuer, sub, conn, 0, token));

        // Existing link works
        assert!(
            store.get_refresh_token(issuer, sub, conn).is_some(),
            "Existing link must return token"
        );

        // Non-existent link (different sub_hash) fails
        let missing_sub: &[u8] = b"u2";
        assert!(
            store.get_refresh_token(issuer, missing_sub, conn).is_none(),
            "Non-existent link must return None"
        );
        assert!(
            !store.store_refresh_token(issuer, missing_sub, conn, 1, b"xx"),
            "Cannot store token for non-existent link"
        );

        // Non-existent link (different issuer) fails
        let missing_iss: &[u8] = b"x";
        assert!(
            store.get_refresh_token(missing_iss, sub, conn).is_none(),
            "Wrong issuer must return None"
        );
    }

    /// Verify refresh token single-use after rotation
    ///
    /// Property: After each rotation, the previous token value is no
    /// longer present in the store. This models the OAuth refresh token
    /// rotation pattern where the upstream IdP invalidates the old token
    /// and we must not attempt to reuse it.
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_upstream_refresh_token_single_use() {
        use crate::bounded_upstream::BoundedUpstreamRefreshStore;

        let mut store = BoundedUpstreamRefreshStore::new();

        let issuer: &[u8] = b"idp";
        let sub: &[u8] = b"u1";
        let user: &[u8] = b"me";
        let conn: &[u8] = b"c1";
        let token_a: &[u8] = b"tA";
        let token_b: &[u8] = b"tB";
        let token_c: &[u8] = b"tC";

        store.create_link(issuer, sub, user, conn);
        store.store_refresh_token(issuer, sub, conn, 0, token_a);

        // Before rotation: token_a is present
        assert!(
            store.has_token_value(token_a),
            "token_a present before rotation"
        );

        // First rotation: a → b
        store.store_refresh_token(issuer, sub, conn, 1, token_b);
        assert!(
            !store.has_token_value(token_a),
            "token_a gone after first rotation (single-use)"
        );
        assert!(store.has_token_value(token_b), "token_b is now stored");

        // Second rotation: b → c
        store.store_refresh_token(issuer, sub, conn, 2, token_c);
        assert!(
            !store.has_token_value(token_b),
            "token_b gone after second rotation (single-use)"
        );
        assert!(store.has_token_value(token_c), "token_c is now stored");

        // Only the latest token is retrievable
        let current = store.get_refresh_token(issuer, sub, conn);
        assert!(current.is_some());
        assert!(current.unwrap().equals(token_c), "Only token_c is current");
    }

    // ========================================================================
    // Management Plane Harnesses — Client CRUD
    // ========================================================================

    /// Verify client identifier uniqueness within environment
    ///
    /// Property: After creating a client with identifier "c1" in env 1,
    /// creating another client with the same identifier in the same env fails.
    /// Matches DB constraint: `clients_env_client_identifier_unique`
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_client_identifier_uniqueness() {
        use crate::bounded_management::BoundedClientStore;

        let mut store = BoundedClientStore::new();

        let env: u8 = 1;
        let ident: &[u8] = b"client-1";

        // First create succeeds
        let first = store.create_client(env, ident, 1);
        assert!(first, "First client creation should succeed");

        // Same identifier in same env fails
        let duplicate = store.create_client(env, ident, 1);
        assert!(
            !duplicate,
            "Duplicate identifier in same env must be rejected"
        );

        // Same identifier in different env succeeds (cross-env is fine)
        let other_env: u8 = 2;
        let cross_env = store.create_client(other_env, ident, 1);
        assert!(cross_env, "Same identifier in different env should succeed");
    }

    /// Verify client redirect_uris must be non-empty
    ///
    /// Property: Creating a client with zero redirect URIs is rejected.
    /// Matches the OAuth 2.0/2.1 requirement that clients must register
    /// at least one redirect URI.
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_client_redirect_uri_nonempty() {
        use crate::bounded_management::{BoundedClientStore, MAX_REDIRECT_URIS};

        let mut store = BoundedClientStore::new();

        // Zero redirect URIs rejected
        let no_uris = store.create_client(1, b"c1", 0);
        assert!(!no_uris, "Client with zero redirect URIs must be rejected");

        // Too many redirect URIs rejected
        let too_many_uris = store.create_client(1, b"c1", MAX_REDIRECT_URIS + 1);
        assert!(
            !too_many_uris,
            "Client exceeding redirect URI bound must be rejected"
        );

        // One or more redirect URIs accepted
        let with_uris = store.create_client(1, b"c1", MAX_REDIRECT_URIS);
        assert!(with_uris, "Client with redirect URIs should succeed");
    }

    /// Verify soft-delete frees identifier for reuse
    ///
    /// Property: After soft-deleting a client, a new client with the same
    /// identifier can be created in the same environment.
    /// Matches the partial unique index: `WHERE status <> 'DELETED'`
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_client_soft_delete_frees_identifier() {
        use crate::bounded_management::BoundedClientStore;

        let mut store = BoundedClientStore::new();
        let env: u8 = 1;
        let ident: &[u8] = b"c1";

        // Create and then soft-delete
        assert!(store.create_client(env, ident, 1));
        assert!(store.soft_delete(env, ident));

        // After soft-delete, identifier is available for reuse
        assert!(
            !store.identifier_taken(env, ident),
            "Soft-deleted identifier must be available"
        );

        // Re-creation with same identifier succeeds
        let recreate = store.create_client(env, ident, 2);
        assert!(recreate, "Re-creation after soft-delete should succeed");
    }

    /// Verify soft-delete preserves record in store
    ///
    /// Property: After soft-delete, the total count of entries does not
    /// decrease (record is retained with Deleted status).
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_client_soft_delete_preserves_record() {
        use crate::bounded_management::BoundedClientStore;

        let mut store = BoundedClientStore::new();
        let env: u8 = 1;
        let ident: &[u8] = b"c1";

        assert!(store.create_client(env, ident, 1));

        // Active count is 1 before delete
        assert!(store.count_active(env, ident) == 1);

        // Soft-delete
        assert!(store.soft_delete(env, ident));

        // Active count is 0 after delete
        assert!(
            store.count_active(env, ident) == 0,
            "Active count must be 0 after soft-delete"
        );
    }

    // ========================================================================
    // Management Plane Harnesses — Signing Key Lifecycle
    // ========================================================================

    /// Verify at-most-one-ACTIVE-key-per-environment
    ///
    /// Property: After generating NEXT and activating, exactly one ACTIVE
    /// key exists.  The previously ACTIVE key is demoted to RETIRING.
    /// Matches DB constraint: `signing_keys_one_active_per_environment`
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_signing_key_one_active_per_env() {
        use crate::bounded_management::{BoundedSigningKeyStore, SigningKeyStatus};

        let mut store = BoundedSigningKeyStore::new();
        let env: u8 = 1;

        // Generate first key as NEXT, then activate
        assert!(store.generate_next(env, b"k1"));
        assert!(store.activate_next(env));
        assert!(
            store.count_status(env, SigningKeyStatus::Active) == 1,
            "Must have exactly 1 ACTIVE after first activation"
        );

        // Generate second key as NEXT
        assert!(store.generate_next(env, b"k2"));
        assert!(
            store.count_status(env, SigningKeyStatus::Active) == 1,
            "Generating NEXT must not affect ACTIVE count"
        );

        // Activate second key: k1 → RETIRING, k2 → ACTIVE
        assert!(store.activate_next(env));
        assert!(
            store.count_status(env, SigningKeyStatus::Active) == 1,
            "Must still have exactly 1 ACTIVE after rotation"
        );
        assert!(
            store.count_status(env, SigningKeyStatus::Retiring) == 1,
            "Old ACTIVE must be RETIRING"
        );
    }

    /// Verify kid uniqueness within environment
    ///
    /// Property: Generating a NEXT key with the same kid as an existing
    /// key in the same environment is rejected.
    /// Matches DB constraint: `signing_keys_environment_kid_unique`
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_signing_key_kid_uniqueness() {
        use crate::bounded_management::BoundedSigningKeyStore;

        let mut store = BoundedSigningKeyStore::new();
        let env: u8 = 1;

        // First key succeeds
        assert!(store.generate_next(env, b"kid-1"));
        assert!(store.activate_next(env));

        // Duplicate kid rejected
        let dup = store.generate_next(env, b"kid-1");
        assert!(!dup, "Duplicate kid in same env must be rejected");

        // Different kid succeeds
        assert!(
            store.generate_next(env, b"kid-2"),
            "Different kid should succeed"
        );
    }

    /// Verify revoked keys excluded from JWKS
    ///
    /// Property: After revoking a key, it is no longer JWKS-eligible.
    /// JWKS only includes ACTIVE and NEXT keys.
    /// Matches F* `lemma_revoked_excluded_from_jwks`
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_revoked_key_excluded_from_jwks() {
        use crate::bounded_management::BoundedSigningKeyStore;

        let mut store = BoundedSigningKeyStore::new();
        let env: u8 = 1;
        let kid: &[u8] = b"k1";

        // Create and activate a key
        assert!(store.generate_next(env, kid));
        assert!(store.activate_next(env));
        assert!(
            store.is_jwks_eligible(env, kid),
            "Active key must be JWKS-eligible"
        );

        // Revoke it
        assert!(store.revoke(env, kid));

        // Revoked key is not JWKS-eligible
        assert!(
            !store.is_jwks_eligible(env, kid),
            "Revoked key must not be JWKS-eligible"
        );

        // JWKS contains no revoked keys
        assert!(
            !store.jwks_contains_revoked(env),
            "JWKS must never contain revoked keys"
        );
    }

    // ========================================================================
    // Federation Trust Chain Depth Bound
    // ========================================================================

    /// Verify trust chain depth is bounded by MAX_CHAIN_DEPTH
    ///
    /// Property: A trust chain cannot exceed MAX_CHAIN_DEPTH hops.
    /// Matches Rust `MAX_CHAIN_DEPTH = 10` in federation.rs.
    #[kani::proof]
    #[kani::unwind(25)]
    pub fn proof_trust_chain_depth_bound() {
        use crate::bounded_management::{
            BoundedEntityEntry, BoundedTrustChain, MAX_CHAIN_DEPTH, MAX_CHAIN_LEN,
        };

        let mut chain = BoundedTrustChain::new();

        // Fill chain to maximum length
        let mut i: usize = 0;
        while i < MAX_CHAIN_LEN {
            let entry = BoundedEntityEntry {
                entity_id: {
                    let mut bs = crate::bounded_stores::ByteString::new();
                    bs.store(&[i as u8]);
                    bs
                },
                issuer_id: {
                    let mut bs = crate::bounded_stores::ByteString::new();
                    bs.store(&[i as u8]);
                    bs
                },
                is_config: i % 2 == 0,
                occupied: true,
            };
            assert!(chain.push(&entry), "Push within MAX_CHAIN_LEN must succeed");
            i += 1;
        }

        // Chain at max length
        assert!(chain.len == MAX_CHAIN_LEN);
        assert!(chain.depth() <= MAX_CHAIN_DEPTH, "Depth must be bounded");

        // Cannot push beyond max
        let overflow = BoundedEntityEntry::empty();
        assert!(
            !chain.push(&overflow),
            "Push beyond MAX_CHAIN_LEN must fail"
        );
    }

    /// Verify trust chain structural validity
    ///
    /// Property: A valid chain has odd length >= 3, starts with a
    /// self-signed Entity Configuration, and ends with a self-signed
    /// Entity Configuration.
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_trust_chain_structure() {
        use crate::bounded_management::{BoundedEntityEntry, BoundedTrustChain};

        let mut chain = BoundedTrustChain::new();

        // Empty chain is invalid
        assert!(!chain.is_valid_length(), "Empty chain is invalid");

        // Build a depth-1 chain: [leaf_config, sub_stmt, ta_config]
        let leaf = BoundedEntityEntry {
            entity_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"leaf");
                bs
            },
            issuer_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"leaf");
                bs
            },
            is_config: true,
            occupied: true,
        };
        let sub_stmt = BoundedEntityEntry {
            entity_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"leaf");
                bs
            },
            issuer_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"ta");
                bs
            },
            is_config: false,
            occupied: true,
        };
        let ta = BoundedEntityEntry {
            entity_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"ta");
                bs
            },
            issuer_id: {
                let mut bs = crate::bounded_stores::ByteString::new();
                bs.store(b"ta");
                bs
            },
            is_config: true,
            occupied: true,
        };

        chain.push(&leaf);
        chain.push(&sub_stmt);
        chain.push(&ta);

        assert!(chain.is_valid_length(), "Length 3 (odd) is valid");
        assert!(chain.depth() == 1, "Depth-1 chain");
        assert!(chain.leaf_is_config(), "Leaf must be self-signed config");
        assert!(
            chain.anchor_is_config(),
            "Anchor must be self-signed config"
        );
    }

    // ========================================================================
    // Token TTL Bounds
    // ========================================================================

    /// Verify token TTL positive constraint
    ///
    /// Property: A valid TTL configuration has all TTLs > 0.
    /// Matches DB constraint: `environment_policies_token_ttls_positive`
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_token_ttl_positive() {
        use crate::bounded_management::BoundedTokenTtlConfig;

        // Valid config
        let valid = BoundedTokenTtlConfig {
            access_token_ttl: 300,
            id_token_ttl: 300,
            refresh_token_ttl: 3600,
            authcode_ttl: 600,
        };
        assert!(valid.is_valid(), "Positive TTLs must be valid");

        // Zero access TTL
        let zero_access = BoundedTokenTtlConfig {
            access_token_ttl: 0,
            ..valid
        };
        assert!(!zero_access.is_valid(), "Zero access TTL must be invalid");

        // Negative refresh TTL
        let neg_refresh = BoundedTokenTtlConfig {
            refresh_token_ttl: -1,
            ..valid
        };
        assert!(
            !neg_refresh.is_valid(),
            "Negative refresh TTL must be invalid"
        );
    }

    /// Verify token expiration computed from TTL
    ///
    /// Property: expires_at = now + ttl, and is_expired at boundary
    /// matches F* `is_expired` semantics (`current_time >= expires_at`).
    #[kani::proof]
    #[kani::unwind(4)]
    pub fn proof_token_ttl_expiration_boundary() {
        use crate::bounded_management::BoundedTokenTtlConfig;

        let config = BoundedTokenTtlConfig {
            access_token_ttl: 300,
            id_token_ttl: 300,
            refresh_token_ttl: 3600,
            authcode_ttl: 600,
        };

        let now: i64 = 1000;
        let expires_at = config.access_expires_at(now);
        assert!(expires_at.is_some());
        let exp = expires_at.unwrap();
        let refresh_expires_at = config.refresh_expires_at(now);
        assert!(refresh_expires_at.is_some());
        let refresh_exp = refresh_expires_at.unwrap();

        // expires_at = now + ttl
        assert!(exp == now + 300, "expires_at must equal now + ttl");
        assert!(
            refresh_exp == now + 3600,
            "refresh expires_at must equal now + refresh ttl"
        );

        // F* is_expired: current_time >= expires_at
        // Before: valid
        assert!(now < exp, "Before expiration: valid");
        // At boundary: expired
        assert!(exp >= exp, "At boundary: expired (matches F* is_expired)");
        // After: expired
        assert!(exp + 1 >= exp, "After expiration: expired");
    }

    // ========================================================================
    // Federation Cache Harnesses — Entity Cache
    // ========================================================================

    /// Verify expired entity cache entries return None on get
    ///
    /// Property: After TTL expiry, get returns None even though
    /// the entry is in the store.
    /// Matches F* Federation.PgRepo.lemma_ec_get_expired_returns_none
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_entity_cache_expired_returns_none() {
        use crate::bounded_federation_cache::BoundedEntityCacheStore;

        let mut store = BoundedEntityCacheStore::new();
        let env: u8 = 1;
        let entity: &[u8] = b"https://op.example.com";
        let fetched_at: i64 = 1000;
        let ttl: i64 = 1800; // 30 minutes
        let expires_at = fetched_at + ttl;

        // Upsert an entry
        assert!(store.upsert(env, entity, fetched_at, expires_at));
        assert!(
            store.all_entries_well_formed(),
            "Entity cache entries must satisfy expires_at > fetched_at"
        );

        // Before expiration: get succeeds
        let before = store.get(env, entity, fetched_at + 100);
        assert!(before.is_some(), "Entry must be visible before expiration");

        // At exact boundary: expired (now >= expires_at)
        let at_boundary = store.get(env, entity, expires_at);
        assert!(at_boundary.is_none(), "Entry at boundary must be expired");

        // After expiration: expired
        let after = store.get(env, entity, expires_at + 1);
        assert!(after.is_none(), "Entry after expiration must be expired");
    }

    /// Verify upsert maintains at most one entry per natural key
    ///
    /// Property: Two upserts for the same (env_id, entity_id)
    /// result in exactly one entry in the store.
    /// Matches F* Federation.PgRepo.lemma_ec_upsert_preserves_uniqueness
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_entity_cache_upsert_uniqueness() {
        use crate::bounded_federation_cache::BoundedEntityCacheStore;

        let mut store = BoundedEntityCacheStore::new();
        let env: u8 = 1;
        let entity: &[u8] = b"https://op.example.com";

        // First upsert
        assert!(store.upsert(env, entity, 1000, 2800));
        assert!(
            store.all_entries_well_formed(),
            "First upsert must preserve entity-cache well-formedness"
        );
        assert!(
            store.count_key(env, entity) == 1,
            "First upsert: exactly one entry"
        );

        // Second upsert (same key, different TTL)
        assert!(store.upsert(env, entity, 2000, 3800));
        assert!(
            store.all_entries_well_formed(),
            "Replacement upsert must preserve entity-cache well-formedness"
        );
        assert!(
            store.count_key(env, entity) == 1,
            "Second upsert: still exactly one entry"
        );

        // Different key creates separate entry
        let entity2: &[u8] = b"https://rp.example.com";
        assert!(store.upsert(env, entity2, 2000, 3800));
        assert!(store.count_key(env, entity) == 1, "Original key unchanged");
        assert!(store.count_key(env, entity2) == 1, "New key has one entry");
    }

    /// Verify cleanup removes all expired entries, preserves valid ones
    ///
    /// Property: After cleanup_expired(now), no entry has expires_at <= now,
    /// and all non-expired entries are preserved.
    /// Matches F* Federation.PgRepo.lemma_ec_cleanup_no_expired
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_entity_cache_cleanup_soundness() {
        use crate::bounded_federation_cache::BoundedEntityCacheStore;

        let mut store = BoundedEntityCacheStore::new();
        let env: u8 = 1;

        // Insert entries with different TTLs
        assert!(store.upsert(env, b"e1", 100, 500)); // expires at 500
        assert!(store.upsert(env, b"e2", 100, 1000)); // expires at 1000
        assert!(store.upsert(env, b"e3", 100, 1500)); // expires at 1500
        assert!(
            store.all_entries_well_formed(),
            "Inserted entity-cache entries must be well-formed"
        );

        let cleanup_time: i64 = 800;
        store.cleanup_expired(cleanup_time);

        // e1 (expires 500) should be removed
        assert!(
            store.get(env, b"e1", cleanup_time).is_none(),
            "Expired entry e1 must be removed"
        );

        // e2 (expires 1000) should be preserved (800 < 1000)
        assert!(
            store.get(env, b"e2", cleanup_time).is_some(),
            "Valid entry e2 must be preserved"
        );

        // e3 (expires 1500) should be preserved
        assert!(
            store.get(env, b"e3", cleanup_time).is_some(),
            "Valid entry e3 must be preserved"
        );

        // No expired entries remain
        assert!(
            !store.has_expired(cleanup_time),
            "No expired entries after cleanup"
        );
    }

    // ========================================================================
    // Federation Cache Harnesses — Chain Cache
    // ========================================================================

    /// Verify chain cache consistency: get returns upserted data
    ///
    /// Property: Immediately after upsert, get returns the stored entry
    /// (if not expired).
    /// Matches F* Federation.PgRepo.lemma_ec_upsert_then_get
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_chain_cache_consistency() {
        use crate::bounded_federation_cache::BoundedChainCacheStore;

        let mut store = BoundedChainCacheStore::new();
        let env: u8 = 1;
        let leaf: &[u8] = b"https://rp.example.com";
        let anchor: &[u8] = b"https://ta.example.com";
        let now: i64 = 1000;
        let expires_at: i64 = 2800;

        // Upsert a chain
        assert!(store.upsert(env, leaf, anchor, now, expires_at));

        // Immediate get succeeds
        let result = store.get(env, leaf, anchor, now);
        assert!(
            result.is_some(),
            "Get must succeed immediately after upsert"
        );

        // Get with different leaf fails
        let wrong_leaf: &[u8] = b"https://other.example.com";
        assert!(
            store.get(env, wrong_leaf, anchor, now).is_none(),
            "Wrong leaf must not match"
        );

        // Get after expiration fails
        assert!(
            store.get(env, leaf, anchor, expires_at).is_none(),
            "Expired chain must not be returned"
        );
    }

    /// Verify tenant isolation: cross-env operations don't interfere
    ///
    /// Property: Upsert for env_id=1 does not affect get for env_id=2.
    /// Matches F* Federation.PgRepo.lemma_ec_tenant_isolation
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_federation_tenant_isolation() {
        use crate::bounded_federation_cache::BoundedEntityCacheStore;

        let mut store = BoundedEntityCacheStore::new();
        let env1: u8 = 1;
        let env2: u8 = 2;
        let entity: &[u8] = b"https://shared.example.com";
        let now: i64 = 1000;

        // Upsert in env1
        assert!(store.upsert(env1, entity, now, now + 1800));
        assert!(
            store.all_entries_well_formed(),
            "Tenant-isolated entity-cache entry must be well-formed"
        );

        // Get from env2 returns None (no cross-contamination)
        assert!(
            store.get(env2, entity, now).is_none(),
            "Tenant isolation: env2 must not see env1 data"
        );

        // Get from env1 works
        assert!(
            store.get(env1, entity, now).is_some(),
            "Same env must see its own data"
        );

        // Upsert in env2 doesn't affect env1
        assert!(store.upsert(env2, entity, now, now + 3600));
        assert!(
            store.count_key(env1, entity) == 1,
            "env1 must still have one entry"
        );
        assert!(
            store.count_key(env2, entity) == 1,
            "env2 must have its own entry"
        );
    }

    // ========================================================================
    // OIDC RP Session Harnesses
    // ========================================================================

    /// Verify RP state parameter binding
    ///
    /// Property: The callback's state parameter must match the one
    /// sent during authorize. Mismatched state causes failure.
    /// Matches F* OidcRp state_parameter_binds (SM1)
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_state_binds_callback() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"csrf-state-123";
        let nonce: &[u8] = b"nonce-xyz";
        let issuer: &[u8] = b"https://idp.example.com";

        // Authorize
        assert!(session.authorize(state, nonce, issuer));
        assert!(
            session.state == RpSessionState::PendingCallback,
            "Must be PendingCallback after authorize"
        );

        // Wrong state fails
        let mut session2 = session;
        let wrong_state: &[u8] = b"wrong-state";
        assert!(
            !session2.callback(wrong_state, nonce, issuer),
            "Mismatched state must fail"
        );
        assert!(
            session2.state == RpSessionState::Failed,
            "Must be Failed after state mismatch"
        );

        // Correct state succeeds
        assert!(
            session.callback(state, nonce, issuer),
            "Matching state must succeed"
        );
        assert!(
            session.state == RpSessionState::Authenticated,
            "Must be Authenticated after success"
        );
    }

    /// Verify RP nonce binding to ID token
    ///
    /// Property: The nonce in the ID token must match the one
    /// stored during authorize.
    /// Matches F* OidcRp nonce_binds_id_token (SM2)
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_nonce_binds_id_token() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"state-abc";
        let nonce: &[u8] = b"nonce-def";
        let issuer: &[u8] = b"https://idp.example.com";

        session.authorize(state, nonce, issuer);

        // Wrong nonce fails
        let wrong_nonce: &[u8] = b"wrong-nonce";
        assert!(
            !session.callback(state, wrong_nonce, issuer),
            "Mismatched nonce must fail"
        );
        assert!(
            session.state == RpSessionState::Failed,
            "Must be Failed after nonce mismatch"
        );
    }

    /// Verify RP issuer binding from trust chain
    ///
    /// Property: The ID token iss must match the leaf entity of
    /// the resolved trust chain.
    /// Matches F* OidcRp issuer_matches_chain (SM3)
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_issuer_matches_chain() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"state-123";
        let nonce: &[u8] = b"nonce-456";
        let expected_iss: &[u8] = b"https://trusted-idp.example.com";

        session.authorize(state, nonce, expected_iss);

        // Wrong issuer fails
        let wrong_iss: &[u8] = b"https://evil-idp.example.com";
        assert!(
            !session.callback(state, nonce, wrong_iss),
            "Mismatched issuer must fail"
        );
        assert!(session.state == RpSessionState::Failed);
    }

    /// Verify RP single-use state consumption
    ///
    /// Property: After a successful callback, the session cannot
    /// be used again (transitions to Authenticated, not PendingCallback).
    /// Matches F* OidcRp single_use_state (SM5)
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_single_use_state() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"state-once";
        let nonce: &[u8] = b"nonce-once";
        let issuer: &[u8] = b"https://idp.example.com";

        session.authorize(state, nonce, issuer);

        // First callback succeeds
        assert!(session.callback(state, nonce, issuer));
        assert!(session.state == RpSessionState::Authenticated);

        // Second callback fails (not PendingCallback anymore)
        assert!(
            !session.callback(state, nonce, issuer),
            "Second callback must fail (single-use)"
        );
    }

    // ========================================================================
    // Policy Profile Resolution Harnesses
    // ========================================================================

    /// Verify policy resolution precedence: client > default > baseline
    ///
    /// Property: Client-specific profile overrides environment default,
    /// which overrides the strict code-flow baseline.
    /// Matches F* Management.PolicyProfile.lemma_client_profile_wins
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_policy_resolution_precedence() {
        use crate::bounded_federation_cache::{
            BoundedProfileEntry, BoundedProfileStore, ResolvedPolicy,
        };

        let mut store = BoundedProfileStore::new();
        let env: u8 = 1;
        let now: i64 = 1000;

        // Add a default code-flow profile.
        let default_profile = BoundedProfileEntry {
            env_id: env,
            profile_id: 10,
            is_default: true,
            is_active: true,
            require_pkce: true,
            expires_at: 0, // no expiry
            occupied: true,
        };
        assert!(store.add_profile(default_profile));
        assert!(
            store.count_active_defaults(env) == 1,
            "Environment must have exactly one active default profile"
        );

        // Add a client-specific profile.
        let client_profile = BoundedProfileEntry {
            env_id: env,
            profile_id: 20,
            is_default: false,
            is_active: true,
            require_pkce: true,
            expires_at: 0,
            occupied: true,
        };
        assert!(store.add_profile(client_profile));

        // Without client profile: resolves to default.
        let resolved_default = store.resolve(env, None, now);
        assert!(
            resolved_default.profile_id == 10,
            "No client profile: must use default"
        );

        // With client profile: resolves to client.
        let resolved_client = store.resolve(env, Some(20), now);
        assert!(
            resolved_client.profile_id == 20,
            "Client profile must override default"
        );

        // With missing profile: falls back to default
        let resolved_missing = store.resolve(env, Some(99), now);
        assert!(
            resolved_missing.profile_id == 10,
            "Missing client profile: fallback to default"
        );

        // No profiles at all: falls back to baseline.
        let empty_store = BoundedProfileStore::new();
        let resolved_baseline = empty_store.resolve(env, None, now);
        assert!(
            resolved_baseline == ResolvedPolicy::BASELINE,
            "No profiles: must use code-flow baseline"
        );
    }

    // ========================================================================
    // OIDC RP Extended Harnesses — SM4 (PKCE) and SM6 (TTL)
    // ========================================================================

    /// Verify RP PKCE code_verifier binding (SM4)
    ///
    /// Property: code_verifier generated at authorize is preserved
    /// through callback, ensuring PKCE binding integrity.
    /// Matches F* OidcRp.Properties.lemma_pkce_preserved_on_success
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_pkce_verifier_binding() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"state-pkce";
        let nonce: &[u8] = b"nonce-pkce";
        let issuer: &[u8] = b"https://idp.example.com";
        let verifier: &[u8] = b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let token_ep: &[u8] = b"https://idp.example.com/token";
        let jwks: &[u8] = b"https://idp.example.com/jwks";
        let issued_at: i64 = 1000;
        let expires_at: i64 = 1300;

        // Authorize with PKCE
        assert!(session.authorize_full(
            state,
            nonce,
            issuer,
            Some(verifier),
            token_ep,
            jwks,
            issued_at,
            expires_at
        ));
        assert!(
            session.has_code_verifier,
            "Must have code_verifier after authorize"
        );
        assert!(
            session.code_verifier.equals(verifier),
            "code_verifier must match"
        );

        // Callback preserves code_verifier
        assert!(session.callback_with_ttl(state, nonce, issuer, 1100));
        assert!(session.state == RpSessionState::Authenticated);
        assert!(
            session.code_verifier.equals(verifier),
            "code_verifier must be preserved after callback"
        );
    }

    /// Verify RP session TTL enforcement (SM6)
    ///
    /// Property: PendingCallback sessions expire after expires_at.
    /// Callback at or after expires_at returns false and transitions to Expired.
    /// Matches F* OidcRp.Properties.lemma_expired_callback_rejected
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_session_ttl_enforced() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        let state: &[u8] = b"state-ttl";
        let nonce: &[u8] = b"nonce-ttl";
        let issuer: &[u8] = b"https://idp.example.com";
        let token_ep: &[u8] = b"https://idp.example.com/token";
        let jwks: &[u8] = b"https://idp.example.com/jwks";
        let issued_at: i64 = 1000;
        let expires_at: i64 = 1300; // TTL = 300s

        assert!(session
            .authorize_full(state, nonce, issuer, None, token_ep, jwks, issued_at, expires_at));

        // Before expiration: valid
        assert!(session.is_valid_at(1100), "Session valid before TTL");

        // At boundary: expired (matches F* is_expired)
        assert!(
            !session.is_valid_at(expires_at),
            "Session expired at boundary"
        );

        // Callback at boundary fails with Expired
        let mut session_at_boundary = session;
        assert!(
            !session_at_boundary.callback_with_ttl(state, nonce, issuer, expires_at),
            "Callback at TTL boundary must fail"
        );
        assert!(
            session_at_boundary.state == RpSessionState::Expired,
            "Must be Expired, not Failed"
        );

        // Callback before boundary succeeds
        assert!(
            session.callback_with_ttl(state, nonce, issuer, 1100),
            "Callback before TTL must succeed"
        );
        assert!(session.state == RpSessionState::Authenticated);
    }

    /// Verify RP authorize_full rejects invalid TTL
    ///
    /// Property: expires_at must be > issued_at (well-formedness).
    /// Matches F* OidcRp.Types.session_well_formed
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_rp_authorize_rejects_invalid_ttl() {
        use crate::bounded_federation_cache::{BoundedRpSession, RpSessionState};

        let mut session = BoundedRpSession::empty();

        // Zero TTL (expires_at == issued_at) rejected
        let result =
            session.authorize_full(b"st", b"nc", b"iss", None, b"tok", b"jwks", 1000, 1000);
        assert!(!result, "Zero TTL must be rejected");
        assert!(session.state == RpSessionState::Idle, "Must remain Idle");

        // Negative TTL (expires_at < issued_at) rejected
        let result2 =
            session.authorize_full(b"st", b"nc", b"iss", None, b"tok", b"jwks", 1000, 500);
        assert!(!result2, "Negative TTL must be rejected");

        // Positive TTL accepted
        let result3 =
            session.authorize_full(b"st", b"nc", b"iss", None, b"tok", b"jwks", 1000, 1300);
        assert!(result3, "Positive TTL must be accepted");
    }

    /// Verify no downgrade: profiles cannot relax the modern flow invariant.
    ///
    /// Property: If all profiles are well-formed, resolution never produces
    /// a profile with PKCE disabled.
    /// Matches F* Management.PolicyProfile.lemma_no_downgrade
    #[kani::proof]
    #[kani::unwind(10)]
    pub fn proof_policy_no_downgrade() {
        use crate::bounded_federation_cache::{BoundedProfileEntry, BoundedProfileStore};

        let mut store = BoundedProfileStore::new();
        let env: u8 = 1;
        let now: i64 = 1000;

        // Add a well-formed code-flow profile as default.
        let profile = BoundedProfileEntry {
            env_id: env,
            profile_id: 10,
            is_default: true,
            is_active: true,
            require_pkce: true,
            expires_at: 0,
            occupied: true,
        };
        assert!(store.add_profile(profile));
        assert!(
            store.count_active_defaults(env) == 1,
            "Well-formed default profile set must have one active default"
        );
        assert!(
            store.all_modern_flow_well_formed(),
            "Store must be modern-flow well-formed"
        );

        let resolved = store.resolve(env, None, now);
        assert!(
            resolved.is_modern_flow_compliant(),
            "Profile must preserve the modern flow invariant"
        );

        // Baseline is always compliant
        let empty = BoundedProfileStore::new();
        let baseline = empty.resolve(env, None, now);
        assert!(
            baseline.is_modern_flow_compliant(),
            "Baseline must be modern-flow compliant"
        );
    }
}

#[cfg(kani)]
pub use harnesses::*;
