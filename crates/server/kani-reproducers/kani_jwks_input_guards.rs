#![cfg(kani)]

mod verification {
    use aegaeon_server::client_registry::{
        KaniFetchedJwk, __has_duplicate_kid, __kid_reuse_changed, __parse_cache_control_val,
        __select_jwk_tuple, __sha256_hex,
    };

    const KTY_EC: u8 = 1;
    const KTY_RSA: u8 = 2;

    #[kani::proof]
    fn parse_cache_control_no_panic() {
        // Common patterns
        let v1 = __parse_cache_control_val("public, max-age=120, must-revalidate");
        let v2 = __parse_cache_control_val("no-cache");
        let v3 = __parse_cache_control_val("max-age=0");
        let v4 = __parse_cache_control_val("");
        let v5 = __parse_cache_control_val("max-age=xyz");
        // Basic sanity: never panic and values are within a reasonable bound when present
        if let Some(n) = v1 {
            kani::assert!(n <= 86400);
        }
        if let Some(n) = v3 {
            kani::assert!(n <= 1);
        }
        // v2/v4/v5 are likely None
        let _ = (v2, v4, v5);
    }

    #[kani::proof]
    fn sha256_hex_len_constant() {
        let a = __sha256_hex(b"");
        let b = __sha256_hex(b"abc");
        // Always 64 hex chars
        kani::assert!(a.len() == 64);
        kani::assert!(b.len() == 64);
    }

    #[kani::proof]
    fn duplicate_kid_detection() {
        let keys = [Some(1u8), Some(1u8), None, None];
        kani::assert!(__has_duplicate_kid(&keys));
    }

    #[kani::proof]
    fn kid_reuse_violation_detected() {
        let prev = [(1u8, 1u8)];
        let newm = [(1u8, 2u8)];
        kani::assert!(__kid_reuse_changed(&prev, &newm));
    }

    #[kani::proof]
    fn select_jwk_by_kid_or_single_signature_key() {
        let keys = [
            KaniFetchedJwk {
                kty: KTY_EC,
                kid: Some(1),
                n: None,
                e: None,
                x: None,
                y: None,
            },
            KaniFetchedJwk {
                kty: KTY_RSA,
                kid: Some(2),
                n: Some(1),
                e: Some(1),
                x: None,
                y: None,
            },
        ];
        // Exact match
        let sel = __select_jwk_tuple(&keys, Some(2));
        kani::assert!(sel.is_some());
        let s = sel.unwrap();
        kani::assert!(s.kty == KTY_RSA);
        // None -> the only signature-capable key, not the first tuple.
        let sel2 = __select_jwk_tuple(&keys, None);
        kani::assert!(sel2.is_some());
        let s2 = sel2.unwrap();
        kani::assert!(s2.kty == KTY_RSA);
    }

    #[kani::proof]
    fn select_jwk_without_kid_rejects_ambiguous_signature_keys() {
        let keys = [
            KaniFetchedJwk {
                kty: KTY_RSA,
                kid: Some(1),
                n: Some(1),
                e: Some(1),
                x: None,
                y: None,
            },
            KaniFetchedJwk {
                kty: KTY_EC,
                kid: Some(2),
                n: None,
                e: None,
                x: Some(1),
                y: Some(1),
            },
        ];

        kani::assert!(__select_jwk_tuple(&keys, None).is_none());
    }
}
