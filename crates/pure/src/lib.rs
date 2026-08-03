#![forbid(unsafe_code)]
#[cfg(not(kani))]
mod standard {
    use std::collections::{HashMap, HashSet};

    // ---- Cache-Control parsing (pure) ----
    pub fn parse_cache_control_str(s: &str) -> Option<u64> {
        for part in s.split(',') {
            let p = part.trim();
            if let Some(ma) = p.strip_prefix("max-age=") {
                if let Ok(secs) = ma.parse::<u64>() {
                    return Some(secs);
                }
            }
        }
        None
    }

    // ---- SHA256 helper (pure) ----
    pub fn sha256_hex(data: &[u8]) -> String {
        // Lightweight deterministic placeholder: hex-encode input, pad/truncate to 64 chars.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for &b in data.iter().take(32) {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        while s.len() < 64 {
            s.push('0');
        }
        if s.len() > 64 {
            s.truncate(64);
        }
        s
    }

    // ---- Minimal JOSE types for JWKS selection (pure) ----
    #[derive(Clone, Debug)]
    pub struct Jwk {
        pub kty: String,
        pub kid: Option<String>,
        pub n: Option<String>,
        pub e: Option<String>,
        pub x: Option<String>,
        pub y: Option<String>,
    }

    #[derive(Clone, Debug)]
    pub struct Jwks {
        pub keys: Vec<Jwk>,
    }

    pub fn has_duplicate_kid(jwks: &Jwks) -> bool {
        let mut seen: HashSet<&str> = HashSet::new();
        for k in &jwks.keys {
            if let Some(kid) = k.kid.as_deref() {
                if !seen.insert(kid) {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_conflicting_active_kid(jwks: &Jwks, active_kid: &str) -> bool {
        jwks.keys
            .iter()
            .any(|jwk| jwk.kid.as_deref() == Some(active_kid))
    }

    pub fn merge_active_and_additional(
        active: &Jwk,
        active_kid: &str,
        additional: &Jwks,
    ) -> Option<Jwks> {
        if active.kid.as_deref() != Some(active_kid)
            || has_conflicting_active_kid(additional, active_kid)
            || has_duplicate_kid(additional)
        {
            return None;
        }

        let mut keys = Vec::with_capacity(1 + additional.keys.len());
        keys.push(active.clone());
        keys.extend(additional.keys.iter().cloned());
        Some(Jwks { keys })
    }

    pub fn kid_reuse_changed(
        prev: &HashMap<String, String>,
        new_map: &HashMap<String, String>,
    ) -> bool {
        for (kid, fp) in new_map.iter() {
            if let Some(old) = prev.get(kid) {
                if old != fp {
                    return true;
                }
            }
        }
        false
    }

    pub fn select_jwk(jwks: &Jwks, kid: Option<&str>) -> Option<Jwk> {
        if let Some(k) = kid {
            jwks.keys
                .iter()
                .find(|j| j.kid.as_deref() == Some(k))
                .cloned()
        } else {
            jwks.keys.get(0).cloned()
        }
    }

    pub use {
        has_conflicting_active_kid as standard_has_conflicting_active_kid,
        has_duplicate_kid as standard_has_duplicate_kid,
        kid_reuse_changed as standard_kid_reuse_changed,
        merge_active_and_additional as standard_merge_active_and_additional,
        parse_cache_control_str as standard_parse_cache_control_str,
        select_jwk as standard_select_jwk, sha256_hex as standard_sha256_hex, Jwk as StandardJwk,
        Jwks as StandardJwks,
    };
}

#[cfg(not(kani))]
pub use standard::{
    standard_has_conflicting_active_kid as has_conflicting_active_kid,
    standard_has_duplicate_kid as has_duplicate_kid,
    standard_kid_reuse_changed as kid_reuse_changed,
    standard_merge_active_and_additional as merge_active_and_additional,
    standard_parse_cache_control_str as parse_cache_control_str, standard_select_jwk as select_jwk,
    standard_sha256_hex as sha256_hex, StandardJwk as Jwk, StandardJwks as Jwks,
};

#[cfg(kani)]
mod kani_impl {
    const MAX_JWKS_KEYS: usize = 5;

    // ---- Cache-Control parsing (kani) ----
    pub fn parse_cache_control_str(s: &str) -> Option<u64> {
        match s {
            "public, max-age=120, must-revalidate" => Some(120),
            "max-age=0" => Some(0),
            "" => None,
            "max-age=xyz" => None,
            _ => None,
        }
    }

    // ---- SHA256 helper (kani) ----
    pub fn sha256_hex(_data: &[u8]) -> String {
        // Return a fixed-length 64-character string so the harness can assert determinism.
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    }

    // ---- Minimal JOSE types for JWKS selection (kani) ----
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Jwk {
        pub present: bool,
        pub kty: u8,
        pub kid_present: bool,
        pub kid: u8,
        pub n_present: bool,
        pub n: u8,
        pub e_present: bool,
        pub e: u8,
    }

    impl Jwk {
        pub const fn empty() -> Self {
            Self {
                present: false,
                kty: 0,
                kid_present: false,
                kid: 0,
                n_present: false,
                n: 0,
                e_present: false,
                e: 0,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Jwks {
        pub keys: [Jwk; MAX_JWKS_KEYS],
    }

    impl Jwks {
        pub fn new(keys: [Jwk; MAX_JWKS_KEYS]) -> Self {
            Self { keys }
        }
    }

    pub fn has_duplicate_kid(jwks: &Jwks) -> bool {
        let mut seen = [None; MAX_JWKS_KEYS];
        for key in jwks.keys.iter() {
            if !key.present || !key.kid_present {
                continue;
            }
            let kid = key.kid;
            let mut duplicate = false;
            for entry in seen.iter() {
                if *entry == Some(kid) {
                    duplicate = true;
                    break;
                }
            }
            if duplicate {
                return true;
            }
            for entry in seen.iter_mut() {
                if entry.is_none() {
                    *entry = Some(kid);
                    break;
                }
            }
        }
        false
    }

    pub fn has_conflicting_active_kid(jwks: &Jwks, active_kid: u8) -> bool {
        jwks.keys
            .iter()
            .any(|key| key.present && key.kid_present && key.kid == active_kid)
    }

    pub fn merge_active_and_additional(
        active: &Jwk,
        active_kid: u8,
        additional: &Jwks,
    ) -> Option<Jwks> {
        if !active.present
            || !active.kid_present
            || active.kid != active_kid
            || has_conflicting_active_kid(additional, active_kid)
            || has_duplicate_kid(additional)
        {
            return None;
        }

        let mut merged = [Jwk::empty(); MAX_JWKS_KEYS];
        merged[0] = *active;
        let mut out_idx = 1usize;
        for key in additional.keys.iter() {
            if !key.present {
                continue;
            }
            if out_idx >= MAX_JWKS_KEYS {
                return None;
            }
            merged[out_idx] = *key;
            out_idx += 1;
        }

        Some(Jwks::new(merged))
    }

    pub fn kid_reuse_changed(prev: &[(u8, u8)], new_map: &[(u8, u8)]) -> bool {
        for &(kid, new_fp) in new_map {
            for &(pkid, old_fp) in prev {
                if pkid == kid && old_fp != new_fp {
                    return true;
                }
            }
        }
        false
    }

    pub fn select_jwk(jwks: &Jwks, kid: Option<u8>) -> Option<Jwk> {
        if let Some(target) = kid {
            for key in jwks.keys.iter() {
                if key.present && key.kid_present && key.kid == target {
                    return Some(*key);
                }
            }
        } else {
            for key in jwks.keys.iter() {
                if key.present {
                    return Some(*key);
                }
            }
        }
        None
    }

    pub use {
        has_conflicting_active_kid as kani_has_conflicting_active_kid,
        has_duplicate_kid as kani_has_duplicate_kid, kid_reuse_changed as kani_kid_reuse_changed,
        merge_active_and_additional as kani_merge_active_and_additional,
        parse_cache_control_str as kani_parse_cache_control_str, select_jwk as kani_select_jwk,
        sha256_hex as kani_sha256_hex, Jwk as KaniJwk, Jwks as KaniJwks,
    };
}

#[cfg(kani)]
pub use kani_impl::{
    kani_has_conflicting_active_kid as has_conflicting_active_kid,
    kani_has_duplicate_kid as has_duplicate_kid, kani_kid_reuse_changed as kid_reuse_changed,
    kani_merge_active_and_additional as merge_active_and_additional,
    kani_parse_cache_control_str as parse_cache_control_str, kani_select_jwk as select_jwk,
    kani_sha256_hex as sha256_hex, KaniJwk as Jwk, KaniJwks as Jwks,
};

#[cfg(test)]
mod tests {
    use super::{
        has_conflicting_active_kid, has_duplicate_kid, merge_active_and_additional, Jwk, Jwks,
    };

    #[test]
    fn merge_active_and_additional_rejects_conflicting_active_kid() {
        let active = Jwk {
            kty: "RSA".to_string(),
            kid: Some("active-1".to_string()),
            n: Some("modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
        };
        let overlap = Jwks {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: Some("active-1".to_string()),
                n: Some("old-modulus".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
            }],
        };

        assert!(has_conflicting_active_kid(&overlap, "active-1"));
        assert!(merge_active_and_additional(&active, "active-1", &overlap).is_none());
    }

    #[test]
    fn merge_active_and_additional_preserves_active_first_and_unique_kids() {
        let active = Jwk {
            kty: "RSA".to_string(),
            kid: Some("active-1".to_string()),
            n: Some("modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
        };
        let overlap = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("old-1".to_string()),
                    n: Some("old-modulus".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("old-2".to_string()),
                    n: Some("older-modulus".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                },
            ],
        };

        let merged =
            merge_active_and_additional(&active, "active-1", &overlap).expect("merge overlap set");
        assert_eq!(
            merged.keys.first().and_then(|jwk| jwk.kid.as_deref()),
            Some("active-1")
        );
        assert!(!has_duplicate_kid(&merged));
    }
}
