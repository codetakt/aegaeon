//! Kani verification harnesses for OpenID Federation OP Entity Configuration.
//!
//! Verifies the security properties of self-signed entity configuration construction:
//!   EC-1: iss == sub (self-signed)
//!   EC-2: JWKS embedded
//!   EC-3: exp ≤ iat + MAX_EXP (86400 seconds)
//!   EC-4: iat present (temporal ordering)
//!   EC-5: required metadata present
//!
//! Mirrors F* spec: fstar/federation/OpEntityConfiguration.fst

/// Maximum entity configuration JWT lifetime (seconds).
/// Matches `MAX_FEDERATION_ENTITY_EXP_SECS` in web/mod.rs.
const MAX_EXP_SECS: u64 = 86400;

/// Simulated entity configuration claims.
#[derive(Debug, Clone)]
struct EntityConfig {
    iss: [u8; 32],
    iss_len: usize,
    sub: [u8; 32],
    sub_len: usize,
    iat: u64,
    exp: u64,
    has_jwks: bool,
    has_op_metadata: bool,
    has_fed_metadata: bool,
    typ_is_correct: bool,
}

/// Build an entity configuration with clamped exp.
fn build_entity_config(
    entity_id: [u8; 32],
    entity_id_len: usize,
    now: u64,
    configured_exp_secs: u64,
) -> EntityConfig {
    // EC-3: clamp configured exp to MAX_EXP_SECS
    let clamped = if configured_exp_secs <= MAX_EXP_SECS {
        configured_exp_secs
    } else {
        MAX_EXP_SECS
    };
    EntityConfig {
        iss: entity_id,
        iss_len: entity_id_len,
        sub: entity_id,       // EC-1: iss == sub
        sub_len: entity_id_len,
        iat: now,
        exp: now.saturating_add(clamped),
        has_jwks: true,        // EC-2: always include JWKS
        has_op_metadata: true, // EC-5: always include openid_provider
        has_fed_metadata: true, // EC-5: always include federation_entity
        typ_is_correct: true,  // Always set correct typ
    }
}

/// Check EC-1: iss == sub.
fn is_self_signed(ec: &EntityConfig) -> bool {
    ec.iss == ec.sub && ec.iss_len == ec.sub_len
}

/// Check EC-2: JWKS embedded.
fn has_jwks(ec: &EntityConfig) -> bool {
    ec.has_jwks
}

/// Check EC-3: exp within bound.
fn exp_within_bound(ec: &EntityConfig) -> bool {
    ec.exp > ec.iat && ec.exp <= ec.iat.saturating_add(MAX_EXP_SECS)
}

/// Check EC-4: iat present.
fn iat_present(ec: &EntityConfig) -> bool {
    ec.iat > 0
}

/// Check EC-5: required metadata present.
fn has_required_metadata(ec: &EntityConfig) -> bool {
    ec.has_op_metadata && ec.has_fed_metadata
}

/// Combined well-formedness.
fn is_well_formed(ec: &EntityConfig) -> bool {
    is_self_signed(ec)
        && has_jwks(ec)
        && exp_within_bound(ec)
        && iat_present(ec)
        && has_required_metadata(ec)
        && ec.typ_is_correct
}

// ============================================================================
// Kani Harnesses
// ============================================================================

#[cfg(kani)]
mod proofs {
    use super::*;
    use kani::any;

    /// EC-1: Entity configuration is always self-signed (iss == sub).
    #[kani::proof]
    fn proof_ec1_self_signed() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);
        let entity_id_len: usize = any();
        kani::assume(entity_id_len > 0 && entity_id_len <= 32);

        let entity_id = [b'e'; 32];
        let ec = build_entity_config(entity_id, entity_id_len, now, 3600);

        assert!(is_self_signed(&ec), "EC-1: iss must equal sub");
    }

    /// EC-2: JWKS is always embedded in the entity configuration.
    #[kani::proof]
    fn proof_ec2_jwks_embedded() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        let entity_id = [b'j'; 32];
        let ec = build_entity_config(entity_id, 5, now, 3600);

        assert!(has_jwks(&ec), "EC-2: JWKS must be embedded");
    }

    /// EC-3: For any configured exp, the clamped result never exceeds MAX_EXP_SECS.
    #[kani::proof]
    fn proof_ec3_exp_bounded() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 200000);

        let entity_id = [b'x'; 32];
        let ec = build_entity_config(entity_id, 5, now, configured_exp);

        assert!(
            ec.exp <= now + MAX_EXP_SECS,
            "EC-3: exp exceeds bound"
        );
        assert!(ec.exp > now, "EC-3: exp must be after iat");
    }

    /// EC-4: iat is always present when now > 0.
    #[kani::proof]
    fn proof_ec4_iat_present() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        let entity_id = [b't'; 32];
        let ec = build_entity_config(entity_id, 5, now, 3600);

        assert!(iat_present(&ec), "EC-4: iat must be present");
    }

    /// EC-5: Required metadata sections are always present.
    #[kani::proof]
    fn proof_ec5_metadata_present() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        let entity_id = [b'm'; 32];
        let ec = build_entity_config(entity_id, 5, now, 3600);

        assert!(has_required_metadata(&ec), "EC-5: required metadata must be present");
    }

    /// Combined: all well-formedness properties hold simultaneously.
    #[kani::proof]
    fn proof_combined_well_formed() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 200000);
        let entity_id_len: usize = any();
        kani::assume(entity_id_len > 0 && entity_id_len <= 32);

        let entity_id = [b'c'; 32];
        let ec = build_entity_config(entity_id, entity_id_len, now, configured_exp);

        assert!(is_well_formed(&ec), "All EC security properties must hold");
    }
}
