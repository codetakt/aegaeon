//! Kani verification harnesses for OpenID Federation OP Subordinate Statements.
//!
//! Verifies the security properties of subordinate statement construction:
//!   SS-1: iss = OP entity_id
//!   SS-2: sub = RP entity_id
//!   SS-3: iss != sub (not self-signed)
//!   SS-4: exp bounded by MAX_EXP_SECS
//!
//! Mirrors F* spec: fstar/federation/OpSubordinateStatement.fst

/// Maximum subordinate statement JWT lifetime (seconds).
const MAX_EXP_SECS: u64 = 86400;

/// Simulated subordinate statement claims.
#[derive(Debug, Clone)]
struct SubordinateStatement {
    iss: [u8; 32],
    iss_len: usize,
    sub: [u8; 32],
    sub_len: usize,
    iat: u64,
    exp: u64,
    has_rp_metadata: bool,
}

/// Build a subordinate statement.
fn build_subordinate(
    op_id: [u8; 32],
    op_id_len: usize,
    rp_id: [u8; 32],
    rp_id_len: usize,
    now: u64,
    configured_exp_secs: u64,
) -> SubordinateStatement {
    let clamped = if configured_exp_secs <= MAX_EXP_SECS {
        configured_exp_secs
    } else {
        MAX_EXP_SECS
    };
    SubordinateStatement {
        iss: op_id,
        iss_len: op_id_len,
        sub: rp_id,
        sub_len: rp_id_len,
        iat: now,
        exp: now.saturating_add(clamped),
        has_rp_metadata: true,
    }
}

/// Check SS-3: not self-signed.
fn not_self_signed(ss: &SubordinateStatement) -> bool {
    ss.iss != ss.sub || ss.iss_len != ss.sub_len
}

/// Check SS-4: exp within bound.
fn exp_within_bound(ss: &SubordinateStatement) -> bool {
    ss.exp > ss.iat && ss.exp <= ss.iat.saturating_add(MAX_EXP_SECS)
}

// ============================================================================
// Kani Harnesses
// ============================================================================

#[cfg(kani)]
mod proofs {
    use super::*;
    use kani::any;

    /// SS-1: iss is always the OP entity_id.
    #[kani::proof]
    fn proof_ss1_iss_is_op() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        let op_id = [b'O'; 32];
        let rp_id = [b'R'; 32];
        let ss = build_subordinate(op_id, 5, rp_id, 5, now, 3600);

        assert!(ss.iss == op_id, "SS-1: iss must be OP entity_id");
    }

    /// SS-2: sub is always the RP entity_id.
    #[kani::proof]
    fn proof_ss2_sub_is_rp() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        let op_id = [b'O'; 32];
        let rp_id = [b'R'; 32];
        let ss = build_subordinate(op_id, 5, rp_id, 5, now, 3600);

        assert!(ss.sub == rp_id, "SS-2: sub must be RP entity_id");
    }

    /// SS-3: Subordinate statements are never self-signed when OP != RP.
    #[kani::proof]
    fn proof_ss3_not_self_signed() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);

        // Different entity IDs
        let op_id = [b'O'; 32];
        let rp_id = [b'R'; 32];
        let ss = build_subordinate(op_id, 5, rp_id, 5, now, 3600);

        assert!(not_self_signed(&ss), "SS-3: iss must differ from sub");
    }

    /// SS-4: exp is always bounded.
    #[kani::proof]
    fn proof_ss4_exp_bounded() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 200000);

        let op_id = [b'O'; 32];
        let rp_id = [b'R'; 32];
        let ss = build_subordinate(op_id, 5, rp_id, 5, now, configured_exp);

        assert!(
            ss.exp <= now + MAX_EXP_SECS,
            "SS-4: exp exceeds bound"
        );
    }

    /// Combined well-formedness.
    #[kani::proof]
    fn proof_combined_subordinate() {
        let now: u64 = any();
        kani::assume(now > 0 && now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 200000);

        let op_id = [b'O'; 32];
        let rp_id = [b'R'; 32];
        let ss = build_subordinate(op_id, 5, rp_id, 5, now, configured_exp);

        assert!(ss.iss == op_id, "iss must be OP");
        assert!(ss.sub == rp_id, "sub must be RP");
        assert!(not_self_signed(&ss), "must not be self-signed");
        assert!(exp_within_bound(&ss), "exp must be bounded");
        assert!(ss.has_rp_metadata, "RP metadata must be present");
    }
}
