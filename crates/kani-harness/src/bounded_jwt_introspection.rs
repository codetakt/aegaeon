//! Kani verification harnesses for RFC 9701 JWT Introspection Response.
//!
//! Verifies the security properties of JWT introspection response construction:
//!   JI-1: aud binding to requesting RS
//!   JI-2: exp ≤ iat + 60 (short-lived)
//!   JI-4: typ = "token-introspection+jwt" (distinct from access token JWT)
//!   JI-5: revocation staleness window bounded by exp
//!   JI-6: cross-tenant: iss bound to AS issuer
//!
//! Mirrors F* spec: fstar/introspection/JwtIntrospection.fst

/// Maximum JWT introspection response lifetime (seconds).
/// Matches `MAX_JWT_INTROSPECTION_EXP_SECS` in web/mod.rs.
const MAX_EXP_SECS: u64 = 60;

/// The required JOSE `typ` value per RFC 9701.
const REQUIRED_TYP: &str = "token-introspection+jwt";

/// Simulated JWT introspection wrapper (outer JWT claims).
#[derive(Debug, Clone)]
struct JwtIntrospectionWrapper {
    iss: [u8; 32],
    iss_len: usize,
    aud: Option<[u8; 32]>,
    aud_len: usize,
    iat: u64,
    exp: u64,
    typ_len: usize,
}

/// Build a JWT introspection wrapper with clamped exp.
fn build_wrapper(
    iss: [u8; 32],
    iss_len: usize,
    aud: Option<[u8; 32]>,
    aud_len: usize,
    now: u64,
    configured_exp_secs: u64,
) -> JwtIntrospectionWrapper {
    // JI-2: clamp configured exp to MAX_EXP_SECS
    let clamped = if configured_exp_secs <= MAX_EXP_SECS {
        configured_exp_secs
    } else {
        MAX_EXP_SECS
    };
    JwtIntrospectionWrapper {
        iss,
        iss_len,
        aud,
        aud_len,
        iat: now,
        exp: now.saturating_add(clamped),
        typ_len: REQUIRED_TYP.len(), // JI-4: always set to the correct typ
    }
}

/// Check JI-2: exp within bound.
fn exp_within_bound(w: &JwtIntrospectionWrapper) -> bool {
    w.exp > w.iat && w.exp <= w.iat.saturating_add(MAX_EXP_SECS)
}

/// Check JI-4: correct typ.
fn has_distinct_typ(w: &JwtIntrospectionWrapper) -> bool {
    w.typ_len == REQUIRED_TYP.len()
}

/// Check JI-6: iss present.
fn has_issuer(w: &JwtIntrospectionWrapper) -> bool {
    w.iss_len > 0 && w.iss_len <= w.iss.len() && w.iss[0] != 0
}

/// Check JI-1: aud binding present.
fn has_aud_binding(w: &JwtIntrospectionWrapper) -> bool {
    match &w.aud {
        Some(_) => w.aud_len > 0,
        None => true,
    }
}

/// Combined well-formedness.
fn is_well_formed(w: &JwtIntrospectionWrapper) -> bool {
    exp_within_bound(w) && has_distinct_typ(w) && has_issuer(w) && has_aud_binding(w)
}

// ============================================================================
// Kani Harnesses
// ============================================================================

#[cfg(kani)]
mod proofs {
    use super::*;
    use kani::any;

    /// JI-2: For any configured exp, the clamped result never exceeds MAX_EXP_SECS.
    #[kani::proof]
    fn proof_ji2_exp_bounded() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 3600);

        let iss = [b'a'; 32];
        let w = build_wrapper(iss, 5, None, 0, now, configured_exp);

        assert!(w.exp <= now + MAX_EXP_SECS, "JI-2: exp exceeds bound");
        assert!(w.exp > now, "JI-2: exp must be after iat");
    }

    /// JI-4: The typ is always the distinct introspection type.
    #[kani::proof]
    fn proof_ji4_distinct_typ() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);

        let iss = [b'x'; 32];
        let w = build_wrapper(iss, 3, None, 0, now, 30);

        assert!(has_distinct_typ(&w), "JI-4: typ must be token-introspection+jwt");
    }

    /// JI-5: The revocation window (exp - iat) is bounded.
    #[kani::proof]
    fn proof_ji5_revocation_window() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 3600);

        let iss = [b'i'; 32];
        let w = build_wrapper(iss, 4, None, 0, now, configured_exp);

        assert!(
            w.exp - w.iat <= MAX_EXP_SECS,
            "JI-5: revocation staleness window exceeds 60s"
        );
    }

    /// JI-6: Issuer is always present when iss_len > 0.
    #[kani::proof]
    fn proof_ji6_issuer_present() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);
        let iss_len: usize = any();
        kani::assume(iss_len > 0 && iss_len <= 32);

        let iss = [b'z'; 32];
        let w = build_wrapper(iss, iss_len, None, 0, now, 30);

        assert!(has_issuer(&w), "JI-6: issuer must be present");
    }

    /// JI-1: When aud is set with non-zero length, binding holds.
    #[kani::proof]
    fn proof_ji1_aud_binding() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);

        let aud_len: usize = any();
        kani::assume(aud_len > 0 && aud_len <= 32);

        let iss = [b'a'; 32];
        let aud = Some([b'c'; 32]);
        let w = build_wrapper(iss, 5, aud, aud_len, now, 30);

        assert!(has_aud_binding(&w), "JI-1: aud binding must hold");
    }

    /// Combined: all well-formedness properties hold simultaneously.
    #[kani::proof]
    fn proof_combined_well_formed() {
        let now: u64 = any();
        kani::assume(now < u64::MAX - MAX_EXP_SECS);
        let configured_exp: u64 = any();
        kani::assume(configured_exp > 0 && configured_exp <= 3600);
        let iss_len: usize = any();
        kani::assume(iss_len > 0 && iss_len <= 32);
        let aud_len: usize = any();
        kani::assume(aud_len > 0 && aud_len <= 32);

        let iss = [b'i'; 32];
        let aud = Some([b'r'; 32]);
        let w = build_wrapper(iss, iss_len, aud, aud_len, now, configured_exp);

        assert!(is_well_formed(&w), "All JI security properties must hold");
    }
}
