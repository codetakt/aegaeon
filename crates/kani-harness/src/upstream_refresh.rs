//! Calls the production RP freshness predicate, without a model/stub replacement.
use aegaeon_pure::upstream_refresh::issued_during_refresh;

#[kani::proof]
fn freshness_full_numeric_domain() {
    let iat: i64 = kani::any();
    let start: u64 = kani::any();
    let skew: u64 = kani::any();
    // Independent wider signed arithmetic, including negative lower bounds.
    let expected = iat >= 0 && i128::from(iat) >= i128::from(start) - i128::from(skew);
    assert_eq!(issued_during_refresh(iat, start, skew), expected);
}
