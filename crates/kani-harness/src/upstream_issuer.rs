//! Direct production functions; byte equality bounded to length 0..=8.
use aegaeon_pure::upstream_issuer as production;

#[kani::proof]
fn policy_version_full_domain() {
    let version: u32 = kani::any();
    let accepted = production::supported_policy_version(version);
    assert_eq!(accepted, version == 1);
    assert!(production::supported_policy_version(production::POLICY_VERSION));
}

#[kani::proof]
fn frozen_requirement_all_metadata_states() {
    let profile: bool = kani::any();
    let discovery: Option<bool> = kani::any();
    let required = production::requires_issuer(profile, discovery);
    if profile || discovery == Some(true) {
        assert!(required);
    } else {
        assert!(!required);
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn exact_issuer_bytes_bounded() {
    let expected: [u8; 8] = kani::any();
    let received: [u8; 8] = kani::any();
    let left_len: usize = kani::any();
    let right_len: usize = kani::any();
    kani::assume(left_len <= 8 && right_len <= 8);
    let accepted = production::issuer_matches(&expected[..left_len], &received[..right_len]);
    let mut same = left_len == right_len;
    for index in 0..left_len.min(right_len) {
        if expected[index] != received[index] {
            same = false;
        }
    }
    assert_eq!(accepted, same);
    assert!(production::issuer_matches(&expected[..left_len], &expected[..left_len]));
}
