use aegaeon_pure::organization_recovery::Preflight;

#[kani::proof]
fn connection_partition_preserves_total_and_reserve() {
    let total: u32 = kani::any();
    let requested: u32 = kani::any();
    match aegaeon_pure::organization_recovery::connection_partition(total, requested) {
        Some((ordinary, reserved)) => {
            assert!(total >= 2 && (1..=64).contains(&requested));
            assert!(ordinary >= 1 && reserved >= 1 && reserved <= requested);
            assert_eq!(ordinary.checked_add(reserved), Some(total));
        }
        None => assert!(total < 2 || requested == 0 || requested > 64),
    }
}

#[kani::proof]
fn preflight_disposition_all_stages() {
    let mutated: bool = kani::any();
    let confirmed: bool = kani::any();
    let mut attempt = Preflight::default();
    if mutated {
        assert!(attempt.begin_mutation());
    }
    if confirmed {
        attempt.finish();
    }
    assert_eq!(attempt.requires_fence(), mutated && !confirmed);
}

#[kani::proof]
fn preflight_finished_cannot_be_rearmed() {
    let mut attempt = Preflight::default();
    if kani::any() {
        assert!(attempt.begin_mutation());
    }
    attempt.finish();
    assert!(!attempt.begin_mutation());
    assert!(!attempt.requires_fence());
}

#[kani::proof]
fn preflight_unknown_mutation_remains_fenced() {
    let mut attempt = Preflight::default();
    assert!(attempt.begin_mutation());
    assert!(attempt.requires_fence());
    // A repeated begin is not a completion receipt.
    assert!(attempt.begin_mutation());
    assert!(attempt.requires_fence());
}
