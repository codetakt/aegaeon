use aegaeon_pure::organization_progress::{can_complete, retain};

#[kani::proof]
fn retained_progress_exact_domain() {
    let minimum: u64 = kani::any();
    let maximum: u64 = kani::any();
    let observed: u64 = kani::any();
    let (floor, before, actual) = (
        i128::from(minimum),
        i128::from(maximum),
        i128::from(observed),
    );
    let expected = before - floor >= 0 && actual - floor >= 0;
    let result = retain(minimum, maximum, observed);
    assert_eq!(result.is_some(), expected);
    if let Some(value) = result {
        assert_eq!(
            i128::from(value),
            if before > actual { before } else { actual }
        );
        assert!(value >= minimum && value >= maximum && value >= observed);
    }
}

#[kani::proof]
fn final_progress_exact_domain() {
    let minimum: u64 = kani::any();
    let maximum: u64 = kani::any();
    let final_position: u64 = kani::any();
    let (floor, before, final_value) = (
        i128::from(minimum),
        i128::from(maximum),
        i128::from(final_position),
    );
    let expected = before - floor >= 0 && final_value - before >= 0;
    assert_eq!(can_complete(minimum, maximum, final_position), expected);
}
