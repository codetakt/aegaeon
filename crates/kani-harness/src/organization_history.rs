use aegaeon_pure::organization_history::{batch_end, page_length};

#[kani::proof]
fn history_batch_end_exact_domain() {
    let from: u64 = kani::any();
    let count: u64 = kani::any();
    let end = u128::from(from) + u128::from(count);
    let expected = count > 0 && count <= 256 && end <= 1_000_000;
    let actual = batch_end(from, count);
    assert_eq!(actual.is_some(), expected);
    if let Some(value) = actual {
        assert_eq!(u128::from(value), end);
        assert!(value > from);
    }
}

#[kani::proof]
fn history_page_length_exact_domain() {
    let total: u64 = kani::any();
    let after: u64 = kani::any();
    let limit: u64 = kani::any();
    let remaining = i128::from(total) - i128::from(after);
    let expected = total <= 1_000_000 && remaining >= 0 && limit > 0 && limit <= 256;
    let actual = page_length(total, after, limit);
    assert_eq!(actual.is_some(), expected);
    if let Some(value) = actual {
        assert_eq!(i128::from(value), remaining.min(i128::from(limit)));
        assert!(u128::from(after) + u128::from(value) <= u128::from(total));
    }
}
