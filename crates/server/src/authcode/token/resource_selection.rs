/// Select from an already-approved single-resource grant (RFC 8707 section 2.2).
/// Inputs have passed protocol parsing. An absent grant resource retains the
/// default; it does not authorize adding an explicit resource at redemption.
/// The outer None rejects, while Some(None) preserves default selection.
pub(super) fn restrict_resource<'a>(
    granted: Option<&'a str>,
    requested: Option<&str>,
) -> Option<Option<&'a str>> {
    resource_is_permitted(granted.map(str::as_bytes), requested.map(str::as_bytes))
        .then_some(granted)
}

fn resource_is_permitted(granted: Option<&[u8]>, requested: Option<&[u8]>) -> bool {
    match requested {
        None => true,
        Some(target) => {
            granted.is_some_and(|allowed| crate::util::constant_time_eq(allowed, target))
        }
    }
}

#[cfg(kani)]
mod proofs {
    // Direct production acceptance predicate for optional byte strings of
    // length 0..=64, including non-ASCII bytes. URI/UTF-8 parsing, the string
    // adapter, grant approval, storage and issuance are outside this harness.
    // No stubs or alternate implementation are used.
    #[kani::proof]
    #[kani::unwind(66)]
    fn resource_choice_preserves_authority() {
        let granted_bytes: [u8; 64] = kani::any();
        let requested_bytes: [u8; 64] = kani::any();
        let granted_len: usize = kani::any();
        let requested_len: usize = kani::any();
        kani::assume(granted_len <= 64 && requested_len <= 64);
        let granted = &granted_bytes[..granted_len];
        let requested = &requested_bytes[..requested_len];
        let has_grant: bool = kani::any();
        let has_request: bool = kani::any();
        let mut same = granted_len == requested_len;
        for index in 0..granted_len {
            if index >= requested_len || granted_bytes[index] != requested_bytes[index] {
                same = false;
            }
        }
        let permitted = super::resource_is_permitted(
            has_grant.then_some(granted),
            has_request.then_some(requested),
        );
        assert!(permitted == (!has_request || (has_grant && same)));
    }
}
