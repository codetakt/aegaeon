use super::{next_projection_revision, ApplicationAuthorizationUpdate};
use crate::application_authorization::inorii::Claims;

#[kani::proof]
#[kani::unwind(2)]
fn revision_update_reserves_disable() {
    let base: i64 = kani::any();
    let source: i64 = kani::any();
    let enabled: bool = kani::any();
    // Metadata is not read by the arithmetic helper. This harness does not
    // model request parsing, metadata validation, authority, or the database.
    let mut request = ApplicationAuthorizationUpdate {
        client_id: String::new(),
        subject: String::new(),
        base_revision: base,
        authority: String::new(),
        source_revision: source,
        audiences: Vec::new(),
        claims: Claims {
            roles: Vec::new(),
            organization_roles: Vec::new(),
        },
        enabled,
        reason: String::new(),
    };
    let result = next_projection_revision(&request);
    let last_allowed = i128::from(i64::MAX) - if enabled { 2 } else { 1 };
    let successor = i128::from(base) + 1;
    let permitted = successor >= 1
        && successor <= last_allowed
        && i128::from(source) >= 1
        && i128::from(source) <= last_allowed;
    assert_eq!(result.is_some(), permitted, "exact arithmetic domain");
    if let Some(revision) = result {
        assert_eq!(i128::from(revision), successor, "exact increment");
        assert!(revision > 0 && revision < i64::MAX, "no terminal overflow");
        if enabled {
            request.base_revision = revision;
            request.source_revision = source + 1;
            request.enabled = false;
            assert_eq!(
                next_projection_revision(&request),
                Some(revision + 1),
                "an accepted enable leaves room for a newer disable"
            );
        }
        if revision == i64::MAX - 1 {
            request.base_revision = revision;
            request.enabled = true;
            assert_eq!(
                next_projection_revision(&request),
                None,
                "an exhausted tombstone cannot be reactivated"
            );
        }
    }
}
