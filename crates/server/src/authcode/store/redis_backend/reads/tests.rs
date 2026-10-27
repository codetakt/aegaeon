use super::{decode_inventory_record, inventory_record_matches_subject, TokenStoreStorageError};
use std::time::{Duration, SystemTime};

#[test]
fn inventory_subject_filter_requires_exact_record_identity_and_live_expiry() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let live = now + Duration::from_nanos(1);
    for (indexed, recorded, requested_subject, owner, expiry, expected) in [
        ("token", "token", "owner", "owner", live, true),
        ("token", "other", "owner", "owner", live, false),
        ("token", "token", "other", "owner", live, false),
        ("token", "token", "owner", "owner", now, false),
        (
            "token",
            "token",
            "owner",
            "owner",
            now - Duration::from_nanos(1),
            false,
        ),
    ] {
        assert_eq!(
            inventory_record_matches_subject(
                indexed,
                recorded,
                requested_subject,
                owner,
                expiry,
                now,
            ),
            expected,
            "indexed={indexed} recorded={recorded} requested={requested_subject} owner={owner}",
        );
    }
}

#[test]
fn inventory_retains_observed_json_bytes_for_conditional_index_pruning() {
    let original = "{ \"owner\" : \"user\", \"id\" : 7 }\n";
    let replacement = "{\"id\":7,\"owner\":\"user\"}";
    let (observed_raw, observed): (String, serde_json::Value) =
        decode_inventory_record(original.to_owned()).unwrap();
    let (replacement_raw, replaced): (String, serde_json::Value) =
        decode_inventory_record(replacement.to_owned()).unwrap();
    assert_eq!(
        observed, replaced,
        "logical equality is insufficient for pruning"
    );
    assert_eq!(observed_raw, original);
    assert_eq!(replacement_raw, replacement);
    assert_ne!(observed_raw, replacement_raw);
}

#[test]
fn inventory_preserves_malformed_record_errors() {
    for raw in ["", "{", "not-json"] {
        assert!(matches!(
            decode_inventory_record::<serde_json::Value>(raw.to_owned()),
            Err(TokenStoreStorageError::Codec(_)),
        ));
    }
}
