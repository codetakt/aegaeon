
// ---------------------------------------------------------------
// P1: collect_snapshot_ids
// ---------------------------------------------------------------

#[test]
fn collect_snapshot_ids_extracts_uuids_from_array() {
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let doc = serde_json::json!({
        "runtimeKeys": [
            { "id": id1.to_string(), "status": "ACTIVE" },
            { "id": id2.to_string(), "status": "NEXT" },
        ]
    });
    let ids = collect_snapshot_ids(&doc, "runtimeKeys", &["id"], Some(&["ACTIVE", "NEXT"]));
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&id1));
    assert!(ids.contains(&id2));
}

#[test]
fn collect_snapshot_ids_filters_by_status() {
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let doc = serde_json::json!({
        "runtimeKeys": [
            { "id": id1.to_string(), "status": "ACTIVE" },
            { "id": id2.to_string(), "status": "REVOKED" },
        ]
    });
    let ids = collect_snapshot_ids(&doc, "runtimeKeys", &["id"], Some(&["ACTIVE"]));
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&id1));
}

#[test]
fn collect_snapshot_ids_returns_empty_for_missing_key() {
    let doc = serde_json::json!({});
    let ids = collect_snapshot_ids(&doc, "nonexistent", &["id"], None);
    assert!(ids.is_empty());
}

#[test]
fn collect_snapshot_ids_deduplicates() {
    let id = Uuid::new_v4();
    let doc = serde_json::json!({
        "keys": [
            { "id": id.to_string() },
            { "id": id.to_string() },
        ]
    });
    let ids = collect_snapshot_ids(&doc, "keys", &["id"], None);
    assert_eq!(ids.len(), 1);
}

#[test]
fn collect_snapshot_ids_tries_multiple_id_fields() {
    let id = Uuid::new_v4();
    let doc = serde_json::json!({
        "items": [
            { "signingKeyId": id.to_string() },
        ]
    });
    let ids = collect_snapshot_ids(&doc, "items", &["id", "signingKeyId"], None);
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&id));
}

#[test]
fn collect_snapshot_ids_no_status_filter_includes_all() {
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let doc = serde_json::json!({
        "items": [
            { "id": id1.to_string(), "status": "REVOKED" },
            { "id": id2.to_string(), "status": "ACTIVE" },
        ]
    });
    let ids = collect_snapshot_ids(&doc, "items", &["id"], None);
    assert_eq!(ids.len(), 2);
}
