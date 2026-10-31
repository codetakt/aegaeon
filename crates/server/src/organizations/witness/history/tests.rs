use super::*;
use serde_json::json;

#[test]
fn permanent_history_digest_matches_independent_binary_vectors() {
    let environment = Uuid::parse_str("01020304-0506-0708-090a-0b0c0d0e0f10").unwrap();
    let owner = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let mut digest = initial_digest(environment, "issuer.example").unwrap();
    assert_eq!(
        hex(&digest),
        "69db1f73eed922fa7ceb6cbc04ba424a2e1ef81abf51d216f3566e58e53e8085"
    );
    let entries = [
        Entry::owner(Uuid::nil()),
        Entry::owner(owner),
        Entry::reservation(Uuid::nil(), "\u{1}A".into()).unwrap(),
        Entry::reservation(owner, "a".into()).unwrap(),
    ];
    let expected = [
        "5f51f81584bc534709faba06acc2d26ff605194870c2579d49bf7d03606e5f48",
        "8342c3c200da298cfeba10723fe023be776df70021175acec8fab100b02411b9",
        "44357b76fdad3b559b3bd296207598087ad1a1298565ca11ef6f384a04002f32",
        "c5f167c5bf4de7ccdd96b344e6baf6bf069a5863f63a274887e27ec56053414b",
    ];
    for (index, entry) in entries.iter().enumerate() {
        digest = entry.extend_digest(digest, index as u64 + 1).unwrap();
        assert_eq!(hex(&digest), expected[index]);
    }
    let initial = initial_digest(environment, "issuer.example").unwrap();
    assert_ne!(
        initial,
        initial_digest(environment, "Issuer.example").unwrap()
    );
    assert_ne!(initial, initial_digest(owner, "issuer.example").unwrap());
    assert_ne!(
        entries[3].extend_digest(initial, 1).unwrap(),
        Entry::reservation(owner, "A".into())
            .unwrap()
            .extend_digest(initial, 1)
            .unwrap()
    );
    assert_ne!(
        entries[3].extend_digest(initial, 1).unwrap(),
        entries[3].extend_digest(initial, 2).unwrap()
    );
}

#[test]
fn permanent_history_retains_subject_domain_and_plain_legacy_uuid() {
    let owner = Uuid::nil();
    for subject in ["".into(), "x".repeat(256), "a\0b".into(), "é".into()] {
        assert!(Entry::reservation(owner, subject).is_err());
    }
    for subject in [
        "x".repeat(255),
        "\u{1}\u{7f}".into(),
        "organization_legacy".into(),
    ] {
        let entry = Entry::reservation(owner, subject.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(entry).unwrap(),
            json!({"kind":"reservation","owner_id":owner,"subject":subject})
        );
    }
    assert_eq!(
        serde_json::to_value(Entry::owner(owner)).unwrap(),
        json!({"kind":"owner","owner_id":owner,"subject":null})
    );
    for issuer in ["".into(), "x".repeat(1025), "issuer\0example".into()] {
        assert!(initial_digest(owner, &issuer).is_err());
    }
    assert!(initial_digest(owner, &"x".repeat(1024)).is_ok());
}

fn artifacts() -> (Vec<u8>, Vec<u8>) {
    let mut value = source::test_manifest();
    let environment = value["namespace"]["environment_id"].clone();
    let owners = [Uuid::from_u128(1), Uuid::nil()];
    value["owners"] = json!(owners.map(|owner| json!({
        "owner_id":owner,"environment_id":environment,"source_refs":["attestation"]
    })));
    value["reservations"] = json!([
        {"owner_id":owners[0],"subject":"z","source_refs":["attestation"]},
        {"owner_id":owners[1],"subject":"A","source_refs":["attestation"]}
    ]);
    let mut manifest = source::parse_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
    let inventory = serde_json::to_vec(&source::test_inventory(&mut manifest)).unwrap();
    manifest.inventory.artifact_sha256 = source::sha256_hex(&inventory);
    (serde_json::to_vec(&manifest).unwrap(), inventory)
}

#[test]
fn permanent_history_plan_binds_existing_manifest_inventory_and_exact_order() {
    let (manifest, inventory) = artifacts();
    let manifest_hash = source::sha256_hex(&manifest);
    let inventory_hash = source::sha256_hex(&inventory);
    let plan =
        Plan::from_artifacts(&manifest, &inventory, &manifest_hash, &inventory_hash).unwrap();
    assert_eq!(plan.counts(), (2, 2));
    assert_eq!(plan.manifest_sha256(), manifest_hash);
    assert_eq!(plan.inventory_sha256(), inventory_hash);
    assert_eq!(plan.entries[0], Entry::owner(Uuid::nil()));
    assert_eq!(plan.entries[2].subject.as_deref(), Some("A"));
    assert_eq!(plan.batches().map(<[Entry]>::len).collect::<Vec<_>>(), [4]);
    let mut reordered: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    reordered["owners"].as_array_mut().unwrap().reverse();
    reordered["reservations"].as_array_mut().unwrap().reverse();
    let reordered = serde_json::to_vec(&reordered).unwrap();
    let other = Plan::from_artifacts(
        &reordered,
        &inventory,
        &source::sha256_hex(&reordered),
        &inventory_hash,
    )
    .unwrap();
    assert_eq!(plan.digest(), other.digest());
    assert_ne!(plan.manifest_sha256(), other.manifest_sha256());
    assert!(Plan::from_artifacts(&reordered, &inventory, &manifest_hash, &inventory_hash).is_err());
    assert!(Plan::from_artifacts(&manifest, &inventory, &manifest_hash, &"0".repeat(64)).is_err());

    let mut incomplete: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    incomplete["completeness"]["sources_exhaustive"] = json!(false);
    let incomplete = serde_json::to_vec(&incomplete).unwrap();
    assert!(Plan::from_artifacts(
        &incomplete,
        &inventory,
        &source::sha256_hex(&incomplete),
        &inventory_hash,
    )
    .is_err());
}
