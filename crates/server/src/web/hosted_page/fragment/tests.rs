use super::*;

const ISSUER: &str = "https://id.example.test";
const NOW: i64 = 1_800_000_000;
const ENV: Uuid = Uuid::from_u128(1);
const INVITATION: Uuid = Uuid::from_u128(2);
const CHILD: Uuid = Uuid::from_u128(3);

fn fixture(template: &str, object: Uuid) -> serde_json::Value {
    serde_json::json!({
        "issuer": ISSUER,
        "domainId": Uuid::from_u128(4),
        "environmentId": ENV,
        "invitationId": INVITATION,
        "objectId": object,
        "template": template,
        "deliveryRevision": 1,
        "capability": URL_SAFE_NO_PAD.encode([3u8;32]),
        "expiresAt": NOW + 299,
    })
}

fn accepts(raw: &[u8]) -> bool {
    parse_fragment(&URL_SAFE_NO_PAD.encode(raw), ISSUER, ENV, NOW).is_some()
}

#[test]
fn permits_each_v2_purpose_and_only_matching_object_kind() {
    for (template, object) in [
        ("organization_invitation", INVITATION),
        ("organization_recipient_challenge", CHILD),
        ("organization_identity_registration", CHILD),
        ("organization_identity_recovery", CHILD),
    ] {
        let fields = fixture(template, object);
        assert!(accepts(fields.to_string().as_bytes()));
        let wrong = if object == CHILD { INVITATION } else { CHILD };
        assert!(!accepts(fixture(template, wrong).to_string().as_bytes()));
    }
}

#[test]
fn rejects_duplicate_unknown_and_noncanonical_inputs_including_at_deadline() {
    let original = fixture("organization_invitation", INVITATION);
    let raw = original.to_string();
    assert!(!accepts(
        raw.replacen('{', r#"{"capab\u0069lity":"duplicate","#, 1)
            .as_bytes()
    ));
    assert!(!accepts(
        raw.replacen('{', r#"{"unknown":1,"#, 1).as_bytes()
    ));
    for (field, value) in [
        ("domainId", serde_json::json!(Uuid::nil())),
        ("environmentId", serde_json::json!(Uuid::from_u128(42))),
        (
            "domainId",
            serde_json::json!(Uuid::from_u128(4).simple().to_string()),
        ),
        ("deliveryRevision", serde_json::json!(6)),
        ("deliveryRevision", serde_json::json!(1.0)),
        ("expiresAt", serde_json::json!(NOW)),
        ("expiresAt", serde_json::json!(NOW + 86_401)),
        ("capability", serde_json::json!("a".repeat(43))),
        ("issuer", serde_json::json!("https://other.example.test")),
    ] {
        let mut fields = original.clone();
        fields[field] = value;
        assert!(!accepts(fields.to_string().as_bytes()), "{field}");
    }
    assert!(!accepts(&[0xff, 0x00]));
    let mut padded = raw.clone();
    padded.push_str(&" ".repeat(MAX_BYTES - raw.len()));
    assert!(accepts(padded.as_bytes()));
    padded.push(' ');
    assert!(!accepts(padded.as_bytes()));
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    assert!(parse_fragment(&(encoded + "="), ISSUER, ENV, NOW).is_none());
}
