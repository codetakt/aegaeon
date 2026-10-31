use super::*;

// ORG-R03/R08, ORG-G01, ORG-P01/P02/P03/P04. These cases also run
// against the predecessor access module as the retained negative control.
#[test]
fn organization_external_identifier_round_trips_exactly() {
    for identifier in [
        "school-01".to_owned(),
        Uuid::new_v4().to_string(),
        format!("organization_{}", Uuid::new_v4()),
        "組織/東京 ?#%+".into(),
        " leading and trailing ".into(),
        "A".repeat(256),
        "é".repeat(128),
        "00000000-0000-0000-0000-000000000000".into(),
    ] {
        let mut f = Fixture::new();
        f.organization.external_id = identifier.clone();
        f.request = AccessRequest::parse(
            &json!([{"type": ORGANIZATION_ACCESS_TYPE, "identifier": identifier}]).to_string(),
        )
        .expect("a valid external selector must not require an internal UUID encoding");
        let decision = f
            .authorize()
            .expect("current membership authorizes external ID");
        assert_eq!(decision.organization_id, f.organization.id);
        assert_eq!(
            decision.authorization_details()[0]["identifier"],
            identifier
        );
        let stored = serde_json::to_string(&decision).unwrap();
        let restored: AccessDecision = serde_json::from_str(&stored).unwrap();
        assert_eq!(restored, decision);
        assert!(restored.is_current(&f.organization, &f.member, &f.roles, 100));
    }
}

#[test]
fn organization_external_identifier_never_normalizes_or_decodes_an_internal_id() {
    for (stored, other) in [
        ("School", "school"),
        ("é", "e\u{0301}"),
        ("school", " school"),
        ("school", "school "),
        ("school/01", "school%2F01"),
    ] {
        let mut f = Fixture::new();
        f.organization.external_id = stored.into();
        f.request.identifier = stored.into();
        let decision = f.authorize().unwrap();
        f.request.identifier = other.into();
        assert_eq!(f.authorize(), Err(AuthorityError::Forbidden));
        f.organization.external_id = other.into();
        assert!(!decision.is_current(&f.organization, &f.member, &f.roles, 100));
    }
    let mut f = Fixture::new();
    // A caller guessing the internal ID cannot bypass the external selector.
    f.request.identifier = format!("organization_{}", f.organization.id);
    assert_eq!(f.authorize(), Err(AuthorityError::Forbidden));
}

#[test]
fn organization_external_identifier_does_not_confer_membership_or_cross_scope_authority() {
    let f = Fixture::new();
    let decision = f.authorize().unwrap();
    for kind in 0..4 {
        let mut f = Fixture::new();
        match kind {
            0 => f.ceiling.memberships.clear(),
            1 => f.member.user_id = Uuid::new_v4(),
            2 => f.ceiling.binding.scope.domain_id = Uuid::new_v4(),
            _ => f.ceiling.binding.scope.environment_id = Uuid::new_v4(),
        }
        assert!(f.authorize().is_err());
    }
    let mut replacement = f.organization.clone();
    replacement.id = Uuid::new_v4();
    assert!(!decision.is_current(&replacement, &f.member, &f.roles, 100));
    let mut snapshot = serde_json::to_value(decision).unwrap();
    snapshot
        .as_object_mut()
        .unwrap()
        .remove("organization_identifier");
    assert!(serde_json::from_value::<AccessDecision>(snapshot).is_err());
}
