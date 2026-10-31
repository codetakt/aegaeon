use super::*;

fn binding() -> Binding {
    Binding {
        scope: Scope {
            environment_id: Uuid::from_u128(1),
            domain_id: Uuid::from_u128(2),
        },
        object_id: Uuid::from_u128(3),
        delivery_revision: 1,
        purpose: Purpose::Invitation,
    }
}

#[test]
fn invitation_capability_preserves_exact_scope_object_purpose_and_delivery_revision() {
    let bound = binding();
    let (secret, retained) = generate(bound).expect("OS random supplier");
    let presented = secret.into_delivery();
    assert_eq!(presented.len(), 43);
    assert!(matches(bound, &retained, &presented));
    let changes = [
        Binding {
            scope: Scope {
                environment_id: Uuid::from_u128(10),
                ..bound.scope
            },
            ..bound
        },
        Binding {
            scope: Scope {
                domain_id: Uuid::from_u128(20),
                ..bound.scope
            },
            ..bound
        },
        Binding {
            object_id: Uuid::from_u128(30),
            ..bound
        },
        Binding {
            delivery_revision: 2,
            ..bound
        },
        Binding {
            purpose: Purpose::RecipientChallenge,
            ..bound
        },
    ];
    for changed in changes {
        assert!(!matches(changed, &retained, &presented));
    }
    let mut changed_hash = retained;
    changed_hash[0] ^= 1;
    assert!(!matches(bound, &changed_hash, &presented));
}

#[test]
fn invitation_capability_rejects_aliases_and_invalid_bindings() {
    let bound = binding();
    let known = [0u8; 32];
    let canonical = URL_SAFE_NO_PAD.encode(known);
    let retained = hash(bound, &known);
    assert!(matches(bound, &retained, &canonical));
    for invalid in [
        String::new(),
        format!("{canonical}="),
        format!(" {canonical}"),
        format!("{canonical}\n"),
        "A".repeat(42),
        "B".repeat(43),
        "é".repeat(43),
    ] {
        assert!(!matches(bound, &retained, &invalid));
    }
    let mut alias = canonical.clone();
    alias.pop();
    alias.push('B');
    assert!(
        !matches(bound, &retained, &alias),
        "nonzero unused base64 bits refuse"
    );
    for invalid in [
        Binding {
            object_id: Uuid::nil(),
            ..bound
        },
        Binding {
            delivery_revision: 0,
            ..bound
        },
        Binding {
            delivery_revision: -1,
            ..bound
        },
        Binding {
            scope: Scope {
                domain_id: Uuid::nil(),
                ..bound.scope
            },
            ..bound
        },
        Binding {
            scope: Scope {
                environment_id: Uuid::nil(),
                ..bound.scope
            },
            ..bound
        },
    ] {
        assert!(generate(invalid).is_err());
        assert!(!matches(invalid, &retained, &canonical));
    }
}

#[test]
fn invitation_and_recipient_windows_refuse_expiry_overflow_and_bad_stored_intervals() {
    assert_eq!(invitation_deadline(100, None), Some(86_500));
    assert_eq!(invitation_deadline(100, Some(60)), Some(160));
    for invalid in [i64::MIN, -1, 0, 59, 86_401, i64::MAX] {
        assert_eq!(invitation_deadline(100, Some(invalid)), None);
    }
    assert_eq!(invitation_deadline(-1, None), None);
    assert_eq!(invitation_deadline(i64::MAX - 59, Some(60)), None);
    assert_eq!(challenge_deadline(100), Some(400));
    assert_eq!(challenge_deadline(-1), None);
    assert_eq!(challenge_deadline(i64::MAX - 299), None);
    for (purpose, expiry) in [
        (Purpose::Invitation, 160),
        (Purpose::RecipientChallenge, 400),
        (Purpose::IdentityRegistration, 700),
        (Purpose::IdentityRecovery, 700),
    ] {
        assert!(!is_live(purpose, 100, expiry, 99));
        assert!(is_live(purpose, 100, expiry, 100));
        assert!(is_live(purpose, 100, expiry, expiry - 1));
        assert!(!is_live(purpose, 100, expiry, expiry));
        assert!(!is_live(purpose, 100, i64::MAX, 101));
        assert!(!is_live(purpose, -1, expiry, 100));
    }
    assert!(!is_live(Purpose::Invitation, 100, 159, 101));
    assert!(!is_live(Purpose::RecipientChallenge, 100, 401, 101));
}

#[test]
fn identity_proofs_are_separated_from_each_other_and_membership_capabilities() {
    let purposes = [
        Purpose::Invitation,
        Purpose::RecipientChallenge,
        Purpose::IdentityRegistration,
        Purpose::IdentityRecovery,
    ];
    let secret = [41u8; 32];
    let presented = URL_SAFE_NO_PAD.encode(secret);
    for purpose in purposes {
        let b = Binding {
            purpose,
            ..binding()
        };
        let retained = hash(b, &secret);
        for other in purposes {
            assert_eq!(
                matches(
                    Binding {
                        purpose: other,
                        ..b
                    },
                    &retained,
                    &presented
                ),
                purpose == other
            );
        }
    }
    assert!(!is_live(Purpose::IdentityRegistration, 100, 701, 101));
    assert!(!is_live(Purpose::IdentityRecovery, 100, 701, 101));
}
