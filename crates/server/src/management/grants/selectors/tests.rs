use super::*;

fn id(value: u8) -> Identity {
    Identity([value; 16])
}

fn path() -> [Resource; 5] {
    [
        ResourceKind::User,
        ResourceKind::Environment,
        ResourceKind::Tenant,
        ResourceKind::Team,
        ResourceKind::Installation,
    ]
    .map(|kind| {
        let value = match kind {
            ResourceKind::User => 1,
            ResourceKind::Environment => 2,
            ResourceKind::Tenant => 3,
            ResourceKind::Team => 4,
            ResourceKind::Installation => 5,
            ResourceKind::Organization => unreachable!(),
        };
        Resource {
            installation: id(5),
            id: id(value),
            incarnation: id(value + 10),
            kind,
        }
    })
}

fn covered(selector: Selector, resources: &[Resource], members: &[Resource]) -> bool {
    selector
        .covers(
            &CurrentPath::new(resources).unwrap(),
            |snapshot, resource| {
                assert_eq!(snapshot, id(20));
                Ok::<bool, ()>(members.contains(&resource))
            },
        )
        .unwrap()
}

#[test]
fn exact_scope_does_not_imply_descendant_coverage() {
    let resources = path();
    assert!(covered(Selector::Exact(resources[0]), &resources, &[]));
    assert!(!covered(Selector::Exact(resources[3]), &resources, &[]));
    assert!(covered(Selector::Exact(resources[3]), &resources[3..], &[]));
}

#[test]
fn current_snapshot_and_future_descendants_differ_after_creation() {
    let resources = path();
    let current = Selector::CurrentDescendants {
        anchor: resources[3],
        snapshot_id: id(20),
    };
    let future = Selector::CurrentAndFutureDescendants {
        anchor: resources[3],
    };
    assert!(covered(current, &resources, &[resources[0]]));
    assert!(!covered(current, &resources, &[]));
    assert!(covered(future, &resources, &[]));
}

#[test]
fn move_out_loses_both_selector_kinds_despite_retained_membership() {
    let resources = path();
    let current = Selector::CurrentDescendants {
        anchor: resources[3],
        snapshot_id: id(20),
    };
    let future = Selector::CurrentAndFutureDescendants {
        anchor: resources[3],
    };
    let mut moved = resources;
    moved[3].id = id(40);
    moved[3].incarnation = id(41);
    assert!(!covered(current, &moved, &[resources[0]]));
    assert!(!covered(future, &moved, &[]));
}

#[test]
fn move_in_does_not_enter_an_older_current_only_snapshot() {
    let resources = path();
    let current = Selector::CurrentDescendants {
        anchor: resources[3],
        snapshot_id: id(20),
    };
    let future = Selector::CurrentAndFutureDescendants {
        anchor: resources[3],
    };
    assert!(!covered(current, &resources, &[]));
    assert!(covered(future, &resources, &[]));
}

#[test]
fn recreated_resource_does_not_inherit_exact_or_snapshot_identity() {
    let original = path();
    let mut replacement = original;
    replacement[0].incarnation = id(99);
    assert!(!covered(Selector::Exact(original[0]), &replacement, &[]));
    assert!(!covered(
        Selector::CurrentDescendants {
            anchor: original[3],
            snapshot_id: id(20)
        },
        &replacement,
        &[original[0]]
    ));
    assert!(covered(
        Selector::CurrentAndFutureDescendants {
            anchor: original[3]
        },
        &replacement,
        &[]
    ));
}

#[test]
fn recreated_anchor_never_reuses_the_old_scope() {
    let original = path();
    let mut replacement = original;
    replacement[3].incarnation = id(99);
    for selector in [
        Selector::CurrentDescendants {
            anchor: original[3],
            snapshot_id: id(20),
        },
        Selector::CurrentAndFutureDescendants {
            anchor: original[3],
        },
    ] {
        assert!(!covered(selector, &replacement, &[original[0]]));
    }
}

#[test]
fn snapshot_store_outage_propagates_without_expanding_coverage() {
    let resources = path();
    let current = Selector::CurrentDescendants {
        anchor: resources[3],
        snapshot_id: id(20),
    };
    let result = current.covers(&CurrentPath::new(&resources).unwrap(), |_, _| {
        Err::<bool, _>("unavailable")
    });
    assert_eq!(result, Err("unavailable"));
}

#[test]
fn current_ancestry_is_checked_before_requesting_membership() {
    let resources = path();
    let mut other = resources[3];
    other.incarnation = id(99);
    let current = Selector::CurrentDescendants {
        anchor: other,
        snapshot_id: id(20),
    };
    assert!(!current
        .covers(
            &CurrentPath::new(&resources).unwrap(),
            |_, _| -> Result<bool, ()> { panic!("outside scope") }
        )
        .unwrap());
}

#[test]
fn invalid_truncated_cross_installation_and_excessive_paths_are_refused() {
    let resources = path();
    assert!(CurrentPath::new(&[]).is_none());
    assert!(CurrentPath::new(&resources[..4]).is_none());
    assert!(CurrentPath::new(&[resources[0]; 6]).is_none());
    for index in 0..5 {
        let mut changed = resources;
        changed[index].installation = id(90);
        assert!(CurrentPath::new(&changed).is_none());
        changed = resources;
        changed[index].incarnation = id(0);
        assert!(CurrentPath::new(&changed).is_none());
    }
}

#[test]
fn organization_identity_is_not_a_user_identity_with_the_same_uuid() {
    let resources = path();
    let mut organization = resources;
    organization[0].kind = ResourceKind::Organization;
    assert!(!covered(Selector::Exact(resources[0]), &organization, &[]));
    assert!(covered(
        Selector::CurrentAndFutureDescendants {
            anchor: resources[4]
        },
        &organization,
        &[]
    ));
}

#[test]
fn absent_snapshot_identity_and_invalid_anchor_never_authorize() {
    let resources = path();
    assert!(!covered(
        Selector::CurrentDescendants {
            anchor: resources[3],
            snapshot_id: id(0)
        },
        &resources,
        &[resources[0]]
    ));
    let mut anchor = resources[3];
    anchor.id = id(0);
    assert!(!covered(
        Selector::CurrentAndFutureDescendants { anchor },
        &resources,
        &[]
    ));
}
