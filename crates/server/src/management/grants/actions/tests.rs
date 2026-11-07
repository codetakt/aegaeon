use super::*;

fn policy(actions: &[Action]) -> ActionPolicy {
    ActionPolicy::Enumerated(ActionSet::from_actions(actions).unwrap())
}

#[test]
fn registry_accepts_only_exact_registered_identifiers() {
    for action in [
        Action::ReadUsers,
        Action::ReadTeams,
        Action::ReadTenants,
        Action::ReadEnvironments,
        Action::ReadOrganizations,
    ] {
        assert_eq!(Action::from_id(action.id()), Some(action));
    }
    for unknown in [
        "*",
        "OWNER",
        "admin",
        "inventory.*",
        "inventory.users.write",
        "Inventory.users.read",
        "inventory.users.read ",
    ] {
        assert_eq!(Action::from_id(unknown), None);
    }
}

#[test]
fn explicit_action_sets_deny_other_registered_actions() {
    let selected = policy(&[Action::ReadTeams]);
    assert!(selected.allows(Action::ReadTeams));
    assert!(!selected.allows(Action::ReadUsers));
    assert!(!selected.allows(Action::ReadOrganizations));
}

#[test]
fn set_encoding_rejects_empty_duplicate_and_oversized_input() {
    assert!(ActionSet::from_actions(&[]).is_none());
    assert!(ActionSet::from_actions(&[Action::ReadUsers, Action::ReadUsers]).is_none());
    assert!(ActionSet::from_actions(&[Action::ReadUsers; 6]).is_none());
}

#[test]
fn future_action_expansion_requires_valid_explicit_acknowledgment() {
    for version in [0, REGISTRY_VERSION + 1, u32::MAX] {
        let future = ActionPolicy::AllCurrentAndFuture {
            acknowledged_registry_version: version,
        };
        assert!(!future.allows(Action::ReadUsers));
        assert!(!future.is_subset_of(future));
    }
    let future = ActionPolicy::AllCurrentAndFuture {
        acknowledged_registry_version: REGISTRY_VERSION,
    };
    assert!(future.allows(Action::ReadOrganizations));
    let all_now = policy(&[
        Action::ReadUsers,
        Action::ReadTeams,
        Action::ReadTenants,
        Action::ReadEnvironments,
        Action::ReadOrganizations,
    ]);
    assert!(!future.is_subset_of(all_now));
    assert!(all_now.is_subset_of(future));
}

#[test]
fn separate_partial_parent_envelopes_cannot_authorize_one_broader_child() {
    let child = policy(&[Action::ReadUsers, Action::ReadTeams]);
    for parent in [policy(&[Action::ReadUsers]), policy(&[Action::ReadTeams])] {
        assert!(!child.is_subset_of(parent));
    }
    assert!(child.is_subset_of(policy(&[
        Action::ReadUsers,
        Action::ReadTeams,
        Action::ReadOrganizations
    ])));
}
