use super::*;

fn id(value: u8) -> Identity {
    Identity([value; 16])
}

fn principal(value: u8) -> Principal {
    Principal {
        installation: id(200),
        id: id(value),
        kind: PrincipalKind::Human,
    }
}

fn authentication() -> Authentication {
    Authentication {
        principal: principal(1),
        credential_id: id(250),
        authenticated_at: 50,
        expires_at: 150,
    }
}

fn root(value: u8) -> GrantNode {
    GrantNode {
        id: id(value),
        principal: principal(value),
        basis: Basis::InstallationBootstrap { operation: id(240) },
        revision: 1,
        delegation_epoch: 1,
        revoked: false,
        valid_from: 0,
        lifetime: Lifetime::Unbounded,
        conditions: Conditions {
            credential: CredentialRestriction::AnyManagementCredential,
            maximum_authentication_age_seconds: None,
        },
    }
}

/// C (the caller) <- B <- A; all nodes come from one current SQL snapshot.
fn chain() -> [GrantNode; 3] {
    let mut nodes = [root(1), root(2), root(3)];
    for index in 0..2 {
        nodes[index].basis = Basis::Delegated {
            parent: nodes[index + 1].id,
            captured_epoch: nodes[index + 1].delegation_epoch,
        };
    }
    nodes
}

#[test]
fn explicit_root_and_complete_chain_validate_without_team_membership() {
    let nodes = chain();
    let validated = validate(&nodes, &authentication(), 100).unwrap();
    assert_eq!(validated.nodes(), &nodes);
    let bootstrap = [root(1)];
    assert!(validate(&bootstrap, &authentication(), 100).is_ok());
}

#[test]
fn absence_truncation_and_middle_bootstrap_do_not_create_authority() {
    assert_eq!(
        validate(&[], &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
    let mut nodes = chain();
    assert_eq!(
        validate(&nodes[..2], &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
    nodes[1].basis = Basis::InstallationBootstrap { operation: id(240) };
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
}

#[test]
fn revocation_of_any_live_ancestor_denies_descendants() {
    for index in 0..3 {
        let mut nodes = chain();
        nodes[index].revoked = true;
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::Revoked
        );
    }
}

#[test]
fn replacement_parent_identity_cannot_revive_an_old_child() {
    for index in 1..3 {
        let mut nodes = chain();
        nodes[index].id = id(90);
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::StaleParent
        );
    }
}

#[test]
fn authority_edit_epochs_invalidate_existing_children() {
    for index in 1..3 {
        let mut nodes = chain();
        nodes[index].delegation_epoch += 1;
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::StaleParent
        );
    }
}

#[test]
fn descriptive_revision_does_not_implicitly_advance_delegation_epoch() {
    let mut nodes = chain();
    nodes[2].revision += 1;
    assert!(validate(&nodes, &authentication(), 100).is_ok());
}

#[test]
fn installation_principal_and_principal_kind_are_exact_identities() {
    for index in 0..3 {
        let mut nodes = chain();
        nodes[index].principal.installation = id(201);
        assert!(validate(&nodes, &authentication(), 100).is_err());
    }
    let mut authenticated = authentication();
    authenticated.principal.id = id(2);
    assert_eq!(
        validate(&chain(), &authenticated, 100).unwrap_err(),
        Denial::DifferentPrincipal
    );
    authenticated = authentication();
    authenticated.principal.kind = PrincipalKind::Service;
    assert_eq!(
        validate(&chain(), &authenticated, 100).unwrap_err(),
        Denial::DifferentPrincipal
    );
}

#[test]
fn zero_identities_and_missing_bootstrap_operation_fail_closed() {
    let mut nodes = chain();
    nodes[1].id = id(0);
    assert!(validate(&nodes, &authentication(), 100).is_err());
    nodes = chain();
    nodes[2].principal.id = id(0);
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidIdentity
    );
    nodes = chain();
    nodes[2].basis = Basis::InstallationBootstrap { operation: id(0) };
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
    let mut authenticated = authentication();
    authenticated.credential_id = id(0);
    assert_eq!(
        validate(&chain(), &authenticated, 100).unwrap_err(),
        Denial::InvalidIdentity
    );
}

#[test]
fn zero_revisions_and_epochs_are_not_valid_authority() {
    for index in 0..3 {
        let mut nodes = chain();
        nodes[index].revision = 0;
        assert!(validate(&nodes, &authentication(), 100).is_err());
        nodes = chain();
        nodes[index].delegation_epoch = 0;
        assert!(validate(&nodes, &authentication(), 100).is_err());
    }
}

#[test]
fn cycles_and_duplicate_grant_identities_are_rejected() {
    let mut nodes = chain();
    nodes[2].id = nodes[0].id;
    nodes[1].basis = Basis::Delegated {
        parent: nodes[2].id,
        captured_epoch: 1,
    };
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
    nodes = chain();
    nodes[2].basis = Basis::Delegated {
        parent: nodes[0].id,
        captured_epoch: 1,
    };
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
}

#[test]
fn exactly_eight_edges_are_supported_and_ninth_is_refused() {
    let mut nodes: [GrantNode; 10] = std::array::from_fn(|index| root((index + 1) as u8));
    for index in 0..8 {
        nodes[index].basis = Basis::Delegated {
            parent: nodes[index + 1].id,
            captured_epoch: 1,
        };
    }
    assert!(validate(&nodes[..9], &authentication(), 100).is_ok());
    nodes[8].basis = Basis::Delegated {
        parent: nodes[9].id,
        captured_epoch: 1,
    };
    assert_eq!(
        validate(&nodes, &authentication(), 100).unwrap_err(),
        Denial::InvalidChain
    );
}

#[test]
fn ancestor_validity_is_current_and_has_an_exclusive_expiry() {
    for index in 0..3 {
        let mut nodes = chain();
        nodes[index].lifetime = Lifetime::Until(101);
        assert!(validate(&nodes, &authentication(), 100).is_ok());
        nodes[index].lifetime = Lifetime::Until(100);
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::OutsideValidity
        );
        nodes[index].lifetime = Lifetime::Unbounded;
        nodes[index].valid_from = 101;
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::OutsideValidity
        );
    }
}

#[test]
fn permanent_assignment_does_not_extend_finite_authentication() {
    let mut authenticated = authentication();
    for (start, end) in [(50, 100), (101, 150), (150, 150), (150, 100)] {
        authenticated.authenticated_at = start;
        authenticated.expires_at = end;
        assert_eq!(
            validate(&chain(), &authenticated, 100).unwrap_err(),
            Denial::CredentialCondition
        );
    }
}

#[test]
fn ancestor_conditions_do_not_disappear_on_delegation() {
    for index in 0..3 {
        let mut nodes = chain();
        nodes[index].conditions.maximum_authentication_age_seconds = Some(49);
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::CredentialCondition
        );
        nodes[index].conditions.maximum_authentication_age_seconds = Some(50);
        assert!(validate(&nodes, &authentication(), 100).is_ok());
        nodes[index].conditions.credential = CredentialRestriction::ServiceCredential;
        assert_eq!(
            validate(&nodes, &authentication(), 100).unwrap_err(),
            Denial::CredentialCondition
        );
    }
}

#[test]
fn exact_credential_restrictions_do_not_accept_another_session() {
    let mut nodes = chain();
    nodes[1].conditions.credential = CredentialRestriction::Exact {
        id: authentication().credential_id,
        kind: PrincipalKind::Human,
    };
    assert!(validate(&nodes, &authentication(), 100).is_ok());
    let mut authenticated = authentication();
    authenticated.credential_id = id(249);
    assert_eq!(
        validate(&nodes, &authenticated, 100).unwrap_err(),
        Denial::CredentialCondition
    );
}

#[test]
fn service_credentials_do_not_fabricate_human_evidence() {
    let mut nodes = [root(1)];
    let mut authenticated = authentication();
    nodes[0].principal.kind = PrincipalKind::Service;
    authenticated.principal.kind = PrincipalKind::Service;
    nodes[0].conditions.credential = CredentialRestriction::ServiceCredential;
    assert!(validate(&nodes, &authenticated, 100).is_ok());
    nodes[0].conditions.credential = CredentialRestriction::HumanSession;
    assert_eq!(
        validate(&nodes, &authenticated, 100).unwrap_err(),
        Denial::CredentialCondition
    );
}
