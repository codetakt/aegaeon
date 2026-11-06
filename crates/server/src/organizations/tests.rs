use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

mod identifiers;

#[test]
fn organization_administrator_recovery_preserves_ids_and_invalidates_original_generation() {
    let mut f = Fixture::new();
    let old = f.authorize().unwrap();
    let before = f.organization.clone();
    f.organization
        .prepare_administrator_recovery(before.revision)
        .unwrap();
    assert_eq!(f.organization.id, before.id);
    assert_eq!(f.organization.external_id, before.external_id);
    assert_eq!(f.organization.scope, before.scope);
    assert_eq!(f.organization.grant_generation, before.grant_generation + 1);
    assert!(f.authorize().is_err());
    assert!(!old.is_current(&f.organization, &f.member, &f.roles, 100));
    f.organization
        .transition(f.organization.revision, OrganizationState::Active)
        .unwrap();
    assert_eq!(f.authorize(), Err(AuthorityError::ReauthorizationRequired));
    assert!(!old.is_current(&f.organization, &f.member, &f.roles, 100));
}

#[test]
fn organization_administrator_recovery_refuses_terminal_or_exhausted_state_atomically() {
    for (state, revision, generation) in [
        (OrganizationState::Provisioning, 1, 1),
        (OrganizationState::Deleted, 2, 2),
        (OrganizationState::Active, i64::MAX - 1, 1),
        (OrganizationState::Suspended, 1, i64::MAX - 1),
    ] {
        let mut value = Fixture::new().organization;
        value.state = state;
        value.revision = revision;
        value.grant_generation = generation;
        let before = value.clone();
        assert!(value.prepare_administrator_recovery(revision).is_err());
        assert_eq!(value, before);
    }
}

fn keys(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).into()).collect()
}

struct Fixture {
    organization: Organization,
    member: Membership,
    roles: BTreeMap<String, RoleDefinition>,
    ceiling: AuthorizationCeiling,
    request: AccessRequest,
}

impl Fixture {
    fn new() -> Self {
        let scope = Scope {
            environment_id: Uuid::new_v4(),
            domain_id: Uuid::new_v4(),
        };
        let organization = Organization {
            scope,
            id: Uuid::new_v4(),
            external_id: "school-01".into(),
            state: OrganizationState::Active,
            revision: 1,
            grant_generation: 1,
        };
        let member = Membership {
            scope,
            organization_id: organization.id,
            user_id: Uuid::new_v4(),
            incarnation: Uuid::new_v4(),
            state: MembershipState::Active,
            revision: 1,
            grant_generation: 1,
            roles: keys(&["reader", "writer"]),
        };
        let roles: BTreeMap<_, _> = [
            ("reader", keys(&["documents.read"])),
            ("writer", keys(&["documents.write"])),
        ]
        .into_iter()
        .map(|(key, privileges)| {
            (
                key.into(),
                RoleDefinition {
                    scope,
                    key: key.into(),
                    version: 1,
                    privileges,
                    manages_members: false,
                    assignable_roles: BTreeSet::new(),
                },
            )
        })
        .collect();
        let binding = Binding {
            scope,
            issuer: "https://issuer.example.org".into(),
            client_id: "workspace".into(),
            client_registration_id: Uuid::new_v4(),
            subject: "user-1".into(),
            user_id: member.user_id,
            root_id: "original-root".into(),
            dpop_jkt: "original-jkt".into(),
        };
        let ceiling = AuthorizationCeiling {
            version: 1,
            binding,
            expires_at: 1000,
            audiences: BTreeMap::from([(
                "https://api.example.org".into(),
                keys(&["documents.read", "documents.write"]),
            )]),
            memberships: BTreeMap::from([(
                organization.id,
                AuthorizationCeiling::capture_membership(&organization, &member, &roles).unwrap(),
            )]),
        };
        let request = AccessRequest {
            detail_type: ORGANIZATION_ACCESS_TYPE.into(),
            admin_access_grant_id: None,
            identifier: organization.external_id.clone(),
            privileges: None,
        };
        Self {
            organization,
            member,
            roles,
            ceiling,
            request,
        }
    }

    fn authorize(&self) -> Result<AccessDecision, AuthorityError> {
        AccessDecision::authorize(AccessInput {
            ceiling: &self.ceiling,
            authenticated: &self.ceiling.binding,
            request: &self.request,
            audience: "https://api.example.org",
            current_client_privileges: &keys(&["documents.read", "documents.write"]),
            organization: &self.organization,
            member: &self.member,
            definitions: &self.roles,
            parent_expires_at: 900,
            now: 100,
        })
    }
}

#[test]
fn organization_selection_rejects_malformed_ambiguous_and_output_only_fields() {
    let f = Fixture::new();
    let good = serde_json::to_value(&f.request).unwrap();
    assert!(AccessRequest::parse(&json!([good.clone()]).to_string()).is_ok());
    for bad in [
        json!([]),
        json!([good.clone(), good.clone()]),
        good.clone(),
        json!(null),
    ] {
        assert!(AccessRequest::parse(&bad.to_string()).is_err(), "{bad}");
    }
    for (name, value) in [
        ("type", json!("urn:unknown")),
        ("identifier", json!("")),
        ("identifier", json!("x".repeat(257))),
        ("identifier", json!("é".repeat(129))),
        ("identifier", json!("school\n01")),
        ("identifier", json!("school\u{0085}01")),
        ("privileges", json!([])),
        ("privileges", json!(null)),
        ("privileges", json!(["read", "read"])),
        ("privileges", json!(["read write"])),
        ("access_basis", json!("membership")),
        ("roles", json!(["admin"])),
        ("admin_access_grant_id", json!("unbound")),
    ] {
        let mut value_object = good.clone();
        value_object[name] = value;
        assert!(AccessRequest::parse(&json!([value_object]).to_string()).is_err());
    }
    let duplicate = format!("[{{\"type\":\"{ORGANIZATION_ACCESS_TYPE}\",\"type\":\"{ORGANIZATION_ACCESS_TYPE}\",\"identifier\":\"{}\"}}]", f.request.identifier);
    assert!(AccessRequest::parse(&duplicate).is_err());
}

#[test]
fn selected_authority_is_scoped_narrowed_and_time_bounded() {
    let mut f = Fixture::new();
    f.request.privileges = Some(vec!["documents.read".into()]);
    let decision = f.authorize().unwrap();
    assert_eq!(decision.privileges, keys(&["documents.read"]));
    assert_eq!(decision.expires_at, 400);
    assert!(decision.is_current(&f.organization, &f.member, &f.roles, 399));
    assert!(!decision.is_current(&f.organization, &f.member, &f.roles, 400));
    assert_eq!(
        decision.authorization_details()[0]["access_basis"],
        "membership"
    );
    assert_eq!(
        decision.authorization_details()[0]["identifier"],
        f.request.identifier
    );
    f.ceiling.expires_at = 150;
    assert_eq!(f.authorize().unwrap().expires_at, 150);
    f.ceiling.expires_at = 100;
    assert_eq!(f.authorize(), Err(AuthorityError::Forbidden));
}

#[test]
fn every_authenticated_binding_is_required() {
    let f = Fixture::new();
    for field in [
        "environment_id",
        "domain_id",
        "issuer",
        "client_id",
        "client_registration_id",
        "subject",
        "user_id",
        "root_id",
        "dpop_jkt",
    ] {
        let mut binding = f.ceiling.binding.clone();
        match field {
            "environment_id" => binding.scope.environment_id = Uuid::new_v4(),
            "domain_id" => binding.scope.domain_id = Uuid::new_v4(),
            "issuer" => binding.issuer.push_str("/other"),
            "client_id" => binding.client_id.push_str("-other"),
            "client_registration_id" => binding.client_registration_id = Uuid::new_v4(),
            "subject" => binding.subject.push_str("-other"),
            "user_id" => binding.user_id = Uuid::new_v4(),
            "root_id" => binding.root_id.push_str("-other"),
            "dpop_jkt" => binding.dpop_jkt.push_str("-other"),
            _ => unreachable!(),
        }
        let result = AccessDecision::authorize(AccessInput {
            ceiling: &f.ceiling,
            authenticated: &binding,
            request: &f.request,
            audience: "https://api.example.org",
            current_client_privileges: &keys(&["documents.read"]),
            organization: &f.organization,
            member: &f.member,
            definitions: &f.roles,
            parent_expires_at: 900,
            now: 100,
        });
        assert_eq!(result, Err(AuthorityError::Forbidden), "{field}");
    }
}

#[test]
fn cross_domain_identity_and_organization_substitutions_fail_closed() {
    for mutate in 0..4 {
        let mut f = Fixture::new();
        let token = f.authorize().unwrap();
        assert!(token.is_current(&f.organization, &f.member, &f.roles, 100));
        match mutate {
            0 => f.member.scope.domain_id = Uuid::new_v4(),
            1 => f.member.scope.environment_id = Uuid::new_v4(),
            2 => f.member.user_id = Uuid::new_v4(),
            _ => f.member.organization_id = Uuid::new_v4(),
        }
        assert!(f.authorize().is_err());
        assert!(!token.is_current(&f.organization, &f.member, &f.roles, 100));
    }
    let mut f = Fixture::new();
    f.request.identifier = format!("organization_{}", Uuid::new_v4());
    assert!(f.authorize().is_err());
}

#[test]
fn demotion_revokes_old_token_and_next_exchange_narrows_original_grant() {
    let mut f = Fixture::new();
    let token = f.authorize().unwrap();
    f.member
        .update(1, MembershipState::Active, keys(&["reader"]))
        .unwrap();
    assert_eq!(f.member.grant_generation, 1);
    assert!(!token.is_current(&f.organization, &f.member, &f.roles, 100));
    assert_eq!(f.authorize().unwrap().privileges, keys(&["documents.read"]));
    f.request.privileges = Some(vec!["documents.write".into()]);
    assert_eq!(f.authorize(), Err(AuthorityError::Forbidden));
}

#[test]
fn promotion_reactivation_rejoin_and_role_version_change_require_authorization() {
    for operation in 0..5 {
        let mut f = Fixture::new();
        match operation {
            0 => {
                f.member
                    .update(1, MembershipState::Active, keys(&["reader"]))
                    .unwrap();
                f.member
                    .update(2, MembershipState::Active, keys(&["reader", "writer"]))
                    .unwrap();
            }
            1 => {
                f.member
                    .update(1, MembershipState::Suspended, f.member.roles.clone())
                    .unwrap();
                f.member
                    .update(2, MembershipState::Active, f.member.roles.clone())
                    .unwrap();
            }
            2 => f.member.incarnation = Uuid::new_v4(),
            3 => {
                f.organization
                    .transition(1, OrganizationState::Suspended)
                    .unwrap();
                f.organization
                    .transition(2, OrganizationState::Active)
                    .unwrap();
            }
            _ => f.roles.get_mut("reader").unwrap().version += 1,
        }
        assert_eq!(
            f.authorize(),
            Err(AuthorityError::ReauthorizationRequired),
            "{operation}"
        );
    }
}

#[test]
fn target_and_client_privilege_removal_cannot_be_recovered_by_request() {
    let mut f = Fixture::new();
    f.ceiling
        .audiences
        .get_mut("https://api.example.org")
        .unwrap()
        .remove("documents.write");
    assert_eq!(f.authorize().unwrap().privileges, keys(&["documents.read"]));
    f.request.privileges = Some(vec!["documents.write".into()]);
    assert_eq!(f.authorize(), Err(AuthorityError::Forbidden));
    f.request.privileges = None;
    let denied = AccessDecision::authorize(AccessInput {
        ceiling: &f.ceiling,
        authenticated: &f.ceiling.binding,
        request: &f.request,
        audience: "https://api.example.org",
        current_client_privileges: &BTreeSet::new(),
        organization: &f.organization,
        member: &f.member,
        definitions: &f.roles,
        parent_expires_at: 900,
        now: 100,
    });
    assert_eq!(denied, Err(AuthorityError::Forbidden));
    f.ceiling.audiences.clear();
    assert!(f.authorize().is_err());
}

#[test]
fn stale_mutations_and_overflow_preserve_original_state_and_terminal_revocation() {
    let mut f = Fixture::new();
    let original = f.organization.clone();
    assert_eq!(
        f.organization.transition(2, OrganizationState::Suspended),
        Err(AuthorityError::Conflict)
    );
    assert_eq!(f.organization, original);
    f.organization.revision = i64::MAX - 1;
    let exhausted = f.organization.clone();
    assert_eq!(
        f.organization
            .transition(i64::MAX - 1, OrganizationState::Suspended),
        Err(AuthorityError::Exhausted)
    );
    assert_eq!(f.organization, exhausted);
    f.organization
        .transition(i64::MAX - 1, OrganizationState::Deleted)
        .unwrap();
    assert_eq!(f.organization.revision, i64::MAX);
    assert_eq!(
        f.organization
            .transition(i64::MAX, OrganizationState::Active),
        Err(AuthorityError::Forbidden)
    );
    f.member.grant_generation = i64::MAX - 1;
    f.member.state = MembershipState::Suspended;
    let suspended = f.member.clone();
    assert_eq!(
        f.member
            .update(1, MembershipState::Active, f.member.roles.clone()),
        Err(AuthorityError::Exhausted)
    );
    assert_eq!(f.member, suspended);
    f.member
        .update(1, MembershipState::Removed, BTreeSet::new())
        .unwrap();
    assert_eq!(
        f.member
            .update(2, MembershipState::Active, keys(&["reader"])),
        Err(AuthorityError::Forbidden)
    );
}

#[test]
fn external_ids_are_opaque_and_validated_as_utf8_bytes() {
    let mut f = Fixture::new();
    for invalid in ["".into(), "x\n".into(), "x\u{85}".into(), "é".repeat(129)] {
        f.organization.external_id = invalid;
        assert!(f.organization.validate().is_err());
    }
    for valid in [
        "School-A".into(),
        "school-a".into(),
        "é".repeat(128),
        "e\u{301}".into(),
    ] {
        f.organization.external_id = valid.clone();
        assert!(f.organization.validate().is_ok());
        assert_eq!(f.organization.external_id, valid);
    }
}

#[test]
fn delegated_management_requires_registered_management_target_and_assignable_roles() {
    use super::delegation::{authorize_membership_change, DelegationInput, MANAGE_MEMBERS};
    let mut f = Fixture::new();
    let role = f.roles.get_mut("reader").unwrap();
    role.manages_members = true;
    role.assignable_roles = keys(&["reader"]);
    role.privileges.insert(MANAGE_MEMBERS.into());
    f.ceiling.memberships.insert(
        f.organization.id,
        AuthorizationCeiling::capture_membership(&f.organization, &f.member, &f.roles).unwrap(),
    );
    let audience = "https://issuer.example.org/organization-management";
    f.ceiling
        .audiences
        .insert(audience.into(), keys(&[MANAGE_MEMBERS]));
    let current = keys(&[MANAGE_MEMBERS]);
    let token = AccessDecision::authorize(AccessInput {
        ceiling: &f.ceiling,
        authenticated: &f.ceiling.binding,
        request: &f.request,
        audience,
        current_client_privileges: &current,
        organization: &f.organization,
        member: &f.member,
        definitions: &f.roles,
        parent_expires_at: 900,
        now: 100,
    })
    .unwrap();
    let assigned = keys(&["reader"]);
    let input = DelegationInput {
        access: &token,
        authenticated: &f.ceiling.binding,
        management_audience: audience,
        current_client_privileges: &current,
        organization: &f.organization,
        actor_membership: &f.member,
        definitions: &f.roles,
        assign_roles: &assigned,
        now: 100,
    };
    assert_eq!(authorize_membership_change(&input), Ok(()));
    assert_eq!(
        authorize_membership_change(&DelegationInput {
            management_audience: "https://business.example.org",
            ..input
        }),
        Err(AuthorityError::Forbidden)
    );
    assert_eq!(
        authorize_membership_change(&DelegationInput {
            assign_roles: &keys(&["writer"]),
            ..input
        }),
        Err(AuthorityError::Forbidden)
    );
    assert_eq!(
        authorize_membership_change(&DelegationInput {
            current_client_privileges: &BTreeSet::new(),
            ..input
        }),
        Err(AuthorityError::Forbidden)
    );
    let mut removed = f.member.clone();
    removed
        .update(1, MembershipState::Suspended, removed.roles.clone())
        .unwrap();
    assert_eq!(
        authorize_membership_change(&DelegationInput {
            actor_membership: &removed,
            ..input
        }),
        Err(AuthorityError::Forbidden)
    );
}
