//! Reuse producer contracts; historical values are never evaluated as live grants.
use crate::organizations::{
    model::{require, valid_keys},
    operators::{
        self,
        mutations::{clients, delivery, identity_policy, support_policy, targets},
    },
    repository::AuditActor,
    snapshot::input::PendingRow,
    support, AuthorityError, Membership, MembershipState, Organization, RoleDefinition, Scope,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, AuthorityError>;

fn get<T: DeserializeOwned>(data: &Value, name: &str) -> Result<T> {
    serde_json::from_value(data.get(name).ok_or(AuthorityError::Invalid)?.clone())
        .map_err(|_| AuthorityError::Invalid)
}

fn scope(data: &Value) -> Result<Scope> {
    Ok(Scope {
        environment_id: get(data, "environment_id")?,
        domain_id: get(data, "domain_id")?,
    })
}

fn keys(data: &Value, name: &str, maximum: usize) -> Result<BTreeSet<String>> {
    let values: Vec<String> = get(data, name)?;
    let unique: BTreeSet<_> = values.iter().cloned().collect();
    require(unique.len() == values.len() && valid_keys(&unique, maximum))?;
    Ok(unique)
}

fn text(data: &Value, name: &str, maximum: usize) -> Result<()> {
    let value: String = get(data, name)?;
    require(
        !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control),
    )
}

pub(super) fn validate(row: &PendingRow) -> Result<()> {
    let d = &row.data;
    for name in ["created_at", "updated_at", "recorded_at"] {
        if let Some(value) = d.get(name) {
            require(value.as_str().is_some_and(super::super::timestamps::valid))?;
        }
    }
    match row.section {
        "organizations" => Organization {
            scope: scope(d)?,
            id: get(d, "id")?,
            external_id: get(d, "external_id")?,
            state: get(d, "state")?,
            revision: get(d, "revision")?,
            grant_generation: get(d, "grant_generation")?,
        }
        .validate(),
        "memberships" => {
            let member = Membership {
                scope: scope(d)?,
                organization_id: get(d, "organization_id")?,
                user_id: get(d, "end_user_id")?,
                incarnation: get(d, "incarnation")?,
                state: get(d, "state")?,
                revision: get(d, "revision")?,
                grant_generation: get(d, "grant_generation")?,
                roles: keys(d, "roles", 64)?,
            };
            member.validate()?;
            require(member.state != MembershipState::Removed || member.roles.is_empty())
        }
        "roles" => RoleDefinition {
            scope: scope(d)?,
            key: get(d, "role_key")?,
            version: get(d, "version")?,
            privileges: keys(d, "privileges", 256)?,
            manages_members: get(d, "manages_members")?,
            assignable_roles: keys(d, "assignable_roles", 64)?,
        }
        .validate(),
        "operators" => {
            let values: Vec<operators::Capability> = get(d, "capabilities")?;
            operators::validate_capabilities(&values).map(|_| ())
        }
        "targets" => targets::Target {
            audience: get(d, "audience")?,
            management: get(d, "management")?,
            introspection_clients: get(d, "introspection_clients")?,
        }
        .validate(),
        "client_bindings" => {
            text(d, "client_identifier", 2048)?;
            let targets: Vec<clients::ClientTarget> = get(d, "targets")?;
            clients::validate_targets(&targets).map_err(|_| AuthorityError::Invalid)
        }
        "domain" => {
            if let Some(channel) = get::<Option<delivery::Channel>>(d, "invitation_delivery")? {
                channel.validate()?;
            }
            if let Some(policy) = get::<Option<support_policy::Policy>>(d, "support_policy")? {
                policy.validate()?;
            }
            text(d, "name", 255)
        }
        "environment_dependency" => {
            if let Some(policy) =
                get::<Option<identity_policy::Policy>>(d, "organization_identity_policy")?
            {
                policy.validate()?;
            }
            Ok(())
        }
        "administrative_grants" => administrative_grant(d),
        "audit" => {
            AuditActor {
                basis: None,
                id: get(d, "actor_id")?,
                kind: get(d, "actor_kind")?,
                client_id: get(d, "client_id")?,
                client_registration_id: get(d, "client_registration_id")?,
                request_id: get(d, "request_id")?,
                reason: get(d, "reason")?,
            }
            .validate()?;
            crate::organizations::audit::retention::validate_data(&d["data"])?;
            text(d, "event_type", 128)
        }
        "invitations" | "challenges" | "identity_requests" => delivery_history(row),
        _ => Ok(()),
    }
}

fn delivery_history(row: &PendingRow) -> Result<()> {
    let d = &row.data;
    let issued: i64 = get(d, "issued_at")?;
    let expires: i64 = get(d, "expires_at")?;
    let maximum = match row.section {
        "invitations" => 86400,
        "challenges" => 300,
        _ => 600,
    };
    let lifetime = expires.checked_sub(issued).ok_or(AuthorityError::Invalid)?;
    require(
        issued >= 0
            && (1..=maximum).contains(&lifetime)
            && (row.section != "invitations" || lifetime >= 60),
    )?;
    let revision: i64 = get(d, "delivery_revision")?;
    let delivered: Option<i64> = get(d, "delivered_at")?;
    let outcome: String = get(d, "delivery_outcome")?;
    require(
        (0..=5).contains(&revision)
            && matches!(
                outcome.as_str(),
                "unclaimed" | "uncertain" | "acknowledged" | "rejected"
            )
            && (revision == 0) == delivered.is_none()
            && (revision == 0) == (outcome == "unclaimed")
            && (revision == 0 || delivered.is_some_and(|t| t >= issued && t < expires)),
    )?;
    if row.section == "invitations" {
        let recipient: String = get(d, "recipient")?;
        require(crate::organizations::invitations::recipient_address(&recipient)? == recipient)?;
        let state: crate::organizations::invitations::State = get(d, "state")?;
        require(
            (state == crate::organizations::invitations::State::Accepted)
                == (!d["accepted_challenge_id"].is_null() && !d["result"].is_null()),
        )?;
        if !d["result"].is_null() {
            let member: Membership = get(d, "result")?;
            member.validate()?;
            require(
                member.scope == scope(d)?
                    && member.organization_id == get::<uuid::Uuid>(d, "organization_id")?,
            )?;
        }
    } else {
        text(d, "request_key", 128)?;
        let parent_revision: i64 = get(d, "invitation_delivery_revision")?;
        require((1..=5).contains(&parent_revision))?;
    }
    crate::organizations::invitations::validate_history_row(row.section, d, scope(d)?)
}

fn administrative_grant(d: &Value) -> Result<()> {
    let grant = support::Grant {
        id: get(d, "id")?,
        authority: get(d, "authority")?,
        revision: get(d, "revision")?,
        active: get(d, "active")?,
        issued_at: get(d, "issued_at")?,
        expires_at: get(d, "expires_at")?,
    };
    grant.validate()?;
    require(
        grant.authority.binding.scope == scope(d)?
            && grant.authority.organization_id == get::<uuid::Uuid>(d, "organization_id")?
            && grant.authority.binding.user_id == get::<uuid::Uuid>(d, "user_id")?
            && grant.authority.binding.client_registration_id
                == get::<uuid::Uuid>(d, "client_registration_id")?
            && grant.authority.binding.root_id == get::<String>(d, "root_id")?,
    )
}
