//! Parse retained history at its recorded issue time; never authenticate it.
use super::*;
use serde::de::DeserializeOwned;
use serde_json::Value;

type Result<T> = std::result::Result<T, AuthorityError>;

fn field<T: DeserializeOwned>(data: &Value, name: &str) -> Result<T> {
    serde_json::from_value(data.get(name).ok_or(AuthorityError::Invalid)?.clone())
        .map_err(|_| AuthorityError::Invalid)
}

fn canonical<T: DeserializeOwned + Serialize>(data: &Value, name: &str) -> Result<T> {
    let value: T = field(data, name)?;
    // Set deserialization must not silently discard repeated array members or
    // unsupported fields in a nested historical value.
    require(serde_json::to_value(&value).map_err(|_| AuthorityError::Invalid)? == data[name])?;
    Ok(value)
}

pub(in crate::organizations) fn validate_row(
    section: &str,
    data: &Value,
    scope: Scope,
) -> Result<()> {
    match section {
        "invitations" => invitation(data, scope),
        "challenges" => challenge(data, scope),
        "identity_requests" => identity_request(data),
        _ => Err(AuthorityError::Invalid),
    }
}

fn invitation(data: &Value, scope: Scope) -> Result<()> {
    let authority: Authority = canonical(data, "authority")?;
    authority.actor.validate()?;
    require(
        authority
            .epoch
            .as_ref()
            .is_none_or(|epoch| epoch.environment_id() == scope.environment_id),
    )?;
    require(
        authority.organization_generation > 0
            && !authority.role_versions.is_empty()
            && authority.role_versions.len() <= MAX_ROLES
            && authority
                .role_versions
                .iter()
                .all(|(key, version)| super::super::model::valid_key(key) && *version > 0),
    )?;
    let invitation = Invitation {
        id: field(data, "id")?,
        organization_id: field(data, "organization_id")?,
        revision: field(data, "revision")?,
        state: field(data, "state")?,
        issued_at: field(data, "issued_at")?,
        expires_at: field(data, "expires_at")?,
    };
    match &authority.delegated {
        None => require(
            matches!(authority.actor.kind, ActorKind::Operator)
                && !authority.team.is_nil()
                && !authority.grant.is_nil()
                && authority.grant_revision > 0,
        )?,
        Some(retained) => {
            require(
                matches!(authority.actor.kind, ActorKind::Member)
                    && authority.team.is_nil()
                    && authority.grant.is_nil()
                    && authority.grant_revision == 0,
            )?;
            require(authority.epoch == retained.original.consent.epoch)?;
            retained.validate_history(&authority.actor, scope, &invitation)?;
        }
    }
    if !data["result"].is_null() {
        let member: Membership = canonical(data, "result")?;
        member.validate()?;
        require(
            member.scope == scope
                && member.organization_id == invitation.organization_id
                && member.state == MembershipState::Active
                && member.roles == authority.role_versions.keys().cloned().collect(),
        )?;
    }
    Ok(())
}

fn challenge(data: &Value, scope: Scope) -> Result<()> {
    let recipient: Recipient = canonical(data, "recipient_binding")?;
    recipient.binding.validate()?;
    let issued: i64 = field(data, "issued_at")?;
    let expires: i64 = field(data, "expires_at")?;
    require(
        recipient.binding.scope == scope
            && (1..i64::MAX).contains(&recipient.identity_revision)
            && recipient.auth_time > 0
            && recipient.auth_time <= issued
            && expires <= recipient.expires_at,
    )
}

fn identity_request(data: &Value) -> Result<()> {
    let purpose: enrollment::Purpose = field(data, "purpose")?;
    let target: Option<Uuid> = field(data, "target_user_id")?;
    let revision: Option<i64> = field(data, "target_identity_revision")?;
    require(target.is_some() == revision.is_some())?;
    match purpose {
        enrollment::Purpose::Registration => require(target.is_none())?,
        enrollment::Purpose::PasswordRecovery => (),
    }
    match data["state"].as_str() {
        Some("pending") => require(data["result"].is_null()),
        Some("completed") => {
            let result: enrollment::CompletionResult = canonical(data, "result")?;
            require(
                (purpose != enrollment::Purpose::PasswordRecovery || target.is_some())
                    && !result.user_id.is_nil()
                    && !result.credential_id.is_nil()
                    && (1..i64::MAX).contains(&result.identity_revision)
                    && !result.subject.is_empty()
                    && result.subject.len() <= 2048
                    && !result.subject.chars().any(char::is_control)
                    && target.is_none_or(|id| id == result.user_id)
                    && revision.is_none_or(|before| {
                        before.checked_add(1) == Some(result.identity_revision)
                    }),
            )
        }
        _ => Err(AuthorityError::Invalid),
    }
}
