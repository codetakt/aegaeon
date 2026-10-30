use super::*;
use crate::organizations::{delegation::DelegationInput, Organization};
use sqlx::{Postgres, Transaction};

pub(super) async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    binding: &Binding,
    selected: &selected::SelectedAuthority,
    organization_id: Uuid,
    action: &Action,
    now: i64,
) -> Result<Representation, RepositoryError> {
    let organization = repository::lock_organization(tx, binding.scope, organization_id).await?;
    match action {
        Action::Read { user } => {
            let member = repository::membership(tx, &organization, *user)
                .await?
                .ok_or(AuthorityError::Forbidden)?;
            single(&organization, member)
        }
        Action::List { limit, after } => {
            list(tx, binding, &organization, *limit, after.as_deref()).await
        }
        Action::Update {
            command,
            actor_reason,
            key,
            request_id,
        } => {
            let Command::SetExistingMember { update, .. } = command else {
                return Err(AuthorityError::Invalid.into());
            };
            let actor = AuditActor {
                basis: None,
                id: binding.user_id,
                kind: ActorKind::Member,
                client_id: binding.client_id.clone(),
                client_registration_id: Some(binding.client_registration_id),
                request_id: request_id.clone(),
                reason: actor_reason.clone(),
            };
            let member = repository::membership(tx, &organization, binding.user_id)
                .await?
                .ok_or(AuthorityError::Forbidden)?;
            let roles = repository::roles(tx, binding.scope).await?;
            let authority = DelegationInput {
                access: &selected.decision,
                authenticated: binding,
                management_audience: &selected.decision.audience,
                // is_current recomputed this exact selected set against current
                // client policy and the original approval in this transaction.
                current_client_privileges: &selected.decision.privileges,
                organization: &organization,
                actor_membership: &member,
                definitions: &roles,
                assign_roles: &update.roles,
                now,
            };
            let result = crate::organizations::commands::apply_member_command(
                tx,
                binding.scope,
                &actor,
                key,
                command,
                &authority,
            )
            .await?;
            let CommandResult::Membership(member) = result else {
                return Err(AuthorityError::Invalid.into());
            };
            single(&organization, member)
        }
    }
}

fn single(
    organization: &Organization,
    member: crate::organizations::Membership,
) -> Result<Representation, RepositoryError> {
    let etag = VersionTag::new(member.incarnation, member.revision)
        .map_err(|_| AuthorityError::Invalid)?
        .header_value();
    let dto =
        input::MemberResponse::new(organization, member).map_err(|_| AuthorityError::Invalid)?;
    Ok(Representation {
        body: serde_json::to_value(dto)?,
        etag: Some(etag),
    })
}

async fn list(
    tx: &mut Transaction<'_, Postgres>,
    binding: &Binding,
    organization: &Organization,
    limit: usize,
    after: Option<&str>,
) -> Result<Representation, RepositoryError> {
    let after =
        input::decode(binding, organization.id, after).map_err(|_| AuthorityError::Invalid)?;
    let bound = i64::try_from(limit.checked_add(1).ok_or(AuthorityError::Invalid)?)
        .map_err(|_| AuthorityError::Invalid)?;
    let users: Vec<Uuid> = sqlx::query_scalar("SELECT end_user_id FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 AND organization_id=$3 AND ($4::uuid IS NULL OR end_user_id>$4) ORDER BY end_user_id LIMIT $5")
        .bind(binding.scope.environment_id).bind(binding.scope.domain_id).bind(organization.id).bind(after).bind(bound).fetch_all(&mut **tx).await?;
    let mut page = input::MemberListResponse {
        members: Vec::new(),
        next_cursor: None,
    };
    for (index, user) in users.iter().take(limit).enumerate() {
        let member = repository::membership(tx, organization, *user)
            .await?
            .ok_or(AuthorityError::Invalid)?;
        page.members.push(
            input::MemberResponse::new(organization, member)
                .map_err(|_| AuthorityError::Invalid)?,
        );
        page.next_cursor = (index + 1 < users.len())
            .then(|| input::encode(binding, organization.id, *user))
            .transpose()
            .map_err(|_| AuthorityError::Invalid)?;
        if serde_json::to_vec(&page)?.len() > http_input::MAX_BODY_BYTES {
            page.members.pop();
            let last = page.members.last().ok_or(AuthorityError::Invalid)?;
            page.next_cursor = Some(
                input::encode(binding, organization.id, last.user_id)
                    .map_err(|_| AuthorityError::Invalid)?,
            );
            break;
        }
    }
    Ok(Representation {
        body: serde_json::to_value(page)?,
        etag: None,
    })
}
