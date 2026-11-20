use super::*;
use crate::organizations::{
    invitation_capabilities as cap, invitations,
    operators::mutations::{delivery, identity_policy},
    Scope,
};
use sqlx::Row;
pub(super) struct Current {
    pub registration: delivery::HostedRegistration,
    pub registration_allowed: bool,
    pub recovery_allowed: bool,
}

pub(super) struct InvitationProof<'a> {
    revision: i64,
    expires: i64,
    capability: &'a str,
}
impl<'a> From<&'a hosted_page::MailLink> for InvitationProof<'a> {
    fn from(link: &'a hosted_page::MailLink) -> Self {
        Self {
            revision: link.delivery_revision,
            expires: link.expires_at,
            capability: &link.capability,
        }
    }
}
impl Flow {
    pub(super) fn pending_proof(&self) -> Result<Option<InvitationProof<'_>>> {
        use flow::Step::{AcceptPending, Closed, Complete, Unconfirmed};
        // A committed accept changes the primary invitation state. Only the
        // original replay or its short-lived local confirmation may continue.
        if matches!(self.step, AcceptPending | Complete | Unconfirmed | Closed) {
            return Ok(None);
        }
        Ok(Some(InvitationProof {
            revision: self.delivery_revision,
            expires: self.invitation_expiry,
            capability: self.capability.as_deref().ok_or(Error::Refused)?,
        }))
    }
}
pub(super) async fn current_for_flow(
    state: &AppState,
    admission: &ResourceAdmission,
    flow: &Flow,
) -> Result<Current> {
    let current = current(
        state,
        admission,
        flow.domain,
        flow.invitation,
        flow.pending_proof()?,
        None,
    )
    .await?;
    if current.registration.client_registration_id != flow.client {
        return Err(Error::Refused);
    }
    Ok(current)
}

pub(super) async fn current(
    state: &AppState,
    admission: &ResourceAdmission,
    domain: Uuid,
    id: Uuid,
    invitation: Option<InvitationProof<'_>>,
    child: Option<(&hosted_page::MailLink, i64)>,
) -> Result<Current> {
    state.require_subject_namespace().map_err(Error::from)?;
    if state.runtime_restart.is_requested() {
        return Err(Error::Unavailable);
    }
    if !state
        .cfg
        .authorization_details_types_supported
        .iter()
        .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE)
    {
        return Err(Error::Refused);
    }
    let scope = Scope {
        environment_id: state.environment_id,
        domain_id: domain,
    };
    let expected = crate::web::organization_authority::projection(state).map_err(Error::from)?;
    let mut connection = admission.0.connection(&state.db_pool).await?;
    let mut tx = connection.begin().await?;
    if let Some(link) = invitation {
        let runtime = invitations::delegated::Runtime {
            store: &state.tokens.store,
            issuer: &state.issuer,
            admission: &admission.0,
        };
        let expiry = invitations::hosted_invitation(
            &mut tx,
            scope,
            id,
            link.revision,
            link.capability,
            now()?,
            &runtime,
        )
        .await
        .map_err(|_| Error::Refused)?;
        if expiry != link.expires {
            return Err(Error::Refused);
        }
    }
    let row = sqlx::query(
        "SELECT authority->>'delivery_profile_revision' AS pin,
                                  authority->>'hosted_client_registration_id' AS client
                           FROM aegaeon.organization_invitations
                           WHERE environment_id=$1 AND domain_id=$2 AND id=$3",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Refused)?;
    let pin = row
        .try_get::<Option<String>, _>("pin")?
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or(Error::Refused)?;
    let client = row
        .try_get::<Option<String>, _>("client")?
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or(Error::Refused)?;
    delivery::resolve(&mut tx, scope, Some(pin), Some(client))
        .await
        .map_err(|_| Error::Refused)?;
    let registration = delivery::hosted_current(&mut tx, scope)
        .await
        .map_err(|_| Error::Refused)?;
    if registration.client_registration_id != client
        || registration.issuer != *state.issuer
        || oauth::domain_for_client(&registration.client_id) != Some(domain)
    {
        return Err(Error::Refused);
    }
    if let Some((link, invitation_revision)) = child {
        verify_related_mail(&mut tx, scope, link, invitation_revision).await?;
    }
    let policy = identity_policy::read_locked(&mut tx, scope.environment_id)
        .await
        .map_err(|_| Error::Refused)?
        .policy;
    crate::web::organization_authority::recheck_projection(state, &mut tx, &expected)
        .await
        .map_err(Error::from)?;
    tx.commit().await?;
    connection.release().await;
    Ok(Current {
        registration,
        registration_allowed: policy.as_ref().is_some_and(|p| p.registration),
        recovery_allowed: policy.is_some_and(|p| p.password_recovery),
    })
}
async fn verify_related_mail(
    tx: &mut PgTransaction<'_>,
    scope: Scope,
    link: &hosted_page::MailLink,
    invitation_revision: i64,
) -> Result<()> {
    let challenge = "SELECT delivery_revision,capability_hash,expires_at FROM aegaeon.organization_invitation_challenges
                     WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 AND invitation_delivery_revision=$5 FOR SHARE";
    let identity = "SELECT delivery_revision,capability_hash,expires_at FROM aegaeon.organization_identity_requests
                    WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 AND invitation_delivery_revision=$5
                    AND state='pending' AND purpose=$6 FOR SHARE";
    let (purpose, query, identity_purpose) = match link.template.as_str() {
        "organization_recipient_challenge" => (cap::Purpose::RecipientChallenge, challenge, None),
        "organization_identity_registration" => (
            cap::Purpose::IdentityRegistration,
            identity,
            Some("registration"),
        ),
        "organization_identity_recovery" => (
            cap::Purpose::IdentityRecovery,
            identity,
            Some("password_recovery"),
        ),
        _ => return Err(Error::Invalid),
    };
    let mut query = sqlx::query(query)
        .bind(scope.environment_id)
        .bind(scope.domain_id)
        .bind(link.invitation_id)
        .bind(link.object_id)
        .bind(invitation_revision);
    if let Some(value) = identity_purpose {
        query = query.bind(value);
    }
    let row = query
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::Refused)?;
    let hash: [u8; 32] = row
        .try_get::<Option<Vec<u8>>, _>("capability_hash")?
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Refused)?;
    if link.delivery_revision != row.try_get::<i64, _>("delivery_revision")?
        || link.expires_at != row.try_get::<i64, _>("expires_at")?
        || now()? >= link.expires_at
        || !cap::matches(
            cap::Binding {
                scope,
                object_id: link.object_id,
                delivery_revision: link.delivery_revision,
                purpose,
            },
            &hash,
            &link.capability,
        )
    {
        return Err(Error::Refused);
    }
    Ok(())
}

pub(super) async fn identity(
    state: &AppState,
    admission: &ResourceAdmission,
    f: &Flow,
    action: crate::web::organization_resource::identity::Action,
) -> Result<Value> {
    let key = Uuid::new_v4().to_string();
    crate::web::organization_resource::identity::transaction(
        state,
        admission,
        Scope {
            environment_id: state.environment_id,
            domain_id: f.domain,
        },
        f.invitation,
        action,
        &key,
    )
    .await
    .map_err(Error::from)
}
