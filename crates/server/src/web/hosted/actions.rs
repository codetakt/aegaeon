use super::*;
use crate::organizations::invitations::enrollment::Purpose;
use crate::web::organization_resource::identity::Action as IdentityAction;
use flow::{Identity, Step::*};

mod recipient;
use hosted_page::MailLink;
pub(super) use recipient::record_intent;
use recipient::{prepare, send, verify};

pub(super) async fn import(
    state: &AppState,
    admission: &ResourceAdmission,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    browser: &str,
    headers: &HeaderMap,
    link: MailLink,
) -> Result<(Flow, Option<Value>)> {
    let original = link.template == "organization_invitation";
    let selector = Find::Invitation(browser, link.domain_id, link.invitation_id);
    if original {
        store
            .lock_invitation(tx, browser, link.domain_id, link.invitation_id)
            .await?;
    }
    let mut previous = store.find(tx, selector).await?;
    let clock = now()?;
    let generation = generation(state.environment_id)?;
    let stale_binding = check_existing_flow(
        previous.as_mut(),
        &generation,
        browser,
        headers,
        clock,
        original,
    )?;
    let matches = previous.as_ref().is_some_and(|f| {
        f.delivery_revision == link.delivery_revision
            && f.proof_tag == store::hash(&link.capability)
    });
    let receipt = original
        && !stale_binding
        && matches
        && previous
            .as_ref()
            .is_some_and(|f| matches!(f.step, Complete | AcceptPending | Unconfirmed));
    let current = authority::current(
        state,
        admission,
        link.domain_id,
        link.invitation_id,
        if original {
            (!receipt).then(|| authority::InvitationProof::from(&link))
        } else {
            previous.as_ref().ok_or(Error::Refused)?.pending_proof()?
        },
        if original {
            None
        } else {
            Some((
                &link,
                previous.as_ref().ok_or(Error::Refused)?.delivery_revision,
            ))
        },
    )
    .await?;
    store.secret(link.domain_id)?;
    let c = current.registration;
    if let Some(old) = &previous {
        if !stale_binding && c.client_registration_id != old.client {
            return Err(Error::Refused);
        }
    }
    if previous.is_none() && original {
        // Hold the installation capacity lock only after primary proof verification.
        store.reserve(tx).await?;
    }
    let mut f = match previous {
        None if original => Flow::start(
            browser,
            generation,
            c.client_registration_id,
            link,
            c.return_url,
            clock,
        ),
        Some(mut f) if original => {
            if !stale_binding && !matches && link.delivery_revision <= f.delivery_revision {
                return Err(Error::Refused);
            }
            if stale_binding || !matches || f.step == Closed {
                f.retire(store, tx).await?;
                let mut next = Flow::start(
                    browser,
                    generation,
                    c.client_registration_id,
                    link,
                    c.return_url,
                    clock,
                );
                next.id = f.id;
                next.step = Restart;
                next
            } else {
                f
            }
        }
        Some(f) => import_related_mail(f, link, clock)?,
        None => return Err(Error::Refused),
    };
    f.can_register = current.registration_allowed;
    f.can_recover = current.recovery_allowed;
    if f.step == Confirm {
        verify(state, store, tx, &mut f, None).await?;
    }
    Ok((f, None))
}

fn check_existing_flow(
    previous: Option<&mut Flow>,
    generation: &Generation,
    browser: &str,
    headers: &HeaderMap,
    clock: i64,
    original: bool,
) -> Result<bool> {
    // A fresh invitation can start a new interactive flow after a restore or
    // session expiry. Never use the previous flow as proof in that case.
    let Some(old) = previous else {
        return Ok(false);
    };
    let stale_binding =
        &old.generation != generation || old.session.is_some() && old.session_until <= clock;
    if stale_binding {
        if !original || old.browser != browser {
            return Err(Error::Refused);
        }
    } else {
        old.bound(generation, browser, headers, clock)?;
    }
    old.expire_interactive(clock);
    Ok(stale_binding)
}

fn import_related_mail(mut f: Flow, link: MailLink, clock: i64) -> Result<Flow> {
    if link.template == "organization_recipient_challenge" {
        if f.session.is_none() || f.grant.is_none() || f.deadline <= clock {
            return Err(Error::Refused);
        }
        let child = f
            .challenge
            .as_mut()
            .filter(|c| c.id == link.object_id && c.expires == link.expires_at)
            .ok_or(Error::Refused)?;
        if child
            .proof
            .as_ref()
            .is_some_and(|p| p.delivery_revision > link.delivery_revision)
        {
            return Err(Error::Refused);
        }
        if child
            .proof
            .as_ref()
            .is_none_or(|p| p.delivery_revision != link.delivery_revision)
        {
            child.proof = Some(link);
            f.display = None;
            f.prepared = None;
            f.step = ProofReady;
        }
    } else {
        if f.deadline <= clock
            || f.session.is_some()
            || !matches!(f.step, IdentityWaiting | IdentityReady)
        {
            return Err(Error::Refused);
        }
        let pending = f.identity.as_mut().ok_or(Error::Refused)?;
        let template = match pending.purpose {
            Purpose::Registration => "organization_identity_registration",
            Purpose::PasswordRecovery => "organization_identity_recovery",
        };
        if pending.request != link.object_id
            || template != link.template
            || pending
                .proof
                .as_ref()
                .is_some_and(|p| p.delivery_revision > link.delivery_revision)
        {
            return Err(Error::Refused);
        }
        pending.until = link.expires_at;
        pending.proof = Some(link);
        f.step = IdentityReady;
    }
    Ok(f)
}

pub(super) async fn act(
    state: &AppState,
    admission: &ResourceAdmission,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    f: &mut Flow,
    action: Action,
    clock: i64,
) -> Result<Option<Value>> {
    f.expire_interactive(clock);
    if matches!(action, Action::Cancel { .. }) {
        f.retire(store, tx).await?;
        f.clear(Closed);
        return Ok(None);
    }
    if matches!(f.step, Closed | Unconfirmed) {
        return Ok(None);
    }
    let current = authority::current_for_flow(state, admission, f).await?;
    match action {
        Action::Resume { .. } => {
            if f.step == Confirm {
                verify(state, store, tx, f, None).await?;
                return Ok(None);
            }
            if f.step == MetadataUnavailable
                && f.challenge.as_ref().is_some_and(|c| c.proof.is_some())
            {
                f.step = ProofReady
            } else if f.step == MetadataUnavailable && f.challenge.is_none() {
                f.step = SignedIn
            }
        }
        Action::Return { .. }
            if f.step == Complete && f.confirmation_until.is_some_and(|u| clock < u) =>
        {
            if let Some(url) = f
                .return_url
                .as_ref()
                .filter(|s| current.registration.return_url.as_ref() == Some(s))
            {
                return Ok(Some(json!({"navigateTo":url})));
            }
            f.return_url = None;
        }
        Action::Restart { .. } if f.step == Restart && clock < f.deadline => {
            f.step = Invitation;
        }
        Action::Login { .. } if matches!(f.step, Invitation | LoginUnavailable) => {
            return login(state, f)
        }
        Action::Switch { .. } if f.grant.is_some() => {
            f.retire(store, tx).await?;
            f.identity = None;
            f.expected_subject = None;
            f.session = None;
            f.session_subject = None;
            f.handle = Uuid::new_v4();
            f.step = Invitation;
            return login(state, f);
        }
        Action::IdentityRequest {
            purpose,
            login_identifier,
            ..
        } if f.step == Invitation && f.authorization.is_none() => {
            request_identity(state, admission, store, f, purpose, login_identifier, clock).await?;
        }
        Action::IdentityComplete {
            password,
            password_confirmation,
            ..
        } if f.step == IdentityReady => {
            complete_identity(state, admission, f, password, password_confirmation, clock).await?;
        }
        Action::Status { .. }
            if f.grant.is_some() && !matches!(f.step, AcceptPending | SendPending | Complete) =>
        {
            prepare(state, store, tx, f, clock).await?;
        }
        Action::Send { confirmation, .. } if f.grant.is_some() => {
            if f.step == Expired {
                prepare(state, store, tx, f, clock).await?;
            } else if matches!(f.step, SendReady | SendPending) {
                send(state, store, tx, f, &confirmation).await?;
            } else if !matches!(f.step, ChallengeWaiting | ProofReady | Confirm) {
                return Err(Error::Refused);
            }
        }
        Action::Preview { .. } if matches!(f.step, ProofReady | Confirm | MetadataUnavailable) => {
            verify(state, store, tx, f, None).await?
        }
        Action::Confirm { confirmation, .. } if matches!(f.step, Confirm | AcceptPending) => {
            verify(state, store, tx, f, Some(&confirmation)).await?
        }
        Action::Confirm { .. } if f.step == Complete => {}
        _ => return Err(Error::Refused),
    }
    Ok(None)
}
async fn request_identity(
    state: &AppState,
    admission: &ResourceAdmission,
    store: &Store,
    f: &mut Flow,
    purpose: Purpose,
    login_identifier: Option<String>,
    clock: i64,
) -> Result<()> {
    // Derive a stable request key before the primary commit. Retrying the
    // same operation after a BFF crash cannot spend another identity slot.
    let key = store.mac(
        "identity",
        &format!(
            "{}:{}:{:?}:{:?}",
            f.handle, f.identity_version, purpose, login_identifier
        ),
    );
    let response = authority::identity(
        state,
        admission,
        f,
        IdentityAction::Request {
            purpose,
            invitation_capability: f.capability.clone().ok_or(Error::Refused)?,
            login_identifier,
            request_key: key,
        },
    )
    .await?;
    let id = uuid(&response, "requestId")?;
    f.identity = Some(Identity {
        request: id,
        purpose,
        proof: None,
        until: (clock + 600).min(f.invitation_expiry),
    });
    f.step = IdentityWaiting;
    Ok(())
}

async fn complete_identity(
    state: &AppState,
    admission: &ResourceAdmission,
    f: &mut Flow,
    password: String,
    password_confirmation: String,
    clock: i64,
) -> Result<()> {
    let i = f.identity.as_ref().ok_or(Error::Refused)?;
    let proof = i
        .proof
        .as_ref()
        .filter(|p| clock < p.expires_at)
        .ok_or(Error::Refused)?;
    let response = authority::identity(
        state,
        admission,
        f,
        IdentityAction::Complete {
            request_id: i.request,
            proof: proof.capability.clone(),
            password,
            password_confirmation,
        },
    )
    .await?;
    f.expected_subject = Some((
        response["subject"]
            .as_str()
            .ok_or(Error::Unavailable)?
            .into(),
        now()?,
    ));
    f.identity = None;
    f.step = Invitation;
    Ok(())
}

fn login(state: &AppState, f: &mut Flow) -> Result<Option<Value>> {
    if f.authorization.is_none() {
        f.authorization = Some(
            oauth::Authorization::begin(&state.issuer, f.domain, f.deadline)
                .map_err(|_| Error::Unavailable)?,
        )
    }
    let url = f
        .authorization
        .as_ref()
        .ok_or(Error::Unavailable)?
        .url()
        .map_err(|_| Error::Unavailable)?;
    Ok(Some(json!({"navigateTo":url})))
}
fn integer(v: &Value, k: &str, min: i64, max: i64) -> Result<i64> {
    v[k].as_i64()
        .filter(|n| (min..=max).contains(n))
        .ok_or(Error::Unavailable)
}
fn uuid(v: &Value, k: &str) -> Result<Uuid> {
    v[k].as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|v| !v.is_nil())
        .ok_or(Error::Unavailable)
}
