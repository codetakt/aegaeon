use super::*;
use flow::{Allocated, Display, Preparation};

pub(super) async fn prepare(
    state: &AppState,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    f: &mut Flow,
    clock: i64,
) -> Result<()> {
    let grant = f.grant.as_ref().ok_or(Error::Refused)?;
    let child = match oauth::exchange(&state.issuer, store.secret(f.domain)?, grant).await {
        Ok(c) => c,
        Err(oauth::Error::Unavailable) => return Err(Error::Unavailable),
        Err(_) => {
            f.retire(store, tx).await?;
            f.authorization = None;
            f.step = Invitation;
            return Ok(());
        }
    };
    let r = oauth::post(
        &state.issuer,
        grant,
        &child,
        f.domain,
        f.invitation,
        oauth::Operation::Status,
        &json!({"invitationCapability":f.capability}),
    )
    .await
    .map_err(|_| Error::Unavailable)?;
    if r.status != 200 {
        return Err(Error::Refused);
    }
    let remaining = integer(&r.body, "remainingChallenges", 0, 5)?;
    let expires = integer(
        &r.body,
        "invitationExpiresAt",
        clock + 1,
        f.invitation_expiry,
    )?
    .min(child.expires_at);
    f.prepared = None;
    if remaining == 0 {
        if let Some(c) = &mut f.challenge {
            c.remaining = 0;
            f.step = if c.proof.is_some() {
                ProofReady
            } else {
                ChallengeWaiting
            }
        } else {
            f.step = Exhausted
        }
    } else {
        f.prepared = Some(Preparation {
            child,
            key: Uuid::new_v4().to_string(),
            confirmation: Uuid::new_v4().to_string(),
            remaining,
            expires,
        });
        f.step = SendReady;
    }
    Ok(())
}

/// Persist the precise user decision before contacting a service that commits
/// independently. A retry reuses the same key or validator, even after a crash.
pub(in crate::web::hosted) fn record_intent(
    store: &Store,
    f: &mut Flow,
    action: &Action,
    now: i64,
) -> Result<bool> {
    if f.deadline <= now {
        return Ok(false);
    }
    match action {
        Action::Send { confirmation, .. } if f.step == SendReady => {
            let p = f.prepared.as_ref().ok_or(Error::Refused)?;
            if p.expires <= now {
                return Ok(false);
            }
            if !cookies::equal(&p.confirmation, confirmation) {
                return Err(Error::Refused);
            }
            f.step = SendPending;
        }
        Action::Confirm { confirmation, .. } if f.step == Confirm => {
            let d = f.display.as_ref().ok_or(Error::Refused)?;
            if !cookies::equal(
                confirmation,
                &store.mac("confirm", &format!("{}:{}", f.handle, d.etag)),
            ) {
                return Err(Error::Refused);
            }
            if f.challenge.as_ref().is_none_or(|c| c.expires <= now) {
                return Ok(false);
            }
            f.step = AcceptPending;
        }
        _ => return Ok(false),
    }
    Ok(true)
}
pub(super) async fn send(
    state: &AppState,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    f: &mut Flow,
    confirmation: &str,
) -> Result<()> {
    let p = f.prepared.as_ref().ok_or(Error::Refused)?;
    if p.confirmation != confirmation {
        return Err(Error::Refused);
    }
    if p.expires <= now()? {
        prepare(state, store, tx, f, now()?).await?;
        return Ok(());
    }
    if f.step != SendPending {
        return Err(Error::Refused);
    }
    let response = oauth::post(
        &state.issuer,
        f.grant.as_ref().ok_or(Error::Refused)?,
        &p.child,
        f.domain,
        f.invitation,
        oauth::Operation::Challenge(&p.key),
        &json!({"invitationCapability":f.capability}),
    )
    .await;
    if let Ok(r) = response {
        match r.status {
            200 | 201 => {
                let id = uuid(&r.body, "challengeId")?;
                let remaining = integer(&r.body, "remainingChallenges", 0, 5)?;
                let expires = integer(
                    &r.body,
                    "expiresAt",
                    1,
                    p.child.expires_at.min(f.invitation_expiry).min(f.deadline),
                )?;
                let p = f.prepared.take().ok_or(Error::Refused)?;
                f.challenge = Some(Allocated {
                    child: p.child,
                    key: p.key,
                    id,
                    expires,
                    remaining,
                    proof: None,
                });
                f.display = None;
                f.step = ChallengeWaiting;
            }
            409 if r.body["error"] == "display_metadata_unavailable" => {
                f.prepared = None;
                f.step = MetadataUnavailable
            }
            400..=499 => {
                f.prepared = None;
                f.step = SignedIn
            }
            _ => {}
        }
    }
    Ok(())
}
pub(super) async fn verify(
    state: &AppState,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    f: &mut Flow,
    confirmation: Option<&str>,
) -> Result<()> {
    if let Some(value) = confirmation {
        let d = f.display.as_ref().ok_or(Error::Refused)?;
        if !cookies::equal(
            value,
            &store.mac("confirm", &format!("{}:{}", f.handle, d.etag)),
        ) {
            return Err(Error::Refused);
        }
        if f.step != AcceptPending {
            return Err(Error::Refused);
        }
    }
    let c = f.challenge.as_ref().ok_or(Error::Refused)?;
    let proof = c
        .proof
        .as_ref()
        .filter(|l| l.expires_at > now().unwrap_or(i64::MAX))
        .ok_or(Error::Refused)?;
    let fields = json!({"invitationCapability":f.capability,"challengeId":c.id,"challengeCapability":proof.capability});
    let op = if confirmation.is_some() {
        oauth::Operation::Accept(&f.display.as_ref().ok_or(Error::Refused)?.etag)
    } else {
        oauth::Operation::Preview
    };
    let grant = f.grant.as_ref().ok_or(Error::Refused)?;
    let response = oauth::post(
        &state.issuer,
        grant,
        &c.child,
        f.domain,
        f.invitation,
        op,
        &fields,
    )
    .await;
    match response {
        Ok(r) if r.status == 200 && confirmation.is_some() => {
            if uuid(&r.body, "userId")? != grant.user_id
                || f.display
                    .as_ref()
                    .is_none_or(|d| r.body["organizationId"] != d.view["organizationId"])
            {
                return Err(Error::Unavailable);
            }
            f.retire(store, tx).await?;
            f.clear(Complete);
            f.confirmation_until = Some((now()? + 300).min(f.session_until));
        }
        Ok(r) if r.status == 200 => {
            let etag = r
                .etag
                .filter(|t| t.len() == 66 && t.starts_with('"') && t.ends_with('"'))
                .ok_or(Error::Unavailable)?;
            f.display = Some(Display { etag, view: r.body });
            f.step = Confirm
        }
        Ok(r) if r.status == 409 && r.body["error"] == "display_metadata_unavailable" => {
            f.display = None;
            f.step = MetadataUnavailable
        }
        Ok(r) if r.status == 412 => {
            f.display = None;
            f.step = ProofReady
        }
        Ok(r) if (400..500).contains(&r.status) => {
            f.display = None;
            if confirmation.is_some() {
                f.retire(store, tx).await?;
                f.clear(Unconfirmed)
            } else {
                f.step = Expired
            }
        }
        Err(_) | Ok(_) if confirmation.is_some() => {}
        _ => return Err(Error::Unavailable),
    }
    Ok(())
}
