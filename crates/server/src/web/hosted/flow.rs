use super::*;
use crate::organizations::invitations::enrollment::Purpose;
use hosted_page::MailLink;
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Generation {
    pub deployment: Uuid,
    pub generation: Uuid,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Step {
    Invitation,
    LoginUnavailable,
    IdentityWaiting,
    IdentityReady,
    SignedIn,
    SendReady,
    SendPending,
    ChallengeWaiting,
    ProofReady,
    Confirm,
    AcceptPending,
    MetadataUnavailable,
    Exhausted,
    Expired,
    Restart,
    Complete,
    Unconfirmed,
    Closed,
}
use Step::*;

#[derive(Serialize, Deserialize)]
pub(super) struct Preparation {
    pub child: oauth::Recipient,
    pub key: String,
    pub confirmation: String,
    pub remaining: i64,
    pub expires: i64,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Allocated {
    pub child: oauth::Recipient,
    pub key: String,
    pub id: Uuid,
    pub expires: i64,
    pub remaining: i64,
    pub proof: Option<MailLink>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Identity {
    pub request: Uuid,
    pub purpose: crate::organizations::invitations::enrollment::Purpose,
    pub proof: Option<MailLink>,
    pub until: i64,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Display {
    pub etag: String,
    pub view: Value,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Flow {
    pub id: Uuid,
    pub browser: String,
    pub domain: Uuid,
    pub invitation: Uuid,
    pub generation: Generation,
    pub client: Uuid,
    pub handle: Uuid,
    pub session: Option<String>,
    pub session_subject: Option<String>,
    pub deadline: i64,
    pub invitation_expiry: i64,
    pub delivery_revision: i64,
    pub proof_tag: String,
    pub capability: Option<String>,
    pub return_url: Option<String>,
    pub step: Step,
    pub can_register: bool,
    pub can_recover: bool,
    pub identity_version: u32,
    pub identity: Option<Identity>,
    pub expected_subject: Option<(String, i64)>,
    pub authorization: Option<oauth::Authorization>,
    pub grant: Option<oauth::Grant>,
    pub prepared: Option<Preparation>,
    pub challenge: Option<Allocated>,
    pub display: Option<Display>,
    pub confirmation_until: Option<i64>,
    pub session_until: i64,
}
impl Flow {
    pub fn start(
        browser: &str,
        generation: Generation,
        client: Uuid,
        link: MailLink,
        return_url: Option<String>,
        now: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            browser: browser.into(),
            domain: link.domain_id,
            invitation: link.invitation_id,
            generation,
            client,
            handle: Uuid::new_v4(),
            session: None,
            session_subject: None,
            deadline: link.expires_at.min(now + 1800),
            invitation_expiry: link.expires_at,
            delivery_revision: link.delivery_revision,
            proof_tag: store::hash(&link.capability),
            capability: Some(link.capability),
            return_url,
            step: Invitation,
            can_register: false,
            can_recover: false,
            identity_version: 0,
            identity: None,
            expected_subject: None,
            authorization: None,
            grant: None,
            prepared: None,
            challenge: None,
            display: None,
            confirmation_until: None,
            session_until: 0,
        }
    }
    pub fn purge_at(&self) -> i64 {
        if self.step == Complete {
            return self.confirmation_until.unwrap_or(self.deadline);
        }
        // Closed records need only a short tombstone for explicit restart.
        if self.step == Closed || self.step == Unconfirmed {
            return self.invitation_expiry;
        }
        let mut next = self.deadline;
        if self.session.is_some() {
            next = next.min(self.session_until);
        }
        for expiry in [
            self.identity.as_ref().map(|i| i.until),
            self.challenge.as_ref().map(|c| c.expires),
            self.prepared.as_ref().map(|p| p.expires),
        ]
        .into_iter()
        .flatten()
        {
            next = next.min(expiry)
        }
        next
    }
    pub fn csrf(&self, store: &Store) -> String {
        store.mac("flow", &format!("{}:{}", self.browser, self.handle))
    }
    pub fn bound(
        &self,
        current: &Generation,
        browser: &str,
        headers: &HeaderMap,
        clock: i64,
    ) -> Result<()> {
        if self.browser != browser || &self.generation != current {
            return Err(Error::Refused);
        }
        if self.session.is_some() != self.session_subject.is_some()
            || self
                .grant
                .as_ref()
                .is_some_and(|g| Some(&g.subject) != self.session_subject.as_ref())
        {
            return Err(Error::Refused);
        }
        if let Some(expected) = &self.session {
            let token =
                cookies::cookie(headers, &cookies::session(self.id)).ok_or(Error::Refused)?;
            if !cookies::equal(&store::hash(token), expected) || clock >= self.session_until {
                return Err(Error::Refused);
            }
        }
        Ok(())
    }
    pub fn expire_interactive(&mut self, now: i64) {
        if matches!(self.step, Complete | Closed | Unconfirmed) {
            return;
        }
        if now >= self.deadline {
            self.clear(if self.step == AcceptPending {
                Unconfirmed
            } else {
                Closed
            });
            self.session = None;
            self.session_subject = None;
            return;
        }
        if self.identity.as_ref().is_some_and(|i| i.until <= now) {
            self.identity = None;
            self.identity_version = self.identity_version.saturating_add(1);
            if matches!(self.step, IdentityReady | IdentityWaiting) {
                self.step = Invitation
            }
        }
        if self.challenge.as_ref().is_some_and(|c| now >= c.expires) {
            self.challenge = None;
            self.display = None;
            if matches!(
                self.step,
                Confirm | ProofReady | ChallengeWaiting | MetadataUnavailable | AcceptPending
            ) {
                self.step = if self.step == AcceptPending {
                    Unconfirmed
                } else {
                    Expired
                };
            }
        }
        if self.prepared.as_ref().is_some_and(|p| now >= p.expires) {
            self.prepared = None;
            if matches!(self.step, SendReady | SendPending) {
                self.step = Expired
            }
        }
    }
    pub async fn finish_interaction(
        &mut self,
        store: &Store,
        tx: &mut PgTransaction<'_>,
        clock: i64,
    ) -> Result<()> {
        self.expire_interactive(clock);
        if self.step == Unconfirmed && self.grant.is_some() {
            self.retire(store, tx).await?;
            self.clear(Unconfirmed);
        }
        Ok(())
    }
    pub fn clear(&mut self, step: Step) {
        self.capability = None;
        self.identity = None;
        self.expected_subject = None;
        self.authorization = None;
        self.grant = None;
        self.prepared = None;
        self.challenge = None;
        self.display = None;
        self.step = step;
    }
    pub async fn retire(&mut self, store: &Store, tx: &mut PgTransaction<'_>) -> Result<()> {
        if let Some(grant) = self.grant.take() {
            store.cleanup(tx, self.domain, &grant.cleanup).await?
        }
        self.prepared = None;
        self.challenge = None;
        self.display = None;
        self.authorization = None;
        Ok(())
    }
    pub fn allows_identity_request(&self, purpose: Purpose) -> bool {
        self.step == Invitation
            && self.authorization.is_none()
            && self.session.is_none()
            && match purpose {
                Purpose::Registration => self.can_register,
                Purpose::PasswordRecovery => self.can_recover,
            }
    }
    pub fn view(&self, store: &Store, clock: i64) -> Value {
        let mut v = json!({"step":self.step,"flow":self.handle,"csrfToken":self.csrf(store)});
        if self.step == Complete && self.confirmation_until.is_none_or(|u| u <= clock) {
            v["step"] = json!(Closed);
            return v;
        }
        if matches!(self.step, Invitation) {
            v["signInPending"] = json!(self.authorization.is_some());
            v["canRegister"] = json!(self.allows_identity_request(Purpose::Registration));
            v["canRecover"] = json!(self.allows_identity_request(Purpose::PasswordRecovery));
        }
        if let Some(g) = &self.grant {
            v["account"] = json!({"identifier":g.account,"subject":g.subject})
        }
        if let Some(c) = &self.challenge {
            v["expiresAt"] = json!(c.expires);
            v["remainingChallenges"] = json!(c.remaining)
        }
        if let Some(p) = &self.prepared {
            if matches!(self.step, SendReady | SendPending) {
                v["expiresAt"] = json!(p.expires);
                v["remainingChallenges"] = json!(p.remaining);
                v["confirmation"] = json!(p.confirmation)
            }
        }
        if let Some(d) = &self.display {
            if matches!(self.step, Confirm | AcceptPending) {
                v["confirmation"] =
                    json!(store.mac("confirm", &format!("{}:{}", self.handle, d.etag)));
                if self.step == Confirm {
                    v["preview"] = d.view.clone();
                }
            }
        }
        if self.step == Complete {
            v["canReturn"] = json!(self.return_url.is_some())
        }
        v
    }
}
