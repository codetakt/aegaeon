//! Bounded fixed-template delivery. Never return provider bodies or URL errors.
use super::{
    worker::{Claim, Outcome},
    Delivery,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use std::{sync::Arc, time::Duration};

pub(crate) struct Credential(String);
impl Credential {
    pub(crate) fn parse(value: String) -> Result<Self, ()> {
        if value.len() != 43 {
            return Err(());
        }
        let decoded = URL_SAFE_NO_PAD.decode(&value).map_err(|_| ())?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(());
        }
        Ok(Self(value))
    }
    pub(crate) fn digest(&self) -> String {
        crate::subject_ownership::history::sha256_hex(self.0.as_bytes())
    }
}

#[cfg(test)]
pub(crate) mod fixture;

pub(crate) fn client() -> Result<reqwest::Client, ()> {
    let builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    #[cfg(test)]
    let builder = fixture::configure(builder);
    builder.build().map_err(|_| ())
}

pub(crate) async fn send(
    client: &reqwest::Client,
    claim: &Claim,
    delivery: Delivery,
    credential: &Credential,
    issuer: &str,
) -> Outcome {
    send_envelope(
        client,
        claim.endpoint(),
        envelope(
            claim.scope,
            claim.invitation,
            claim.revision,
            delivery,
            issuer,
        ),
        credential,
    )
    .await
}

pub(crate) async fn send_identity(
    client: &reqwest::Client,
    claim: &super::enrollment::delivery::Claim,
    delivery: Delivery,
    credential: &Credential,
    issuer: &str,
) -> Outcome {
    send_envelope(
        client,
        claim.endpoint(),
        envelope(
            claim.scope,
            claim.invitation,
            claim.revision,
            delivery,
            issuer,
        ),
        credential,
    )
    .await
}

fn envelope(
    scope: crate::organizations::Scope,
    invitation: uuid::Uuid,
    revision: i64,
    delivery: Delivery,
    issuer: &str,
) -> serde_json::Value {
    let template = match delivery.purpose {
        super::cap::Purpose::Invitation => "organization_invitation",
        super::cap::Purpose::RecipientChallenge => "organization_recipient_challenge",
        super::cap::Purpose::IdentityRegistration => "organization_identity_registration",
        super::cap::Purpose::IdentityRecovery => "organization_identity_recovery",
    };
    let body = serde_json::json!({"version":1,"template":template,"recipient":delivery.recipient,
        "issuer":issuer,"environmentId":scope.environment_id,"domainId":scope.domain_id,
        "invitationId":invitation,"objectId":delivery.object_id,"deliveryRevision":revision,
        "capability":delivery.capability.into_delivery(),"expiresAt":delivery.expires_at});
    body
}

async fn send_envelope(
    client: &reqwest::Client,
    endpoint: &str,
    body: serde_json::Value,
    credential: &Credential,
) -> Outcome {
    let Ok(bytes) = serde_json::to_vec(&body) else {
        return Outcome::Uncertain;
    };
    if bytes.len() > 8192 {
        return Outcome::Uncertain;
    }
    let Ok(mut authorization) = HeaderValue::from_str(&format!("Bearer {}", credential.0)) else {
        return Outcome::Uncertain;
    };
    authorization.set_sensitive(true);
    match tokio::time::timeout(Duration::from_secs(10), async {
        let mut response = client
            .post(endpoint)
            .header(AUTHORIZATION, authorization)
            .header("content-type", "application/json")
            .body(bytes)
            .send()
            .await
            .map_err(|_| ())?;
        let status = response.status().as_u16();
        let mut size = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            size = size.checked_add(chunk.len()).ok_or(())?;
            if size > 1024 {
                return Err(());
            }
        }
        Ok(if status == 204 && size == 0 {
            Outcome::Acknowledged
        } else if (400..500).contains(&status) && !matches!(status, 408 | 429) {
            Outcome::Rejected
        } else {
            Outcome::Uncertain
        })
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        _ => Outcome::Uncertain,
    }
}
