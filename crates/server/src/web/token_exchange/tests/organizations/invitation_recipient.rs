//! Real code redemption/exchange, DPoP, Redis validation and routed recipient API.
//! Initial user login and outbound mail remain explicit fixture suppliers here.
use super::*;
use crate::organizations::{invitations as service, Organization, OrganizationState};
use sha2::{Digest, Sha256};
use std::future::Future;
use uuid::Uuid;

mod delivery;
mod enrollment;
pub(super) mod setup;

const SCOPE: &str = service::recipient::PRIVILEGE;

use crate::organizations::witness::tests::caller_fixture::CallerFixture;

struct RecipientFixture {
    witness: Arc<CallerFixture>,
    base: Fixture,
    state: AppState,
    organization: Organization,
    invitation: Uuid,
    capability: String,
}

impl RecipientFixture {
    async fn finish(self, result: TestResult) -> TestResult {
        let pools = fixture::finish(&self.state).await;
        let witness = Arc::try_unwrap(self.witness).map_err(|_| "retained witness fixture")?;
        let cleanup = witness
            .finish()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
        self.base.cleanup(result.and(pools).and(cleanup)).await
    }

    fn path(&self, operation: &str) -> String {
        format!(
            "/organization-invitations/{}/{}/{operation}",
            self.organization.scope.domain_id, self.invitation
        )
    }

    async fn token(
        &self,
        key: &aegaeon_crypto::signing::Ed25519KeyData,
    ) -> TestResult<(Value, String)> {
        setup::token(self, key).await
    }

    fn proof(
        &self,
        key: &aegaeon_crypto::signing::Ed25519KeyData,
        token: &str,
        path: &str,
    ) -> TestResult<String> {
        crate::web::test_support::native_dpop::proof(
            &self.state,
            key,
            json!({"htm":"POST","htu":format!("{}{path}",self.state.issuer),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
        )
    }

    async fn post(
        &self,
        path: &str,
        token: &str,
        proof: Option<&str>,
        value: &Value,
    ) -> TestResult<(StatusCode, Value)> {
        let mut request = Request::post(path)
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "recipient-challenge");
        if let Some(proof) = proof {
            request = request.header("DPoP", proof);
        }
        let mut request = request.body(Body::from(serde_json::to_vec(value)?))?;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
        let response = crate::web::build_router(self.state.clone())
            .oneshot(request)
            .await?;
        let status = response.status();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        Ok((
            status,
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
        ))
    }

    async fn challenge(
        &self,
        key: &aegaeon_crypto::signing::Ed25519KeyData,
        token: &str,
    ) -> TestResult<(Uuid, String)> {
        let path = self.path("challenges");
        let proof = self.proof(key, token, &path)?;
        let (status, value) = self
            .post(
                &path,
                token,
                Some(&proof),
                &json!({"invitationCapability":self.capability}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value.as_object().ok_or("challenge")?.len(), 1);
        let id = Uuid::parse_str(value["challengeId"].as_str().ok_or("challenge")?)?;
        let mut tx = self.base.pool.begin().await?;
        let delivery = service::claim_challenge_delivery(
            &mut tx,
            self.organization.scope,
            self.invitation,
            id,
            i64::try_from(crate::util::now_unix_epoch_secs()?)?,
        )
        .await?;
        tx.commit().await?;
        assert_eq!(delivery.recipient, "Invitee@example.test");
        Ok((id, delivery.capability.into_delivery()))
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_invitation_recipient_acceptance_and_current_replay(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = f.token(&key).await?;
        let (challenge, secret) = f.challenge(&key, &token).await?;
        let path = f.path("accept");
        let body = json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":secret});
        let signed = f.proof(&key,&token,&path)?;
        let first = f.post(&path,&token,Some(&signed),&body).await?;
        assert_eq!(first.0,StatusCode::OK,"{}",first.1);
        assert_eq!(first.1["organizationId"],f.organization.id.to_string());
        assert_eq!(first.1["userId"],f.base.users[1].to_string());
        assert_eq!(first.1.as_object().ok_or("member")?.len(),4);
        assert_eq!(f.post(&path,&token,Some(&signed),&body).await?.0,StatusCode::UNAUTHORIZED,"same DPoP proof is replay");
        let signed = f.proof(&key,&token,&path)?;
        assert_eq!(f.post(&path,&token,Some(&signed),&body).await?,first);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1").bind(f.organization.id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,1);
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET active=false,revision=revision+1 WHERE environment_id=$1").bind(f.state.environment_id).execute(&f.base.pool).await?;
        let signed=f.proof(&key,&token,&path)?;
        assert_eq!(f.post(&path,&token,Some(&signed),&body).await?.0,StatusCode::FORBIDDEN);
        Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_invitation_recipient_rejects_wrong_scope_key_root_and_subject(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (parent, token) = f.token(&key).await?;
        let path=f.path("challenges");
        let body=json!({"invitationCapability":f.capability});
        let parent=parent["access_token"].as_str().ok_or("parent")?;
        let signed=f.proof(&key,parent,&path)?;
        assert_eq!(f.post(&path,parent,Some(&signed),&body).await?.0,StatusCode::UNAUTHORIZED);
        assert_eq!(f.post(&path,&token,None,&body).await?.0,StatusCode::UNAUTHORIZED);
        let wrong=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let signed=f.proof(&wrong,&token,&path)?;
        assert_eq!(f.post(&path,&token,Some(&signed),&body).await?.0,StatusCode::UNAUTHORIZED);
        for override_claims in [json!({"htm":"GET"}),json!({"htu":format!("{}/other",f.state.issuer)}),json!({"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(b"another-token"))})] {
            let mut claims=json!({"htm":"POST","htu":format!("{}{path}",f.state.issuer),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
            for (key,value) in override_claims.as_object().ok_or("proof overrides")? { claims[key]=value.clone(); }
            let signed=crate::web::test_support::native_dpop::proof(&f.state,&key,claims)?;
            assert_eq!(f.post(&path,&token,Some(&signed),&body).await?.0,StatusCode::UNAUTHORIZED);
        }
        let mut get=Request::get(f.path("accept")).body(Body::empty())?;
        get.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127,0,0,1],12543))));
        assert_eq!(crate::web::build_router(f.state.clone()).oneshot(get).await?.status(),StatusCode::METHOD_NOT_ALLOWED);
        let foreign=format!("/organization-invitations/{}/{}/challenges",Uuid::new_v4(),f.invitation);
        let signed=f.proof(&key,&token,&foreign)?;
        assert!(f.post(&foreign,&token,Some(&signed),&body).await?.0.is_client_error());
        let (challenge,secret)=f.challenge(&key,&token).await?;
        let (_, replacement)=f.token(&key).await?;
        let accept=f.path("accept");
        let body=json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":secret});
        let signed=f.proof(&key,&replacement,&accept)?;
        assert!(f.post(&accept,&replacement,Some(&signed),&body).await?.0.is_client_error(),"a new root cannot consume the earlier recipient proof");
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1").bind(f.base.users[1]).execute(&f.base.pool).await?;
        let signed=f.proof(&key,&token,&accept)?;
        assert_eq!(f.post(&accept,&token,Some(&signed),&body).await?.0,StatusCode::FORBIDDEN);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1").bind(f.organization.id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,0);
        Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_invitation_recipient_rejects_long_lifetime_and_disabled_domain(
) -> TestResult {
    let mut f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        setup::lifetime(&mut f.state, 601).await?;
        let (_,long) = f.token(&key).await?;
        let path = f.path("challenges");
        let body = json!({"invitationCapability":f.capability});
        let proof = f.proof(&key,&long,&path)?;
        assert_eq!(f.post(&path,&long,Some(&proof),&body).await?.0,StatusCode::UNAUTHORIZED);
        setup::lifetime(&mut f.state,300).await?;
        let (_,short) = f.token(&key).await?;
        let proof = f.proof(&key,&short,&path)?;
        let (status,_) = f.post(&path,&short,Some(&proof),&body).await?;
        assert_eq!(status,StatusCode::OK);
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false,revision=revision+1 WHERE id=$1").bind(f.organization.scope.domain_id).execute(&f.base.pool).await?;
        let proof=f.proof(&key,&short,&path)?;
        assert_eq!(f.post(&path,&short,Some(&proof),&body).await?.0,StatusCode::FORBIDDEN);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1").bind(f.organization.id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,0);
        Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_identity_resume_requires_new_recipient_authentication(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = f.token(&key).await?;
        for status in ["SUSPENDED", "ACTIVE"] {
            sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status WHERE id=$1")
                .bind(f.base.users[1]).bind(status).execute(&f.base.pool).await?;
        }
        let path = f.path("challenges");
        let proof = f.proof(&key, &token, &path)?;
        let (status, _) = f.post(&path, &token, Some(&proof), &json!({"invitationCapability":f.capability})).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let challenges:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitation_challenges WHERE invitation_id=$1")
            .bind(f.invitation).fetch_one(&f.base.pool).await?;
        assert_eq!(challenges,0);
        // Original token metadata stays old across exchanges. A new issuer
        // authentication in a later second can request the address challenge.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let (_, fresh) = f.token(&key).await?;
        f.challenge(&key, &fresh).await?;
        Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}
// Fixture operations use the same live epoch across issuance and each caller.
// This is explicit actual-store admission, not serialized authority or recovery.
async fn in_epoch<T>(
    witness: &CallerFixture,
    future: impl std::future::Future<Output = TestResult<T>>,
) -> TestResult<T> {
    let work = witness.begin().await?;
    let result = {
        let mut running = Box::pin(work.store_scope(future));
        std::future::poll_fn(|context| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                running.as_mut().poll(context)
            })) {
                Ok(value) => value.map(Ok),
                Err(_) => std::task::Poll::Ready(Err("recipient fixture assertion failed")),
            }
        })
        .await
    };
    let completion = work.complete().await;
    let result = result??;
    completion?;
    result
}
