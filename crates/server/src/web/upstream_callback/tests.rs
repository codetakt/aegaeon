//! Signed ID Tokens through the real callback persistence transaction and session step.
use super::*;
use crate::upstream::{
    UpstreamJitProvisioningCollisionPolicy as Collision,
    UpstreamJitProvisioningInitialStatus as Initial, UpstreamJitProvisioningPolicy,
};
use crate::web::upstream_callback_exchange::UpstreamCallbackExchange;
use crate::web::upstream_id_token::{decode_upstream_id_token, UpstreamIdTokenDecodeInput};
use crate::web::{test_support::*, upstream_tests};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{error::Error, time::Duration};
use uuid::Uuid;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;
mod cases;
mod reservations;

struct Fixture {
    pool: PgPool,
    env: TestEnvironment,
    state: AppState,
    request: UpstreamAuthRequest,
    key: crate::oidc::OidcSigningKey,
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let env = setup_test_environment(&pool).await?;
        let version: Uuid = sqlx::query_scalar(
            "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        let conn: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,'jit-test','jit-test','https://issuer.example','client','none','ACTIVE') RETURNING id").bind(env.environment_id).bind(version).fetch_one(&pool).await?;
        let state = test_app_state(pool.clone(), &env).await?;
        let mut request = upstream_tests::make_auth_request("jit-context", Duration::from_secs(60));
        request.context = crate::upstream::UpstreamConnectionContext::new(
            conn,
            env.team_id,
            env.tenant_id,
            env.environment_id,
            version,
        );
        request.jit_provisioning_policy = Some(UpstreamJitProvisioningPolicy {
            enabled: true,
            require_verified_email: false,
            domain_allowlist: vec![],
            collision_policy: Collision::RejectExistingEmail,
            initial_status: Initial::Active,
        });
        request.attribute_mappings = vec![crate::upstream::UpstreamAttributeMapping {
            from: "name".into(),
            target: crate::upstream::UpstreamAttributeMappingTarget::DisplayName,
            rule: crate::upstream::UpstreamAttributeMappingRule::Copy,
        }];
        let key = crate::oidc::OidcSigningKey::from_rsa_pem(
            "jit-test".into(),
            include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem"),
        )?;
        Ok(Self {
            pool,
            env,
            state,
            request,
            key,
        })
    }
    async fn with_issuer(&self, issuer: &str) -> TestResult<UpstreamAuthRequest> {
        let mut request = self.request.clone();
        let c = request.managed_connection_context();
        let conn:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,$3,'jit-test',$4,'client','none','ACTIVE') RETURNING id").bind(c.environment_id).bind(c.configuration_version_id).bind(Uuid::new_v4().to_string()).bind(issuer).fetch_one(&self.pool).await?;
        request.context = crate::upstream::UpstreamConnectionContext::new(
            conn,
            c.team_id,
            c.tenant_id,
            c.environment_id,
            c.configuration_version_id,
        );
        request.issuer = issuer.into();
        Ok(request)
    }
    fn exchange(
        &self,
        request: &UpstreamAuthRequest,
        sub: &str,
        email: Option<&str>,
    ) -> TestResult<UpstreamCallbackExchange> {
        let now = now_epoch_secs()?;
        let mut claims = json!({"iss":request.issuer,"sub":sub,"aud":"client","iat":now,"exp":now+3600,"auth_time":now-30,"nonce":"nonce","name":"Projected Name"});
        if let Some(email) = email {
            claims["email"] = json!(email);
            claims["email_verified"] = json!(true);
        }
        let raw = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::RS256,
                kid: Some(self.key.kid().into()),
                ..Default::default()
            },
            &claims,
            self.key.local_encoding_key().ok_or("encoding key")?,
        )?;
        let jwks = aegaeon_jose::jwk::JwkSet::from_value(serde_json::to_value(self.key.jwks())?)?;
        let discovery = upstream_tests::base_discovery(&request.issuer)?;
        let id_token = decode_upstream_id_token(UpstreamIdTokenDecodeInput {
            token: &raw,
            jwks: &jwks,
            discovery: &discovery,
            request,
            access_token: Some("access-token"),
            code: "code",
            jwt_leeway_secs: 60,
            jose_header_max_len: self.state.cfg.jose_header_max_len,
        })
        .map_err(|e| e.message)?;
        Ok(UpstreamCallbackExchange {
            discovery,
            token_response: crate::web::upstream_token_response::UpstreamTokenResponse {
                id_token: Some(raw),
                access_token: Some("access-token".into()),
                token_type: Some("Bearer".into()),
                expires_in: Some(3600),
                refresh_token: None,
            },
            id_token,
            upstream_sub_hash: crate::upstream::upstream_subject_link_hash(&request.issuer, sub),
        })
    }
    async fn callback(
        &self,
        request: &UpstreamAuthRequest,
        sub: &str,
        email: Option<&str>,
    ) -> TestResult<Response> {
        Ok(persist_bound_upstream_callback(
            &self.state,
            request,
            &self.exchange(request, sub, email)?,
            "jit-test",
        )
        .await)
    }
    async fn local(&self, subject: &str, email: Option<&str>) -> TestResult<Uuid> {
        Ok(sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,email,status) VALUES($1,$2,$3,'ACTIVE') RETURNING id").bind(self.env.environment_id).bind(subject).bind(email).fetch_one(&self.pool).await?)
    }
    async fn snapshot(&self) -> TestResult<Value> {
        let mut all = Vec::new();
        for table in ["end_users", "account_links", "audit_events"] {
            let sql=format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1");
            all.push(
                sqlx::query_scalar::<_, Value>(&sql)
                    .bind(self.env.environment_id)
                    .fetch_one(&self.pool)
                    .await?,
            );
        }
        all.push(sqlx::query_scalar::<_,Value>("SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.end_user_id),'[]'::jsonb) FROM aegaeon.end_user_profiles p JOIN aegaeon.end_users u ON u.id=p.end_user_id WHERE u.environment_id=$1").bind(self.env.environment_id).fetch_one(&self.pool).await?);
        all.push(sqlx::query_scalar::<_,Value>("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.subject),'[]'::jsonb) FROM aegaeon.upstream_subject_reservations r WHERE environment_id=$1").bind(self.env.environment_id).fetch_one(&self.pool).await?);
        Ok(json!(all))
    }
    async fn owner(
        &self,
        request: &UpstreamAuthRequest,
        sub: &str,
    ) -> TestResult<(Uuid, String, String, i64)> {
        let row=sqlx::query("SELECT u.id,u.subject,al.binding_provenance,al.binding_revision FROM aegaeon.account_links al JOIN aegaeon.end_users u ON u.id=al.end_user_id WHERE al.environment_id=$1 AND al.upstream_issuer=$2 AND al.upstream_sub_hash=$3").bind(self.env.environment_id).bind(&request.issuer).bind(crate::upstream::upstream_subject_link_hash(&request.issuer,sub)).fetch_one(&self.pool).await?;
        Ok((
            row.try_get(0)?,
            row.try_get(1)?,
            row.try_get(2)?,
            row.try_get(3)?,
        ))
    }
    async fn rejected(
        &self,
        request: &UpstreamAuthRequest,
        sub: &str,
        email: Option<&str>,
    ) -> TestResult {
        let before = self.snapshot().await?;
        let mut exchange = self.exchange(request, sub, email)?;
        // A refused callback must never reach refresh encryption/persistence.
        exchange.token_response.refresh_token = Some("must-not-be-stored".into());
        let response =
            persist_bound_upstream_callback(&self.state, request, &exchange, "jit-test-refusal")
                .await;
        assert!(response.status().is_client_error() || response.status().is_server_error());
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(
            self.snapshot().await?,
            before,
            "refusal changed persistent identity/profile/refresh/audit state"
        );
        Ok(())
    }
    async fn success_subject(&self, response: Response) -> TestResult<String> {
        assert!(response.status().is_redirection(), "{}", response.status());
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("session cookie")?
            .to_str()?;
        let sid = cookie
            .split(';')
            .next()
            .ok_or("cookie value")?
            .split_once('=')
            .ok_or("cookie pair")?
            .1;
        let session = self
            .state
            .browser_auth
            .auth_sessions
            .try_get_async(sid.into())
            .await?
            .ok_or("persisted browser session")?;
        Ok(session.user_id)
    }
    async fn cleanup(&self) -> TestResult {
        sqlx::query("DELETE FROM aegaeon.account_links WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM aegaeon.connections WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        cleanup_test_environment(&self.pool, &self.env).await?;
        Ok(())
    }
}
