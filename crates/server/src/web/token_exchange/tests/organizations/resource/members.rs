use super::*;
use uuid::Uuid;

mod invitations;
mod mutations;

const READ: &str = "organization.members.read";
const MANAGE: &str = "organization.members.manage";

async fn setup_members(f: &Fixture) -> TestResult<AppState> {
    let state = setup(f).await?;
    let audience = format!("{}/organizations", state.issuer);
    let mut tx = f.pool.begin().await?;
    crate::organizations::repository::lock_domain(&mut tx, f.organization.scope).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=$1,revision=revision+1 WHERE environment_id=$2")
        .bind(json!([{"audience":audience,"privileges":[PRIVILEGE,READ,MANAGE]}])).bind(state.environment_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.organization_role_definitions SET privileges=privileges || $1::jsonb,version=version+1,manages_members=true,assignable_roles='[\"admin\",\"reader\"]' WHERE environment_id=$2 AND role_key='reader'")
        .bind(json!([READ,MANAGE])).bind(state.environment_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(state)
}

struct MemberClient<'a> {
    app: Option<axum::Router>,
    state: &'a AppState,
    key: &'a aegaeon_crypto::signing::Ed25519KeyData,
    read: String,
    write: String,
    list: String,
}

impl<'a> MemberClient<'a> {
    async fn new(
        f: &Fixture,
        state: &'a AppState,
        key: &'a aegaeon_crypto::signing::Ed25519KeyData,
    ) -> TestResult<Self> {
        let (_, read) = issue(f, state, key, READ).await?;
        let (_, write) = issue(f, state, key, MANAGE).await?;
        Ok(Self {
            app: None,
            state,
            key,
            read,
            write,
            list: format!("/organizations/{}/members", f.organization.id),
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        etag: Option<&str>,
        receipt: Option<&str>,
        body: &str,
    ) -> TestResult<(StatusCode, Value, Option<String>)> {
        let htu = format!(
            "{}{}",
            self.state.issuer,
            path.split('?').next().ok_or("path")?
        );
        let signed = proof(
            self.state,
            self.key,
            token,
            method.as_str(),
            json!({"htu":htu}),
        )?;
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", signed)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(etag) = etag {
            request = request.header(header::IF_MATCH, etag);
        }
        if let Some(key) = receipt {
            request = request.header("idempotency-key", key);
        }
        let mut request = request.body(Body::from(body.to_owned()))?;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
        let response = self
            .app
            .clone()
            .unwrap_or_else(|| crate::web::build_router(self.state.clone()))
            .oneshot(request)
            .await?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        if status.is_client_error() {
            assert!(response.headers()[header::WWW_AUTHENTICATE]
                .to_str()?
                .starts_with("DPoP"));
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .map(|s| s.to_str().map(str::to_owned))
            .transpose()?;
        let bytes = to_bytes(response.into_body(), 65536).await?;
        let body = if method == Method::HEAD {
            assert!(bytes.is_empty());
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, body, etag))
    }

    async fn get(&self, path: &str) -> TestResult<(StatusCode, Value, Option<String>)> {
        self.request(Method::GET, path, &self.read, None, None, "")
            .await
    }

    async fn put(
        &self,
        path: &str,
        tag: &str,
        key: &str,
        body: &str,
    ) -> TestResult<(StatusCode, Value, Option<String>)> {
        self.request(Method::PUT, path, &self.write, Some(tag), Some(key), body)
            .await
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_members_read_scoped_cursor_and_primary_failure() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup_members(&f).await?;
    let result = f.in_epoch(Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let client = MemberClient::new(&f, &state, &key).await?;
        let (status, page, _) = client.get(&format!("{}?limit=1", client.list)).await?;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["members"].as_array().ok_or("members")?.len(), 1);
        let cursor = page["nextCursor"].as_str().ok_or("cursor")?;
        let (status, next, _) = client.get(&format!("{}?limit=1&after={cursor}", client.list)).await?;
        assert_eq!(status, StatusCode::OK, "{next}");
        assert_ne!(page["members"][0]["userId"], next["members"][0]["userId"]);
        assert!(next["nextCursor"].is_null());
        for user in f.users {
            let path = format!("{}/{user}", client.list);
            let (status, value, etag) = client.get(&path).await?;
            assert_eq!(status, StatusCode::OK, "{value}");
            assert_eq!(value["organizationIdentifier"], IDENTIFIER);
            assert_eq!(value["organizationId"], f.organization.id.to_string());
            assert_eq!(value["userId"], user.to_string());
            assert_eq!(value.as_object().ok_or("member")?.len(), 7);
            assert!(etag.is_some());
            assert_eq!(client.request(Method::HEAD, &path, &client.read, None, None, "").await?.0, StatusCode::OK);
        }
        let mut bytes: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor)?)?;
        for index in 0..5 {
            let old = bytes[1][index].clone();
            bytes[1][index] = json!(Uuid::new_v4());
            let bad = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&bytes)?);
            assert_eq!(client.get(&format!("{}?after={bad}", client.list)).await?.0, StatusCode::BAD_REQUEST);
            bytes[1][index] = old;
        }
        for query in ["limit=0", "limit=101", "limit=01", "limit=1&limit=2", "after=x&after=y", "unknown=1", "after=", "access_token=forbidden"] {
            assert_eq!(client.get(&format!("{}?{query}", client.list)).await?.0, StatusCode::BAD_REQUEST, "{query}");
        }
        // A real foreign row distinguishes authorization from missing-object refusal.
        let foreign = Uuid::new_v4();
        let mut tx = f.pool.begin().await?;
        crate::organizations::repository::lock_domain(&mut tx, f.organization.scope).await?;
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES ($1,$2,$3,'foreign-existing','active')")
            .bind(foreign).bind(state.environment_id).bind(f.organization.scope.domain_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES ($1,$2,$3,$4,$5,'active','[\"reader\"]')")
            .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(foreign).bind(f.users[0]).bind(Uuid::new_v4()).execute(&mut *tx).await?;
        tx.commit().await?;
        for path in [format!("/organizations/{foreign}/members"), format!("/organizations/{foreign}/members/{}", f.users[0])] {
            assert_eq!(client.get(&path).await?.0, StatusCode::FORBIDDEN);
        }
        assert_eq!(client.get(&format!("/organizations/{}/members", Uuid::new_v4())).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(client.request(Method::GET, &client.list, &client.write, None, None, "").await?.0, StatusCode::FORBIDDEN);
        let mut unavailable = state.clone();
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new().connect_with(f.pool.connect_options().as_ref().clone()).await?;
        unavailable.validate_subject_namespace().await?;
        unavailable.db_pool.close().await;
        let failed = MemberClient { app: None, state: &unavailable, key: &key, read: client.read.clone(), write: client.write.clone(), list: client.list.clone() };
        assert_eq!(failed.get(&client.list).await?.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(client.get(&client.list).await?.0, StatusCode::OK);
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=version+1 WHERE environment_id=$1 AND role_key='reader'").bind(state.environment_id).execute(&f.pool).await?;
        assert_eq!(client.get(&client.list).await?.0, StatusCode::UNAUTHORIZED, "changed original role requires new consent");
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
