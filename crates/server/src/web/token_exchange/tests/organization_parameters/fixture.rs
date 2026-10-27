use super::reader_contract::ReaderContract;
use super::*;
use crate::application_authorization::{inorii::Grant, store::capture, Authority};

pub(super) struct Membership {
    pub pool: PgPool,
    pub schema: String,
    reader: ReaderContract,
}

impl Membership {
    pub async fn create(admin: &PgPool) -> TestResult<Self> {
        let reader = ReaderContract::load()?;
        let ddl = reader.fixture_ddl()?;
        let schema = format!("token_selector_{}", uuid::Uuid::new_v4().simple());
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(admin)
            .await?;
        let result = async {
            let search_path = format!("{schema},pg_catalog");
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect_with(
                    admin
                        .connect_options()
                        .as_ref()
                        .clone()
                        .options([("search_path", search_path)]),
                )
                .await?;
            sqlx::raw_sql(&ddl).execute(&pool).await?;
            Ok(pool)
        }
        .await;
        match result {
            Ok(pool) => Ok(Self {
                pool,
                schema,
                reader,
            }),
            Err(error) => {
                let cleanup = sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
                    .execute(admin)
                    .await;
                finish_test(Err(error), cleanup.map(|_| ()))?;
                unreachable!()
            }
        }
    }

    pub async fn restore(&self, issuer: &str) -> TestResult {
        sqlx::raw_sql("TRUNCATE authorization_subject_bindings, organization_users, organizations;
            INSERT INTO organizations (id,public_id,deleted_at) VALUES (1,'00000000-0000-4000-8000-000000000001',NULL), (2,'00000000-0000-4000-8000-000000000002',NULL)")
            .execute(&self.pool).await?;
        let [admin_role, staff_role] = self.reader.role_labels()?;
        sqlx::query("INSERT INTO organization_users (user_id,organization_id,role,status) VALUES (7,1,$1,$3),(7,2,$2,$3)")
            .bind(admin_role).bind(staff_role).bind(self.reader.active_status())
            .execute(&self.pool).await?;
        sqlx::query("INSERT INTO authorization_subject_bindings (issuer,subject,user_id) VALUES ($1,'exchange-user',7)")
            .bind(issuer)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn restore_complementary_bindings(&self, issuer: &str) -> TestResult {
        self.restore(issuer).await?;
        let [admin_role, staff_role] = self.reader.role_labels()?;
        sqlx::query("INSERT INTO organization_users (user_id,organization_id,role,status) VALUES (8,1,$1,$3),(8,2,$2,$3)")
            .bind(staff_role).bind(admin_role).bind(self.reader.active_status())
            .execute(&self.pool).await?;
        sqlx::query("INSERT INTO authorization_subject_bindings (issuer,subject,user_id) VALUES ($1,'exchange-user',8)")
            .bind(issuer).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn finish(self, admin: &PgPool, result: TestResult) -> TestResult {
        self.pool.close().await;
        finish_test(
            result,
            sqlx::raw_sql(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(admin)
                .await
                .map(|_| ()),
        )
    }
}

pub(super) async fn state_with_projection(
    pool: &PgPool,
    env: &TestEnvironment,
    membership: &Membership,
    organizations: bool,
) -> TestResult<(AppState, Grant)> {
    let claims = json!({"roles":["USER","SUPER_ADMIN"],"organization_roles":if organizations {
        json!([{"organization_id":ORG_A,"roles":["ORGANIZATION_ADMIN"]},{"organization_id":ORG_B,"roles":["ORGANIZATION_STAFF"]}])
    } else { json!([]) }});
    state_with_projection_claims(pool, env, membership, claims).await
}

pub(super) async fn state_with_projection_claims(
    pool: &PgPool,
    env: &TestEnvironment,
    membership: &Membership,
    claims: Value,
) -> TestResult<(AppState, Grant)> {
    let mut state = fixture(pool, env).await?;
    state.application_authority = Some(Authority {
        projections: pool.clone(),
        memberships: Some(membership.pool.clone()),
    });
    membership.restore(&env.issuer_url).await?;
    seed_test_projection(
        pool,
        env,
        CLIENT,
        "exchange-user",
        json!([format!("{}/userinfo", state.issuer), "internal-api"]),
        claims,
    )
    .await?;
    let grant = capture(
        pool,
        env.environment_id,
        &env.issuer_url,
        CLIENT,
        "exchange-user",
    )
    .await?
    .ok_or("projection missing")?;
    Ok((state, grant))
}

pub(super) fn projected_code(state: &AppState, grant: &Grant) -> TestResult<String> {
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback","resource":format!("{}/userinfo",state.issuer),
        "scope":SOURCE_SCOPE,"state":uuid::Uuid::new_v4().to_string(),
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    let client = state.clients.try_get(CLIENT)?.ok_or("client")?;
    Ok(state
        .tokens
        .issuer
        .issue_authorization_code_with_local_profile(
            crate::authcode::AuthorizationCodeIssueInput {
                application_grant: Some(grant.clone()),
                exchange_scope_ceiling: client.allowed_scopes,
                ..crate::authcode::AuthorizationCodeIssueInput::new(
                    req,
                    "exchange-user".into(),
                    true,
                    0,
                )
            },
        )?
        .0)
}

pub(super) async fn send(
    state: &AppState,
    body: String,
    valid_auth: bool,
) -> TestResult<(StatusCode, Value)> {
    let app = Router::new()
        .route("/token", post(crate::web::token_endpoint::token))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12453,
        )))))
        .with_state(state.clone());
    let secret = if valid_auth { SECRET } else { "wrong-secret" };
    let response = app
        .oneshot(
            Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{secret}"))),
                )
                .body(Body::from(body))?,
        )
        .await?;
    check!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            == Some("no-store")
    );
    check!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|v| v.to_str().ok())
            == Some("no-cache")
    );
    Ok((
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?,
    ))
}

pub(super) fn code_body(code: &str) -> TestResult<String> {
    Ok(serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", CLIENT),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_verifier", VERIFIER),
    ])?)
}

pub(super) async fn exchange_raw(
    state: &AppState,
    token: &str,
    suffix: &str,
) -> TestResult<(StatusCode, Value)> {
    let body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", token),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", "internal-api"),
    ])?;
    send(state, format!("{body}{suffix}"), true).await
}

pub(super) fn output(
    state: &AppState,
    body: &Value,
    expected: Option<&Grant>,
    audience: &str,
    scope: &str,
) -> TestResult<String> {
    let token = body["access_token"]
        .as_str()
        .ok_or("access token missing")?;
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(token)?
        .ok_or("output metadata")?;
    check!(meta.application_grant.as_ref() == expected);
    check!(meta.audience == audience);
    check!(
        meta.granted_scopes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == scope.split(' ').collect::<std::collections::BTreeSet<_>>()
    );
    check!(body["scope"] == scope);
    let claims = jwt(body)?;
    check!(claims["aud"] == audience);
    check!(claims["scope"] == scope);
    let name = crate::application_authorization::inorii::CLAIM_NAME;
    if let Some(grant) = expected {
        check!(claims[name] == serde_json::to_value(&grant.claims)?);
    } else {
        check!(claims.get(name).is_none());
    }
    Ok(token.to_owned())
}
