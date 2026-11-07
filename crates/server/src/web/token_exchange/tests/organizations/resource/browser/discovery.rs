//! Mounted browser selection, distinct discovery resource and existing exchange path.
use super::*;
use crate::organizations::selection::{DISCOVERY_SCOPE, TYPE};

mod bounds;
mod concurrency;
mod request_objects;
mod roleless;

async fn configured_discovery(f: &Fixture) -> TestResult<AppState> {
    let mut state = configured(f).await?;
    crate::web::test_support::update_test_policy(&mut state, |policy| {
        policy
            .authorization_details_types_supported
            .push(TYPE.into());
    })
    .await?;
    let discovery = format!("{}/organization-discovery", state.issuer);
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management,membership_discovery) VALUES($1,$2,$3,false,true)")
        .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(&discovery).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=array_append(allowed_scopes,$1) WHERE environment_id=$2 AND client_identifier=$3")
        .bind(DISCOVERY_SCOPE).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2 AND client_identifier=$3")
        .bind(json!([{"audience":discovery,"privileges":[DISCOVERY_SCOPE]}])).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
    Ok(state)
}

fn selector_uri(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let ordinary = authorize(state, key)?;
    let mut fields: Vec<(String, String)> =
        serde_urlencoded::from_str(ordinary.split_once('?').ok_or("query")?.1)?;
    fields.iter_mut().find(|(k,_)| k=="authorization_details").ok_or("details")?.1 = json!([
        {"type":TYPE,"locations":[format!("{}/organizations",state.issuer)],"privileges":[PRIVILEGE],"selection":"interactive"}
    ]).to_string();
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string(fields)?
    ))
}

async fn redeem(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    value: &str,
) -> TestResult<Value> {
    let signed = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let (status, body) = http(
        state,
        "/token",
        OWNER,
        &[
            ("grant_type", "authorization_code"),
            ("code", value),
            ("redirect_uri", "https://example.test/cb"),
            ("code_verifier", VERIFIER),
        ],
        Some(&signed),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body)
}

async fn discovery_parent(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    sid: &str,
) -> TestResult<Value> {
    let ordinary = authorize(state, key)?;
    let mut fields: Vec<(String, String)> =
        serde_urlencoded::from_str(ordinary.split_once('?').ok_or("query")?.1)?;
    fields.retain(|(k, _)| k != "authorization_details");
    for (k, v) in &mut fields {
        if k == "resource" {
            *v = format!("{}/organization-discovery", state.issuer);
        }
        if k == "scope" {
            *v = DISCOVERY_SCOPE.into();
        }
    }
    let uri = format!("/authorize?{}", serde_urlencoded::to_string(fields)?);
    let (status, html) = page(state, sid, &uri, None).await?;
    assert_eq!(status, StatusCode::OK, "{html}");
    let form = [
        ("transaction", transaction(&html)?),
        ("decision", "approve"),
    ];
    let (status, approved) = page(state, sid, "/auth/consent", Some(&form)).await?;
    assert_eq!(status, StatusCode::OK, "{approved}");
    redeem(state, key, &code(&approved, &state.issuer)?).await
}

async fn memberships(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
    query: &str,
) -> TestResult<(StatusCode, Value)> {
    let signed = super::super::proof(
        state,
        key,
        token,
        "GET",
        json!({"htu":format!("{}/organizations/memberships",state.issuer)}),
    )?;
    get(
        state,
        Method::GET,
        &format!("/organizations/memberships?{query}"),
        Some(&format!("DPoP {token}")),
        Some(&signed),
        "",
    )
    .await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_selection_browser_to_existing_exchange() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result=fixture::in_epoch(&state,Box::pin(async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let subject=format!("organization-user-{}",f.users[1]);
        let sid=session(&state,subject.clone()).await?;
        let other=session(&state,subject).await?;
        let uri=selector_uri(&state,&key)?;
        let (status,html)=page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        assert!(html.contains("Select organization") && html.contains(IDENTIFIER));
        assert!(!html.contains("Allow access"));
        let picker=transaction(&html)?.to_owned();
        let select=[("transaction",picker.as_str()),("decision","select:0")];
        assert_eq!(page(&state,&other,"/auth/consent",Some(&select)).await?.0,StatusCode::BAD_REQUEST);
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&[("transaction",picker.as_str()),("decision","approve")])).await?.0,StatusCode::BAD_REQUEST);
        let (status,consent)=page(&state,&sid,"/auth/consent",Some(&select)).await?;
        assert_eq!(status,StatusCode::OK,"{consent}");
        assert!(consent.contains("Organization access") && consent.contains(IDENTIFIER) && consent.contains(PRIVILEGE));
        assert!(code(&consent,&state.issuer).is_err(),"selection must not issue a code");
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&select)).await?.0,StatusCode::BAD_REQUEST);
        let approval=[("transaction",transaction(&consent)?),("decision","approve")];
        let (status,approved)=page(&state,&sid,"/auth/consent",Some(&approval)).await?;
        assert_eq!(status,StatusCode::OK,"{approved}");
        let parent=redeem(&state,&key,&code(&approved,&state.issuer)?).await?;
        assert_eq!(parent["authorization_details"][0]["type"],GRANT_TYPE);
        assert_eq!(parent["authorization_details"][0]["organizations"][0]["identifier"],IDENTIFIER);
        assert!(parent["refresh_token"].is_string());
        let token=parent["access_token"].as_str().ok_or("parent")?;
        let details=json!([{"type":crate::organizations::ORGANIZATION_ACCESS_TYPE,"identifier":IDENTIFIER,"privileges":[PRIVILEGE]}]).to_string();
        let signed=crate::web::test_support::native_dpop::proof(&state,&key,json!({}))?;
        let (status,selected)=http(&state,"/token",OWNER,&[("grant_type",TOKEN_EXCHANGE_GRANT_TYPE),("subject_token",token),("subject_token_type","urn:ietf:params:oauth:token-type:access_token"),("audience",&format!("{}/organizations",state.issuer)),("authorization_details",&details)],Some(&signed),false).await?;
        assert_eq!(status,StatusCode::OK,"{selected}");
        let selected=selected["access_token"].as_str().ok_or("selected")?;
        let signed=super::super::proof(&state,&key,selected,"GET",json!({}))?;
        assert_eq!(get(&state,Method::GET,PATH,Some(&format!("DPoP {selected}")),Some(&signed),"").await?.0,StatusCode::OK);
        let discovery=discovery_parent(&state,&key,&sid).await?;
        assert!(discovery.get("refresh_token").is_none());
        assert!(discovery["expires_in"].as_u64().is_some_and(|v| v<=300));
        let discovery=discovery["access_token"].as_str().ok_or("discovery")?;
        let query=serde_urlencoded::to_string([("audience",format!("{}/organizations",state.issuer))])?;
        let (status,body)=memberships(&state,&key,discovery,&query).await?;
        assert_eq!(status,StatusCode::OK,"{body}");
        assert_eq!(body,json!({"organizations":[{"identifier":IDENTIFIER}],"next_cursor":null}));
        assert_eq!(memberships(&state,&key,selected,&query).await?.0,StatusCode::UNAUTHORIZED);
        assert_eq!(memberships(&state,&key,token,&query).await?.0,StatusCode::UNAUTHORIZED);
        let signed=crate::web::test_support::native_dpop::proof(&state,&key,json!({}))?;
        let (status,body)=http(&state,"/token",OWNER,&[("grant_type",TOKEN_EXCHANGE_GRANT_TYPE),("subject_token",discovery),("subject_token_type","urn:ietf:params:oauth:token-type:access_token"),("audience",&format!("{}/organizations",state.issuer)),("authorization_details",&details)],Some(&signed),false).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"{body}");
        assert_eq!(body["error"],"invalid_grant");
        // More than one page, with minimal projection and a fresh proof per page.
        for i in 0..26 {
            let id=uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,$4,'active')")
                .bind(id).bind(state.environment_id).bind(f.organization.scope.domain_id).bind(format!("page-{i:02}")).execute(&f.pool).await?;
            sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,gen_random_uuid(),'active','[\"reader\"]')")
                .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(id).bind(f.users[1]).execute(&f.pool).await?;
        }
        let (status,first)=memberships(&state,&key,discovery,&query).await?;
        assert_eq!(status,StatusCode::OK,"{first}");
        assert_eq!(first["organizations"].as_array().ok_or("first page")?.len(),25);
        let cursor=first["next_cursor"].as_str().ok_or("cursor")?;
        let wrong_key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        assert_eq!(memberships(&state,&wrong_key,discovery,&query).await?.0,StatusCode::UNAUTHORIZED);
        let continued=serde_urlencoded::to_string([("audience",format!("{}/organizations",state.issuer)),("cursor",cursor.to_owned())])?;
        let foreign_sid=session(&state,format!("organization-user-{}",f.users[0])).await?;
        let foreign=discovery_parent(&state,&key,&foreign_sid).await?;
        assert_eq!(memberships(&state,&key,foreign["access_token"].as_str().ok_or("foreign")?,&continued).await?.0,StatusCode::BAD_REQUEST);
        let (status,last)=memberships(&state,&key,discovery,&continued).await?;
        assert_eq!(status,StatusCode::OK,"{last}");
        assert_eq!(last["organizations"].as_array().ok_or("last page")?.len(),2);
        assert!(last["next_cursor"].is_null());
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=version+1 WHERE environment_id=$1 AND role_key='reader'").bind(state.environment_id).execute(&f.pool).await?;
        assert_eq!(memberships(&state,&key,discovery,&continued).await?.0,StatusCode::BAD_REQUEST);
        sqlx::query("UPDATE aegaeon.organization_memberships SET state='suspended',revision=revision+1,grant_generation=grant_generation+1 WHERE environment_id=$1 AND end_user_id=$2")
            .bind(state.environment_id).bind(f.users[1]).execute(&f.pool).await?;
        let (status,body)=memberships(&state,&key,discovery,&query).await?;
        assert_eq!(status,StatusCode::OK,"{body}");assert_eq!(body["organizations"],json!([]));
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selection_rejects_stale_membership_and_expired_choice(
) -> TestResult {
    let f = Fixture::with_identifier("<School & \"Team\">").await?;
    let state = configured_discovery(&f).await?;
    let result=fixture::in_epoch(&state,Box::pin(async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid=session(&state,format!("organization-user-{}",f.users[1])).await?;
        let uri=selector_uri(&state,&key)?;
        let (status,html)=page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        assert!(html.contains("&lt;School &amp; &quot;Team&quot;&gt;") && !html.contains("<School"));
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=version+1 WHERE environment_id=$1 AND role_key='reader'").bind(state.environment_id).execute(&f.pool).await?;
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&[("transaction",transaction(&html)?),("decision","select:0")])).await?.0,StatusCode::BAD_REQUEST);
        let (status,html)=page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        sqlx::query("UPDATE aegaeon.authorization_consents SET expires_at=now()-interval '1 second' WHERE environment_id=$1").bind(state.environment_id).execute(&f.pool).await?;
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&[("transaction",transaction(&html)?),("decision","select:0")])).await?.0,StatusCode::BAD_REQUEST);
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selection_denial_csrf_and_changed_client() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let uri = selector_uri(&state, &key)?;
        let (_, html) = page(&state, &sid, &uri, None).await?;
        let transaction_id = transaction(&html)?;
        let form = [("transaction", transaction_id), ("decision", "select:0")];
        let mut request = Request::post("/auth/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
            .body(Body::from(serde_urlencoded::to_string(form)?))?;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127,0,0,1],12543))));
        let response = crate::web::build_router(state.clone()).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "missing Origin");
        assert_eq!(page(&state, &sid, "/auth/consent", Some(&[("transaction",transaction_id),("decision","select:0"),("identifier","forged")])).await?.0,StatusCode::BAD_REQUEST);
        let saved:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_consents WHERE environment_id=$1 AND decision IS NULL ORDER BY created_at DESC LIMIT 1")
            .bind(state.environment_id).fetch_one(&f.pool).await?;
        assert_eq!(saved["authorization"]["request"]["authorization_details"][0]["type"],TYPE);
        assert!(saved["authorization"]["request"]["authorization_details"][0].get("organizations").is_none());
        let (_,denied)=page(&state,&sid,"/auth/consent",Some(&[("transaction",transaction_id),("decision","deny")])).await?;
        assert!(denied.contains("access_denied") && code(&denied,&state.issuer).is_err());
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&form)).await?.0,StatusCode::BAD_REQUEST);
        let (_,html)=page(&state,&sid,&uri,None).await?;
        let (_,approval)=page(&state,&sid,"/auth/consent",Some(&[("transaction",transaction(&html)?),("decision","select:0")])).await?;
        let approval_snapshot:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_consents WHERE environment_id=$1 AND decision IS NULL AND authorize_uri='/authorize' ORDER BY created_at DESC LIMIT 1")
            .bind(state.environment_id).fetch_one(&f.pool).await?;
        assert_eq!(approval_snapshot["authorization"],saved["authorization"],"selection must preserve admitted input");
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET revision=revision+1 WHERE environment_id=$1")
            .bind(state.environment_id).execute(&f.pool).await?;
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&[("transaction",transaction(&approval)?),("decision","approve")])).await?.0,StatusCode::BAD_REQUEST);
        let mut fields:Vec<(String,String)>=serde_urlencoded::from_str(uri.split_once('?').ok_or("query")?.1)?;
        fields.iter_mut().find(|(k,_)|k=="prompt").ok_or("prompt")?.1="none".into();
        let no_prompt=format!("/authorize?{}",serde_urlencoded::to_string(fields)?);
        let (_,body)=page(&state,&sid,&no_prompt,None).await?;
        assert!(!body.contains("Select organization") && transaction(&body).is_err());
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
