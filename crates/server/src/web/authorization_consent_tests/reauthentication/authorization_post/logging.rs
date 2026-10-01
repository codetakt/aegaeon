use super::*;
use std::sync::Mutex;
use tracing::instrument::WithSubscriber;

#[derive(Clone)]
struct Writer(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log lock"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Writer(buffer.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let uri = authorize_uri(state, Some("login consent"))?;
    let mut pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query")?.1)?;
    for (k, v) in &mut pairs {
        if k == "state" {
            *v = "sensitive-post-state-marker".into();
        }
        if k == "nonce" {
            *v = "sensitive-post-nonce-marker".into();
        }
    }
    pairs.push(("max_age".into(), "0".into()));
    let uri = format!("/authorize?{}", serde_urlencoded::to_string(pairs)?);
    let sensitive = async {
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = post_input(&mut browser, state, &uri).await?;
        let login = page.location.ok_or("login")?;
        let page = browser.request(state, &login, None).await?;
        let return_to = field(&page.body, "return_to")?;
        let csrf = field(&page.body, "csrf_token")?;
        assert!(!page.body.contains("sensitive-post-"));
        assert!(!login.contains("sensitive-post-"));
        let failed = super::super::negative::login(
            &mut browser,
            state,
            &return_to,
            &csrf,
            "sensitive-password-marker",
        )
        .await?;
        assert_eq!(failed.status, StatusCode::UNAUTHORIZED);
        assert!(
            !failed.body.contains("sensitive-post-")
                && !failed.body.contains("sensitive-password-marker")
        );
        let csrf = field(&failed.body, "csrf_token")?;
        let logged =
            super::super::negative::login(&mut browser, state, &return_to, &csrf, PASSWORD).await?;
        assert_eq!(logged.status, StatusCode::SEE_OTHER);
        let page = browser.request(state, &return_to, None).await?;
        assert_eq!(page.status, StatusCode::OK);
        assert!(!page.body.contains("sensitive-post-"));
        let token = transaction(&page.body)?.to_string();
        let new_sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("session")?;
        // The inherited helper injects a closed database pool at the actual
        // consent handler, after middleware, and observes its static error path.
        super::super::super::storage_failure(state, new_sid, &token).await?;
        let jwt = request_objects::signed_request(state, "jar-login")?;
        let object_uri =
            request_objects::authorization_uri(state, new_sid, &jwt, "jar-login").await?;
        let object_page = post_input(&mut browser, state, &object_uri).await?;
        assert_eq!(object_page.status, StatusCode::FOUND);
        Ok::<_, Box<dyn std::error::Error>>((return_to, token, jwt))
    }
    .with_subscriber(subscriber)
    .await?;
    let logs = String::from_utf8(buffer.lock().map_err(|_| "log lock")?.clone())?;
    assert!(
        logs.contains("step-up authentication required")
            && logs.contains("consent_storage_unavailable"),
        "expected actual diagnostic paths"
    );
    for forbidden in [
        "sensitive-post-state-marker",
        "sensitive-post-nonce-marker",
        "sensitive-password-marker",
        PASSWORD,
        "login consent",
        sensitive.0.as_str(),
        sensitive.1.as_str(),
        sensitive.2.as_str(),
    ] {
        assert!(
            !logs.contains(forbidden),
            "sensitive payload reached diagnostics"
        );
    }
    let token = sensitive
        .0
        .strip_prefix("/authorize?aeg_login_continue=")
        .ok_or("token")?;
    assert!(!logs.contains(token));
    Ok(())
}
