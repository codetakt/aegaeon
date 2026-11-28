//! Direct same-issuer requests. Never follow redirects with a bearer proof,
//! confidential credential, PKCE verifier or authorization code.
use super::{Error, ProofKey};
use serde_json::Value;
use std::time::Duration;

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) json: Value,
    pub(super) etag: Option<String>,
}
fn client() -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8));
    // A deployment can add its private issuer CA. Read a bounded regular PEM
    // file. The certificate chain and exact issuer hostname are still verified.
    if let Some(path) = std::env::var_os("AEGAEON_HOSTED_INVITATION_CA_FILE") {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(path)
            .map_err(|_| Error::Unavailable)?;
        if !file
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() <= 65536)
        {
            return Err(Error::Unavailable);
        }
        let mut pem = Vec::new();
        file.take(65537)
            .read_to_end(&mut pem)
            .map_err(|_| Error::Unavailable)?;
        if pem.len() > 65536 {
            return Err(Error::Unavailable);
        }
        let roots = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| Error::Unavailable)?;
        if roots.is_empty() {
            return Err(Error::Unavailable);
        }
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    builder.build().map_err(|_| Error::Unavailable)
}
pub(super) fn form(
    url: &str,
    client_id: &str,
    secret: &str,
    fields: &[(&str, &str)],
) -> Result<reqwest::RequestBuilder, Error> {
    if secret.is_empty() {
        return Err(Error::Unavailable);
    }
    Ok(client()?
        .post(url)
        .basic_auth(
            crate::oauth_basic::encode_component(client_id),
            Some(crate::oauth_basic::encode_component(secret)),
        )
        .form(fields))
}
fn secret_header(value: &str) -> Result<reqwest::header::HeaderValue, Error> {
    let mut header = reqwest::header::HeaderValue::from_str(value).map_err(|_| Error::Refused)?;
    header.set_sensitive(true);
    Ok(header)
}
pub(super) fn json(url: &str, token: &str, body: &Value) -> Result<reqwest::RequestBuilder, Error> {
    Ok(client()?
        .post(url)
        .header("Authorization", secret_header(&format!("DPoP {token}"))?)
        .json(body))
}
pub(super) async fn send(
    req: reqwest::RequestBuilder,
    url: &str,
    proof: Option<(&ProofKey, Option<&str>)>,
) -> Result<Response, Error> {
    let req = req.header(reqwest::header::USER_AGENT, "Aegaeon-Hosted-Invitations");
    let mut nonce = None;
    for attempt in 0..2 {
        let mut req = req.try_clone().ok_or(Error::Unavailable)?;
        if let Some((key, access)) = proof {
            req = req.header(
                "DPoP",
                secret_header(&key.proof(url, access, nonce.as_deref())?)?,
            );
        }
        let mut response = req.send().await.map_err(|_| Error::Unavailable)?;
        let code = response.status().as_u16();
        if response.status().is_redirection() {
            return Err(Error::Refused);
        }
        let next_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty() && v.len() <= 512)
            .map(str::to_owned);
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() <= 256)
            .map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 64 * 1024 {
                return Err(Error::Refused);
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            crate::util::deserialize_json_without_duplicate_object_keys(&bytes)
                .map_err(|_| Error::Unavailable)?
        };
        if attempt == 0
            && matches!(code, 400 | 401)
            && next_nonce.is_some()
            && proof.is_some()
            && value.get("error").and_then(Value::as_str) == Some("use_dpop_nonce")
        {
            nonce = next_nonce;
            continue;
        }
        return Ok(Response {
            status: code,
            json: value,
            etag,
        });
    }
    Err(Error::Unavailable)
}
