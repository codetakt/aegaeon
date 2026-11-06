use super::super::jwks_cache_control::ResponseTiming;
use super::*;
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use reqwest::{
    header::{HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LOCATION},
    StatusCode,
};
use url::Url;

pub(super) fn client(
    policy: &JwksRuntimePolicy,
    loopback: bool,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .no_proxy()
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(policy.http_timeout_secs));
    if !(cfg!(test) && loopback) {
        builder = builder
            .https_only(true)
            .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver));
    }
    if let Some(path) = &policy.ca_bundle {
        let pem = std::fs::read(path).map_err(|_| unavailable())?;
        builder = builder
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).map_err(|_| unavailable())?);
    }
    builder.build().map_err(|_| unavailable())
}

pub(super) fn validate_target(
    policy: &JwksRuntimePolicy,
    uri: &str,
    redirect: bool,
) -> Result<Url, String> {
    if uri.len() > 8192 {
        return Err(unavailable());
    }
    let url = Url::parse(uri).map_err(|_| unavailable())?;
    if (!redirect && url.fragment().is_some())
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(unavailable());
    }
    if !redirect && super::super::jwks_url::jwks_http_loopback_allowed_for_tests(policy, uri) {
        return Ok(url);
    }
    if url.scheme() != "https" {
        return Err(unavailable());
    }
    // Syntactic/literal checks are nonblocking. Every actual resolution is checked
    // by NonRoutableDnsResolver, also for redirects, without a blocking DNS preflight.
    crate::ssrf::validate_url_host_not_non_routable_literal(&url).map_err(|_| unavailable())?;
    Ok(url)
}

fn target_identity(url: &Url) -> Option<String> {
    let mut url = url.clone();
    url.set_fragment(None);
    url.as_str()
        .parse::<http::Uri>()
        .ok()
        .map(|u| u.to_string())
}
fn redirected(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}
fn redirect_location(headers: &HeaderMap, target: &str) -> Result<Option<Url>, String> {
    let Some(value) = headers.get(LOCATION) else {
        return Ok(None);
    };
    let Some(relative) = std::str::from_utf8(value.as_bytes())
        .ok()
        .and_then(|s| UriReferenceStr::new(s).ok())
    else {
        return Ok(None);
    };
    let Ok(base) = UriAbsoluteString::try_from(target.to_string()) else {
        return Ok(None);
    };
    let resolved = relative.resolve_against(&base).to_string();
    let Ok(uri) = resolved.parse::<http::Uri>() else {
        return Ok(None);
    };
    Url::parse(&uri.to_string())
        .map(Some)
        .map_err(|_| unavailable())
}
struct BoundResponse {
    response: reqwest::Response,
    target: String,
    timing: ResponseTiming,
    follows: usize,
}
enum RequestError {
    Transport,
    Correspondence,
    UrlPolicy,
}

async fn phase(
    runtime: &NativeJwksRuntime,
    original: &Url,
    identity: &str,
    conditional: Option<&(Option<HeaderValue>, Option<HeaderValue>)>,
) -> Result<BoundResponse, RequestError> {
    let client = &runtime.client;
    #[cfg(test)]
    let client = if super::super::jwks_url::jwks_http_loopback_allowed_for_tests(
        &runtime.policy,
        original.as_str(),
    ) {
        &runtime.loopback_client
    } else {
        client
    };
    let mut url = original.clone();
    let mut follows = 0;
    loop {
        let mut request = client.get(url.clone());
        if let Some((etag, date)) = conditional {
            if let Some(etag) = etag {
                request = request.header(IF_NONE_MATCH, etag.clone());
            }
            if let Some(date) = date {
                request = request.header(IF_MODIFIED_SINCE, date.clone());
            }
        }
        let request = request.build().map_err(|_| RequestError::Transport)?;
        let target = target_identity(request.url()).ok_or(RequestError::Correspondence)?;
        if follows == 0 && target != identity {
            return Err(RequestError::Correspondence);
        }
        let start = Instant::now();
        let response = client
            .execute(request)
            .await
            .map_err(|_| RequestError::Transport)?;
        let timing = ResponseTiming::received(start);
        if target_identity(response.url()).as_deref() != Some(target.as_str()) {
            return Err(RequestError::Correspondence);
        }
        let bound = BoundResponse {
            response,
            timing,
            target,
            follows,
        };
        if conditional.is_some() || !redirected(bound.response.status()) {
            return Ok(bound);
        }
        let Some(next) = redirect_location(bound.response.headers(), &bound.target)
            .map_err(|_| RequestError::Transport)?
        else {
            return Ok(bound);
        };
        if follows >= 2 {
            return Ok(bound);
        }
        url = validate_target(&runtime.policy, next.as_str(), true)
            .map_err(|_| RequestError::UrlPolicy)?;
        drop(bound);
        follows += 1;
    }
}

pub(super) struct Fetched {
    pub(super) body: Arc<Body>,
    pub(super) metadata: CacheMetadata,
    pub(super) validators: JwksValidators,
    pub(super) timing: ResponseTiming,
    pub(super) target: String,
    pub(super) eligible: bool,
    pub(super) revalidated: bool,
    pub(super) header_charge: usize,
}

pub(super) async fn fetch(
    runtime: &NativeJwksRuntime,
    uri: &str,
    candidate: Option<Arc<Entry>>,
) -> Result<Fetched, String> {
    let uri_hash = super::super::sha256_hex(uri.as_bytes())[..8].to_string();
    let original = validate_target(&runtime.policy, uri, false)?;
    let identity = target_identity(&original).ok_or_else(unavailable)?;
    let mut conditional = candidate
        .as_ref()
        .filter(|e| e.target == identity)
        .and_then(|e| e.validators.conditional_headers());
    let mut attempt = 0u32;
    loop {
        let bound = match phase(runtime, &original, &identity, conditional.as_ref()).await {
            Ok(bound) => bound,
            Err(RequestError::Transport)
                if retry(&mut attempt, runtime.policy.http_retries).await =>
            {
                continue
            }
            Err(error) => {
                let reason = match error {
                    RequestError::Transport => "transport",
                    RequestError::Correspondence => "response_target",
                    RequestError::UrlPolicy => "url_policy",
                };
                super::super::metrics::record_jwks_http_failure_reason(reason, &uri_hash);
                return Err(unavailable());
            }
        };
        let status = bound.response.status();
        let validators =
            JwksValidators::from_headers(bound.response.headers(), bound.timing.date_context);
        let header_charge = bound
            .response
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len().saturating_add(v.as_bytes().len()))
            .sum::<usize>()
            .saturating_mul(4);
        if conditional.is_some() && status == StatusCode::NOT_MODIFIED {
            if let Some(entry) = candidate
                .as_ref()
                .filter(|e| validators.identifies(&e.validators))
            {
                let mut selected = entry.validators.clone();
                validators.update_selected(&mut selected);
                return Ok(Fetched {
                    body: entry.body.clone(),
                    metadata: entry
                        .metadata
                        .freshen(bound.response.headers(), bound.timing.date_context),
                    validators: selected,
                    timing: bound.timing,
                    target: bound.target,
                    eligible: true,
                    revalidated: true,
                    header_charge: header_charge.max(entry.header_charge),
                });
            }
            conditional = None;
            continue;
        }
        if conditional.is_some()
            && redirected(status)
            && redirect_location(bound.response.headers(), &bound.target)?.is_some()
        {
            conditional = None;
            continue;
        }
        if !status.is_success() {
            super::super::metrics::record_jwks_http_event(status.as_str(), &uri_hash);
            super::super::metrics::record_jwks_http_failure_reason("http_status", &uri_hash);
            drop(bound);
            if status.is_server_error() && retry(&mut attempt, runtime.policy.http_retries).await {
                continue;
            }
            return Err(unavailable());
        }
        return admit_response(runtime, bound, validators, header_charge, uri_hash).await;
    }
}
async fn admit_response(
    runtime: &NativeJwksRuntime,
    bound: BoundResponse,
    validators: JwksValidators,
    header_charge: usize,
    uri_hash: String,
) -> Result<Fetched, String> {
    let status = bound.response.status();
    let metadata = CacheMetadata::from_headers(bound.response.headers(), bound.timing.date_context);
    let bytes = crate::outbound_http::read_response_body_limited(
        bound.response,
        runtime.policy.max_body_bytes,
    )
    .await
    .map_err(|_| {
        super::super::metrics::record_jwks_http_failure_reason(
            "body_limit_or_transport",
            &uri_hash,
        );
        unavailable()
    })?;
    let body = crate::organizations::request_work::async_store::blocking(move || {
        let value =
            crate::util::deserialize_json_without_duplicate_object_keys(&bytes).map_err(|_| {
                super::super::metrics::record_jwks_http_failure_reason("json_parse", &uri_hash);
                unavailable()
            })?;
        let jwks = FetchedJwks::from_value(&value).map_err(|_| {
            super::super::metrics::record_jwks_http_failure_reason("key_validation", &uri_hash);
            unavailable()
        })?;
        let admission = AdmittedKeys::from_validated(&jwks)?;
        Ok::<_, String>(Arc::new(Body {
            jwks,
            admission,
            charge: bytes.len().saturating_mul(16).saturating_add(1024),
        }))
    })
    .await
    .map_err(|_| unavailable())??;
    Ok(Fetched {
        body,
        metadata,
        validators,
        timing: bound.timing,
        target: bound.target,
        eligible: status == StatusCode::OK && bound.follows == 0,
        revalidated: false,
        header_charge,
    })
}

async fn retry(attempt: &mut u32, retries: u32) -> bool {
    if *attempt >= retries.min(10) {
        return false;
    }
    *attempt += 1;
    tokio::time::sleep(Duration::from_millis(100 * (1 << *attempt))).await;
    true
}
