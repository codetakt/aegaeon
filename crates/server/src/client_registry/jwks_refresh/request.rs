use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use reqwest::blocking::{Client, Request, Response};
use reqwest::header::{HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LOCATION, REFERER};
use reqwest::StatusCode;
use url::Url;

pub(super) enum RequestError {
    Transport,
    Correspondence,
}

pub(super) struct BoundResponse {
    pub(super) response: Response,
    pub(super) target: String,
    pub(super) timing: super::super::jwks_cache_control::ResponseTiming,
    pub(super) follows: usize,
}

impl BoundResponse {
    pub(super) fn validators(&self) -> super::super::jwks_validators::JwksValidators {
        super::super::jwks_validators::JwksValidators::from_headers(
            self.response.headers(),
            self.timing.date_context,
        )
    }
}

pub(super) fn target_identity(url: &Url) -> Option<String> {
    let mut transmitted = url.clone();
    transmitted.set_fragment(None);
    transmitted
        .as_str()
        .parse::<http::Uri>()
        .ok()
        .map(|uri| uri.to_string())
}

pub(super) fn is_supported_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

pub(super) fn redirect_location(bound: &BoundResponse) -> Result<Option<Url>, RequestError> {
    let Some(location) = bound.response.headers().get(LOCATION) else {
        return Ok(None);
    };
    let Some(relative) = std::str::from_utf8(location.as_bytes())
        .ok()
        .and_then(|text| UriReferenceStr::new(text).ok())
    else {
        return Ok(None);
    };
    let Ok(base) = UriAbsoluteString::try_from(bound.target.clone()) else {
        return Ok(None);
    };
    let resolved = relative.resolve_against(&base).to_string();
    let Ok(uri) = resolved.parse::<http::Uri>() else {
        return Ok(None);
    };
    Url::parse(&uri.to_string())
        .map(Some)
        .map_err(|_| RequestError::Transport)
}

fn referer(previous: &Url, next: &Url) -> Option<HeaderValue> {
    if previous.scheme() == "https" && next.scheme() == "http" {
        return None;
    }
    let mut value = previous.clone();
    let _ = value.set_username("");
    let _ = value.set_password(None);
    value.set_fragment(None);
    HeaderValue::from_str(value.as_str()).ok()
}

pub(super) fn original_request(client: &Client, uri: &str) -> Result<Request, RequestError> {
    client.get(uri).build().map_err(|_| RequestError::Transport)
}

pub(super) fn execute_phase(
    client: &Client,
    original_url: &Url,
    original_target: &str,
    conditional: Option<&(Option<HeaderValue>, Option<HeaderValue>)>,
) -> Result<BoundResponse, RequestError> {
    let mut url = original_url.clone();
    let mut previous = None;
    let mut follows = 0;
    loop {
        let mut builder = client.get(url.clone());
        if let Some((etag, date)) = conditional {
            if let Some(etag) = etag {
                builder = builder.header(IF_NONE_MATCH, etag.clone());
            }
            if let Some(date) = date {
                builder = builder.header(IF_MODIFIED_SINCE, date.clone());
            }
        }
        if let Some(previous) = previous.as_ref() {
            if let Some(value) = referer(previous, &url) {
                builder = builder.header(REFERER, value);
            }
        }
        let request = builder.build().map_err(|_| RequestError::Transport)?;
        let sent_url = request.url().clone();
        let target = target_identity(request.url()).ok_or(RequestError::Correspondence)?;
        if follows == 0 && target != original_target {
            return Err(RequestError::Correspondence);
        }
        // Capture the identity of this actual Request before execute consumes it.
        // The immutable client cannot automatically follow any request.
        let request_at = std::time::Instant::now();
        let response = client
            .execute(request)
            .map_err(|_| RequestError::Transport)?;
        let timing = super::super::jwks_cache_control::ResponseTiming::received(request_at);
        if target_identity(response.url()).as_deref() != Some(target.as_str()) {
            return Err(RequestError::Correspondence);
        }
        let bound = BoundResponse {
            response,
            target,
            timing,
            follows,
        };
        if conditional.is_some() || !is_supported_redirect(bound.response.status()) {
            return Ok(bound);
        }
        let Some(next) = redirect_location(&bound)? else {
            return Ok(bound);
        };
        if follows >= 2 {
            return Ok(bound);
        }
        crate::ssrf::validate_redirect_target(&next, None).map_err(|_| RequestError::Transport)?;
        // No previous request/default/proxy/conditional headers are copied.
        // Release the intermediate response before the next explicitly built GET.
        drop(bound);
        previous = Some(sent_url);
        url = next;
        follows += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn built_target_identity_retains_complete_resource_distinctions() {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let identity = |s: &str| target_identity(client.get(s).build().unwrap().url()).unwrap();
        assert_eq!(
            identity("https://1.1.1.1/a?q=1#fragment"),
            "https://1.1.1.1/a?q=1"
        );
        for (a, b) in [
            ("https://1.1.1.1/a", "https://1.1.1.1/b"),
            ("https://1.1.1.1/a", "https://1.1.1.1/a?"),
            ("https://1.1.1.1/a", "https://1.1.1.1:444/a"),
            ("https://1.1.1.1/%41", "https://1.1.1.1/A"),
        ] {
            assert_ne!(identity(a), identity(b));
        }
        assert_eq!(
            identity("https://1.1.1.1/dir/%2e%2e/jwks?x=1"),
            "https://1.1.1.1/jwks?x=1"
        );
        assert!(matches!(
            execute_phase(
                &client,
                &Url::parse("https://1.1.1.1/a").unwrap(),
                "https://1.1.1.1/b",
                None
            ),
            Err(RequestError::Correspondence)
        ));
    }
}
