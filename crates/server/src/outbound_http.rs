use std::{fmt, io::Read};

use reqwest::header::CONTENT_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedBodyError {
    InvalidContentLength,
    TooLarge { observed: u64, max: usize },
    ReadFailed(String),
}

impl fmt::Display for BoundedBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContentLength => write!(f, "invalid content-length header"),
            Self::TooLarge { observed, max } => {
                write!(f, "response body too large: {observed} bytes (max {max})")
            }
            Self::ReadFailed(message) => write!(f, "response body read failed: {message}"),
        }
    }
}

impl std::error::Error for BoundedBodyError {}

fn content_length(headers: &reqwest::header::HeaderMap) -> Result<Option<u64>, BoundedBodyError> {
    headers
        .get(CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|raw| raw.parse::<u64>().ok())
                .ok_or(BoundedBodyError::InvalidContentLength)
        })
        .transpose()
}

fn validate_content_length(
    headers: &reqwest::header::HeaderMap,
    max_bytes: usize,
) -> Result<(), BoundedBodyError> {
    match content_length(headers)? {
        Some(length) if length > max_bytes as u64 => Err(BoundedBodyError::TooLarge {
            observed: length,
            max: max_bytes,
        }),
        _ => Ok(()),
    }
}

fn read_cap(max_bytes: usize) -> u64 {
    max_bytes.saturating_add(1) as u64
}

fn validate_buffer_len(bytes: &[u8], max_bytes: usize) -> Result<(), BoundedBodyError> {
    if bytes.len() > max_bytes {
        return Err(BoundedBodyError::TooLarge {
            observed: bytes.len() as u64,
            max: max_bytes,
        });
    }
    Ok(())
}

/// Read a blocking reqwest response while enforcing a hard byte cap.
///
/// This rejects oversized `Content-Length` values before reading and never reads more than
/// `max_bytes + 1` bytes when the peer omits or lies about `Content-Length`.
pub fn read_blocking_response_body_limited(
    mut response: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedBodyError> {
    validate_content_length(response.headers(), max_bytes)?;
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(read_cap(max_bytes))
        .read_to_end(&mut bytes)
        .map_err(|err| BoundedBodyError::ReadFailed(err.to_string()))?;
    validate_buffer_len(&bytes, max_bytes)?;
    Ok(bytes)
}

/// Read an async reqwest response while enforcing a hard byte cap.
///
/// This rejects oversized `Content-Length` values before reading and stops as soon as the
/// accumulated body exceeds `max_bytes`.
pub async fn read_response_body_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedBodyError> {
    validate_content_length(response.headers(), max_bytes)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| BoundedBodyError::ReadFailed(err.to_string()))?
    {
        let observed = bytes.len().saturating_add(chunk.len());
        if observed > max_bytes {
            return Err(BoundedBodyError::TooLarge {
                observed: observed as u64,
                max: max_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    #[test]
    fn invalid_content_length_is_rejected() -> TestResult {
        let mut headers = reqwest::header::HeaderMap::new();
        let value = "not-a-number"
            .parse()
            .map_err(|err| format!("invalid test header value: {err}"))?;
        headers.insert(CONTENT_LENGTH, value);

        assert_eq!(
            validate_content_length(&headers, 16),
            Err(BoundedBodyError::InvalidContentLength)
        );
        Ok(())
    }

    #[test]
    fn oversized_content_length_is_rejected_before_read() -> TestResult {
        let mut headers = reqwest::header::HeaderMap::new();
        let value = "17"
            .parse()
            .map_err(|err| format!("valid test header value: {err}"))?;
        headers.insert(CONTENT_LENGTH, value);

        assert_eq!(
            validate_content_length(&headers, 16),
            Err(BoundedBodyError::TooLarge {
                observed: 17,
                max: 16
            })
        );
        Ok(())
    }
}
