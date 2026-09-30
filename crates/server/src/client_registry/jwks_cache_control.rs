//! Explicit application policy for parsed OP client keys, not an HTTP cache.
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AGE, CACHE_CONTROL, DATE, EXPIRES, VARY,
};
use std::time::{Duration, Instant};

use super::jwks_validators::{parse_http_date, DateContext, DateError, HttpDate, Metadata};
use super::MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS;

mod grammar;
use grammar::{control, delta_seconds, trim_ows, vary};

#[derive(Clone, Debug, Default)]
pub(super) struct CacheControl {
    pub(super) no_store: bool,
    pub(super) no_cache: bool,
    pub(super) private: bool,
    pub(super) max_age: Option<u64>,
    pub(super) s_maxage: Option<u64>,
}

#[derive(Clone, Debug)]
pub(super) struct CacheMetadata {
    control: Metadata<CacheControl>,
    date: Metadata<HttpDate>,
    age: Metadata<u64>,
    expires: Metadata<HttpDate>,
    vary: Metadata<bool>,
}

fn date_field(headers: &HeaderMap, name: HeaderName, context: DateContext) -> Metadata<HttpDate> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Metadata::Absent;
    };
    if values.next().is_some() {
        return Metadata::Multiple;
    }
    match HeaderValue::from_bytes(trim_ows(first.as_bytes()))
        .ok()
        .map(|value| parse_http_date(value, context))
    {
        Some(Ok(date)) => Metadata::Valid(date),
        Some(Err(DateError::ClockOutOfRange)) => Metadata::ClockOutOfRange,
        _ => Metadata::Invalid,
    }
}

impl CacheMetadata {
    pub(super) fn from_headers(headers: &HeaderMap, context: DateContext) -> Self {
        let age = match headers.get_all(AGE).iter().next() {
            None => Metadata::Absent,
            Some(value) => delta_seconds(trim_ows(
                value
                    .as_bytes()
                    .split(|b| *b == b',')
                    .next()
                    .unwrap_or_default(),
            ))
            .map_or(Metadata::Invalid, Metadata::Valid),
        };
        Self {
            control: control(headers),
            date: date_field(headers, DATE, context),
            age,
            expires: date_field(headers, EXPIRES, context),
            vary: vary(headers),
        }
    }

    // Whole-group replacement. Absent validation Date/Age intentionally start
    // a new exchange; an absent Cache-Control/Expires/Vary inherits its group.
    pub(super) fn freshen(&self, headers: &HeaderMap, context: DateContext) -> Self {
        let mut next = Self::from_headers(headers, context);
        if !headers.contains_key(CACHE_CONTROL) {
            next.control = self.control.clone();
        }
        if !headers.contains_key(EXPIRES) {
            next.expires = self.expires.clone();
        }
        if !headers.contains_key(VARY) {
            next.vary = self.vary.clone();
        }
        next
    }

    pub(super) fn permits_retention(&self) -> bool {
        matches!(
            &self.control,
            Metadata::Absent
                | Metadata::Valid(CacheControl {
                    no_store: false,
                    private: false,
                    ..
                })
        ) && matches!(&self.vary, Metadata::Absent | Metadata::Valid(false))
    }

    fn no_cache(&self) -> bool {
        matches!(&self.control, Metadata::Valid(cc) if cc.no_cache)
    }

    fn date_nanos(&self, timing: ResponseTiming) -> Option<i128> {
        match &self.date {
            Metadata::Absent => timing.receipt_utc,
            Metadata::Valid(date) => date.unix_nanos(),
            _ => None,
        }
    }

    fn lifetime(&self, date: Option<i128>, default_ttl: u64) -> Option<u128> {
        let explicit = match &self.control {
            Metadata::Valid(cc) => match (cc.s_maxage, cc.max_age) {
                (Some(shared), Some(max)) => Some(shared.min(max)),
                (Some(n), None) | (None, Some(n)) => Some(n),
                _ => None,
            },
            Metadata::Absent => None,
            _ => return None,
        };
        if let Some(seconds) = explicit {
            return Some(
                Duration::from_secs(seconds.min(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS)).as_nanos(),
            );
        }
        let nanos = match &self.expires {
            Metadata::Absent => Duration::from_secs(default_ttl).as_nanos(),
            Metadata::Invalid => 0, // Includes Expires: 0; never heuristic.
            Metadata::Valid(expires) => positive_difference(expires.unix_nanos()?, date?)?,
            _ => return None,
        };
        Some(nanos.min(Duration::from_secs(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS).as_nanos()))
    }

    pub(super) fn freshness(&self, timing: ResponseTiming, default_ttl: u64) -> Freshness {
        let date = self.date_nanos(timing);
        let initial_age = (|| {
            let receipt_utc = timing.receipt_utc?;
            let apparent_age = positive_difference(receipt_utc, date?)?;
            let delay = timing
                .receipt
                .checked_duration_since(timing.request)?
                .as_nanos();
            let age = match self.age {
                Metadata::Absent => 0,
                Metadata::Valid(seconds) => Duration::from_secs(seconds).as_nanos(),
                _ => return None,
            };
            Some(apparent_age.max(saturated_age(age, delay)))
        })();
        Freshness {
            receipt: timing.receipt,
            initial_age,
            lifetime: self.lifetime(date, default_ttl),
            no_cache: self.no_cache(),
        }
    }
}

fn positive_difference(later: i128, earlier: i128) -> Option<u128> {
    Some(
        u128::try_from(later.checked_sub(earlier)?.max(0))
            .ok()?
            .min(Duration::MAX.as_nanos()),
    )
}

fn saturated_age(a: u128, b: u128) -> u128 {
    a.saturating_add(b).min(Duration::MAX.as_nanos())
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ResponseTiming {
    pub(super) request: Instant,
    pub(super) receipt: Instant,
    pub(super) receipt_utc: Option<i128>,
}

impl ResponseTiming {
    pub(super) fn received(request: Instant) -> Self {
        let receipt = Instant::now();
        Self {
            request,
            receipt,
            receipt_utc: DateContext::capture().unix_nanos(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Freshness {
    pub(super) receipt: Instant,
    pub(super) initial_age: Option<u128>,
    pub(super) lifetime: Option<u128>,
    pub(super) no_cache: bool,
}

impl Freshness {
    pub(super) fn current_age(&self, now: Instant) -> Option<u128> {
        Some(saturated_age(
            self.initial_age?,
            now.checked_duration_since(self.receipt)?.as_nanos(),
        ))
    }

    pub(super) fn remaining(&self, now: Instant) -> Option<Duration> {
        let nanos = self.lifetime?.checked_sub(self.current_age(now)?)?;
        // Lifetime is capped to 86,400s before this conversion.
        Some(Duration::from_nanos(u64::try_from(nanos).ok()?))
    }

    pub(super) fn reusable(&self, now: Instant) -> bool {
        !self.no_cache
            && self
                .remaining(now)
                .is_some_and(|remaining| !remaining.is_zero())
    }

    pub(super) fn retention_deadline(&self, now: Instant, default_ttl: u64) -> Option<Instant> {
        let seconds = Duration::from_secs(default_ttl.min(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS));
        let remaining = self.remaining(now).unwrap_or(Duration::ZERO);
        now.checked_add(
            remaining
                .max(seconds)
                .min(Duration::from_secs(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS)),
        )
    }
}

// Compatibility for the existing test/Kani helper, never used for retention.
#[cfg(any(test, kani))]
pub(super) fn parse_cache_control(headers: &HeaderMap) -> Option<u64> {
    match control(headers) {
        Metadata::Valid(cc) if !cc.no_store && !cc.private => cc
            .max_age
            .map(|n| n.min(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
